"""Root-private, resumable panel observation of complete read-only reviews."""
import json
import hashlib
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import sqlite3
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import log_analysis
import storage


def directory(state, job):
    if not isinstance(job, str) or not re.fullmatch('[0-9a-f]{32}', job):
        raise ValueError('Invalid analysis job identity')
    base = Path(state) / 'analysis-jobs'
    storage.private_directory(base)
    path = base / job
    if path.is_symlink() or not path.is_dir():
        raise ValueError('Unknown analysis job')
    storage.private_directory(path)
    return path


def read(path, filename):
    raw = storage.read(path / filename)
    return json.loads(raw) if raw is not None else None


def write(path, filename, value):
    storage.replace(path / filename, storage.json_bytes(value), 0o600)


def owned(state, job, actor, kind="scan", owner=None):
    path = directory(state, job)
    request = read(path, 'request.json')
    if (request['actor'] != actor or request.get('kind', 'scan') != kind or request.get('owner') != owner):
        raise PermissionError('Review job belongs to another account context')
    return path


def latest_name(actor, kind, owner):
    return 'latest-' + hashlib.sha256(json.dumps([actor, kind, owner]).encode()).hexdigest() + '.json'


def cleanup(state):
    import ban_history
    days = ban_history.settings(state)['days']
    base = Path(state) / 'analysis-jobs'
    if not base.exists():
        return
    storage.private_directory(base)
    for item in base.iterdir():
        if not re.fullmatch('[0-9a-f]{32}', item.name) or item.is_symlink() or not item.is_dir():
            continue
        storage.private_directory(item)
        request, current = read(item, 'request.json'), read(item, 'status.json')
        if (request and current and current['state'] in ('complete', 'failed', 'cancelled')
                and request.get('requested_at', time.time()) < time.time() - days * 86400):
            shutil.rmtree(item)  # Root-private completed reports only; never bans or active work.


def start(state, sites, actor, target, minutes, verify_google=False, kind="scan", owner=None):
    if kind not in ('scan', 'activity'):
        raise ValueError('Invalid review type')
    if owner is not None and (not isinstance(owner, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]*', owner)):
        raise PermissionError('Invalid account context')
    if sites is None:
        log_analysis.selection([], 'all', minutes)
        if not isinstance(target, str) or not target:
            raise ValueError('Select a web domain or all web domains')
    else:
        log_analysis.selection(sites, target, minutes)
    if type(verify_google) is not bool:
        raise ValueError('Invalid verification switch')
    base = Path(state) / 'analysis-jobs'
    storage.private_directory(base)
    if not isinstance(actor, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]*', actor):
        raise PermissionError('Invalid administrator identity')
    cleanup(state)
    job = secrets.token_hex(16)
    path = base / job
    path.mkdir(mode=0o700)
    write(path, 'request.json', dict(actor=actor, kind=kind, owner=owner, sites=sites, target=target, minutes=minutes, verify_google=verify_google, requested_at=time.time()))
    write(path, 'status.json', dict(state='queued', progress={}, created=time.time()))
    pid = launch_worker(state, job)
    write(path, 'process.json', {'pid': pid, 'worker': str(Path(__file__).resolve())})
    write(base, latest_name(actor, kind, owner), {'id': job})
    return {'id': job, 'state': 'queued', 'progress': {}}


def launch_worker(state, job):
    """Launch one detached review; its short-lived CLI parent may exit immediately."""
    argv = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), str(Path(state).resolve()), job]
    actions = [(os.POSIX_SPAWN_OPEN, descriptor, os.devnull, flags, 0o600)
               for descriptor, flags in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY))]
    return os.posix_spawn(sys.executable, argv,
                          {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'},
                          file_actions=actions, setsid=True)


def status(state, job, actor, page=1, kind="scan", owner=None):
    if type(page) is not int or page < 1:
        raise ValueError('Invalid report page')
    if not job:
        if not isinstance(actor, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]*', actor):
            raise PermissionError('Invalid administrator identity')
        base = Path(state) / 'analysis-jobs'
        storage.private_directory(base)
        latest = read(base, latest_name(actor, kind, owner))
        if not latest:
            return {'id': None, 'state': 'idle', 'progress': {}}
        job = latest['id']
        if not (base / job).is_dir():
            return {'id': None, 'state': 'idle', 'progress': {}}
    path = owned(state, job, actor, kind, owner)
    value = read(path, 'status.json')
    process = read(path, 'process.json')
    if value['state'] in ('queued', 'running') and process:
        try:
            command = (Path('/proc') / str(process['pid']) / 'cmdline').read_bytes().split(b'\0')
            if process.get('worker', str(Path(__file__).resolve())).encode() not in command or job.encode() not in command:
                raise ProcessLookupError()
        except (ProcessLookupError, FileNotFoundError):
            value = (dict(state='cancelled', progress=value.get('progress', {})) if (path / 'cancel.json').exists() else
                     dict(state='failed', error='The review process stopped before completing. Start a new review.', progress=value.get('progress', {})))
            write(path, 'status.json', value)
    request = read(path, 'request.json')
    result = {'id': job, **value, 'selection': {key: request[key] for key in ('target', 'minutes', 'verify_google')}}
    if value['state'] == 'complete':
        analysis = read(path, 'result.json')
        # Display pages only; the complete report remains available on disk.
        total = analysis['findings_total']
        pages = max(1, (total + 19) // 20)
        page = min(page, pages)
        if analysis.get('findings_database'):
            database = path / 'report.sqlite'
            # Ownership checks happen before SQLite opens the read-only URI.
            with storage.parent(database):
                info = database.lstat()
                import stat
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                    raise ValueError('Untrusted analysis report database')
            connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
            try:
                query = ('SELECT payload FROM events ORDER BY stamp DESC LIMIT ? OFFSET ?' if kind == 'activity' else
                         'SELECT payload FROM findings ORDER BY rank,count DESC,site,path LIMIT ? OFFSET ?')
                analysis['findings'] = [json.loads(row[0]) for row in connection.execute(query, (20, (page - 1) * 20))]
            finally:
                connection.close()
        else:
            analysis['findings'] = analysis['findings'][(page - 1) * 20:page * 20]
        analysis['page'] = page
        analysis['pages'] = pages
        result['analysis'] = analysis
    return result


def cancel(state, job, actor, kind="scan", owner=None):
    path = owned(state, job, actor, kind, owner)
    current = read(path, 'status.json')
    if current['state'] not in ('queued', 'running'):
        return {'id': job, **current}
    write(path, 'cancel.json', {'requested': time.time()})
    process = read(path, 'process.json')
    if process:
        pid = process['pid']
        try:
            command = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
            if (process.get('worker', str(Path(__file__).resolve())).encode() in command and job.encode() in command
                    and os.getpgid(pid) == pid):
                os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, FileNotFoundError):
            pass
    return {'id': job, 'state': 'cancelled', 'progress': read(path, 'status.json').get('progress', {})}


def worker(state, job):
    path = directory(state, job)
    request = read(path, 'request.json')
    last = 0
    progress_value = {}
    def progress(value):
        nonlocal last, progress_value
        progress_value = value
        if time.monotonic() - last >= 0.5:
            write(path, 'status.json', dict(state='running', progress=value))
            last = time.monotonic()
    def stop(*args):
        raise InterruptedError('Review cancelled by administrator')
    signal.signal(signal.SIGTERM, stop)
    try:
        os.nice(10)
        with log_analysis.scan_lock(state):
            if (path / 'cancel.json').exists():
                raise InterruptedError('Review cancelled by administrator')
            write(path, 'status.json', dict(state='running', progress={}))
            sites = request['sites']
            if sites is None:
                write(path, 'status.json', dict(state='running', progress={'stage': 'Discovering web domains'}))
                from engine import collect
                sites = collect()
            if request.get('owner') is not None:
                sites = [site for site in sites if site.get('owner') == request['owner']]
            if request.get('kind') == 'activity':
                import activity
                result = activity.summary({site['domain'] for site in sites}, now=request.get('requested_at'),
                    minutes=request['minutes'], progress=progress, cancelled=lambda: (path / 'cancel.json').exists(),
                    report_path=path / 'report.sqlite')
            else:
                result = log_analysis.scan(sites, request['target'], request['minutes'], state,
                    request['verify_google'], now=request.get('requested_at'), progress=progress,
                    cancelled=lambda: (path / 'cancel.json').exists(), report_path=path / 'report.sqlite')
            write(path, 'result.json', result)
            write(path, 'status.json', dict(state='complete', progress=progress_value))
    except InterruptedError:
        write(path, 'status.json', dict(state='cancelled', progress=progress_value))
    except Exception:
        # No raw log values or private paths/credentials in panel errors.
        write(path, 'status.json', dict(state='failed', progress=progress_value,
            error='Log review failed. No protection settings were changed.'))


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    if os.geteuid() != 0:
        raise PermissionError('Analysis worker requires root')
    worker(Path(sys.argv[1]), sys.argv[2])
