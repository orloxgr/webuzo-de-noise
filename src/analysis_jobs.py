"""Root-private, resumable panel observation of complete read-only reviews."""
import json
from contextlib import contextmanager
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

sys.dont_write_bytecode = True
sys.pycache_prefix = str(Path(__file__).resolve().parent / '.bytecode')
sys.path.insert(0, str(Path(__file__).resolve().parent))
import log_analysis
import storage
import listing
import review_findings


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
    if kind not in ('scan', 'activity', 'agents', 'php_files'):
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


@contextmanager
def report_database(path):
    database = path / 'report.sqlite'
    # The containing job has already passed actor, scope and kind checks.
    with storage.parent(database):
        info = database.lstat()
        import stat
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Untrusted analysis report database')
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
    try:
        yield connection
    finally:
        connection.close()


def agent_rows(state, job, actor, offset=0):
    """Read a bounded transfer chunk from one completed, immutable inventory."""
    if type(offset) is not int or offset < 0:
        raise ValueError('Invalid export offset')
    path = owned(state, job, actor, kind='agents')
    if read(path, 'status.json')['state'] != 'complete':
        raise ValueError('Complete the agent analysis first')
    analysis = read(path, 'result.json')
    total = analysis['findings_total']
    if offset > total:
        raise ValueError('Invalid export offset')
    if analysis.get('findings_database'):
        with report_database(path) as connection:
            rows = [json.loads(row[0]) for row in connection.execute(
                'SELECT payload FROM findings ORDER BY rank,count DESC,site,path LIMIT ? OFFSET ?', (500, offset))]
    else:
        rows = analysis['findings'][offset:offset + 500]
    if not rows and offset < total:
        raise ValueError('The agent report is incomplete')
    end = offset + len(rows)
    return dict(rows=rows, total=total,
                next_offset=end if end < total else None)


def export_agents(state, job, actor, offset=0):
    chunk = agent_rows(state, job, actor, offset)
    return {**chunk, 'rows': [[row['value'], row['count']] for row in chunk['rows']]}


def agent_candidates(state, job, actor, category, offset=0):
    """Only recognized literal names from this category, never arbitrary UAs."""
    import agent_catalog
    if not isinstance(category, str) or category not in agent_catalog.CATEGORIES:
        raise ValueError('Invalid agent category')
    chunk = agent_rows(state, job, actor, offset)
    names = agent_catalog.CATEGORIES[category]['entries'] + agent_catalog.EXTRA.get(category, [])
    known = {name.casefold(): name for name in names}
    candidates = []
    for row in chunk['rows']:
        value = row.get('candidate')
        if (row.get('category') == category and isinstance(value, str)
                and value.casefold() in known):
            candidates.append(known[value.casefold()])
    return dict(category=category, names=list(dict.fromkeys(candidates)),
                scanned=len(chunk['rows']), total=chunk['total'], next_offset=chunk['next_offset'])


def finding_rows(path, analysis):
    if analysis.get('findings_database'):
        with report_database(path) as connection:
            for (raw,) in connection.execute('SELECT payload FROM findings ORDER BY rank,count DESC,site,path'):
                yield json.loads(raw)
    else:
        yield from analysis.get('findings', [])


def php_features(kind):
    return review_findings.php_findings.TAGS if kind == 'php_files' else {
        k:v for k,v in review_findings.FEATURES.items() if k not in review_findings.php_findings.TAGS}


def finding_view(state, path, analysis, kind, chosen):
    values, available = [], set()
    saved = review_findings.notes(state)
    ignored = 0
    for row in finding_rows(path, analysis):
        for member in row.get('members') or [row]:
            item = member['value'] if kind == 'php_files' else member['path']
            for d in review_findings.domains(member, kind):
                available.add(d['domain'])
                if saved.get(review_findings.identity(kind, d['domain'], item), {}).get('state') == 'ignored': ignored += 1
        value = review_findings.view(row, kind, chosen, saved)
        if value is not None:
            if kind == 'scan' and not value.get('endpoint_work'):
                work = log_analysis.endpoint(value['path'])
                value['endpoint_work'] = [work] if work else []
            values.append(value)
    if kind == 'scan' and chosen['group_rejected']:
        from collections import Counter
        buckets, other = {}, []
        for row in values:
            rejected = sum(row.get('statuses', {}).get(code,0) for code in ('401','403','429'))
            if row.get('kind') == 'security' and rejected == row['count']:
                buckets.setdefault(row['domain'], []).append(row)
            else:
                other.append(row)
        for domain, members in buckets.items():
            if len(members) == 1:
                other.extend(members); continue
            statuses = Counter()
            for row in members: statuses.update(row['statuses'])
            group = dict(domain=domain, path='Rejected secret-file probes', kind='security', title='Rejected secret-file probes',
                         count=sum(r['count'] for r in members), statuses=dict(statuses), grouped_probes=members)
            group['review_info'] = review_findings.scan_info(group)
            other.append(group)
        values = other
    # Stable, explicit review priority first; frequency breaks ties.
    values.sort(key=lambda r: (('high','normal','low').index(r['review_info']['priority']), -r['count'], r.get('path',r.get('value',''))))
    revision = hashlib.sha256(storage.json_bytes([chosen, saved])).hexdigest()
    return values, dict(filter_domains=sorted(available), filters=chosen, filter_features=php_features(kind),
                        ignored_contributions=ignored, view_revision=revision)


def mark_review(state, job, actor, kind, domain, item, value):
    if kind not in ('scan', 'php_files') or not all(isinstance(x, str) for x in (domain,item,value)):
        raise ValueError('Invalid review note selection')
    path = owned(state, job, actor, kind=kind)
    if read(path, 'status.json')['state'] != 'complete':
        raise ValueError('Complete the review first')
    analysis = read(path, 'result.json')
    for row in finding_rows(path, analysis):
        for member in row.get('members') or [row]:
            target = member['value'] if kind == 'php_files' else member['path']
            if target == item and any(d['domain']==domain for d in review_findings.domains(member, kind)):
                review_findings.mark(state, actor, kind, domain, item, value)
                return dict(domain=domain, item=item, state=value)
    raise ValueError('Select an exact path and domain from this report')


def status(state, job, actor, page=1, kind="scan", owner=None, domain='all', per_page=20, filters=None):
    listing.size(per_page)
    chosen = review_findings.filters(filters)
    if filters is not None and kind not in ('scan', 'php_files'):
        raise ValueError('Finding filters apply only to log and PHP reviews')
    if type(page) is not int or page < 1:
        raise ValueError('Invalid report page')
    if kind == 'activity' and (not isinstance(domain, str) or not domain):
        raise ValueError('Select a site or all sites for Activity')
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
        if kind in ('scan', 'php_files'):
            values, view = finding_view(state, path, analysis, kind, chosen)
            meta = listing.pagination(len(values), page, per_page)
            limit, offset = listing.bounds(meta)
            analysis.update(view, review_total=analysis['findings_total'], findings_total=len(values),
                findings=values[offset:] if limit == -1 else values[offset:offset+limit],
                page=meta['page'], pages=meta['pages'], per_page=per_page)
            result['analysis'] = analysis
            return result
        if kind == 'activity':
            from datetime import datetime
            # This is a saved snapshot, not a new rolling "last N minutes" read.
            end = request['requested_at']
            analysis.setdefault('window_start', datetime.fromtimestamp(end - request['minutes'] * 60).astimezone().isoformat(timespec='seconds'))
            analysis.setdefault('window_end', datetime.fromtimestamp(end).astimezone().isoformat(timespec='seconds'))
            analysis['selected_domain'] = domain
            analysis['review_total'] = analysis['total']
            if domain != 'all':
                analysis['rows'] = [row for row in analysis['rows'] if row['domain'] == domain]
                analysis['total'] = sum(row['count'] for row in analysis['rows'])
                analysis['findings_total'] = analysis['total']
        # Display pages only; the complete report remains available on disk.
        total = analysis['findings_total']
        meta = listing.pagination(total, page, per_page)
        limit, offset = listing.bounds(meta)
        if analysis.get('findings_database'):
            with report_database(path) as connection:
                if kind == 'activity':
                    query = 'SELECT payload FROM events' + (' WHERE domain = ?' if domain != 'all' else '') + ' ORDER BY stamp DESC LIMIT ? OFFSET ?'
                    arguments = ((domain,) if domain != 'all' else ()) + (limit, offset)
                else:
                    query = 'SELECT payload FROM findings ORDER BY rank,count DESC,site,path LIMIT ? OFFSET ?'
                    arguments = (limit, offset)
                analysis['findings'] = [json.loads(row[0]) for row in connection.execute(query, arguments)]
        else:
            findings = analysis.get('findings', analysis.get('recent', []))
            if kind == 'activity' and domain != 'all':
                findings = [row for row in findings if row['domain'] == domain]
            analysis['findings'] = findings[offset:] if limit == -1 else findings[offset:offset + limit]
        analysis.update(page=meta['page'], pages=meta['pages'], per_page=per_page)
        if kind == 'agents':
            import agent_catalog
            for row in analysis['findings']:
                row['bot_info'] = agent_catalog.describe(row['value'])
        elif kind == 'php_files':
            import php_findings
            for row in analysis['findings']:
                row.setdefault('php_info', php_findings.describe(row['value'], row.get('candidate')))
        result['analysis'] = analysis
    return result


def export_review(state, job, actor, kind='scan', owner=None, domain='all', offset=0, filters=None):
    """Export complete saved results in transfer chunks, retaining ownership scope."""
    if kind not in ('scan', 'activity', 'php_files') or type(offset) is not int or offset < 0:
        raise ValueError('Invalid review export selection')
    # status validates job ownership, kind and current account scope before reads.
    report = status(state, job, actor, kind=kind, owner=owner, domain=domain,
                    per_page='all' if kind in ('scan','php_files') else 500, filters=filters)
    if report['state'] != 'complete':
        raise ValueError('Complete the review before exporting')
    analysis = report['analysis']; total = analysis['findings_total']
    if offset > total:
        raise ValueError('Invalid export offset')
    path = owned(state, job, actor, kind, owner)
    if kind in ('scan', 'php_files'):
        values = analysis['findings'][offset:offset+500]
    elif analysis.get('findings_database'):
        with report_database(path) as connection:
            if kind == 'activity':
                sql = 'SELECT payload FROM events' + (' WHERE domain=?' if domain != 'all' else '') + ' ORDER BY stamp DESC LIMIT 500 OFFSET ?'
                args = ((domain,) if domain != 'all' else ()) + (offset,)
            else:
                sql = 'SELECT payload FROM findings ORDER BY rank,count DESC,site,path LIMIT 500 OFFSET ?'
                args = (offset,)
            values = [json.loads(row[0]) for row in connection.execute(sql, args)]
    else:
        saved = read(path, 'result.json')
        values = saved.get('findings', saved.get('recent', []))
        if kind == 'activity' and domain != 'all':
            values = [row for row in values if row['domain']==domain]
        values = values[offset:offset+500]
    if not values and offset < total:
        raise ValueError('The saved report is incomplete')
    if kind == 'activity':
        columns = ['Time','Site','Rule','Declared agent','Result','HTTP status']
        rows = [[r.get(k,'') for k in ('time','domain','rule','agent','outcome','status')] for r in values]
    elif kind == 'php_files':
        import php_findings
        columns = ['PHP path','Hits','Source domains / hits','Classification','Explanation','First seen UTC','Last seen UTC',
                   'Review priority','Characteristics','Declared agents / hits','Distinct clients','Cross-domain clients','Multi-path clients','Review state / domain','Evidence scope','Busiest matching client']
        from datetime import datetime, timezone
        rows = []
        for group in values:
            for r in group.get('members') or [group]:
                info = r['php_info']
                rows.append([r['value'],r['count'],'; '.join(d['domain']+': '+str(d['count']) for d in r['domains']),
                    info['label'],info['reason'],*(datetime.fromtimestamp(r[k],timezone.utc).isoformat() if r.get(k) is not None else '' for k in ('first','last')),
                    info['priority_label'], '; '.join(php_findings.TAGS[t] for t in info['tags']),
                    '; '.join(a['agent']+': '+str(a['count']) for a in r.get('agents',[])),r.get('clients',''),r.get('cross_domain_clients',''),r.get('multi_path_clients',''),
                    '; '.join(m['domain']+': '+m['state'] for m in r.get('review_marks',[])), r.get('evidence_scope',''),json.dumps(r.get('busiest_client',{}))])
    else:
        columns = ['Site','Path','Finding','Hits','Distinct clients','Peak per minute','HTTP statuses','Advice',
                   'Parameter names','Methods','Declared agents','First seen UTC','Last seen UTC','Endpoint work','Review priority','Explanation','Review state','Native log files']
        from datetime import datetime, timezone
        exact_values = [r for group in values for r in group.get('grouped_probes', [group])]
        rows = [[r.get('domain',''),r.get('path',''),r.get('title',''),r.get('count',0),r.get('clients',0),
                 r.get('peak_per_minute',0),json.dumps(r.get('statuses',{})),r.get('advice',''),
                 '; '.join(r.get('parameters',[])),json.dumps(r.get('methods',{})),json.dumps(r.get('agents',{})),
                 *(datetime.fromtimestamp(r[k],timezone.utc).isoformat() if r.get(k) is not None else '' for k in ('first','last')),
                 '; '.join(r.get('endpoint_work',[])),r['review_info']['priority_label'],r['review_info']['reason'],
                 '; '.join(m['state'] for m in r.get('review_marks',[])), '; '.join(r.get('log_sources',[]))] for r in exact_values]
    end = offset+len(values)
    return dict(columns=columns, rows=rows, scanned=len(values), total=total, next_offset=end if end < total else None,
                view_revision=analysis.get('view_revision'))


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
                    report_path=path / 'report.sqlite', state=state,
                    include_webmail=any(site.get('shared_webmail') for site in sites))
            else:
                result = log_analysis.scan(sites, request['target'], request['minutes'], state,
                    request['verify_google'], now=request.get('requested_at'), progress=progress,
                    cancelled=lambda: (path / 'cancel.json').exists(), report_path=path / 'report.sqlite',
                    inventory_kind=request['kind'] if request.get('kind') in ('agents', 'php_files') else None)
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
