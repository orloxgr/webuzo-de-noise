#!/usr/bin/python3
"""Install/remove only De-Noise state and native custom-configuration hooks."""
import json
import os
from pathlib import Path
import stat
import sys
import pwd
import shlex

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine
import storage
import webuzo
import transport
import wordpress

LOGS = Path('/var/log/webuzo-de-noise')
CONFIG = Path('/etc/webuzo-de-noise')
MARKER = b'webuzo-de-noise\n'
CRON = Path('/etc/cron.d/webuzo-de-noise')
ROTATE = Path('/etc/logrotate.d/webuzo-de-noise')
TMPFILES = Path('/etc/tmpfiles.d/webuzo-de-noise.conf')
HEADER = b'# Managed by webuzo-de-noise\n'


def directory(path, mode):
    if not path.exists():
        path.mkdir(mode=mode)
    with storage.parent(path / '.check'):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError('Unexpected De-Noise directory permissions: ' + str(path))


def owned_artifact(path, data):
    previous = storage.read(path)
    if previous is not None and not previous.startswith(HEADER):
        raise ValueError('Existing integration file is not owned by De-Noise: ' + str(path))
    if previous != data:
        storage.replace(path, data, 0o644)
    return previous


def prepare_logs():
    directory(LOGS, 0o755)
    for name in ('matches.log', 'ban-events.log', 'maintenance.log'):
        path = LOGS / name
        if not path.exists():
            storage.replace(path, b'', 0o600)
        with storage.log_stream(path):
            pass


def artifacts():
    script = shlex.quote(str(Path(__file__).resolve().with_name('addon.py')))
    cron = (HEADER.decode() + 'SHELL=/bin/sh\nMAILTO=""\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
            '* * * * * root /usr/bin/flock -n /var/lib/webuzo-de-noise/maintenance.lock '
            '/usr/bin/python3 -I -B ' + script + ' sync >> /var/log/webuzo-de-noise/maintenance.log 2>&1\n')
    rotate = (HEADER.decode() + '/var/log/webuzo-de-noise/*.log {\n'
              '    daily\n    rotate 7\n    maxsize 10M\n    missingok\n    notifempty\n'
              '    compress\n    delaycompress\n    create 0640 root root\n    sharedscripts\n'
              '    postrotate\n        ' + shlex.quote(str(webuzo.NGINX)) + ' -s reopen\n    endscript\n}\n')
    tmpfiles = HEADER.decode() + 'd /run/webuzo-de-noise 0730 root webuzo -\n'
    return {CRON: cron.encode(), ROTATE: rotate.encode(), TMPFILES: tmpfiles.encode()}


def install():
    if not webuzo.NGINX.is_file():
        raise ValueError('The native Webuzo website Nginx is required')
    for path, mode in ((webuzo.STATE, 0o700), (CONFIG, 0o755),
                       (webuzo.SNIPPETS, 0o755), (LOGS, 0o755)):
        directory(path, mode)
    panel = pwd.getpwnam('webuzo')
    if panel.pw_uid == 0 or panel.pw_gid == 0:
        raise ValueError('Unexpected native panel identity')
    members = [entry for entry in pwd.getpwall() if entry.pw_gid == panel.pw_gid]
    import grp
    members += [pwd.getpwnam(name) for name in grp.getgrgid(panel.pw_gid).gr_mem]
    if any(entry.pw_uid not in (0, panel.pw_uid) for entry in members):
        raise ValueError('The native panel group includes a hosting account')
    if not transport.DIRECTORY.exists():
        transport.DIRECTORY.mkdir(mode=0o730)
        os.chown(transport.DIRECTORY, 0, panel.pw_gid)
        os.chmod(transport.DIRECTORY, 0o730)
    info = transport.DIRECTORY.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != panel.pw_gid or stat.S_IMODE(info.st_mode) != 0o730:
        raise ValueError('Untrusted panel request directory')
    prepare_logs()
    # Validate all destinations before applying any server integration.
    desired = artifacts()
    before = {}
    for path in desired:
        previous = storage.read(path)
        if previous is not None and not previous.startswith(HEADER):
            raise ValueError('Existing integration file is not owned by De-Noise: ' + str(path))
        before[path] = previous
    with engine.locked():
        engine.recover()
        previous_active = engine.load('active.json', None)
        sites = webuzo.collect()
        policy = engine.validate(engine.load('policy.json', engine.DEFAULT))
        result = engine.apply(policy, sites)
        try:
            for path, data in desired.items():
                owned_artifact(path, data)
            storage.replace(webuzo.STATE / 'active.json', storage.json_bytes({'active': True}), 0o600)
            wordpress.install(webuzo.STATE, webuzo.run)
        except Exception:
            for path, data in before.items():
                storage.replace(path, data, 0o644)
            storage.replace(webuzo.STATE / 'active.json', None if previous_active is None else storage.json_bytes(previous_active), 0o600)
            if not previous_active or previous_active.get('active') is not True:
                engine.apply(policy, sites, remove=True)
            raise
    return {'ok': True, **result}


def remove():
    if not webuzo.STATE.exists():
        return {'ok': True, 'state': 'disabled'}
    with engine.locked():
        engine.recover()
        policy = engine.validate(engine.load('policy.json', engine.DEFAULT))
        preference = wordpress.read_json(webuzo.STATE, wordpress.SETTINGS)
        wordpress.uninstall(webuzo.STATE, webuzo.run)
        if preference is not None:
            storage.replace(webuzo.STATE / wordpress.SETTINGS, storage.json_bytes(preference), 0o600)
        result = engine.synchronize(policy, webuzo.collect(), remove=True)
        for path in artifacts():
            owned_artifact(path, None)
        storage.replace(webuzo.STATE / 'active.json', storage.json_bytes({'active': False}), 0o600)
    return {'ok': True, 'state': 'disabled', **result}


if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise PermissionError('Use the Webuzo plugin lifecycle as administrator')
        if sys.argv[1:] == ['install']:
            result = install()
        elif sys.argv[1:] == ['remove']:
            result = remove()
        else:
            raise ValueError('Commands: install, remove')
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__, 'error': str(error)}))
        raise SystemExit(1)
