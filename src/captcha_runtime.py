"""Managed socket service and private native Nginx cookie-verification keys."""
import json
from pathlib import Path
import re
import secrets

import captcha

SOURCE = Path(__file__).resolve().parent

NAME = 'webuzo-de-noise-captcha'
SOCKET = Path('/run') / NAME / 'service.sock'
UNITS = Path('/etc/systemd/system')
CONFIG_NAME = 'captcha-sites.conf'
MARKER = '# Managed by webuzo-de-noise'


def unit_files(group):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', group): raise ValueError('Invalid native Nginx group')
    return {
        UNITS / (NAME + '.socket'): MARKER + '\n[Unit]\nDescription=Local De-Noise CAPTCHA socket\n[Socket]\nListenStream=' + str(SOCKET) + '\nSocketUser=root\nSocketGroup=' + group + '\nSocketMode=0660\nDirectoryMode=0755\n[Install]\nWantedBy=sockets.target\n',
        UNITS / (NAME + '.service'): MARKER + '''
[Unit]
Description=Local De-Noise math CAPTCHA
Requires=webuzo-de-noise-captcha.socket
After=webuzo-de-noise-captcha.socket
[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/bin/python3 -I ''' + json.dumps(str(SOURCE / 'captcha_server.py')) + '''
LoadCredential=signing-key:/var/lib/webuzo-de-noise/captcha.key
StateDirectory=webuzo-de-noise-captcha
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
UMask=0077
'''}


def worker_group():
    import grp
    import storage
    import webuzo
    raw = storage.read(webuzo.CONFIG) or b''
    match = re.search(rb'^\s*user\s+[\'\"]?([A-Za-z0-9_-]+)[\'\"]?(?:\s+[\'\"]?([A-Za-z0-9_-]+)[\'\"]?)?\s*;', raw, re.M)
    if match:
        # Nginx uses a group with the same name when the directive omits it;
        # this can differ from the user's primary group on Webuzo installations.
        group = (match[2] or match[1]).decode()
    else:
        build = webuzo.nginx_build()
        configured = re.search(r'(?:^|\s)--group=([A-Za-z0-9_-]+)(?:\s|$)', build)
        user = re.search(r'(?:^|\s)--user=([A-Za-z0-9_-]+)(?:\s|$)', build)
        group = configured[1] if configured else user[1] if user else 'nobody'
    grp.getgrnam(group)
    return group


def prepare(state_directory, directory, settings, sites, site_mode):
    import access_protection as access
    import storage
    active = [(site, access.effective(settings, site['key'])) for site in sites
              if site.get('supported') and not site.get('suspended') and site.get('kind') != 'mail'
              and site_mode(site) != 'off' and access.effective(settings, site['key'])['enabled']
              and access.effective(settings, site['key'])['method'] == 'captcha']
    if not active: return {}, False
    key_path = state_directory / 'captcha.key'
    secret = storage.read(key_path)
    if secret is None:
        secret = secrets.token_bytes(32); storage.replace(key_path, secret, 0o600)
    if len(secret) != 32: raise ValueError('Invalid retained CAPTCHA key')
    directory.mkdir(mode=0o755, exist_ok=True)
    with storage.parent(directory / '.check'):
        pass
    desired, entries = {}, {}
    for site, profile in active:
        scope = access.identifier(site['key']); rev = captcha.revision(profile)
        entries[scope] = dict(hosts=access.hosts(site),
                              revision=rev, seconds=profile['captcha_seconds'])
        key = captcha.scope_key(secret, scope, rev)
        desired[str(directory / (scope + '.captcha.conf'))] = (MARKER + '\nsecure_link $ha' + scope + '_token;\n' +
                'secure_link_md5 "$secure_link_expires|$host|$scheme|' + key + '";\n')
    desired[str(directory / CONFIG_NAME)] = MARKER + '\n' + json.dumps({'sites': entries}, sort_keys=True) + '\n'
    return desired, True


def enable(run):
    run('/usr/bin/systemctl', 'enable', '--now', NAME + '.socket')


def disable(run):
    import storage
    for suffix in ('.socket', '.service'):
        previous = storage.read(UNITS / (NAME + suffix))
        if previous is not None and not previous.startswith(MARKER.encode()):
            raise ValueError('Existing CAPTCHA service unit is not owned by De-Noise')
    # A ZIP upgrade or interrupted installation can leave no unit files. An
    # absent unit is already stopped, not a rollback failure. Check systemd,
    # rather than just the filesystem: a deleted file can still be loaded.
    for suffix, arguments in (('.socket', ('disable', '--now')), ('.service', ('stop',))):
        name = NAME + suffix
        if run('/usr/bin/systemctl', 'show', '--property=LoadState', '--value', name).strip() != 'not-found':
            run('/usr/bin/systemctl', *arguments, name)


def install(run):
    import storage
    changed = False
    desired = unit_files(worker_group())
    before = {}
    for path in desired:
        previous = storage.read(path)
        if previous is not None and not previous.startswith(MARKER.encode()):
            raise ValueError('Existing CAPTCHA service unit is not owned by De-Noise')
        before[path] = previous
    try:
        for path, text in desired.items():
            if before[path] != text.encode():
                storage.replace(path, text.encode(), 0o644)
                changed = True
        if changed:
            run('/usr/bin/systemctl', 'daemon-reload')
    except Exception:
        restore_units(before, run)
        raise
    return before


def restore_units(before, run):
    import storage
    for path, value in before.items():
        storage.replace(path, value, 0o644)
    run('/usr/bin/systemctl', 'daemon-reload')


def refresh(run):
    # An addon upgrade replaces Python source; an already running worker must
    # pick it up too. Inactive services remain inactive.
    run('/usr/bin/systemctl', 'try-restart', NAME + '.service')


def uninstall(run):
    import storage
    paths = list(unit_files(worker_group()))
    for path in paths:
        value = storage.read(path)
        if value is not None and not value.startswith(MARKER.encode()):
            raise ValueError('Existing CAPTCHA service unit is not owned by De-Noise')
    if any(path.exists() for path in paths):
        disable(run)
        for path in paths:
            storage.replace(path, None)
        run('/usr/bin/systemctl', 'daemon-reload')
