"""Keep a new OS Fail2ban package stopped until its jails are reviewed."""
import os
import json
from pathlib import Path
import re
import stat

import host_protection as host
import storage
import wordpress
from policy import MARKER

GUARD = 'fail2ban-bootstrap.json'
MASK = Path('/etc/systemd/system/fail2ban.service')
PROFILE = Path('/etc/fail2ban/jail.d/webuzo-de-noise-bootstrap.local')


def package_defaults(run):
    # Native include/interpolation handling, without resolving log files or
    # filters: a new Ubuntu host need not have /var/log/auth.log yet.
    code = ('import json,sys; from fail2ban.client.jailsreader import JailsReader; '
            'r=JailsReader(); r.setBaseDir(sys.argv[1]); '
            'assert r.read(), "Cannot read Fail2ban configuration"; '
            'print(json.dumps([s for s in r.sections() if s!="INCLUDES" '
            'and r.get(s,"enabled").strip().lower() in ("1","yes","true","on")]))')
    names = json.loads(run('/usr/bin/python3', '-I', '-c', code, str(host.ETC)))
    if not isinstance(names, list) or any(not isinstance(n, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', n) for n in names):
        raise ValueError('Invalid Fail2ban package defaults')
    return set(names)


def systemctl():
    value = host.binary('systemctl')
    if not value:
        raise ValueError('Systemd is required to install Fail2ban through De-Noise')
    return value


def mask_present():
    with storage.parent(MASK) as directory:
        try:
            info = os.stat(MASK.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if info.st_uid != 0 or not stat.S_ISLNK(info.st_mode) or os.readlink(MASK.name, dir_fd=directory) != '/dev/null':
            raise ValueError('An independently managed Fail2ban service file exists; it was not changed')
    return True


def prepare(state, run):
    record = wordpress.read_json(state, GUARD)
    if record is None:
        if mask_present():
            raise ValueError('Fail2ban is already masked by the administrator; its mask was not changed')
        active = run(systemctl(), 'show', 'fail2ban.service', '--property=ActiveState', '--value').strip()
        if active not in ('', 'inactive', 'failed'):
            raise ValueError('An existing Fail2ban service is active; refresh its status instead')
        # Existing configuration is never rewritten to obtain a WordPress-only start.
        had_configuration = host.ETC.exists()
        if had_configuration:
            with storage.parent(host.ETC / '.check'):
                had_configuration = any(p.is_file() or p.is_symlink() for p in host.ETC.rglob('*'))
        record = {'had_configuration': had_configuration}
        storage.replace(Path(state) / GUARD, storage.json_bytes(record), 0o600)
    if not mask_present():
        run(systemctl(), 'mask', 'fail2ban.service')
        if not mask_present():
            raise ValueError('Fail2ban could not be kept stopped during package installation')


def finish(state, run):
    """Resume a guarded installation, including after an APT/configuration failure."""
    record = wordpress.read_json(state, GUARD)
    if record is None:
        return False
    mask_present()  # Refuse a replacement administrator unit before changing anything.
    if not record['had_configuration']:
        PROFILE.parent.mkdir(mode=0o755, exist_ok=True)
        previous = storage.owned(PROFILE)
        if previous is None:
            defaults = package_defaults(run) - {wordpress.JAIL}
            text = MARKER + '\n# New installation: authentication jails are opt-in.\n[DEFAULT]\nenabled = false\n'
            for jail in sorted(defaults):
                text += '\n[' + jail + ']\nenabled = false\n'
            storage.replace(PROFILE, text.encode(), 0o644)
    if host.configured_jails(run) - {wordpress.JAIL}:
        raise ValueError('Fail2ban was installed but not started: existing non-WordPress jails are enabled. Their configuration was left unchanged. The installation guard is retained.')
    run(host.client(), '-t')
    if mask_present():
        run(systemctl(), 'unmask', 'fail2ban.service')
        if mask_present():
            raise ValueError('The Fail2ban installation mask could not be removed')
    storage.replace(Path(state) / GUARD, None)
    return True
