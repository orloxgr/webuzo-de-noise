"""Opt-in native Fail2ban jails for detected server authentication services."""
import base64
import ast
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from contextlib import contextmanager
import stat

import storage
import wordpress
from policy import MARKER

ETC = Path('/etc/fail2ban')
SETTINGS = 'host-protection.json'
JOURNAL = 'host-protection-transaction.json'
RECEIPT = 'host-protection-install.json'
CONFIG = 'jail.d/webuzo-de-noise-services.local'
COMPETING_PROTECTION = {
    'CSF': ('/etc/csf/csf.conf', '/usr/sbin/csf', '/usr/bin/csf', '/usr/local/sbin/csf', '/usr/local/bin/csf',
            '/usr/local/csf/bin/csf.pl', '/etc/init.d/csf',
            '/etc/systemd/system/csf.service', '/usr/lib/systemd/system/csf.service', '/lib/systemd/system/csf.service'),
    'LFD': ('/usr/sbin/lfd', '/usr/bin/lfd', '/usr/local/sbin/lfd', '/usr/local/bin/lfd',
            '/usr/local/csf/bin/lfd', '/etc/init.d/lfd', '/etc/systemd/system/lfd.service',
            '/usr/lib/systemd/system/lfd.service', '/lib/systemd/system/lfd.service'),
}
SERVICES = {
    'ssh': dict(title='SSH', filter='sshd', processes=['sshd'], units=['ssh', 'sshd'],
                logs=['/var/log/auth.log', '/var/log/secure'], journal='_COMM=sshd + _COMM=sshd-session'),
    'imap': dict(title='Mail — IMAP / POP3', filter='dovecot', processes=['dovecot', 'imap-login', 'pop3-login'],
                 units=['dovecot'], logs=['/var/log/maillog', '/var/log/mail.log'],
                 journal='_SYSTEMD_UNIT=dovecot.service + SYSLOG_IDENTIFIER=dovecot'),
    'smtp': dict(title='Mail — SMTP authentication', filter='exim', processes=['exim', 'exim4'],
                 units=['exim', 'exim4'], logs=['/var/log/exim/main.log', '/var/log/exim4/mainlog'], journal=''),
    'ftp': dict(title='FTP', filter='pure-ftpd', processes=['pure-ftpd', 'pure-ftpd (SER'],
                units=['pure-ftpd', 'pureftpd'], logs=['/var/log/messages', '/var/log/syslog'],
                journal='_COMM=pure-ftpd'),
}
DEFAULT = {key: dict(enabled=False, maxretry=5, findtime=600, bantime=600, ignore_ips=[])
           for key in SERVICES}


def binary(name):
    """Search only system directories, never a hosting user's PATH."""
    return shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin')


def client():
    path = binary('fail2ban-client')
    if not path:
        raise ValueError('Fail2ban is not installed. Open Fail2ban to install it first.')
    return path


def service_blockers():
    """Detect installed CSF/LFD without executing or modifying either tool."""
    found = []
    for name, candidates in COMPETING_PROTECTION.items():
        for candidate in candidates:
            try:
                Path(candidate).lstat()
            except FileNotFoundError:
                continue
            # A link or a stopped unit still identifies an existing installation.
            # Unexpected inspection errors propagate, so activation fails closed.
            found.append(name)
            break
    return found


def activation_error(blockers):
    return ('CSF/LFD detected: ' + ', '.join(blockers) +
            '. SSH, mail and FTP protection cannot be enabled in De-Noise. '
            'WordPress login protection remains available. '
            'Existing jails are not changed automatically.')


def check_service_start(run):
    """With CSF/LFD, only a WordPress-only (or empty) jail setup may start."""
    if not service_blockers():
        return
    parsed = False
    for line in run(client(), '-d').splitlines():
        if not line.strip():
            continue
        try:
            command = ast.literal_eval(line)
        except (ValueError, SyntaxError) as error:
            raise ValueError('Cannot inspect enabled Fail2ban jails; service start blocked while CSF/LFD is installed.') from error
        if (not isinstance(command, list) or not command or not isinstance(command[0], str)
                or command[0] not in ('set', 'multi-set', 'add', 'start')):
            raise ValueError('Invalid Fail2ban configuration dump; service start blocked.')
        parsed = True
        if command[0] in ('add', 'start') and (len(command) < 2 or command[1] != wordpress.JAIL):
            raise ValueError('CSF/LFD detected: service start is blocked because enabled jails include protection other than the De-Noise WordPress jail. Review the existing Fail2ban configuration first. No jails were changed.')
    if not parsed:
        raise ValueError('Cannot inspect enabled Fail2ban jails; service start blocked while CSF/LFD is installed.')


def jail(key):
    if not isinstance(key, str) or key not in SERVICES:
        raise ValueError('Select a supported authentication service')
    return 'webuzo-denoise-' + key


def validate(value):
    if not isinstance(value, dict) or set(value) != set(SERVICES):
        raise ValueError('Expected the four service protection settings')
    result = copy.deepcopy(value)
    for settings in result.values():
        if not isinstance(settings, dict) or set(settings) != set(DEFAULT['ssh']):
            raise ValueError('Invalid service protection settings')
        if type(settings['enabled']) is not bool:
            raise ValueError('Enabled must be a switch')
        for name in ('maxretry', 'findtime', 'bantime'):
            if type(settings[name]) is not int or settings[name] < 1:
                raise ValueError('Attempts, counting window and ban duration must be positive integers')
        if not isinstance(settings['ignore_ips'], list) or any(not isinstance(v, str) for v in settings['ignore_ips']):
            raise ValueError('Exemptions must be IP addresses or CIDR networks')
        settings['ignore_ips'] = list(dict.fromkeys(str(ipaddress.ip_network(v, strict=False)) for v in settings['ignore_ips']))
    return result


def settings(state):
    return validate(wordpress.read_json(state, SETTINGS, DEFAULT))


def active_jails(run):
    output = run(client(), 'status')
    match = re.search(r'Jail list:\s*([^\n]*)', output)
    values = [s.strip() for s in match[1].split(',') if s.strip()] if match else []
    if any(not re.fullmatch(r'[A-Za-z0-9_.-]+', name) for name in values):
        raise ValueError('Fail2ban reported an unsupported jail name')
    return values


def listeners(output):
    found = {key: set() for key in SERVICES}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        match = re.search(r':([0-9]+)$', parts[3])
        if not match or not 1 <= int(match[1]) <= 65535:
            continue
        for key, spec in SERVICES.items():
            if any('"' + process + '"' in line for process in spec['processes']):
                found[key].add(int(match[1]))
    return {key: sorted(ports) for key, ports in found.items()}


@contextmanager
def log_stream(path):
    """Pin fixed log paths; accept root and native log/service identities only."""
    import pwd
    import grp
    uids = {0}
    for name in ('syslog', 'mail', 'exim', 'Debian-exim', 'dovecot'):
        try:
            entry = pwd.getpwnam(name)
            if entry.pw_shell.endswith(('/nologin', '/false')):
                uids.add(entry.pw_uid)
        except KeyError:
            pass
    def trusted(info, directory=False):
        if info.st_uid not in uids or info.st_mode & 0o002 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise ValueError('Authentication log is not controlled by root or its native service')
        if info.st_mode & 0o020:
            group = grp.getgrgid(info.st_gid)
            members = [pwd.getpwnam(name).pw_uid for name in group.gr_mem]
            members += [entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid == info.st_gid]
            if any(uid not in uids for uid in members):
                raise ValueError('Authentication log path is writable by another account')
    path = Path(path)
    if str(path) not in {name for spec in SERVICES.values() for name in spec['logs']}:
        raise ValueError('Unsupported authentication log path')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                            (0 if last else os.O_DIRECTORY), dir_fd=descriptor)
            os.close(descriptor); descriptor = child
            trusted(os.fstat(descriptor), directory=not last)
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            yield stream
    finally:
        os.close(descriptor)


def safe_log(path):
    try:
        with log_stream(path):
            return True
    except FileNotFoundError:
        return False


def discover(run):
    ss = binary('ss')
    if not ss:
        raise ValueError('The system ss utility is required to detect service ports')
    ports = listeners(run(ss, '-H', '-ltnp'))
    result = {}
    journal = Path('/run/systemd/journal').is_dir() and importlib.util.find_spec('systemd') is not None
    for key, spec in SERVICES.items():
        row = dict(title=spec['title'], ports=ports[key], source=None, ready=False, error='')
        try:
            if key == 'ssh' and ports[key]:
                sshd = binary('sshd')
                if not sshd:
                    raise ValueError('Cannot verify the SSH configuration')
                configured = sorted({int(p) for p in re.findall(r'^port ([0-9]+)$', run(sshd, '-T'), re.M)})
                # Include both configured and actually listening ports (socket activation).
                row['ports'] = sorted(set(configured) | set(ports[key]))
            configured_log = None
            if key == 'imap':
                doveconf = next((p for p in ('/usr/local/apps/dovecot/bin/doveconf', '/usr/bin/doveconf') if Path(p).is_file()), None)
                if doveconf:
                    configured_log = run(doveconf, '-h', 'log_path').strip()
                    if configured_log != 'syslog' and configured_log not in spec['logs']:
                        raise ValueError('Dovecot uses a custom log path; configure that service jail manually: ' + configured_log)
            if configured_log and configured_log != 'syslog':
                if not safe_log(configured_log):
                    raise ValueError('The configured Dovecot authentication log is missing')
                row['source'] = dict(backend='auto', logpath=configured_log)
            elif journal and spec['journal'] and (key == 'ssh' or configured_log == 'syslog'):
                row['source'] = dict(backend='systemd', journalmatch=spec['journal'])
            else:
                for name in spec['logs']:
                    if safe_log(name):
                        row['source'] = dict(backend='auto', logpath=name)
                        break
                if row['source'] is None and journal and spec['journal']:
                    row['source'] = dict(backend='systemd', journalmatch=spec['journal'])
            if not row['ports']:
                raise ValueError('Service is not listening on TCP; no protection will be enabled')
            if row['source'] is None:
                raise ValueError('No supported authentication log source was found')
            if not (ETC / ('filter.d/' + spec['filter'] + '.conf')).is_file():
                raise ValueError('Install Fail2ban with its native ' + spec['filter'] + ' filter first')
            row['ready'] = True
        except (OSError, ValueError, RuntimeError) as error:
            row['error'] = str(error)
        result[key] = row
    return result


def duplicates(run, key, detected, active):
    """Recognize service names and shared sources; never overwrite another jail."""
    spec = SERVICES[key]
    hints = {'ssh': ('ssh',), 'imap': ('dovecot', 'imap', 'pop3'),
             'smtp': ('exim', 'smtp'), 'ftp': ('ftp',)}[key]
    matches = []
    for name in active:
        if name == jail(key) or name.startswith('webuzo-denoise-'):
            continue
        if any(hint in name.lower() for hint in hints):
            matches.append(name)
            continue
        source = detected.get('source') or {}
        if source.get('logpath'):
            try:
                paths = run(client(), 'get', name, 'logpath')
            except RuntimeError:
                continue  # Journal-backed jail has no file paths.
            if source['logpath'] in paths:
                matches.append(name)
        elif source.get('journalmatch'):
            try:
                match = run(client(), 'get', name, 'journalmatch')
            except RuntimeError:
                continue  # File-backed jail has no journal selector.
            if any(hint in match.lower() for hint in (spec['filter'], *spec['processes'])):
                matches.append(name)
    return matches


def sample(key, detected, run):
    source = detected['source']
    if source['backend'] == 'systemd':
        return run(binary('journalctl') or '/usr/bin/journalctl', '--no-pager', '-n', '5000',
                   '--since=-24 hours', '-o', 'short-iso', *source['journalmatch'].split()).encode()
    path = Path(source['logpath'])
    with log_stream(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        stream.seek(max(0, size - 2 * 1024 * 1024))
        if stream.tell(): stream.readline()
        return b''.join(stream.readlines()[-5000:])


def test_filter(state, key, detected, run):
    jail(key)
    if not detected['ready']:
        raise ValueError(detected['error'])
    regex = binary('fail2ban-regex')
    if not regex:
        raise ValueError('The installed Fail2ban regex utility is missing')
    data = sample(key, detected, run)
    # Only the root-private test sample is created, then removed; no service logs change.
    with storage.parent(Path(state) / '.sample-check'), tempfile.TemporaryDirectory(prefix='fail2ban-sample-', dir=state) as folder:
        name = Path(folder) / 'sample.log'
        name.write_bytes(data)
        filter_name = SERVICES[key]['filter'] + '[mode=normal]' if key != 'ftp' else 'pure-ftpd'
        if key == 'imap':
            target = Path(folder) / 'dovecot-auth.conf'
            target.write_bytes(dovecot_filter(str(ETC / 'filter.d/dovecot.conf')))
            filter_name = str(target)
        output = run(regex, str(name), filter_name,
                     '--print-no-missed', '--print-no-ignored')
        match = re.search(r'Lines:\s*(\d+) lines,\s*\d+ ignored,\s*(\d+) matched', output)
        if not match:
            raise ValueError('Fail2ban did not return a valid filter test result')
        return dict(lines=int(match[1]), matches=int(match[2]),
                    note='Recent authentication logs only; zero matches can mean no failed logins were recorded.')


def dovecot_filter(before='dovecot.conf'):
    """Retain the OS normal-mode filter and support Dovecot 2.4 auth_failed logs."""
    return (MARKER + '\n# Native Dovecot filter plus explicit Dovecot 2.4 authentication failures.\n'
            '[INCLUDES]\nbefore = ' + before + '\n[Definition]\nmode = normal\n'
            'failregex = %(known/failregex)s\n'
            '            ^Login aborted: [^()\\r\\n]*\\(auth failed, [0-9]+ attempts? in [0-9]+ secs?\\) '
            '\\(auth_failed\\): user=<<F-USER>[^<>\\r\\n]*</F-USER>>, method=[A-Za-z0-9_-]+, '
            'rip=<ADDR>, lip=[0-9A-Fa-f:.]+(?:, (?:TLS|secured))?(?:, session=<[A-Za-z0-9+/=]+>)?\\s*$\n').encode()


def inherited_exclusions(run):
    code = ('import json,configparser; from fail2ban.client.jailsreader import JailsReader; '
            'r=JailsReader(); r.read();\ntry: value=r.get("DEFAULT","ignoreip")\n'
            'except (configparser.NoOptionError,configparser.NoSectionError): value=None\n'
            'print(json.dumps(value))')
    value = json.loads(run('/usr/bin/python3', '-I', '-c', code))
    if value is not None and not isinstance(value, str):
        raise ValueError('Fail2ban reported invalid default exclusions')
    return value is not None


def render(value, detected, action, has_default_exclusions=False):
    value = validate(value)
    if action not in ('iptables-multiport', 'nftables-multiport'):
        raise ValueError('A native multiport firewall action is required')
    lines = [MARKER, '# Authentication services; only the listed TCP ports are banned.']
    for key, rule in value.items():
        lines += ['', '[' + jail(key) + ']', 'enabled = ' + str(rule['enabled']).lower()]
        if not rule['enabled']:
            continue
        row = detected[key]
        if not row['ready'] or not row['ports'] or any(type(p) is not int or not 1 <= p <= 65535 for p in row['ports']):
            raise ValueError('Cannot safely configure ' + row['title'])
        source = row['source']
        lines += ['filter = ' + ('wdn-dovecot-auth' if key == 'imap' else SERVICES[key]['filter']) + ('[mode=normal]' if key != 'ftp' else ''),
                  'backend = ' + source['backend']]
        if source['backend'] == 'systemd':
            lines += ['journalmatch = ' + source['journalmatch']]
        else:
            if source.get('logpath') not in SERVICES[key]['logs']:
                raise ValueError('Unexpected service log path')
            lines += ['logpath = ' + source['logpath'] + ' tail']
        lines += ['usedns = no', 'port = ' + ','.join(map(str, row['ports'])), 'protocol = tcp',
                  'maxretry = ' + str(rule['maxretry']), 'findtime = ' + str(rule['findtime']),
                  'bantime = ' + str(rule['bantime']), 'bantime.increment = false',
                  'ignoreself = true',
                  'action = ' + action + '[name=WDN_' + key.upper() + ',port="' +
                  ','.join(map(str, row['ports'])) + '",protocol=tcp]']
        if rule['ignore_ips']:
            lines += ['ignoreip = ' + ('%(default/ignoreip)s ' if has_default_exclusions else '') +
                      '127.0.0.0/8 ::1 ' + ' '.join(rule['ignore_ips'])]
    return ('\n'.join(lines) + '\n').encode()


def firewall_action():
    if binary('nft') and (ETC / 'action.d/nftables-multiport.conf').is_file():
        return 'nftables-multiport'
    if binary('iptables') and binary('ip6tables') and (ETC / 'action.d/iptables-multiport.conf').is_file():
        return 'iptables-multiport'
    raise ValueError('No supported IPv4/IPv6 multiport firewall action is installed')


def paths(state):
    return [ETC / CONFIG, ETC / 'filter.d/wdn-dovecot-auth.conf', Path(state) / SETTINGS]


def restore(state, before):
    if not isinstance(before, dict) or set(before) != {str(p) for p in paths(state)}:
        raise ValueError('Invalid service recovery paths')
    for path in paths(state):
        raw = before[str(path)]
        storage.replace(path, None if raw is None else base64.b64decode(raw, validate=True),
                        0o600 if path.name == SETTINGS else 0o644)


def recover(state, run):
    record = wordpress.read_json(state, JOURNAL)
    if record is None:
        return
    if (set(record) != {'before', 'reload_started', 'receipt_created'} or
            type(record['reload_started']) is not bool or type(record['receipt_created']) is not bool):
        raise ValueError('Invalid service recovery journal')
    restore(state, record['before'])
    if record['reload_started']:
        run(client(), '-t')
        run(client(), 'reload')
    if record['receipt_created']:
        storage.replace(Path(state) / RECEIPT, None)
    storage.replace(Path(state) / JOURNAL, None)


def apply(state, value, run):
    value = validate(value)
    if any(rule['enabled'] for rule in value.values()):
        blockers = service_blockers()
        if blockers:
            raise ValueError(activation_error(blockers))
    active = active_jails(run)
    detected = discover(run)
    tests = {}
    for key, rule in value.items():
        if rule['enabled']:
            existing = duplicates(run, key, detected[key], active)
            if existing:
                raise ValueError('Existing protection for ' + SERVICES[key]['title'] + ': ' + ', '.join(existing) +
                                 '. Manage that jail separately; De-Noise will not replace it.')
            tests[key] = test_filter(state, key, detected[key], run)
    data = render(value, detected, firewall_action(), inherited_exclusions(run))
    target = ETC / CONFIG
    for path in paths(state)[:-1]:
        storage.owned(path)
    before = wordpress.capture(paths(state))
    desired = {target: data, ETC / 'filter.d/wdn-dovecot-auth.conf': dovecot_filter(),
               Path(state) / SETTINGS: storage.json_bytes(value)}
    if all(storage.read(p) == raw for p, raw in desired.items()):
        return {'changed': False, 'tests': tests}
    created = storage.read(Path(state) / RECEIPT) is None
    record = dict(before=before, reload_started=False, receipt_created=created)
    storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
    try:
        if created:
            storage.replace(Path(state) / RECEIPT, storage.json_bytes(before), 0o600)
        for path, raw in desired.items():
            storage.replace(path, raw, 0o600 if path.name == SETTINGS else 0o644)
        run(client(), '-t')
        record['reload_started'] = True
        storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
        run(client(), 'reload')
        loaded = active_jails(run)
        for key, rule in value.items():
            if (jail(key) in loaded) != rule['enabled']:
                raise RuntimeError('Fail2ban did not apply the requested ' + SERVICES[key]['title'] + ' state')
    except Exception as error:
        try:
            recover(state, run)
        except Exception as recovery:
            raise RuntimeError(str(error) + '\nService protection recovery failed: ' + str(recovery)) from error
        raise
    storage.replace(Path(state) / JOURNAL, None)
    return {'changed': True, 'tests': tests}


def uninstall(state, run):
    recover(state, run)
    before = wordpress.read_json(state, RECEIPT)
    if before is None:
        return
    for path in paths(state)[:-1]:
        storage.owned(path)
    record = dict(before=wordpress.capture(paths(state)), reload_started=True, receipt_created=False)
    storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
    try:
        restore(state, before)
        run(client(), '-t')
        run(client(), 'reload')
    except Exception:
        recover(state, run)
        raise
    storage.replace(Path(state) / RECEIPT, None)
    storage.replace(Path(state) / JOURNAL, None)


def snapshot(state, run, live=False):
    result = dict(installed=binary('fail2ban-client') is not None, loaded=live, settings=settings(state), services={},
                  active_jails=[], conflicts=[], running=False)
    try:
        result['service_blockers'] = service_blockers()
        result['service_activation_blocked'] = bool(result['service_blockers'])
        result['conflicts'] = list(result['service_blockers'])
        if result['service_activation_blocked']:
            result['service_activation_error'] = activation_error(result['service_blockers'])
    except OSError as error:
        result.update(service_activation_blocked=True,
                      service_activation_error='Cannot check CSF/LFD installation. SSH, mail and FTP activation is blocked: ' + str(error))
    if not live or not result['installed']:
        return result
    try:
        active = active_jails(run)
        result.update(running=True, active_jails=active)
        for key, row in discover(run).items():
            row.update(jail=jail(key), active=jail(key) in active, ips=[], existing=duplicates(run, key, row, active))
            if row['active']:
                row['ips'] = wordpress.addresses(run(client(), 'get', jail(key), 'banip'))
            result['services'][key] = row
        for unit in ('lfd', 'csf', 'bfd'):
            try:
                if run(binary('systemctl') or '/usr/bin/systemctl', 'is-active', unit).strip() == 'active':
                    if unit.upper() not in result['conflicts']:
                        result['conflicts'].append(unit.upper())
            except RuntimeError:
                pass
    except (OSError, RuntimeError, ValueError) as error:
        result['error'] = str(error)
    return result


def unban(state, key, ips, run):
    name = jail(key)
    if wordpress.read_json(state, RECEIPT) is None:
        raise ValueError('Only De-Noise-managed service bans can be removed here')
    current = wordpress.addresses(run(client(), 'get', name, 'banip'))
    if not isinstance(ips, list) or not ips or any(not isinstance(ip, str) or ip not in current for ip in ips):
        raise ValueError('Select existing IP bans from this service')
    for ip in dict.fromkeys(ips):
        run(client(), 'set', name, 'unbanip', ip)
