"""Administrator controls for one native Fail2ban jail; no WordPress discovery."""
import base64
import copy
import ipaddress
import importlib.util
import json
from pathlib import Path
import re

import storage
import ban_history
from policy import MARKER

JAIL = 'webuzo-denoise-wordpress'
CLIENT = '/usr/bin/fail2ban-client'
ETC = Path('/etc/fail2ban')
ROOT = Path(__file__).resolve().parents[1]
SETTINGS = 'wordpress.json'
JOURNAL = 'wordpress-transaction.json'
RECEIPT = 'wordpress-install.json'
JOURNAL_DIRECTORY = Path('/run/systemd/journal')
AUTH_LOGS = (Path('/var/log/auth.log'), Path('/var/log/secure'))
DEFAULT = {'enabled': False, 'maxretry': 3, 'findtime': 300,
           'durations': [300, 259200, -1]}


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT):
        raise ValueError('Expected WordPress login protection settings')
    if type(value['enabled']) is not bool:
        raise ValueError('Enabled must be a switch')
    for key in ('maxretry', 'findtime'):
        if type(value[key]) is not int or value[key] < 1:
            raise ValueError(key + ' must be a positive integer')
    times = value['durations']
    if (not isinstance(times, list) or len(times) != 3 or
            any(type(t) is not int for t in times) or
            times[0] < 1 or times[1] < times[0] or
            (times[2] != -1 and times[2] < times[1])):
        raise ValueError('Use three increasing ban durations; the last can be permanent')
    return copy.deepcopy(value)


def read_json(state, name, default=None):
    raw = storage.read(Path(state) / name)
    return json.loads(raw) if raw is not None else copy.deepcopy(default)


def paths(state):
    return [ETC / 'filter.d/wdn-wordpress-login.conf',
            ETC / 'action.d/wdn-wordpress.conf',
            ETC / 'jail.d/webuzo-denoise-wordpress.local',
            ETC / 'fail2ban.d/webuzo-denoise-history.local', Path(state) / SETTINGS]


def settings(state):
    saved = read_json(state, SETTINGS)
    if saved is not None:
        return validate(saved)
    return copy.deepcopy(DEFAULT)


def log_source():
    """Prefer native journal events; syslog files can collapse repeated failures."""
    if JOURNAL_DIRECTORY.is_dir() and importlib.util.find_spec('systemd') is not None:
        return 'backend = systemd[journalflags=1]\njournalmatch = _TRANSPORT=syslog\n'
    for path in AUTH_LOGS:
        if path.is_file() and not path.is_symlink():
            return 'backend = auto\nlogpath = ' + str(path) + ' tail\n'
    raise ValueError('WordPress login protection requires journald support or an authentication log')


def render(value, state, history_seconds=30 * 86400, source=None):
    value = validate(value)
    if source is None:
        source = log_source() if value['enabled'] else 'backend = auto\nlogpath = /var/log/auth.log tail\n'
    first, second, third = value['durations']
    header = MARKER + '\n# WordPress failed authentication\n'
    jail = (header + '[' + JAIL + ']\n' +
            'enabled = ' + str(value['enabled']).lower() + '\n' +
            'filter = wdn-wordpress-login\n' + source +
            'usedns = no\nport = 80,443\nprotocol = tcp\n' +
            'findtime = ' + str(value['findtime']) + '\nmaxretry = ' + str(value['maxretry']) + '\n' +
            'bantime = ' + str(first) + '\nbantime.increment = true\n' +
            # Native formulas clamp -1; reciprocal floats lose its exact value
            # for some first durations. Native multiplier evaluation permits a
            # factor expression: normalize the base to integer 1, then multiply
            # by the exact, validated integer durations. No imports or hooks.
            'bantime.factor = type("ExactBanUnit", (), {"__rmul__": lambda self, base: 1})()\n' +
            'bantime.multipliers = ' + ' '.join(map(str, (first, second, third))) +
            '\nbantime.overalljails = false\n' +
            'action = wdn-wordpress[actname=webuzo-denoise-wordpress,name=WDN_WORDPRESS]\n')
    filter_text = (header + '[INCLUDES]\nbefore = common.conf\n[Definition]\n' +
                   '_daemon = (?:wordpress|wp)(?:\\([A-Za-z0-9_.:/-]+\\))?\n' +
                   'failregex = ^%(__prefix_line)s(?:Authentication|(?:REST|XML-RPC) authentication) ' +
                   '(?:failure for|attempt for unknown user) .* from <HOST>$\nignoreregex =\n')
    destinations = paths(state)
    return dict(zip(destinations, [filter_text.encode(),
        (ROOT / 'config/wordpress-action.conf').read_text(encoding='utf-8').encode(), jail.encode(),
        (header + '[Definition]\ndbpurgeage = ' + str(history_seconds) + '\n').encode()
        if value['enabled'] else None, storage.json_bytes(value)]))


def capture(destinations):
    return {str(p): None if (raw := storage.read(p)) is None else
            base64.b64encode(raw).decode('ascii') for p in destinations}


def restore(record, state):
    allowed = {str(p) for p in paths(state)}
    if not isinstance(record, dict) or set(record) != allowed:
        raise ValueError('Invalid WordPress recovery paths')
    for name, raw in record.items():
        storage.replace(Path(name), None if raw is None else base64.b64decode(raw, validate=True),
                        0o600 if name == str(Path(state) / SETTINGS) else 0o644)


def recover(state, run):
    record = read_json(state, JOURNAL)
    if record is None:
        return
    if (set(record) != {'before', 'reload_started', 'receipt_created'} or
            type(record['reload_started']) is not bool or type(record['receipt_created']) is not bool):
        raise ValueError('Invalid WordPress recovery journal')
    restore(record['before'], state)
    if record['reload_started']:
        run(CLIENT, '-t')
        run(CLIENT, 'reload')
    if record['receipt_created']:
        storage.replace(Path(state) / RECEIPT, None)
    storage.replace(Path(state) / JOURNAL, None)


def apply(state, value, run):
    value = validate(value)
    history_seconds = max(30 * 86400, *value['durations'])
    if value['enabled']:
        current = run(CLIENT, 'get', 'dbpurgeage')
        match = re.search(r'(?:^|\n)(?:`-\s*)?([0-9]+)\s*seconds\s*$', current)
        if not match:
            raise ValueError('Fail2ban did not report its current history retention')
        history_seconds = max(history_seconds, int(match[1]))
    desired = render(value, state, history_seconds)
    before = capture(desired)
    for p in desired:
        raw = storage.read(p)
        if raw is None or p == Path(state) / SETTINGS or raw.startswith((MARKER + '\n').encode()):
            continue
        raise ValueError('Existing file is not owned by De-Noise: ' + str(p))
    if all(storage.read(p) == data for p, data in desired.items()):
        return {'changed': False}
    for p in desired:
        if not p.parent.is_dir():
            raise ValueError('An installed Fail2ban configuration directory is required: ' + str(p.parent))
    receipt = Path(state) / RECEIPT
    receipt_created = storage.read(receipt) is None
    record = {'before': before, 'reload_started': False, 'receipt_created': receipt_created}
    storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
    try:
        if receipt_created:
            storage.replace(receipt, storage.json_bytes(before), 0o600)
        for p, data in desired.items():
            storage.replace(p, data, 0o600 if p == Path(state) / SETTINGS else 0o644)
        run(CLIENT, '-t')
        record['reload_started'] = True
        storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
        run(CLIENT, 'reload')
    except Exception as error:
        try:
            recover(state, run)
        except Exception as recovery:
            raise RuntimeError(str(error) + '\nWordPress protection recovery failed: ' + str(recovery)) from error
        raise
    storage.replace(Path(state) / JOURNAL, None)
    return {'changed': True}


def install(state, run):
    """An empty installation stays off; reinstall restores only our saved settings."""
    saved = read_json(state, SETTINGS)
    if not ETC.is_dir():
        if saved is not None and saved.get('enabled'):
            raise ValueError('WordPress login protection requires an installed Fail2ban service')
        return {'managed': False}
    if saved is None:
        return {'managed': False}
    result = apply(state, settings(state), run)
    return {'managed': True, **result}


def uninstall(state, run):
    before = read_json(state, RECEIPT)
    if before is None:
        return
    current = capture(paths(state))
    for p in paths(state)[:-1]:
        raw = storage.read(p)
        if raw is not None and not raw.startswith((MARKER + '\n').encode()):
            raise ValueError('A managed WordPress configuration was replaced: ' + str(p))
    record = {'before': current, 'reload_started': True, 'receipt_created': False}
    storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
    try:
        restore(before, state)
        run(CLIENT, '-t')
        run(CLIENT, 'reload')
    except Exception:
        recover(state, run)
        raise
    storage.replace(Path(state) / JOURNAL, None)
    storage.replace(Path(state) / RECEIPT, None)


def addresses(output):
    result = set()
    for token in output.split():
        try:
            result.add(str(ipaddress.ip_address(token.strip("[],'\""))))
        except ValueError:
            continue
    return sorted(result, key=lambda s: (':' in s, s))


def snapshot(state, run, live=False, page=1, per_page=ban_history.PAGE_SIZE):
    ban_history.selection(page)
    result = {'settings': settings(state), 'managed': read_json(state, RECEIPT) is not None,
              'loaded': live, 'ips': [], 'pagination': ban_history.pagination(0, page, per_page=per_page)}
    if not live:
        return result
    try:
        status = run(CLIENT, 'status')
        match = re.search(r'Jail list:\s*([^\n]+)', status)
        active = JAIL in [s.strip() for s in match[1].split(',')] if match else False
        result['active'] = active
        if active:
            all_ips = addresses(run(CLIENT, 'get', JAIL, 'banip'))
            meta = ban_history.pagination(len(all_ips), page, per_page=per_page)
            limit, offset = ban_history.listing.bounds(meta)
            result.update(ips=all_ips[offset:] if limit == -1 else all_ips[offset:offset+limit], pagination=meta)
        result['available'] = True
    except FileNotFoundError:
        result.update(available=False, error='Fail2ban is not installed. Install it from the Fail2ban section first.')
    except (OSError, RuntimeError) as error:
        result.update(available=False, error=str(error))
    return result


def unban(state, selection, run):
    if read_json(state, RECEIPT) is None:
        raise ValueError('Apply WordPress protection settings before managing its bans')
    active = addresses(run(CLIENT, 'get', JAIL, 'banip'))
    if selection == 'all':
        selection = active
    if (not isinstance(selection, list) or
            any(not isinstance(s, str) or s not in active for s in selection)):
        raise ValueError('Select existing WordPress bans')
    for address in dict.fromkeys(selection):
        run(CLIENT, 'set', JAIL, 'unbanip', address)
