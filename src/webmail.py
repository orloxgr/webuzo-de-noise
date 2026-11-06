"""Shared Webuzo webmail through the documented EMPS server custom include."""
import agent_catalog
import fnmatch
import json
import math
from pathlib import Path
import re
import time
from datetime import datetime
import os
import posixpath
import pwd
from urllib.parse import unquote

import storage
import webuzo
from policy import MARKER, PRIVATE_PATTERNS, pattern

BINARY = Path('/usr/local/emps/sbin/nginx')
CONFIG = Path('/usr/local/emps/etc/nginx/nginx.conf')
CUSTOM = Path('/usr/local/emps/etc/nginx/conf.d/custom.conf')
SNIPPET = Path('/etc/webuzo-de-noise/webmail.conf')
HISTORY = 'webmail-history.json'
DOMAIN = 'webmail'  # Activity service identifier, not a server hostname.
KEY = 'root/' + DOMAIN


def sections(dump):
    parts = re.split(r'^# configuration file ([^\r\n]+):\s*\n', dump, flags=re.M)
    return {str(Path(parts[index])): webuzo.directives(parts[index + 1])
            for index in range(1, len(parts), 2)}


def inspect():
    """Ask the native binary to resolve its own includes, including vendor links."""
    if not BINARY.is_file():
        raise ValueError('The native Webuzo panel Nginx is unavailable')
    files = sections(webuzo.run(BINARY, '-T'))
    if str(CONFIG) not in files:
        raise ValueError('The native panel configuration could not be identified')
    http = [children for key, args, children in files[str(CONFIG)] if key == 'http']
    if len(http) != 1:
        raise ValueError('A single native panel HTTP context is required')
    def expand(nodes, stack=frozenset()):
        output = []
        for key, args, child in nodes:
            if key == 'include' and len(args) == 1:
                path = Path(args[0])
                if not path.is_absolute():
                    path = CONFIG.parent / path
                for name, included in files.items():
                    if fnmatch.fnmatchcase(name, str(path)):
                        if name in stack:
                            raise ValueError('Recursive native panel configuration')
                        output.extend(expand(included, stack | {name}))
            else:
                output.append((key, args, None if child is None else expand(child, stack)))
        return output
    # Preserve the unexpanded custom include as evidence of the supported hook.
    custom_pattern = str(CUSTOM.parent / '*')
    native_servers = [child for key, args, child in http[0] if key == 'server' and child is not None]
    protected = []
    for server in native_servers:
        if not any(key == 'include' and args in ([custom_pattern], [str(CUSTOM)]) for key, args, child in server):
            continue
        resolved = expand(server)
        # Webuzo serves /mail through the native end-user server; Roundcube
        # can be installed later without a separate location in nginx.conf.
        if any(key == 'include' and any('enduser_locations' in arg for arg in args)
               for key, args, child in server):
            protected.append(resolved)
    if not protected:
        raise ValueError('The native webmail route has no documented custom include')
    global_logs = [args for key, args, child in http[0] if key == 'access_log' and args and args[0] != 'off']
    logs = set()
    for server in protected:
        local = [args for key, args, child in server if key == 'access_log']
        for args in local or global_logs:
            if args and args[0].startswith('/') and (len(args) == 1 or args[1] in ('main', 'combined')):
                logs.add(args[0])
    return {'logs': sorted(logs), 'servers': len(protected)}


def verify():
    dump = webuzo.run(BINARY, '-T')
    if '# configuration file ' + str(SNIPPET) + ':' not in dump:
        raise RuntimeError('The native panel does not load the webmail include')


def reload():
    # EMPS distributes nginx.conf as a vendor symlink on some installations.
    # Let its native binary read it; generic metadata reads still refuse links.
    nodes = sections(webuzo.run(BINARY, '-T')).get(str(CONFIG))
    if nodes is None:
        raise ValueError('The native panel configuration could not be identified')
    webuzo.reload_instance(BINARY, CONFIG, nodes=nodes)


def worker_uids():
    nodes = sections(webuzo.run(BINARY, '-T')).get(str(CONFIG), [])
    users = [args for key, args, child in nodes if key == 'user']
    if len(users) != 1 or not users[0] or not re.fullmatch(r'[A-Za-z0-9_-]+', users[0][0]):
        raise ValueError('The native panel Nginx worker identity is unavailable')
    return {0, pwd.getpwnam(users[0][0]).pw_uid}


def discover():
    try:
        info = inspect()
        reason = ''
    except (OSError, RuntimeError, ValueError):
        info = {'logs': [], 'servers': 0}
        reason = 'The native panel webmail route or its custom configuration hook is unavailable'
    return dict(key=KEY, owner='root', domain=DOMAIN, aliases='', kind='mail', shared_webmail=True,
                template='webuzo-panel-webmail', supported=not reason, reason=reason, suspended=False,
                paths=[str(SNIPPET)], roots={}, include_loaded=not reason, native_logs=info['logs'])


def profile(policy):
    mode = policy['overrides'].get(KEY, policy['mode']) if policy['mail_protection'] else 'off'
    if mode == 'off':
        return dict(mode='off', agents=[], scanners=False)
    agents = agent_catalog.enabled(policy)
    return dict(mode=mode, agents=list(dict.fromkeys(agents)), scanners=policy['scanners'])


def compile(value):
    lines = [MARKER]
    if value['mode'] != 'enforce':
        return '\n'.join(lines) + '\n'
    lines += ['set $wdn_mail_scope 0;',
              'if ($uri ~ "^/mail(?:/|$)") { set $wdn_mail_scope 1; }']
    if value['scanners']:
        lines.append('set $wdn_mail_path "$wdn_mail_scope:$uri";')
        for reason, expression in PRIVATE_PATTERNS:
            regex = '"' + pattern(r'^1:[\s\S]*' + expression)[3:]
            lines.append('if ($wdn_mail_path ~* ' + regex + ') { return 403; }')
    if value['agents']:
        lines.append('set $wdn_mail_agent "$wdn_mail_scope:$http_user_agent";')
        for agent in value['agents']:
            literal = ''.join(r'\x' + format(ord(char), '02x') for char in agent)
            regex = '"' + pattern(r'^1:[\s\S]*' + literal)[3:]
            lines.append('if ($wdn_mail_agent ~* ' + regex + ') { return 403; }')
    return '\n'.join(lines) + '\n'


def match(value, uri, agent):
    if value['mode'] == 'off' or not re.match(r'^/mail(?:/|$)', uri):
        return None
    if value['scanners'] and any(re.search(expression, uri, re.I | re.ASCII) for reason, expression in PRIVATE_PATTERNS):
        return 'private-file'
    declared = agent.encode('utf-8').lower()
    if any(entry.encode('ascii').lower() in declared for entry in value['agents']):
        return 'agent'
    return None


def history(state):
    raw = storage.read(Path(state) / HISTORY)
    result = json.loads(raw) if raw is not None else []
    if not isinstance(result, list):
        raise ValueError('Invalid webmail policy history')
    previous = -1
    for row in result:
        if (not isinstance(row, dict) or set(row) != {'since', 'profile', 'logs'} or
                type(row['since']) not in (int, float) or not math.isfinite(row['since']) or
                row['since'] < previous or not isinstance(row['logs'], list) or
                any(not isinstance(path, str) or not path.startswith('/') or '..' in Path(path).parts for path in row['logs'])):
            raise ValueError('Invalid webmail policy history entry')
        value = row['profile']
        if (not isinstance(value, dict) or set(value) != {'mode', 'agents', 'scanners'} or
                value['mode'] not in ('off', 'observe', 'enforce') or type(value['scanners']) is not bool or
                not isinstance(value['agents'], list) or any(not isinstance(agent, str) or not agent.isascii() for agent in value['agents'])):
            raise ValueError('Invalid webmail policy history settings')
        previous = row['since']
    return result


def remember(state, value, logs, now=None):
    records = history(state)
    if not records and value['mode'] == 'off':
        return
    if records and records[-1]['profile'] == value and records[-1]['logs'] == logs:
        return
    now = time.time() if now is None else now
    if not records:
        records.append(dict(since=0, profile=dict(mode='off', agents=[], scanners=False), logs=[]))
    records.append(dict(since=max(now, records[-1]['since']), profile=value, logs=logs))
    # Keep the boundary preceding retention so a still-current policy remains
    # usable even when it was enabled long before the retained log window.
    import ban_history
    cutoff = now - ban_history.settings(state)['days'] * 86400
    boundary = max((index for index, row in enumerate(records) if row['since'] <= cutoff), default=0)
    storage.replace(Path(state) / HISTORY, storage.json_bytes(records[boundary:]), 0o600)


def events(state, cutoff, now, coverage, progress=None, cancelled=None):
    """Classify existing native mail records without copying IPs, URLs or tokens.

    The native format has whole-second timestamps. A second spanning a policy
    transition is reported only as matched, without asserting a block or observe.
    No server access_log directive is added or replaced by this integration.
    """
    import log_files
    from log_analysis import COMBINED
    records = history(state)
    if not records:
        return
    names = sorted({path for row in records for path in row['logs']})
    seen = set()
    trusted = worker_uids()
    coverage.update(available=False, files_read=0, bytes_read=0,
                    classification='Saved webmail policy and native response status')
    def unescape(value):
        return re.sub(rb'\\x([0-9a-fA-F]{2})', lambda m: bytes([int(m[1], 16)]),
                      value.encode('utf-8')).decode('utf-8', errors='replace')
    for name in names:
        for path in log_files.rotations(name):
            try:
                context = log_files.opened(path, trusted)
                stream, raw = context.__enter__()
            except (OSError, ValueError):
                coverage['unavailable_files'] = coverage.get('unavailable_files', 0) + 1
                continue
            try:
                info = os.fstat(raw.fileno())
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                coverage.update(available=True, files_read=coverage['files_read'] + 1)
                position = 0
                for value in stream:
                    if cancelled and cancelled():
                        raise InterruptedError('Activity review cancelled')
                    position += len(value)
                    if not log_files.compressed(path) and position > info.st_size:
                        break
                    coverage['bytes_read'] += len(value)
                    if progress:
                        progress(dict(stage='Reading webmail activity', bytes=coverage['bytes_read']))
                    if not value.endswith(b'\n'):
                        continue
                    parsed = COMBINED.fullmatch(value.decode('utf-8', errors='replace').rstrip('\r\n'))
                    if not parsed:
                        continue
                    address, date, request, status, agent, extra = parsed.groups()
                    try:
                        stamp = datetime.strptime(date, '%d/%b/%Y:%H:%M:%S %z').timestamp()
                    except ValueError:
                        continue
                    if not cutoff <= stamp <= now:
                        continue
                    parts = unescape(request).split()
                    if len(parts) != 3:
                        continue
                    uri = '/' + posixpath.normpath(unquote(parts[1].split('?', 1)[0])).lstrip('/')
                    agent = unescape(agent)
                    candidates = []
                    for index, row in enumerate(records):
                        end = records[index + 1]['since'] if index + 1 < len(records) else float('inf')
                        if row['since'] < stamp + 1 and end > stamp:
                            rule = match(row['profile'], uri, agent) if name in row['logs'] else None
                            candidates.append((row['profile']['mode'], rule))
                    matched = next((rule for mode, rule in candidates if rule), None)
                    if not matched:
                        continue
                    outcome = 'matched'
                    if len(set(candidates)) == 1:
                        mode, rule = candidates[0]
                        if mode == 'observe':
                            outcome = 'observed'
                        elif mode == 'enforce' and status == '403':
                            outcome = 'blocked'
                    yield stamp, dict(time=datetime.fromtimestamp(stamp).astimezone().isoformat(),
                        domain=DOMAIN, rule=matched, outcome=outcome, status=int(status), agent=agent)
            finally:
                context.__exit__(None, None, None)
