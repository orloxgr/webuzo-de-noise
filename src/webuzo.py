"""Webuzo metadata and Nginx integration; never edit generated virtual hosts."""
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import time

from policy import account, domain

HOME = Path('/usr/local/webuzo')
NGINX = Path('/usr/local/apps/nginx/sbin/nginx')
CONFIG = Path('/usr/local/apps/nginx/etc/nginx.conf')
VHOST = Path('/usr/local/apps/nginx/etc/conf.d/webuzoVH.conf')
GLOBAL = Path('/etc/webuzo-de-noise/http.conf')
GLOBAL_CUSTOM = Path('/usr/local/apps/nginx/etc/conf.d/custom.conf')
CUSTOM = Path('/var/webuzo-data/nginx/custom/domains')
STATE = Path('/var/lib/webuzo-de-noise')
SNIPPETS = Path('/etc/webuzo-de-noise/domains')
PHP = Path('/usr/local/emps/bin/php')
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


def run(*args, timeout=90):
    result = subprocess.run([str(v) for v in args], env=ENV, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(str(v) for v in args) +
                           '\n' + (result.stderr or result.stdout).strip())
    return result.stdout


def nginx_build():
    # Nginx writes -V information to stderr even on success.
    result = subprocess.run([str(NGINX), '-V'], env=ENV, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Could not read native Nginx build configuration')
    return result.stdout + result.stderr


def native_read(path):
    """Read panel-owned metadata without following links or trusting site owners."""
    panel = pwd.getpwnam('webuzo')
    path = Path(path)
    # /var/run is the distribution's standard root-owned alias to /run.
    # Resolve that one known prefix; arbitrary symlinks remain forbidden.
    if path.parent == Path('/var/run'):
        link = Path('/var/run').lstat()
        if stat.S_ISLNK(link.st_mode) and link.st_uid == 0 and os.readlink('/var/run') == '/run':
            path = Path('/run') / path.name
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    if not path.is_absolute() or '..' in path.parts:
        os.close(fd)
        raise ValueError('Invalid native metadata path')
    try:
        for index, piece in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            new = os.open(piece, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                          (0 if last else os.O_DIRECTORY), dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            if (info.st_uid not in (0, panel.pw_uid) or info.st_mode & 0o002 or
                    (info.st_mode & 0o020 and info.st_gid not in (0, panel.pw_gid)) or
                    not (stat.S_ISREG(info.st_mode) if last else stat.S_ISDIR(info.st_mode))):
                raise ValueError('Untrusted native metadata: ' + str(path))
        with os.fdopen(os.dup(fd), 'rb') as stream:
            return stream.read()
    finally:
        os.close(fd)


def api(action, owner=None, **values):
    """Official local API transport: no saved panel passwords or API keys."""
    if action not in ('users', 'domains', 'domainmanage', 'cronjob'):
        raise ValueError('Unsupported native API action')
    args = [PHP, HOME / 'cli.php']
    if action in ('users', 'domains'):
        if owner is not None:
            raise ValueError('User discovery requires administrator context')
        args += ['--api', 'act=' + action]
    else:
        args += ['--enduser-api', '--act=' + action, '--loginAs=' + account(owner)]
    allowed = {'reslen', 'page'} if action in ('users', 'domains') else (
        {'edit_record', 'minute', 'hour', 'day', 'month', 'weekday', 'cmd'} if action == 'cronjob' else set())
    if set(values) - allowed:
        raise ValueError('Unsupported native API parameter')
    for key, value in values.items():
        if not isinstance(value, (str, int)) or '\x00' in str(value):
            raise ValueError('Invalid native API value')
        args.append('--' + key + '=' + str(value))
    result = json.loads(run(*args))
    if not isinstance(result, dict):
        raise RuntimeError('Native Webuzo API returned an invalid response')
    if result.get('error'):
        raise RuntimeError('Native Webuzo API failed: ' + json.dumps(result.get('error')))
    return result


def native_list(action):
    data = api(action)
    requested = 0
    while True:
        native = data.get(action)
        total = int(data['num_res'])
        if native == [] and total == 0:
            native = {}
        if not isinstance(native, dict) or total < 0:
            raise ValueError('Native Webuzo ' + action + ' list is unavailable')
        if len(native) == total:
            break
        if len(native) > total or total <= requested:
            raise ValueError('Native Webuzo ' + action + ' list is incomplete')
        # Ask the native API for its reported account count, without a plugin
        # account quota or relying on undocumented pagination parameters.
        requested = total
        data = api(action, reslen=total)
    return native


def users():
    result = {}
    native = native_list('users')
    for row in native.values():
        name = account(row['user'])
        unix = pwd.getpwnam(name)
        if name == 'webuzo' or unix.pw_uid == 0 or Path(unix.pw_dir) != Path(row['homedir']):
            raise ValueError('Native account identity mismatch')
        result[name] = {**row, 'suspended': bool(row['status'])}
    return result


TOKEN = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\#[^\n]*|[{};]|(?:\\.|[^\s{};\#"'])+''')


def directives(text):
    """Parse directive boundaries, preserving quoted braces and comments."""
    tokens = [v for v in TOKEN.findall(text) if not v.startswith('#')]
    def parse(index, nested=False):
        output, words = [], []
        while index < len(tokens):
            value = tokens[index]
            index += 1
            if value == '{':
                if not words:
                    raise ValueError('Unexpected Nginx block')
                children, index = parse(index, True)
                output.append((words[0], words[1:], children))
                words = []
            elif value == ';':
                if not words:
                    raise ValueError('Empty Nginx directive')
                output.append((words[0], words[1:], None))
                words = []
            elif value == '}':
                if not nested or words:
                    raise ValueError('Unexpected Nginx block end')
                return output, index
            else:
                words.append(value[1:-1] if value[:1] in ('"', "'") else value)
        if nested or words:
            raise ValueError('Incomplete Nginx configuration')
        return output, index
    return parse(0)[0]


def servers():
    result = []
    for name, args, children in directives(native_read(VHOST).decode('utf-8')):
        if name != 'server' or children is None:
            continue
        values = {}
        for key, arguments, block in children:
            if block is None:
                values.setdefault(key, []).append(arguments)
        if len(values.get('server_name', [])) != 1:
            continue
        def uses_cache(nodes):
            return any((key in ('proxy_cache', 'fastcgi_cache') and arguments != ['off']) or
                       (block is not None and uses_cache(block))
                       for key, arguments, block in nodes)
        result.append({'names': values['server_name'][0],
                       'roots': values.get('root', []),
                       'access_logs': [args[0] for args in values.get('access_log', []) if args],
                       'cache': uses_cache(children),
                       'includes': [v[0] for v in values.get('include', []) if len(v) == 1],
                       'limits': has_limits(children)})
        result[-1]['authentication'] = has_authentication(children)
    return result


def has_limits(nodes):
    return any(key.startswith('limit_req') or (child is not None and has_limits(child))
               for key, args, child in nodes)


def has_authentication(nodes):
    return any(key in ('auth_basic', 'auth_basic_user_file') or
               (child is not None and has_authentication(child)) for key, args, child in nodes)


def collect():
    accounts = users()
    blocks = servers()
    result = []
    domains = list(native_list('domains').values())
    canonical_rows = {(row['user'], row['domain']): row for row in domains}
    groups = {}
    for row in domains:
        owner, name = account(row['user']), domain(row['domain'])
        if owner not in accounts:
            raise ValueError('Domain refers to an unavailable hosting account')
        matches = [block for block in blocks if name in block['names']]
        canonical = name
        visited = set()
        while canonical_rows[(owner, canonical)].get('type') == 'alias':
            if canonical in visited:
                raise ValueError('Recursive native domain alias')
            visited.add(canonical)
            canonical = domain(canonical_rows[(owner, canonical)]['alias'])
            if (owner, canonical) not in canonical_rows:
                raise ValueError('Native alias target does not belong to its account')
        if canonical == name and matches:
            canonical = domain(matches[0]['names'][0])
        groups.setdefault((owner, canonical), set()).add(name)
    for (owner, canonical), names in groups.items():
        # Webuzo can generate separate server blocks for native aliases. Their
        # custom includes still load one canonical policy and rate-budget key.
        matches = [block for block in blocks if names.intersection(block['names'])]
        key = owner + '/' + canonical
        custom = CUSTOM / (canonical + '.conf')
        snippet = SNIPPETS / (canonical + '.conf')
        primary = canonical_rows.get((owner, canonical))
        root = primary['path'] if primary is not None else None
        valid_root = (isinstance(root, str) and re.fullmatch(r'/[A-Za-z0-9_./-]+', root)
                      and '..' not in root.split('/') and
                      Path(root).is_relative_to(Path(accounts[owner]['homedir'])))
        if primary is None:
            reason = 'Canonical domain metadata is unavailable for this account'
        elif not matches:
            reason = 'No native Nginx virtual host'
        elif not valid_root or any(block['roots'] != [[root]] for block in matches):
            reason = 'Unsupported or ambiguous native document root'
        elif any(block['limits'] for block in matches):
            reason = 'Native virtual host already defines request limits'
        elif not all(str(CUSTOM / (domain(b['names'][0]) + '.conf')) in b['includes'] for b in matches):
            reason = 'Native custom include is missing; rebuild this domain through Webuzo'
        else:
            reason = ''
        result.append({'key': key, 'owner': owner, 'domain': canonical,
                       'aliases': ' '.join(dict.fromkeys(n for b in matches for n in b['names'])),
                       'template': 'caching-webuzo-native' if any(b['cache'] for b in matches) else 'webuzo-native', 'kind': 'web',
                       'suspended': accounts[owner]['suspended'],
                       'supported': not reason, 'reason': reason,
                       'native_authentication': any(b.get('authentication', False) for b in matches),
                       'paths': [str(snippet)] if not reason else [],
                       'roots': {str(snippet): root}, 'custom': str(custom),
                       'custom_domains': sorted({domain(b['names'][0]) for b in matches}),
                       'log_domains': sorted({domain(b['names'][0]) for b in matches}),
                       'native_access_logging': bool(matches) and all(
                           '/usr/local/apps/nginx/var/log/' + domain(b['names'][0]) + '.log' in b.get('access_logs', [])
                           for b in matches),
                       'include_loaded': bool(matches) and all(str(CUSTOM / (domain(b['names'][0]) + '.conf')) in b['includes'] for b in matches)})
    return sorted(result, key=lambda site: site['key'])


def cron_metadata(operation, owner=None):
    if operation == 'accounts':
        return {name: {'SUSPENDED': 'yes' if row['suspended'] else 'no'} for name, row in users().items()}
    if operation != 'cron_jobs':
        raise ValueError('Unsupported cron metadata operation')
    result = api('cronjob', account(owner)).get('read_cron')
    if result == []:
        return {}
    if not isinstance(result, dict):
        raise ValueError('Unsupported native cron response')
    fields = {'min': 'MIN', 'hou': 'HOUR', 'day': 'DAY', 'mon': 'MONTH', 'wee': 'WDAY', 'cmd': 'CMD'}
    return {str(key): {**{target: row[source] for source, target in fields.items()}, 'SUSPENDED': 'no'}
            for key, row in result.items()}


def change_cron(owner, ident, minute, hour, day, month, weekday, command):
    owner = account(owner)
    current = cron_metadata('cron_jobs', owner).get(str(ident))
    if current is None or current['CMD'] != command:
        raise ValueError('The native cron job changed; generate a new preview')
    result = api('cronjob', owner, edit_record=str(ident), minute=minute, hour=hour,
                 day=day, month=month, weekday=weekday, cmd=command)
    if not result.get('done'):
        raise RuntimeError('Native Webuzo cron edit was not confirmed')


def cli(task, **values):
    if task not in ('rebuild_vhost', 'clear_cache'):
        raise ValueError('Unsupported native Webuzo command')
    args = [PHP, HOME / 'cli.php', '--' + task]
    if task == 'clear_cache':
        if set(values) != {'users'}:
            raise ValueError('An account is required')
        args.append('--users=' + account(values['users']))
    elif values:
        raise ValueError('Unexpected rebuild arguments')
    return run(*args)


def reload_nginx():
    return reload_instance(NGINX, CONFIG)


def reload_instance(binary, config, nodes=None):
    """Use Nginx's configured native PID; do not assume a systemd MainPID."""
    nodes = directives(native_read(config).decode()) if nodes is None else nodes
    values = [args for name, args, child in nodes if name == 'pid' and child is None]
    if len(values) != 1 or len(values[0]) != 1 or not values[0][0].startswith('/'):
        raise ValueError('A single absolute native Nginx pid path is required')
    raw = native_read(Path(values[0][0])).decode().strip()
    if not re.fullmatch('[1-9][0-9]*', raw):
        raise ValueError('Invalid native Nginx master PID')
    master = int(raw)
    proc = Path('/proc') / raw
    if (proc / 'exe').resolve() != binary.resolve() or proc.stat().st_uid != 0:
        raise ValueError('PID does not belong to the native Nginx master')
    def workers():
        children = (proc / 'task' / raw / 'children').read_text().split()
        active = set()
        for child in children:
            try:
                command = (Path('/proc') / child / 'cmdline').read_bytes()
                if b'nginx: worker process' in command and b'shutting down' not in command:
                    active.add(child)
            except FileNotFoundError:
                pass
        return active
    before = workers()
    run(binary, '-t')
    os.kill(master, signal.SIGHUP)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        current = workers()
        # A newly spawned worker can appear before the master tells every old
        # worker to stop accepting connections. Require that transition too;
        # graceful workers may continue serving their existing connections.
        if current - before and not current & before:
            return
        time.sleep(.05)
    raise RuntimeError('Nginx did not start new workers after reload')
