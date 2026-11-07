"""Literal probe presets and bounded native Nginx query matchers."""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote

FILES = (Path(__file__).with_name('php-probes.txt')).read_text(encoding='utf-8').splitlines()


def event_format(name, reason, event_token):
    payload = dict(v=1, ts='$msec', ip='$remote_addr', domain='$hdn_site',
                   reason=reason, token=event_token, path='$hdn_request_path', method='$request_method')
    return "log_format " + name + " escape=json '" + json.dumps(payload, separators=(',', ':')) + "';"


def is_previous_preset(paths):
    """Upgrade unchanged bundled lists, preserving custom lists."""
    return (all(isinstance(value, str) for value in paths) and
            hashlib.sha256('\n'.join(sorted(paths)).encode()).hexdigest() in
            {'8c0d5ef9de2ee5814ef00179557bb611f311d6bda0e7cdbeba3d3600cbd10dce',
             '67568236cc1dbad6c373062fb4a361ec9c2ad20e8c13026371c2e81855b1cd67',
             '667fd8e9488d0313098dd34c5582edf1c95ee02b11cda209b38ecf23a6f48830'})

QUERY_PARAMETERS = ['file', 'path', 'page', 'include', 'download_file', 'src',
                    'resource', 'template', 'view', 'document', 'filename', 'apis']
QUERY_TARGETS = ['/etc/passwd', '/etc/shadow', '/etc/gshadow', '/proc/self/environ',
                 '/proc/self/cmdline', '/var/run/secrets/kubernetes.io/serviceaccount/token',
                 '/root/.ssh/id_rsa', '/root/.ssh/id_ed25519', '/.aws/credentials',
                 '/.kube/config', '/.docker/config.json', '/.git/config', '/.git/HEAD',
                 '/.svn/entries', '/.hg/hgrc', '/var/log/auth.log',
                 '/var/log/nginx/access.log', '/var/log/apache2/access.log',
                 '/var/log/nginx/error.log', '/var/log/apache2/error.log',
                 'wp-config.php', '.env', 'c:/windows/win.ini']


def token(kind, value):
    return kind + hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]


def encoded_literal(text):
    """Each ASCII character may be literal, percent encoded, or encoded twice.

    Match bounded spelling alternatives in PCRE, without decoding arbitrary
    requests in a script or interpreting administrator text as a regex.
    """
    out = []
    for char in text:
        code = format(ord(char), '02x')
        values = [re.escape(char), '%' + code, '%25' + code]
        if char == '/':
            values += [r'\\', '%5c', '%255c']
        out.append('(?:' + '|'.join(values) + ')')
    return ''.join(out)


def query_pattern(target, parameters=None):
    slash = encoded_literal('/')
    traversal = '(?:' + encoded_literal('..') + slash + ')*'
    # Entire file argument, optionally with traversal or a PHP filter wrapper.
    # A search sentence merely mentioning wp-config.php does not match.
    wrapper = '(?:' + encoded_literal('php://filter/') + '[^&]*' + encoded_literal('resource=') + ')?'
    if target.startswith('/'):
        value = '(?:' + slash + '|' + traversal + ')' + encoded_literal(target[1:])
    else:
        value = traversal + encoded_literal(target)
    names = '|'.join(''.join('(?:' + re.escape(char) + '|%' + format(ord(char), '02x') + ')' for char in name)
                     for name in (QUERY_PARAMETERS if parameters is None else parameters))
    return '(?:^|&)(?:' + names + ')=' + wrapper + value + '(?:%00|%2500)?(?:&|$)'


def validate_settings(data, path_validator, target_validator):
    settings = data['bans']
    for key, field in [('missing_files', 'paths'), ('suspicious_queries', 'targets')]:
        rule = settings[key]
        fields = {'enabled', 'maxretry', 'findtime', 'duration_days', field} | ({'parameters'} if key == 'suspicious_queries' else set())
        if (not isinstance(rule, dict) or set(rule) != fields
                or type(rule['enabled']) is not bool or type(rule['maxretry']) is not int or not rule['maxretry'] >= 1
                or type(rule['findtime']) is not int or not rule['findtime'] > 0
                or type(rule['duration_days']) is not int or not rule['duration_days'] >= 0):
            raise ValueError('Invalid ' + key + ' controls')
        entries = rule[field]
        if not isinstance(entries, list):
            raise ValueError('Use a list of selected probe paths/targets')
        if key == 'missing_files':
            clean = [path_validator(value) for value in entries]
            if any(not value.lower().endswith('.php') for value in clean):
                raise ValueError('Selected PHP probe paths must end in .php')
        else:
            clean = []
            for value in entries:
                if (not isinstance(value, str) or not bool(value)
                        or not re.fullmatch(r'[A-Za-z0-9_./:\\-]+', value)
                        or '..' in value.replace('\\', '/').split('/')):
                    raise ValueError('Query targets must be literal file paths, without wildcards, traversal or expressions')
                clean.append(value.replace('\\', '/'))
        rule[field] = list(dict.fromkeys(clean))
        if key == 'suspicious_queries':
            names = rule['parameters']
            if (not isinstance(names, list) or any(not isinstance(name, str)
                    or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name) for name in names)):
                raise ValueError('Use literal query parameter names, one per line')
            rule['parameters'] = list(dict.fromkeys(name.lower() for name in names))
    exceptions = data['probe_exceptions']
    if not isinstance(exceptions, dict) or set(exceptions) != {'files', 'queries'}:
        raise ValueError('Invalid probe exceptions')
    total = 0
    for kind in exceptions:
        if not isinstance(exceptions[kind], dict):
            raise ValueError('Invalid domain probe exceptions')
        for site, paths in exceptions[kind].items():
            target_validator(site)
            if not isinstance(paths, list):
                raise ValueError('Use a probe-exception list')
            exceptions[kind][site] = list(dict.fromkeys(path_validator(value) for value in paths))
            total += sum(len(value) for value in exceptions[kind][site])


def reason_settings(settings):
    """Keep direct, selected-file, selected-query and general-404 limits separate."""
    common = {key: settings[key] for key in ('maxretry', 'findtime', 'duration_days')}
    return {**({'private-file': common} if settings['private_files'] else {}),
            **({'repository': common} if settings['repositories'] else {}),
            **({'missing-file': settings['missing_files']} if settings['missing_files']['enabled'] else {}),
            **({'suspicious-query': settings['suspicious_queries']} if settings['suspicious_queries']['enabled'] else {}),
            **({'not-found': settings['any_404']} if settings['any_404']['enabled'] else {})}


def compile_maps(policy, sites, pattern, exact):
    lines = ['map $hdn_site $hdn_probe_web_site {', '    default 0;']
    lines += ['    ' + site.get('domain', site['key'].split('/', 1)[1]) + ' 1;'
              for site in sites if site.get('supported', True) and not site.get('suspended')]
    lines += ['}']
    settings = policy['bans']
    for kind, key in [('file', 'missing_files'), ('query', 'suspicious_queries')]:
        lines += ['map "$hdn_ban_site:$hdn_probe_web_site" $hdn_probe_' + kind + '_site {',
                  '    default 0;']
        if settings['enabled'] and settings[key]['enabled']:
            lines += ['    ~^1:1$ 1;']
        lines += ['}']
    for kind in ('files', 'queries'):
        lines += ['map "$hdn_site:$uri" $hdn_probe_' + kind + '_exempt {', '    default 0;']
        for site in sites:
            if site.get('supported', True) and not site.get('suspended'):
                host = site.get('domain', site['key'].split('/', 1)[1])
                lines += ['    ' + exact(host + ':' + unquote(value)) + ' 1;'
                          for value in policy['probe_exceptions'][kind].get(site['key'], [])]
        lines += ['}']
    lines += ['map $uri $hdn_probe_file_path {', '    default "";']
    if settings['enabled'] and settings['missing_files']['enabled']:
        lines += ['    ' + exact(unquote(path)) + ' ' + token('f', path) + ';'
                  for path in settings['missing_files']['paths']]
    query_enabled = settings['enabled'] and settings['suspicious_queries']['enabled']
    source = '$args' if query_enabled else '""'
    lines += ['}', 'map ' + source + ' $hdn_probe_query_path {', '    default "";']
    if query_enabled and settings['suspicious_queries']['parameters']:
        def matchers(value, names):
            expression = pattern(query_pattern(value, names))
            # Nginx config tokens have a bounded parser buffer. Split long
            # administrator name lists without widening the matching scope.
            if len(expression.encode()) > 3900:
                if len(names) == 1:
                    raise ValueError('Query target/name is too long for a native matcher; shorten the entry')
                middle = len(names)//2
                return matchers(value, names[:middle]) + matchers(value, names[middle:])
            return ['    ' + expression + ' ' + token('q', value) + ';']
        for value in settings['suspicious_queries']['targets']:
            lines += matchers(value, settings['suspicious_queries']['parameters'])
    lines += ['}']
    for kind, source in [('file', 'files'), ('query', 'queries')]:
        lines += ['map "$hdn_mode:$hdn_probe_' + kind + '_site:$hdn_probe_' + source + '_exempt:$hdn_probe_' + kind + '_path" $hdn_probe_' + kind + ' {',
                  '    default "";', '    ' + pattern('^(observe|enforce):1:0:[fq][0-9a-f]{16}$') + ' $hdn_probe_' + kind + '_path;', '}']
    lines += ['map "$hdn_direct_reject:$hdn_ban_signal:$hdn_probe_query:$hdn_probe_file" $hdn_event_reason {',
              '    default "";', '    ~^1:private-file: private-file;', '    ~^1:repository: repository;',
              '    ' + pattern(':q[0-9a-f]{16}:') + ' suspicious-query;', '    ' + pattern(':f[0-9a-f]{16}$') + ' missing-file;', '}',
              'map "$hdn_probe_query:$hdn_probe_file" $hdn_event_token {', '    default -;',
              '    ' + pattern('^q[0-9a-f]{16}:') + ' $hdn_probe_query;', '    ' + pattern(':f[0-9a-f]{16}$') + ' $hdn_probe_file;', '}',
              'map "$hdn_mode:$hdn_ban_site:$hdn_event_reason:$status" $hdn_autoban_log {',
              '    default 0;', '    ~^enforce:1:(private-file|repository):403$ 1;',
              *(['    ~^enforce:1:missing-file:404$ 1;'] if settings['missing_files']['enabled'] else []),
              *(['    ~^enforce:1:suspicious-query:404$ 1;'] if settings['suspicious_queries']['enabled'] else []), '}',
              'map $request_uri $hdn_request_path {', '    default "";',
              '    ' + pattern('^([^?]*)') + ' $1;', '}',
              event_format('hdn_bans', '$hdn_event_reason', '$hdn_event_token')]
    # Fallback for configurations without complete native server-level logging.
    # Standard Webuzo virtual hosts already log these local 404s, so their site
    # snippets omit this extra event to retain one strike per actual request.
    lines += ['map "$hdn_mode:$status:$upstream_status" $hdn_early_404_log {',
              '    default 0;', '    ~^enforce:404:(-|)$ 1;', '}',
              event_format('hdn_early_404', 'not-found', '-')]
    return lines
