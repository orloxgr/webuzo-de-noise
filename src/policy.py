"""Validated policy and a deterministic native Nginx compiler."""
import copy
import hashlib
import ipaddress
import re
from urllib.parse import quote, unquote
import probe_rules
import enumeration
import agent_catalog

MARKER = '# Managed by webuzo-de-noise'
VERSION = '0.2.0'
MODES = ('off', 'observe', 'enforce')
SCANNER_AGENTS = agent_catalog.SCANNERS
CRAWLER_AGENTS = ['meta-externalagent', 'GoogleOther', 'MJ12bot', 'Bytespider',
                  'ClaudeBot', 'Amazonbot', 'Reflectionbot', 'GPTBot',
                  'AhrefsBot', 'SemrushBot', 'DotBot', 'BLEXBot', 'YisouSpider',
                  'ElevenlabsCrawler', 'CCBot']
SEARCH_AGENTS = agent_catalog.SEARCH
PRESET_AGENTS = SCANNER_AGENTS + CRAWLER_AGENTS[:3]
FILTER_AGENTS = ['Applebot', 'Amazonbot', 'Reflectionbot', 'Googlebot', 'bingbot']
DEFAULT = {'schema': 10, 'mode': 'observe', 'agents': [], 'scanners': False,
           'enumeration': copy.deepcopy(enumeration.SETTINGS),
           'log_rejections': False, 'mail_protection': False,
           'login': {'enabled': False, 'rate': 5, 'burst': 3},
           'xmlrpc': {'enabled': False, 'rate': 10, 'burst': 3}, 'overrides': {},
           'filters': [], 'static': [], 'static_exceptions': {},
           'tool_agents': [], 'tool_agents_enabled': True, 'agents_enabled': True,
           'bans': {'enabled': False, 'private_files': True, 'repositories': True,
                    'maxretry': 1, 'findtime': 300, 'duration_days': 0,
                    'ignore_ips': [], 'targets': [],
                    'any_404': {'enabled': False, 'maxretry': 10, 'findtime': 300, 'duration_days': 3,
                                'exclude_static': True, 'min_distinct_paths': 3},
                    'missing_files': {'enabled': False, 'maxretry': 2, 'findtime': 60,
                                      'duration_days': 3, 'paths': list(probe_rules.FILES)},
                    'suspicious_queries': {'enabled': False, 'maxretry': 2, 'findtime': 60,
                                           'duration_days': 3, 'targets': list(probe_rules.QUERY_TARGETS),
                                           'parameters': list(probe_rules.QUERY_PARAMETERS)}},
           'probe_exceptions': {'files': {}, 'queries': {}},
           'domain_bans': {'allow_users': True, 'sites': {}}}
for _field in ('ai_agents', 'search_agents', 'seo_agents'):
    DEFAULT[_field] = []
    DEFAULT[_field + '_enabled'] = True
AGENT_KEYS = {key for field in ('ai_agents', 'search_agents', 'seo_agents') for key in (field, field + '_enabled')}
V9_KEYS = set(DEFAULT) - AGENT_KEYS
LEGACY_KEYS = {'schema', 'mode', 'agents', 'scanners', 'login', 'xmlrpc', 'overrides'}
V7_KEYS = V9_KEYS - {'log_rejections', 'mail_protection', 'enumeration'}
PRIVATE_PATTERNS = [
    ('private-file', r'(?:^|/)\.env(?:[./]|$)'),
    ('repository', r'(?:^|/)\.(?:git|svn|hg)(?:/|$)'),
    ('private-file', r'(?:^|/)wp-config\.php\.(?:bak|backup|old|orig|save|swp|zip|sql)$'),
    ('private-file', r'(?:^|/)\.htpasswd(?:/|$)'),
    ('metadata', r'(?:^|/)\.DS_Store(?:/|$)'),
    ('private-file', r'(?:^|/)\.aws/(?:credentials|config)(?:/|$)'),
    ('private-file', r'(?:^|/)\.docker/(?:config|secrets)\.json(?:/|$)'),
    ('private-file', r'(?:^|/)\.kube/config(?:/|$)'),
    ('private-file', r'(?:^|/)\.terraform/(?:credentials\.tfrc\.json|terraform\.tfstate)(?:/|$)'),
    ('private-file', r'(?:^|/)proc/(?:self|[0-9]+)/(?:environ|cmdline)(?:/|$)'),
    ('private-file', r'(?:^|/)etc/(?:passwd|shadow|gshadow)(?:/|$)'),
    ('private-file', r'(?:^|/)var/run/secrets/kubernetes\.io/serviceaccount(?:/|$)')]


def account(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', value):
        raise ValueError('Invalid account name')
    return value


def domain(value):
    if (not isinstance(value, str) or len(value) > 253 or
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in value.split('.'))):
        raise ValueError('Invalid ASCII domain name')
    return value


def target(value):
    if not isinstance(value, str) or value.count('/') != 1:
        raise ValueError('Invalid site selection')
    owner, name = value.split('/')
    account(owner); domain(name)
    return value


def validate(raw):
    if not isinstance(raw, dict):
        raise ValueError('Unsupported policy format')
    data = copy.deepcopy(raw)
    if type(data.get('schema')) is int and 1 <= data['schema'] < 8:
        data.pop('log_rejections', None)
        data.pop('mail_protection', None)
    if data.get('schema') == 1 and set(data) == LEGACY_KEYS:
        data.update(schema=2, filters=[], static=[])
    if data.get('schema') == 2 and set(data) == LEGACY_KEYS | {'filters', 'static'}:
        data.update(schema=3, static_exceptions={})
    if data.get('schema') == 3 and set(data) == LEGACY_KEYS | {'filters', 'static', 'static_exceptions'}:
        tools = {name.lower() for name in SCANNER_AGENTS}
        previous = data['agents']
        if not isinstance(previous, list) or any(not isinstance(entry, str) for entry in previous):
            raise ValueError('Invalid saved User-Agent list')
        data.update(schema=4, tool_agents=[entry for entry in previous if entry.strip().lower() in tools],
                    agents=[entry for entry in previous if entry.strip().lower() not in tools],
                    tool_agents_enabled=True, agents_enabled=True, bans={key: copy.deepcopy(value) for key, value in DEFAULT['bans'].items() if key not in ('missing_files', 'suspicious_queries', 'any_404')})
    if data.get('schema') == 4 and set(data) == V7_KEYS - {'probe_exceptions', 'domain_bans'}:
        if not isinstance(data.get('bans'), dict):
            raise ValueError('Invalid saved automatic-ban settings')
        data['bans'].update({key: copy.deepcopy(DEFAULT['bans'][key]) for key in ('missing_files', 'suspicious_queries')})
        data.update(schema=5, probe_exceptions={'files': {}, 'queries': {}})
    if data.get('schema') == 5 and set(data) == V7_KEYS - {'domain_bans'}:
        data.update(schema=6, domain_bans=copy.deepcopy(DEFAULT['domain_bans']))
    if data.get('schema') == 6 and set(data) == V7_KEYS:
        if not isinstance(data.get('bans'), dict) or not isinstance(data.get('domain_bans'), dict):
            raise ValueError('Invalid saved automatic-ban settings')
        data['bans']['any_404'] = copy.deepcopy(DEFAULT['bans']['any_404'])
        if not isinstance(data['domain_bans'].get('sites'), dict):
            raise ValueError('Invalid saved domain trigger selections')
        for flags in data['domain_bans']['sites'].values():
            if not isinstance(flags, dict) or set(flags) != {'missing_files', 'suspicious_queries'}:
                raise ValueError('Invalid saved domain trigger switches')
            flags['any_404'] = False
        paths = data['bans'].get('missing_files', {}).get('paths')
        if isinstance(paths, list) and probe_rules.is_previous_preset(paths):
            data['bans']['missing_files']['paths'] = list(probe_rules.FILES)
        data['schema'] = 7
    if data.get('schema') == 7 and set(data) == V7_KEYS:
        rule = data.get('bans', {}).get('any_404')
        if not isinstance(rule, dict):
            raise ValueError('Invalid saved general 404 controls')
        rule.setdefault('exclude_static', True)
        rule.setdefault('min_distinct_paths', 3)
        paths = data['bans'].get('missing_files', {}).get('paths')
        if isinstance(paths, list) and probe_rules.is_previous_preset(paths):
            data['bans']['missing_files']['paths'] = list(probe_rules.FILES)
        data.update(schema=8, log_rejections=False, mail_protection=False)
    if data.get('schema') == 8 and set(data) == V9_KEYS - {'enumeration'}:
        data.update(schema=9, enumeration=copy.deepcopy(enumeration.SETTINGS))
    if data.get('schema') == 9 and set(data) == V9_KEYS:
        previous = data.get('agents')
        if not isinstance(previous, list) or any(not isinstance(value, str) for value in previous):
            raise ValueError('Invalid saved User-Agent list')
        for field in ('ai_agents', 'search_agents', 'seo_agents'):
            data[field] = [value for value in previous if agent_catalog.classify(value) == field]
            data[field + '_enabled'] = data['agents_enabled']
        data['agents'] = [value for value in previous if agent_catalog.classify(value) not in ('ai_agents', 'search_agents', 'seo_agents')]
        data['schema'] = 10
    if data.get('schema') != 10 or set(data) != set(DEFAULT):
        raise ValueError('Unsupported policy format')
    enumeration.validate(data['enumeration'], target)
    if data['mode'] not in MODES or type(data['scanners']) is not bool:
        raise ValueError('Invalid mode or private-file setting')
    if any(type(data[key]) is not bool for key in tuple(field + '_enabled' for field in agent_catalog.CATEGORIES) + ('log_rejections', 'mail_protection')):
        raise ValueError('Invalid User-Agent list switch')
    for field in agent_catalog.CATEGORIES:
        data[field] = validate_agents(data[field])
    ban = data['bans']
    if (not isinstance(ban, dict) or set(ban) != set(DEFAULT['bans']) or
            any(type(ban[key]) is not bool for key in ('enabled', 'private_files', 'repositories')) or
            type(ban['maxretry']) is not int or not ban['maxretry'] >= 1 or
            type(ban['findtime']) is not int or not ban['findtime'] > 0 or
            type(ban['duration_days']) is not int or not ban['duration_days'] >= 0):
        raise ValueError('Automatic-ban attempts/window must be positive; duration must be nonnegative')
    if not isinstance(ban['targets'], list):
        raise ValueError('Invalid automatic-ban domain selection')
    ban['targets'] = list(dict.fromkeys(target(name) for name in ban['targets']))
    if not isinstance(ban['ignore_ips'], list):
        raise ValueError('Invalid never-ban IP list')
    if any(not isinstance(value, str) for value in ban['ignore_ips']):
        raise ValueError('Never-ban entries must be IP addresses or CIDR networks')
    try:
        ban['ignore_ips'] = list(dict.fromkeys(str(ipaddress.ip_network(value, strict=False)) for value in ban['ignore_ips']))
    except ValueError as error:
        raise ValueError('Never-ban entries must be IP addresses or CIDR networks') from error
    probe_rules.validate_settings(data, exception_path, target)
    # Expand only an exact prior bundled list, including current-schema policies.
    # An edited list remains the administrator's choice; the panel can merge it.
    if probe_rules.is_previous_preset(ban['missing_files']['paths']):
        ban['missing_files']['paths'] = list(probe_rules.FILES)
    rule = ban['any_404']
    if (not isinstance(rule, dict) or set(rule) != set(DEFAULT['bans']['any_404'])
            or type(rule['enabled']) is not bool or type(rule['maxretry']) is not int or not rule['maxretry'] >= 1
            or type(rule['findtime']) is not int or not rule['findtime'] > 0
            or type(rule['duration_days']) is not int or not rule['duration_days'] >= 0
            or type(rule['exclude_static']) is not bool or type(rule['min_distinct_paths']) is not int
            or not rule['min_distinct_paths'] >= 1):
        raise ValueError('Invalid general 404 automatic-ban controls')
    delegation = data['domain_bans']
    if (not isinstance(delegation, dict) or set(delegation) != {'allow_users', 'sites'}
            or type(delegation['allow_users']) is not bool or not isinstance(delegation['sites'], dict)
            ):
        raise ValueError('Invalid domain automatic-ban settings')
    for key, rules in delegation['sites'].items():
        target(key)
        if (not isinstance(rules, dict) or set(rules) != {'missing_files', 'suspicious_queries', 'any_404'}
                or any(type(value) is not bool for value in rules.values())):
            raise ValueError('Domain owners may select trigger categories only')
    return validate_rules(data)


def validate_agents(entries):
    if not isinstance(entries, list):
        raise ValueError('Use a User-Agent list')
    agents = []
    for entry in entries:
        # Printable ASCII keeps the literal substring behavior explicit across
        # Nginx/PCRE builds. Quotes, regex and config punctuation are escaped.
        if (not isinstance(entry, str) or not bool(entry.strip()) or
                any(ord(c) < 32 or ord(c) > 126 for c in entry)):
            raise ValueError('User-Agents must be nonempty printable text')
        entry = entry.strip()
        if entry.lower() not in [x.lower() for x in agents]:
            agents.append(entry)
    return agents


def validate_rules(data):
    for key in ('login', 'xmlrpc'):
        rule = data[key]
        if (not isinstance(rule, dict) or set(rule) != {'enabled', 'rate', 'burst'} or
                type(rule['enabled']) is not bool or type(rule['rate']) is not int or
                not rule['rate'] >= 1 or type(rule['burst']) is not int or
                not rule['burst'] >= 0):
            raise ValueError('Rate must be positive and burst nonnegative')
    if not isinstance(data['overrides'], dict):
        raise ValueError('Invalid domain overrides')
    for key, mode in data['overrides'].items():
        target(key)
        if mode not in MODES:
            raise ValueError('Invalid domain mode')
    ids = set()
    for module in ('filters', 'static'):
        if not isinstance(data[module], list):
            raise ValueError('Use a rule list')
        for rule in data[module]:
            fields = {'id', 'enabled', 'path', 'targets'} | (
                {'parameters', 'agents', 'action', 'rate', 'burst'} if module == 'filters' else {'extensions'})
            if not isinstance(rule, dict) or set(rule) != fields:
                raise ValueError('Invalid ' + module + ' rule fields')
            ident = rule['id']
            if not isinstance(ident, str) or not re.fullmatch(r'[a-z][a-z0-9_]*', ident) or ident in ids:
                raise ValueError('Rule IDs must be unique lowercase names')
            ids.add(ident)
            if type(rule['enabled']) is not bool:
                raise ValueError('Invalid rule switch')
            path = rule['path']
            if (not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9_./~-]*', path) or
                    '..' in path.split('/') or '//' in path):
                raise ValueError('Enter a literal URL path, without query, wildcard or traversal')
            if module == 'static' and (path == '/' or not path.endswith('/')):
                raise ValueError('Static directories must end in / and cannot be the site root')
            if not isinstance(rule['targets'], list):
                raise ValueError('Invalid rule domain selection')
            rule['targets'] = list(dict.fromkeys(target(x) for x in rule['targets']))
            if module == 'filters':
                if rule['action'] not in ('limit', 'block'):
                    raise ValueError('Choose limit or block for filtered URLs')
                if (type(rule['rate']) is not int or not rule['rate'] >= 1 or
                        type(rule['burst']) is not int or not rule['burst'] >= 0):
                    raise ValueError('Rate must be positive and burst nonnegative')
                if not isinstance(rule['parameters'], list) or not bool(rule['parameters']):
                    raise ValueError('Enter filter parameter names')
                if any(not isinstance(x, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]*', x)
                       for x in rule['parameters']):
                    raise ValueError('Invalid filter parameter name')
                rule['parameters'] = list(dict.fromkeys(x.lower() for x in rule['parameters']))
                if (not isinstance(rule['agents'], list) or not bool(rule['agents']) or
                        any(not isinstance(x, str) or not bool(x) or
                            any(ord(c) < 32 or ord(c) > 126 for c in x) for x in rule['agents'])):
                    raise ValueError('Enter literal crawler names for a filter rule')
                rule['agents'] = list(dict.fromkeys(x.lower() for x in rule['agents']))
            else:
                if (not isinstance(rule['extensions'], list) or not bool(rule['extensions']) or
                        any(not isinstance(x, str) or not re.fullmatch(r'[a-z0-9]+', x)
                            for x in rule['extensions'])):
                    raise ValueError('Enter lowercase static file extensions, without dots')
                rule['extensions'] = list(dict.fromkeys(rule['extensions']))
    exceptions = data['static_exceptions']
    if not isinstance(exceptions, dict):
        raise ValueError('Invalid static-file exceptions')
    normalized = {}
    for site, paths in exceptions.items():
        target(site)
        if not isinstance(paths, list):
            raise ValueError('Use a file-exception list')
        paths = list(dict.fromkeys(exception_path(path) for path in paths))
        if paths:
            normalized[site] = paths
    data['static_exceptions'] = normalized
    return data


def exception_path(value):
    """Canonical URL-encoded representation; decode exactly once when compiling."""
    if not isinstance(value, str) or not value.startswith('/') or re.search(r'%(?![0-9A-Fa-f]{2})', value):
        raise ValueError('File exceptions must be URL paths starting with /, one per line')
    try:
        decoded = unquote(value, encoding='utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('File exceptions must contain valid UTF-8 URL paths') from error
    if (decoded.endswith('/') or '//' in decoded or
            any(part in ('.', '..') for part in decoded.split('/')) or
            any(char in decoded for char in '?#*\\') or not decoded.isprintable()):
        raise ValueError('Enter exact file paths without query strings, wildcards or traversal')
    return quote(decoded, safe='/-._~$&()+,;=:@')


def exact_uri_pattern(value):
    return '"~^' + ''.join(r'\\x' + format(byte, '02x') for byte in value.encode('utf-8')) + '$"'


def literal_regex(value):
    """A PCRE literal inside one Nginx double-quoted config token."""
    # Hex every byte: neither Nginx config interpolation nor PCRE metacharacters
    # can reinterpret an administrator's literal text. Nginx consumes one of
    # the two backslashes before PCRE receives each \xHH escape.
    return '"~*' + ''.join(r'\\x' + format(ord(c), '02x') for c in value) + '"'


def pattern(value):
    """Quote only compiler-created PCRE expressions, never administrator regex."""
    return '"~*' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def applies(rule, site):
    return rule['enabled'] and (not rule['targets'] or site['key'] in rule['targets'])


def path_pattern(value):
    return '^' if value == '/' else '^' + re.escape(value.rstrip('/')) + '(?:/|$)'


def parameter_pattern(value):
    # Also recognize percent-encoded ASCII parameter names, not just literal ones.
    return ''.join('(?:' + re.escape(c) + '|%' + format(ord(c), '02x') + ')' for c in value)


def scope_map(variable, rule, sites):
    names = sorted({s.get('domain', s['key'].split('/', 1)[1]) for s in sites
                    if applies(rule, s) and s.get('supported', True) and not s.get('suspended')})
    return ['map $hdn_site $' + variable + ' {', '    default 0;'] + [
        '    ' + domain(name) + ' 1;' for name in names] + ['}']


def site_mode(policy, site):
    if site.get('kind') == 'mail' and not policy['mail_protection']:
        return 'off'
    return policy['overrides'].get(site['key'], policy['mode']) if not site.get('suspended') else 'off'


def global_config(policy, sites, domain_blocks=None, global_blocks=None):
    policy = validate(policy)
    # Declare a safe mode even on a new server with no domains yet. Supported
    # virtual hosts set this changeable variable during their rewrite phase.
    lines = [MARKER, 'map $server_name $hdn_site { default $server_name; }']
    lines += ['geo $remote_addr $hdn_global_blocked {', '    default 0;']
    for value in sorted(global_blocks or []):
        address = ipaddress.ip_address(value)
        lines.append('    ' + str(address) + ('/32' if address.version == 4 else '/128') + ' 1;')
    lines += ['}']
    block_variables = []
    known = {site['key']: site for site in sites if site.get('supported', True) and not site.get('suspended')}
    for key, addresses in sorted((domain_blocks or {}).items()):
        if key not in known or site_mode(policy, known[key]) != 'enforce' or not addresses:
            continue
        name = 'hdn_domain_' + hashlib.sha256(key.encode()).hexdigest()[:16]
        lines += ['geo $remote_addr $' + name + ' {', '    default 0;']
        for address in sorted(addresses):
            ip = ipaddress.ip_address(address)
            lines += ['    ' + str(ip) + ('/32' if ip.version == 4 else '/128') + ' 1;']
        lines += ['}']
        block_variables.append((domain(known[key].get('domain', key.split('/', 1)[1])), name))
    lines += ['map $hdn_site $hdn_domain_blocked {', '    default 0;']
    lines += ['    ' + host + ' $' + name + ';' for host, name in block_variables]
    lines += ['}', 'map $hdn_site $hdn_mode { default off; }',
             'map $http_user_agent $hdn_agent {', '    default 0;']
    entries = agent_catalog.enabled(policy)
    lines += ['    ' + literal_regex(entry) + ' 1;' for entry in dict.fromkeys(entries)]
    lines += ['}', 'map $uri $hdn_private {', '    default 0;']
    if policy['scanners']:
        lines += ['    ' + pattern(p) + ' 1;' for _, p in PRIVATE_PATTERNS]
    lines += ['}']
    lines += ['map $uri $hdn_ban_signal {', '    default "";']
    for signal, regex in PRIVATE_PATTERNS:
        if policy['bans']['enabled'] and ((signal == 'private-file' and policy['bans']['private_files']) or
                                          (signal == 'repository' and policy['bans']['repositories'])):
            lines += ['    ' + pattern(regex) + ' ' + signal + ';']
    lines += ['}']
    lines += scope_map('hdn_ban_site', policy['bans'], sites)
    lines += ['map "$hdn_mode:$hdn_ban_site:$hdn_ban_signal" $hdn_direct_reject {',
              '    default 0;', '    ~^enforce:1:(private-file|repository)$ 1;', '}']
    web_sites = [site for site in sites if site.get('kind') != 'mail']
    lines += enumeration.compiled(policy, web_sites, pattern, parameter_pattern)
    lines += probe_rules.compile_maps(policy, web_sites, pattern, exact_uri_pattern)
    lines += ['map "$hdn_site:$uri" $hdn_static_exempt {', '    default 0;']
    for site in sites:
        if site.get('supported', True) and not site.get('suspended'):
            name = domain(site.get('domain', site['key'].split('/', 1)[1]))
            lines += ['    ' + exact_uri_pattern(name + ':' + unquote(path)) + ' 1;'
                      for path in policy['static_exceptions'].get(site['key'], [])]
    lines += ['}']
    block_variables = []
    for index, rule in enumerate(policy['filters']):
        tag = 'hdn_f' + str(index)
        lines += scope_map(tag + '_site', rule, web_sites)
        lines += ['map $uri $' + tag + '_path {', '    default 0;',
                  '    ' + pattern(path_pattern(rule['path'])) + ' 1;', '}']
        args = '(?:^|&)(?:' + '|'.join(parameter_pattern(x) for x in rule['parameters']) + ')(?:=|&|$)'
        lines += ['map $args $' + tag + '_arg {', '    default 0;', '    ' + pattern(args) + ' 1;', '}']
        lines += ['map $http_user_agent $' + tag + '_agent {', '    default "";']
        lines += ['    ' + literal_regex(agent) + ' a' + hashlib.sha256(agent.encode()).hexdigest()[:12] + ';' for agent in rule['agents']]
        lines += ['}', 'map "$hdn_mode:$' + tag + '_site:$' + tag + '_path:$' + tag + '_arg:$' + tag + '_agent" $' + tag + '_key {',
                  '    default "";', '    ' + pattern('^(observe|enforce):1:1:1:a[0-9a-f]+$') + ' "$hdn_site:' + rule['id'] + ':$' + tag + '_agent";', '}']
        if rule['action'] == 'limit':
            lines += ['limit_req_zone $' + tag + '_key zone=' + tag + ':10m rate=' + str(rule['rate']) + 'r/m;']
        block_variables.append((tag + '_key', 'filter-' + rule['action'] + '-' + rule['id']))
    for index, (variable, label) in enumerate(block_variables):
        lines += ['map $' + variable + ' $hdn_b' + str(index) + ' {', '    default ' + label + ';', '    "" "";', '}']
    static = []
    for index, rule in enumerate(policy['static']):
        tag = 'hdn_s' + str(index)
        lines += scope_map(tag + '_site', rule, web_sites)
        regex = '^' + re.escape(rule['path']) + '.*\\.(?:' + '|'.join(rule['extensions']) + ')$'
        lines += ['map "$hdn_mode:$' + tag + '_site:$hdn_static_exempt:$request_method:$uri" $' + tag + '_candidate {', '    default "";',
                  '    ' + pattern('^(observe|enforce):1:0:(GET|HEAD):' + regex[1:]) + ' static-' + rule['id'] + ';', '}']
        static.append('$' + tag + '_candidate')
    lines += ['map "' + ':'.join(static) + '" $hdn_static_candidate {', '    default "";']
    for rule in policy['static']:
        label = 'static-' + rule['id']
        lines += ['    ' + pattern('(?:^|:)' + label + '(?:$|:)') + ' ' + label + ';']
    lines += ['}', 'map "$hdn_direct_reject:$hdn_private:$hdn_agent:' + ':'.join('$hdn_b' + str(i) for i in range(len(block_variables))) + ':$hdn_static_candidate:$hdn_login_label:$hdn_xmlrpc_label:$hdn_probe_query:$hdn_probe_file:$hdn_enum_match" $hdn_match_base {',
              '    default "";', '    ' + pattern('^1:') + ' private-file;',
              '    ' + pattern('^[01]:1:') + ' private-file;',
              '    ' + pattern('^[01]:[01]:1:') + ' agent;']
    lines += ['    ' + pattern(':1$') + ' user-enumeration;',
              '    ' + pattern(':q[0-9a-f]{16}:') + ' suspicious-query;', '    ' + pattern(':f[0-9a-f]{16}:') + ' missing-file;']
    for _, label in block_variables:
        lines += ['    ' + pattern('(?:^|:)' + label + '(?:$|:)') + ' ' + label + ';']
    for rule in policy['static']:
        label = 'static-' + rule['id']
        lines += ['    ' + pattern('(?:^|:)' + label + '(?:$|:)') + ' ' + label + ';']
    lines += ['    ' + pattern('(?:^|:)login(?:$|:)') + ' login;',
              '    ' + pattern('(?:^|:)xmlrpc(?:$|:)') + ' xmlrpc;']
    lines += ['}', 'map "$hdn_global_blocked:$hdn_domain_blocked:$hdn_match_base" $hdn_match {',
              '    default $hdn_match_base;', '    ~^1: global-ban;', '    ~^0:1: domain-ban;', '}',
              'map $hdn_match $hdn_block {', '    default 0;', '    private-file 1;',
              '    agent 1;', '    ~^filter-block- 1;', '}',
              'map "$hdn_mode:$hdn_static_candidate" $hdn_static_reject {', '    default 0;', '    ~^enforce:static- 1;', '}',
              'map $limit_req_status $hdn_limit_status { default $limit_req_status; "" "-"; }',
              # The JSON-escaped User-Agent follows the legacy fields, separated
              # by a tab. Never record IPs, URLs, queries or other headers here.
              'log_format hdn escape=json \'$time_iso8601 $hdn_site $hdn_match $hdn_limit_status $status $hdn_mode\\t"$http_user_agent"\';',
              'map "$hdn_mode:$hdn_match:$limit_req_status" $hdn_log {',
              '    default 0;', '    ~^(observe|enforce):[^:]+: 1;',
              '    ~^(observe|enforce):.*:(REJECTED|REJECTED_DRY_RUN|DELAYED_DRY_RUN)$ 1;', '}',
              'map "$hdn_mode:$request_method:$uri" $hdn_login_key {', '    default "";']
    if policy['login']['enabled']:
        lines.append('    ~^(observe|enforce):POST:/wp-login\\.php/?$ "$hdn_site:$binary_remote_addr";')
    lines += ['}', 'map "$hdn_mode:$request_method:$uri" $hdn_xmlrpc_key {', '    default "";']
    if policy['xmlrpc']['enabled']:
        lines.append('    ~^(observe|enforce):POST:/xmlrpc\\.php/?$ "$hdn_site:$binary_remote_addr";')
    lines += ['}']
    for key in ('login', 'xmlrpc'):
        lines += ['map $hdn_' + key + '_key $hdn_' + key + '_label {',
                  '    default ' + key + ';', '    "" "";', '}']
        if policy[key]['enabled']:
            lines.append('limit_req_zone $hdn_' + key + '_key zone=hdn_' + key + ':10m rate=' + str(policy[key]['rate']) + 'r/m;')
    return '\n'.join(lines) + '\n'


def site_config(policy, site, document_root=None):
    mode = site_mode(policy, site)
    lines = [MARKER, 'set $hdn_site ' + domain(site.get('domain', site['key'].split('/', 1)[1])) + ';', 'set $hdn_mode ' + mode + ';']
    if policy['bans']['enabled'] or site.get('global_bans'):
        lines += ['if ($hdn_global_blocked) { return 403; }']
    if mode == 'enforce':
        lines += ['if ($hdn_domain_blocked) { return 403; }']
    if site.get('kind') == 'mail':
        if mode == 'enforce':
            lines += ['if ($hdn_direct_reject) { return 403; }', 'if ($hdn_block) { return 403; }']
        lines += ['access_log /var/log/webuzo-de-noise/matches.log hdn if=$hdn_log;']
        if policy['bans']['enabled']:
            lines += ['access_log /var/log/webuzo-de-noise/ban-events.log hdn_bans if=$hdn_autoban_log;']
        return '\n'.join(lines) + '\n'
    local = policy['domain_bans']['sites'].get(site['key'], {})
    if mode != 'off' and ((policy['bans']['enabled'] and policy['bans']['missing_files']['enabled']) or local.get('missing_files')):
        if not document_root or not re.fullmatch(r'/[A-Za-z0-9_./-]+', document_root) or '..' in document_root.split('/'):
            raise ValueError('PHP probe protection needs one literal document root: ' + site['key'])
        lines += ['set $hdn_probe_filename "";',
                  'if ($hdn_probe_file != "") { set $hdn_probe_filename "' + document_root.rstrip('/') + '$uri"; }',
                  'if (-f $hdn_probe_filename) { set $hdn_probe_file ""; }']
    if mode != 'off' and any(applies(rule, site) for rule in policy['static']):
        if not document_root or not re.fullmatch(r'/[A-Za-z0-9_./-]+', document_root) or '..' in document_root.split('/'):
            raise ValueError('Static-file rules need one literal document root in the existing template: ' + site['key'])
        lines += ['set $hdn_static_file "";',
                  'if ($hdn_static_candidate != "") { set $hdn_static_file "' + document_root.rstrip('/') + '$uri"; }',
                  'if (-f $hdn_static_file) { set $hdn_static_candidate ""; }']
    if mode == 'enforce':
        lines += ['if ($hdn_direct_reject) { return 403; }', 'if ($hdn_block) { return 403; }',
                  'if ($hdn_probe_query != "") { return 404; }', 'if ($hdn_probe_file != "") { return 404; }',
                  'if ($hdn_static_reject) { return 404; }']
        if policy['enumeration']['enabled'] and site.get('enumeration_ready'):
            lines.append('if ($hdn_enum_reject) { return 403; }')
    for key in ('login', 'xmlrpc'):
        if policy[key]['enabled']:
            burst = policy[key]['burst']
            lines.append('limit_req zone=hdn_' + key + ((' burst=' + str(burst) + ' nodelay') if burst else '') + ';')
    rate_rules = [rule for rule in policy['filters'] if rule['action'] == 'limit' and applies(rule, site)]
    for index, rule in enumerate(policy['filters']):
        if rule['action'] == 'limit' and applies(rule, site):
            lines.append('limit_req zone=hdn_f' + str(index) + ((' burst=' + str(rule['burst']) + ' nodelay') if rule['burst'] else '') + ';')
    if any(policy[key]['enabled'] for key in ('login', 'xmlrpc')) or rate_rules:
        lines += ['limit_req_status 429;', 'limit_req_dry_run ' + ('off' if mode == 'enforce' else 'on') + ';',
                  'limit_req_log_level ' + ('error' if policy['log_rejections'] else 'notice') + ';']
    lines += ['access_log /var/log/webuzo-de-noise/matches.log hdn if=$hdn_log;']
    if policy['bans']['enabled']:
        lines += ['access_log /var/log/webuzo-de-noise/ban-events.log hdn_bans if=$hdn_autoban_log;']
    if any(local.values()):
        lines += ['access_log /var/log/webuzo-de-noise/ban-events.log hdn_domain_bans if=$hdn_domain_autoban_log;']
    if not site.get('native_access_logging') and ((policy['bans']['enabled'] and policy['bans']['any_404']['enabled']) or local.get('any_404')):
        lines += ['access_log /var/log/webuzo-de-noise/ban-events.log hdn_early_404 if=$hdn_early_404_log;']
    return '\n'.join(lines) + '\n'
