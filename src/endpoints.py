"""Administrator-selected exact paths / native PCRE rules. No implicit defaults."""
import hashlib
import json
import re
from urllib.parse import unquote


def validate(rows, target):
    if not isinstance(rows, list):
        raise ValueError('Custom endpoints must be a rule list')
    ids = set()
    for rule in rows:
        if not isinstance(rule, dict) or set(rule) != {
                'id', 'name', 'enabled', 'type', 'pattern', 'targets', 'also_ban', 'duration_seconds'}:
            raise ValueError('Invalid custom endpoint fields')
        ident = rule['id']
        if not isinstance(ident, str) or not re.fullmatch('[a-z][a-z0-9_]*', ident) or ident in ids:
            raise ValueError('Custom endpoint IDs must be unique lowercase names')
        ids.add(ident)
        for field in ('name', 'pattern'):
            if (not isinstance(rule[field], str) or not rule[field].strip()
                    or any(ord(c) < 32 or ord(c) == 127 for c in rule[field])):
                raise ValueError('Endpoint ' + ident + ': use nonempty text without control characters')
        if rule['type'] not in ('exact', 'regex'):
            raise ValueError('Endpoint ' + ident + ': choose exact path or PCRE regex')
        if rule['type'] == 'exact' and (not rule['pattern'].startswith('/')
                or '?' in rule['pattern'] or '#' in rule['pattern']
                or any(ord(c) < 32 or ord(c) == 127 for c in unquote(rule['pattern']))):
            raise ValueError('Endpoint ' + ident + ': exact paths start with / and exclude queries/fragments')
        if any(type(rule[k]) is not bool for k in ('enabled', 'also_ban')):
            raise ValueError('Invalid endpoint enable / ban switch')
        if type(rule['duration_seconds']) is not int or rule['duration_seconds'] < 0:
            raise ValueError('Endpoint ban duration must be nonnegative (0 = permanent)')
        if not isinstance(rule['targets'], list):
            raise ValueError('Invalid endpoint domain selection')
        rule['targets'] = list(dict.fromkeys(target(value) for value in rule['targets']))
    # PCRE is validated by the native nginx -t transaction, not Python's different regex engine.


def reason(rule):
    return 'endpoint-' + rule['id']


def event_token(rule):
    # Changing pattern/scope invalidates queued events from the old matcher.
    raw = json.dumps([rule[k] for k in ('id', 'type', 'pattern', 'targets', 'also_ban')], ensure_ascii=False)
    return 'e' + hashlib.sha256(raw.encode()).hexdigest()[:16]


def ban_rules(policy, sites, mode):
    rules, scopes, tokens = {}, {}, {}
    for row in policy.get('custom_endpoints', []):
        if not row['enabled'] or not row['also_ban']:
            continue
        key = reason(row)
        rules[key] = dict(maxretry=1, findtime=0, duration_days=0,
                          duration_seconds=row['duration_seconds'], rule_name=row['name'])
        scopes[key] = {site['domain'] for site in sites if site.get('supported') and not site.get('suspended')
                       and site.get('kind') != 'mail' and mode(policy, site) == 'enforce'
                       and (not row['targets'] or site['key'] in row['targets'])}
        tokens[key] = {event_token(row)}
    settings = policy.get('endpoint_404', {})
    if settings.get('enabled') and settings.get('paths'):
        key = 'endpoint-404-list'
        rules[key] = dict(maxretry=settings.get('maxretry',1), findtime=settings.get('findtime',300), duration_days=0, duration_seconds=settings['duration_seconds'], rule_name='Selected endpoint 404 paths')
        scopes[key] = {site['domain'] for site in sites if site.get('supported') and not site.get('suspended') and site.get('kind') != 'mail'
                       and mode(policy, site) == 'enforce' and (not settings['targets'] or site['key'] in settings['targets'])}
        tokens[key] = {'selected-404'}
    return rules, scopes, tokens


def compile_maps(policy, sites, scope_map, exact_uri_pattern, event_format):
    lines, labels, banning = [], [], []
    for i, row in enumerate(policy.get('custom_endpoints', [])):
        tag = 'hdn_e' + str(i)
        label = reason(row)
        lines += scope_map(tag + '_site', row, sites)
        # Quote the whole Nginx token; braces, semicolons, # and quotes stay data.
        expression = (exact_uri_pattern(unquote(row['pattern'])) if row['type'] == 'exact' else
                      '"~' + row['pattern'].replace('\\', '\\\\').replace('"', '\\"') + '"')
        lines += ['map $uri $' + tag + '_path {', '    default 0;', '    ' + expression + ' 1;', '}',
                  'map "$hdn_mode:$' + tag + '_site:$' + tag + '_path" $' + tag + '_match {',
                  '    default "";', '    ~^(observe|enforce):1:1$ ' + label + ';', '}']
        labels.append((tag, label))
        if row['enabled'] and row['also_ban']:
            banning.append((label, event_token(row)))
    # A balanced reduction preserves first-match order without one growing map
    # token or a linear variable-recursion chain on large administrator lists.
    variables = ['$' + tag + '_match' for tag, _ in labels]
    generation = 0
    while len(variables) > 1:
        reduced = []
        for i in range(0, len(variables), 2):
            if i + 1 == len(variables):
                reduced.append(variables[i]); continue
            left, right = variables[i:i+2]
            result = '$hdn_ep' + str(generation) + '_' + str(i)
            lines += ['map "' + left + ':' + right + '" ' + result + ' {',
                      '    default ' + left + ';', '    ~^: ' + right + ';', '}']
            reduced.append(result)
        variables = reduced; generation += 1
    lines += ['map "" $hdn_endpoint { default ' + (variables[0] if variables else '""') + '; }',
              'map $hdn_endpoint $hdn_endpoint_token {', '    default "";']
    lines += ['    ' + label + ' ' + token + ';' for label, token in banning]
    lines += ['}', 'map "$hdn_mode:$hdn_endpoint_token:$status" $hdn_endpoint_ban_log {',
              '    default 0;', '    "~^enforce:e[0-9a-f]{16}:403$" 1;', '}',
              event_format('hdn_endpoint_bans', '$hdn_endpoint', '$hdn_endpoint_token')]
    return lines
