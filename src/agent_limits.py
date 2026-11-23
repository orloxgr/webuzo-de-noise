"""Explicit server-wide User-Agent budgets, independent of source IP and host."""
import hashlib

import agent_catalog


DEFAULT = {field: {'group': {'enabled': False, 'agents': [], 'rate': None,
                           'unit': 'm', 'burst': 0}, 'individual': []}
           for field in agent_catalog.CATEGORIES}


def validate(settings, validate_agents):
    if not isinstance(settings, dict) or set(settings) != set(DEFAULT):
        raise ValueError('Invalid User-Agent rate-limit categories')
    individuals, groups = {}, {}
    for field, category in settings.items():
        if not isinstance(category, dict) or set(category) != {'group', 'individual'}:
            raise ValueError('Invalid User-Agent rate-limit settings')
        group = category['group']
        if not isinstance(group, dict) or set(group) != {'enabled', 'agents', 'rate', 'unit', 'burst'}:
            raise ValueError('Invalid group rate-limit fields')
        group['agents'] = validate_agents(group['agents'])
        rate_fields(group)
        if group['enabled'] and not group['agents']:
            raise ValueError('An enabled group rate limit needs at least one agent')
        if group['enabled']:
            for name in group['agents']:
                key = name.casefold()
                if key in groups:
                    raise ValueError('Agent appears in multiple enabled rate-limit groups: ' + name)
                groups[key] = field
        if not isinstance(category['individual'], list):
            raise ValueError('Use an individual User-Agent rule list')
        for rule in category['individual']:
            if not isinstance(rule, dict) or set(rule) != {'enabled', 'agent', 'rate', 'unit', 'burst'}:
                raise ValueError('Invalid individual rate-limit fields')
            rule['agent'] = validate_agents([rule['agent']])[0]
            rate_fields(rule)
            if rule['enabled']:
                key = rule['agent'].casefold()
                # Equivalent units are equivalent rules, e.g. 1r/s and 60r/m.
                budget = (rule['rate'] * (60 if rule['unit'] == 's' else 1), rule['burst'])
                if key in individuals and individuals[key] != budget:
                    raise ValueError('Conflicting individual rate limits for: ' + rule['agent'])
                individuals[key] = budget


def rate_fields(rule):
    if (type(rule['enabled']) is not bool or rule['unit'] not in ('m', 's') or
            type(rule['burst']) is not int or rule['burst'] < 0 or
            not (rule['rate'] is None or type(rule['rate']) is int and rule['rate'] > 0) or
            rule['enabled'] and rule['rate'] is None):
        raise ValueError('Choose a positive rate, seconds/minutes and a nonnegative burst')


def rules(settings):
    """Stable identities retain counters across unrelated edits and reordering."""
    result, seen = [], set()
    for field in sorted(settings):
        category = settings[field]
        group = category['group']
        if group['enabled']:
            result.append(dict(group, label='agent-group-' + field, field=field))
        for rule in category['individual']:
            name = rule['agent'].casefold()
            if not rule['enabled'] or name in seen:
                continue
            seen.add(name)
            ident = hashlib.sha256(name.encode('ascii')).hexdigest()[:16]
            result.append(dict(rule, agents=[rule['agent']],
                               label='agent-individual-' + field + '-' + ident, field=field))
    return result


def compile_maps(settings, literal_regex):
    selected = rules(settings)
    # Individual beats every group; within a level the longest literal wins.
    matches = [(rule, name) for rule in selected for name in rule['agents']]
    matches.sort(key=lambda item: (not item[0]['label'].startswith('agent-individual-'),
                                  -len(item[1]), item[1].casefold(), item[0]['label']))
    lines = ['map $http_user_agent $hdn_ua_rule {', '    default "";']
    lines += ['    ' + literal_regex(name) + ' ' + rule['label'] + ';' for rule, name in matches]
    lines += ['}']
    for rule in selected:
        tag = zone(rule)
        # Only two constant keys, shared by every IP and website. Observe must
        # never debit the real Enforce budget. Off has an empty, uncounted key.
        lines += ['map "$hdn_mode:$hdn_ua_rule" $' + tag + '_key {', '    default "";',
                  '    ~^observe:' + rule['label'] + '$ observe;',
                  '    ~^enforce:' + rule['label'] + '$ enforce;', '}',
                  'limit_req_zone $' + tag + '_key zone=' + tag + ':1m rate=' +
                  str(rule['rate']) + 'r/' + rule['unit'] + ';']
    return lines


def zone(rule):
    return 'hdn_ua_' + hashlib.sha256(rule['label'].encode('ascii')).hexdigest()[:16]


def site_lines(settings, mode):
    selected = rules(settings)
    if not selected or mode == 'off':
        return []
    lines = ['limit_req zone=' + zone(rule) +
             ((' burst=' + str(rule['burst']) + ' nodelay') if rule['burst'] else '') + ';'
             for rule in selected]
    return lines
