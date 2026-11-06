"""Native enumeration gates and an authenticated WordPress companion.

Cookie/header presence only selects the WordPress verification path. It is never
treated as authentication. Website files are accessed as their Webuzo owner.
"""
import copy
import hashlib
import json
import re
from pathlib import Path
import subprocess

SETTINGS = {'enabled': False, 'rest': True, 'author_ids': True,
            'author_archives': False, 'targets': []}
MANIFEST = 'user-enumeration.json'
PLUGIN = 'webuzo-de-noise-user-enumeration.php'
ROOT = Path(__file__).resolve().parents[1]


def validate(value, target):
    if not isinstance(value, dict) or set(value) != set(SETTINGS):
        raise ValueError('Invalid user-enumeration settings')
    if any(type(value[key]) is not bool for key in SETTINGS if key != 'targets'):
        raise ValueError('User-enumeration switches must be booleans')
    if not isinstance(value['targets'], list):
        raise ValueError('Invalid user-enumeration domain selection')
    value['targets'] = list(dict.fromkeys(target(key) for key in value['targets']))


def selected(policy, site):
    settings = policy['enumeration']
    return (settings['enabled'] and site.get('kind', 'web') == 'web' and
            site.get('supported', True) and not site.get('suspended') and
            (not settings['targets'] or site['key'] in settings['targets']))


def payload(settings, hosts=None):
    flags = {key: settings[key] for key in ('rest', 'author_ids', 'author_archives')}
    flags['hosts'] = hosts
    return (ROOT / 'wordpress/user-enumeration.php').read_text(encoding='utf-8').replace(
        '__HDN_FLAGS__', json.dumps(flags, separators=(',', ':')))


def helper(owner, root, action, **values):
    # No shell, no WordPress bootstrap and no PHP executed as root.
    result = subprocess.run(['/usr/sbin/runuser', '-u', owner, '--', '/usr/bin/python3',
                             '-I', str(ROOT / 'src/enumeration_site.py')],
                            input=json.dumps(dict(root=root, action=action, **values)),
                            capture_output=True, text=True, timeout=None)
    if result.returncode:
        raise ValueError('User enumeration: ' + (result.stderr.strip() or 'website operation failed'))
    return json.loads(result.stdout)


def fingerprint(root):
    result = []
    for name in ('wp-load.php', 'wp-includes/version.php', 'wp-config.php',
                 'wp-content/mu-plugins/' + PLUGIN):
        try:
            info = (Path(root) / name).lstat()
            result.append([name, info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size,
                           info.st_mode, info.st_uid, info.st_nlink])
        except FileNotFoundError:
            result.append([name, None])
    return result


def prepare(policy, sites, previous, site_mode, remove=False):
    """Plan website changes before the shared Nginx recovery journal is written."""
    prepared = copy.deepcopy(sites)
    desired, changes = {}, []
    host_groups = {}
    for site in prepared:
        if selected(policy, site) and site_mode(policy, site) == 'enforce':
            hosts = [site['domain'], *re.split(r'[\s,]+', site.get('aliases', ''))]
            hosts = sorted({name.lower().rstrip('.') for name in hosts if name})
            if any(not re.fullmatch(r'(?:\*\.)?[a-z0-9][a-z0-9.-]*[a-z0-9]', name) for name in hosts):
                raise ValueError('Invalid WordPress enumeration hostname')
            for root in site.get('roots', {}).values():
                host_groups.setdefault(root.rstrip('/'), set()).update(hosts)
    for site in prepared:
        site['enumeration_ready'] = False
        if remove or not selected(policy, site) or site_mode(policy, site) == 'off':
            continue
        roots = set(site.get('roots', {}).values())
        if len(roots) != 1:
            raise ValueError('User enumeration requires one shared HTTP/HTTPS document root: ' + site['key'])
        root = roots.pop().rstrip('/')
        marks = fingerprint(root)
        if marks[0][1] is None or marks[1][1] is None:
            continue
        if site_mode(policy, site) == 'observe':
            site['enumeration_ready'] = True
            continue
        body = payload(policy['enumeration'], sorted(host_groups[root]))
        digest = hashlib.sha256(body.encode()).hexdigest()
        entry = dict(owner=site['owner'], root=root, digest=digest, fingerprint=marks)
        old = previous.get(site['key'])
        if old == entry:
            site['enumeration_ready'] = True
            desired[site['key']] = entry
            continue
        inspected = helper(site['owner'], root, 'inspect')
        if not inspected['wordpress']:
            continue  # HTML/PHP sites are not given WordPress files or URL blocks.
        site['enumeration_ready'] = True
        desired[site['key']] = entry
        if inspected['body'] != body:
            changes.append(dict(owner=site['owner'], root=root, before=inspected['body'], after=body))
    wanted = {(entry['owner'], entry['root']) for entry in desired.values()}
    for old in previous.values():
        if (old['owner'], old['root']) in wanted:
            continue
        if not Path(old['root']).exists():
            continue  # Deleted Webuzo accounts/domains stay deleted.
        inspected = helper(old['owner'], old['root'], 'inspect', removing=True)
        if inspected['body'] is not None:
            changes.append(dict(owner=old['owner'], root=old['root'], before=inspected['body'], after=None))
    return prepared, desired, [change for change in changes if change['before'] != change['after']]


def apply(changes, reverse=False):
    for row in reversed(changes) if reverse else changes:
        if reverse and not Path(row['root']).exists():
            continue
        helper(row['owner'], row['root'], 'replace',
               expected=row['after'] if reverse else row['before'],
               body=row['before'] if reverse else row['after'])


def compiled(policy, sites, pattern, parameter_pattern):
    settings = policy['enumeration']
    if not settings['enabled']:
        return ['map $hdn_site $hdn_enum_match { default 0; }']
    lines = ['map $hdn_site $hdn_enum_site {', '    default 0;']
    lines += ['    ' + site['domain'] + ' 1;' for site in sites
              if selected(policy, site) and site.get('enumeration_ready')]
    lines += ['}', 'map $uri $hdn_enum_rest_path {', '    default 0;']
    if settings['rest']:
        lines += ['    ' + pattern(r'(?:^|/)wp-json/wp/v2/users(?:/[0-9]+)?/?$') + ' 1;']
    route = parameter_pattern('rest_route')
    value = parameter_pattern('/wp/v2/users')
    lines += ['}', 'map $args $hdn_enum_rest_query {', '    default 0;']
    if settings['rest']:
        lines += ['    ' + pattern(r'(?:^|&)' + route + '=' + value + r'(?:(?:/|%2f)[0-9]+)?(?:/|%2f)?(?:&|$)') + ' 1;']
    lines += ['}', 'map "$uri:$args" $hdn_enum_author_id {', '    default 0;']
    if settings['author_ids']:
        lines += ['    ' + pattern(r'^/(?:index[.]php)?:.*(?:^|&)' + parameter_pattern('author') + r'=(?:[0-9]|%3[0-9])+(?:&|$)') + ' 1;',
                  '    ' + pattern(r'^/(?:index[.]php)?:' + parameter_pattern('author') + r'=(?:[0-9]|%3[0-9])+(?:&|$)') + ' 1;']
    lines += ['}', 'map $uri $hdn_enum_archive {', '    default 0;']
    if settings['author_archives']:
        lines += ['    ' + pattern(r'(?:^|/)author/[^/]+(?:/|$)') + ' 1;']
    lines += ['}', 'map $http_cookie $hdn_enum_cookie {', '    default 0;',
              '    ' + pattern(r'(^|;)[ ]*wordpress_logged_in_[^=; ]+=') + ' 1;', '}',
              'map $http_authorization $hdn_enum_authorization { default 1; "" 0; }',
              'map "$hdn_enum_site:$hdn_enum_rest_path:$hdn_enum_rest_query:$hdn_enum_author_id:$hdn_enum_archive" $hdn_enum_candidate {',
              '    default 0;', '    ~^1:.*1 1;', '}',
              'map "$hdn_mode:$hdn_enum_candidate:$hdn_enum_cookie:$hdn_enum_authorization" $hdn_enum_reject {',
              '    default 0;', '    ~^enforce:1:0:0$ 1;', '}',
              'map "$hdn_mode:$hdn_enum_candidate:$hdn_enum_cookie:$hdn_enum_authorization" $hdn_enum_match {',
              '    default 0;', '    ~^(observe|enforce):1:0:0$ 1;', '}']
    return lines
