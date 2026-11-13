"""Inherited native Nginx administration gates. No WordPress request worker."""
import copy
import hashlib
import re
import subprocess
from pathlib import Path
import captcha
import captcha_runtime

SETTINGS = 'access.json'
DIRECTORY = Path('/etc/webuzo-de-noise/access')
DEFAULT = {'method': 'basic', 'captcha_seconds': captcha.DEFAULT_SECONDS, 'enabled': False, 'bypass_internal': True, 'username': 'wp', 'password_hash': '',
           'country': {'enabled': False, 'scope': 'admin', 'mode': 'deny',
                       'countries': [], 'allow_unknown': True}}
# Match complete path segments, including installations below a URL prefix.
ADMIN = r'^/(?:[^/]+/)*(?:wp-login\.php(?:/.*)?|wp-admin(?:/.*)?)$'
EXEMPT = r'^/(?:[^/]+/)*wp-admin/(?:admin-ajax\.php|admin-post\.php|js/password-strength-meter(?:\.min)?\.js)$'


def defaults():
    return {'defaults': copy.deepcopy(DEFAULT), 'accounts': {}, 'sites': {}}

def hosts(site):
    return list(dict.fromkeys([site['domain'], *(h for h in re.split(r'[\s,]+', site.get('aliases', '')) if h)]))


def identifier(key):
    return hashlib.sha256(key.encode()).hexdigest()[:24]


def validate(value, target):
    if (not isinstance(value, dict) or set(value) != {'defaults', 'accounts', 'sites'}
            or not isinstance(value['sites'], dict) or not isinstance(value['accounts'], dict)):
        raise ValueError('Invalid domain access settings')
    result = copy.deepcopy(value)
    for key in result['sites']:
        target(key)
    for owner in result['accounts']:
        if not isinstance(owner, str):
            raise ValueError('Invalid access account')
        target(owner + '/access.invalid')
    for entry in [result['defaults'], *result['accounts'].values(), *result['sites'].values()]:
        if not isinstance(entry, dict) or set(entry) != set(DEFAULT):
            raise ValueError('Invalid domain access controls')
        if entry['method'] not in ('basic', 'captcha') or type(entry['captcha_seconds']) is not int or entry['captcha_seconds'] <= 0:
            raise ValueError('Select HTTP password or CAPTCHA and a positive verification lifetime')
        if any(type(entry[k]) is not bool for k in ('enabled', 'bypass_internal')):
            raise ValueError('Access switches must be booleans')
        if not isinstance(entry['username'], str) or not re.fullmatch(r'[A-Za-z0-9_.@-]+', entry['username']):
            raise ValueError('Use a nonempty HTTP username containing letters, numbers, _, ., @ or -')
        hashed = entry['password_hash']
        if not isinstance(hashed, str) or hashed and not re.fullmatch(r'\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}', hashed):
            raise ValueError('Invalid saved HTTP password hash')
        country = entry['country']
        if not isinstance(country, dict) or set(country) != set(DEFAULT['country']):
            raise ValueError('Invalid country controls')
        if any(type(country[k]) is not bool for k in ('enabled', 'allow_unknown')):
            raise ValueError('Country switches must be booleans')
        if country['scope'] not in ('admin', 'site') or country['mode'] not in ('allow', 'deny'):
            raise ValueError('Select a country scope and allow/deny policy')
        if not isinstance(country['countries'], list) or any(
                not isinstance(c, str) or not re.fullmatch(r'[A-Z]{2}', c) or c == 'ZZ'
                for c in country['countries']):
            raise ValueError('Use two-letter country codes, for example GR and CY')
        country['countries'] = sorted(set(country['countries']))
        if country['enabled'] and not country['countries']:
            raise ValueError('Select at least one country before enabling the country filter')
    profiles = [result['defaults']]
    profiles += [effective(result, owner + '/access.invalid', account_only=True) for owner in result['accounts']]
    profiles += [effective(result, key) for key in result['sites']]
    if any(profile['enabled'] and profile.get('method', 'basic') == 'basic' and not profile['password_hash'] for profile in profiles):
        raise ValueError('Set an HTTP password before enabling administration protection')
    return result


def effective(settings, key, account_only=False):
    """Resolve whole profiles in order, with independently inherited passwords."""
    owner = key.split('/', 1)[0]
    entry = {**copy.deepcopy(DEFAULT), **copy.deepcopy(settings.get('defaults', {}))}
    levels = [settings.get('accounts', {}).get(owner)]
    if not account_only:
        levels += [settings.get('sites', {}).get(key)]
    for override in levels:
        if override is not None:
            inherited_hash = entry['password_hash']
            entry = {**copy.deepcopy(DEFAULT), **copy.deepcopy(override)}
            entry['password_hash'] = entry['password_hash'] or inherited_hash
    return entry


def public_profile(entry, override=False, source='global', password_inherited=False):
    return {**{k: copy.deepcopy(v) for k, v in entry.items() if k != 'password_hash'},
            'password_set': bool(entry['password_hash']), 'override': override,
            'source': source, 'password_inherited': password_inherited}


def public_accounts(settings, owners):
    return {owner: public_profile(effective(settings, owner + '/access.invalid', account_only=True),
                override=owner in settings.get('accounts', {}),
                source='account' if owner in settings.get('accounts', {}) else 'global',
                password_inherited=not settings.get('accounts', {}).get(owner, {}).get('password_hash'))
            for owner in sorted(owners)}


def password_hash(password):
    if not isinstance(password, str) or not password or any(c in password for c in '\x00\r\n'):
        raise ValueError('Enter a nonempty HTTP password without line breaks')
    # The plaintext travels only over stdin, never in process arguments or logs.
    result = subprocess.run(['/usr/bin/openssl', 'passwd', '-6', '-stdin'],
                            input=password + '\n', text=True, capture_output=True)
    if result.returncode or not result.stdout.startswith('$6$'):
        raise ValueError('Could not hash the HTTP password with OpenSSL')
    return result.stdout.strip()


def public(settings, visible):
    return {key: public_profile(effective(settings, key), override=key in settings['sites'],
                source='domain' if key in settings['sites'] else ('account' if key.split('/', 1)[0]
                       in settings.get('accounts', {}) else 'global'),
                password_inherited=not settings['sites'].get(key, {}).get('password_hash'))
            for key in sorted(visible)}


def compile_maps(settings, sites, pattern, geo_path=None):
    entries = [(s, effective(settings, s['key'])) for s in sites
               if s.get('supported', True) and not s.get('suspended') and s.get('kind') != 'mail'
               and (effective(settings, s['key'])['enabled'] or effective(settings, s['key'])['country']['enabled'])]
    if not entries:
        return []
    lines = ['map $uri $hdn_admin_path {', '    default 0;',
             '    ' + pattern(EXEMPT) + ' 0;', '    ' + pattern(ADMIN) + ' 1;', '}']
    lines += ['map $uri $hdn_acme_path { default 0; ~^/\\.well-known/acme-challenge/ 1; }']
    if any(e['country']['enabled'] for _, e in entries):
        if not geo_path:
            raise ValueError('Download the country database before enabling a country filter')
        lines += ['geo $remote_addr $hdn_country {', '    default ZZ;',
                  '    include ' + str(geo_path) + ';', '}']
    else:
        lines += ['map $remote_addr $hdn_country { default ZZ; }']
    basic, countries = [], []
    if any(e.get('method', 'basic') == 'captcha' and e['enabled'] for _, e in entries):
        lines += ['upstream hdn_captcha_service { server unix:' + str(captcha_runtime.SOCKET) + '; }']
        lines += ['map "$status:$upstream_http_x_hdn_captcha_result" $hdn_captcha_event { default captcha-request; "200:" captcha-check; "200:verified" captcha-verified; "303:" captcha-verified; }',
                  'log_format hdn_captcha escape=json \'$time_iso8601 $hdn_site $hdn_captcha_event - $status $hdn_mode\\t"$http_user_agent"\';']
    for site, entry in entries:
        tag = 'ha' + identifier(site['key'])
        # Origin includes scheme, exact hostname and port; same-site is not same-origin.
        names = hosts(site)
        origin_checks = []
        for host in names:
            origin_checks.append(re.escape(host) + r':https:https://' + re.escape(host) + r'(?::443)?(?:/|$)')
            origin_checks.append(re.escape(host) + r':http:http://' + re.escape(host) + r'(?::80)?(?:/|$)')
        lines += ['map "$host:$scheme:$http_referer" $' + tag + '_r {', '    default 0;']
        lines += ['    ' + pattern('^' + check) + ' 1;' for check in origin_checks]
        lines += ['}',
                  'map "$http_sec_fetch_site:$' + tag + '_r" $' + tag + '_i {',
                  '    default 0;', '    ~^same-origin:[01]$ 1;', '    ":1" 1;', '}']
        enabled = '1' if entry['enabled'] else '0'
        bypass = '1' if entry['bypass_internal'] else '0'
        lines += ['map "' + enabled + ':$hdn_admin_path:' + bypass + ':$' + tag + '_i" $' + tag + '_b {',
                  '    default 0;', '    ~^1:1:(0:[01]|1:0)$ 1;', '}',
                  'map "$hdn_mode:$' + tag + '_b" $' + tag + '_a {',
                  '    default off;', '    "enforce:1" "WordPress administration";', '}']
        if entry.get('method', 'basic') == 'captcha' and entry['enabled']:
            scope = identifier(site['key'])
            lines += ['map $cookie_' + captcha.cookie(scope) + ' $' + tag + '_token {',
                      '    default ",";',
                      '    "~^(?<' + tag + '_hash>[A-Za-z0-9_-]{22})[.](?<' + tag + '_exp>[0-9]+)$" "$' + tag + '_hash,$' + tag + '_exp";', '}',
                      'map "$hdn_mode:$' + tag + '_b:$secure_link" $' + tag + '_challenge {',
                      '    default 0;', '    "enforce:1:" 1;', '    "enforce:1:0" 1;', '}']
        country = entry['country']
        lines += ['map $hdn_country $' + tag + '_cm {', '    default ' + ('1' if country['mode'] == 'allow' else '0') + ';']
        lines += ['    ' + c + ' ' + ('0' if country['mode'] == 'allow' else '1') + ';' for c in country['countries']]
        lines += ['    ZZ ' + ('0' if country['allow_unknown'] else '1') + ';', '}']
        scope = '$hdn_admin_path' if country['scope'] == 'admin' else '1'
        lines += ['map "' + ('1' if country['enabled'] else '0') + ':' + scope + ':$' + tag + '_cm:$hdn_acme_path" $' + tag + '_c {',
                  '    default 0;', '    "1:1:1:0" 1;', '}']
        host = site.get('domain', site['key'].split('/', 1)[1])
        basic.append('    ' + host + ' $' + tag + '_b;')
        countries.append('    ' + host + ' $' + tag + '_c;')
    lines += ['map $hdn_site $hdn_access_basic {', '    default 0;', *basic, '}',
              'map $hdn_site $hdn_access_country {', '    default 0;', *countries, '}',
              'map "$hdn_mode:$hdn_access_country:$hdn_access_basic:$status:$upstream_status" $hdn_access_event {',
              '    default "";', '    ~^observe:1: country-filter;', '    ~^enforce:1:[01]:403:(-|)$ country-filter;',
              '    ~^observe:0:1: wordpress-access;', '    ~^enforce:0:1:401:(-|)$ wordpress-access;', '}',
              'map $hdn_access_event $hdn_access_log { default 1; "" 0; }',
              'log_format hdn_access escape=json \'$time_iso8601 $hdn_site $hdn_access_event - $status $hdn_mode\\t"$http_user_agent"\';']
    return lines


def site_lines(settings, site, mode):
    entry = effective(settings, site['key'])
    if not entry or mode == 'off' or site.get('kind') == 'mail':
        return []
    tag = 'ha' + identifier(site['key'])
    lines = []
    if entry['enabled'] and entry.get('method', 'basic') == 'basic':
        lines += ['auth_basic $' + tag + '_a;',
                  'auth_basic_user_file ' + str(DIRECTORY / (identifier(site['key']) + '.htpasswd')) + ';']
    if entry['enabled'] and entry.get('method', 'basic') == 'captcha':
        scope = identifier(site['key'])
        proxy = ['proxy_pass http://hdn_captcha_service;',
                 'proxy_set_header X-HDN-Site "' + scope + '";',
                 'proxy_set_header X-HDN-Host $host;', 'proxy_set_header X-HDN-Scheme $scheme;',
                 'proxy_set_header Cookie "";', 'proxy_set_header Authorization "";',
                 'proxy_cache off;', 'proxy_intercept_errors off;',
                 'access_log /var/log/webuzo-de-noise/matches.log hdn_captcha;']
        lines += ['include ' + str(DIRECTORY / (scope + '.captcha.conf')) + ';',
                  'error_page 470 = @hdn_captcha_' + scope + ';',
                  'location @hdn_captcha_' + scope + ' {',
                  '    proxy_method GET;', '    proxy_pass_request_body off;',
                  '    proxy_set_header Content-Length "";',
                  '    proxy_set_header X-HDN-Action challenge;',
                  '    proxy_set_header X-HDN-Target $request_uri;',
                  '    proxy_set_header X-HDN-Method $request_method;',
                  *('    ' + line for line in proxy), '}',
                  'location ^~ ' + captcha.PREFIX + ' {',
                  '    proxy_set_header X-HDN-Action verify;',
                  '    proxy_set_header X-HDN-Target "";',
                  '    proxy_set_header X-HDN-Method $request_method;',
                  *('    ' + line for line in proxy), '}']
    if entry['country']['enabled'] and mode == 'enforce':
        lines += ['if ($' + tag + '_c) { return 403; }']
    if entry['enabled'] or entry['country']['enabled']:
        lines += ['access_log /var/log/webuzo-de-noise/matches.log hdn_access if=$hdn_access_log;']
    return lines


def challenge_line(settings, site, mode):
    entry = effective(settings, site['key'])
    return ['if ($ha' + identifier(site['key']) + '_challenge) { return 470; }'] if entry['enabled'] and entry.get('method') == 'captcha' and mode != 'off' and site.get('kind') != 'mail' else []
