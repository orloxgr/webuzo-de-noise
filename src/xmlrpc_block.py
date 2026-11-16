"""Explicit per-site XML-RPC rejection, separate from request rate limits."""

import hashlib
import ipaddress
import urllib.error
import urllib.request

DEFAULT = {'enabled': False, 'global': False, 'targets': [], 'global_exceptions': [], 'exceptions': {}}
PATH = r'^/(?:[^/]+/)*xmlrpc\.php(?:/.*)?$'
JETPACK_URL = 'https://jetpack.com/ips-v4.txt'


def jetpack_ips():
    """Read the complete official list; never modify policy or fetch a user URL."""
    try:
        with urllib.request.urlopen(JETPACK_URL, timeout=30) as response:
            values = response.read().decode('utf-8').splitlines()
        networks = list(dict.fromkeys(str(ipaddress.IPv4Network(value.strip(), strict=False))
                                     for value in values if value.strip()))
        if not networks:
            raise ValueError('the published IP list is empty')
    except (OSError, UnicodeError, ValueError, urllib.error.URLError) as error:
        raise ValueError('Could not load the official Jetpack IP list: ' + str(error)) from error
    return networks


def validate(settings, target):
    if (not isinstance(settings, dict) or set(settings) != set(DEFAULT)
            or type(settings['enabled']) is not bool or type(settings['global']) is not bool
            or not isinstance(settings['targets'], list)):
        raise ValueError('Invalid XML-RPC disable settings')
    settings['targets'] = list(dict.fromkeys(target(value) for value in settings['targets']))
    settings['global_exceptions'] = normalize_networks(settings['global_exceptions'])
    if not isinstance(settings['exceptions'], dict):
        raise ValueError('XML-RPC IP exceptions must be grouped by site')
    exceptions = {}
    for site, addresses in settings['exceptions'].items():
        site = target(site)
        networks = normalize_networks(addresses)
        if networks:
            exceptions[site] = networks
    settings['exceptions'] = exceptions


def normalize_networks(addresses):
    if not isinstance(addresses, list):
        raise ValueError('XML-RPC exceptions must be IP addresses or CIDRs, one per line')
    networks = []
    for address in addresses:
        if not isinstance(address, str) or '%' in address:
            raise ValueError('Invalid XML-RPC exception IP address or CIDR')
        try:
            network = str(ipaddress.ip_network(address, strict=False))
        except ValueError as error:
            raise ValueError('Invalid XML-RPC exception IP address or CIDR: ' + address) from error
        if network not in networks:
            networks.append(network)
    return networks


def compile_maps(settings, sites, scope_map, pattern):
    # All current/future sites require the explicit Global checkbox.
    selected = [site for site in sites if (settings['global'] or site['key'] in settings['targets'])
                and site.get('kind') != 'mail']
    scope = {**settings, 'targets': []} if settings['global'] else settings
    lines = scope_map('hdn_xmlrpc_disabled_site', scope, selected)
    lines += ['geo $remote_addr $hdn_xmlrpc_global_exempt {', '    default 0;']
    if settings['enabled'] and settings['global']:
        lines += ['    ' + network + ' 1;' for network in settings['global_exceptions']]
    lines += ['}']
    allowed_hosts = []
    for site in selected:
        networks = settings['exceptions'].get(site['key'], [])
        if not settings['enabled'] or not networks or not site.get('supported', True) or site.get('suspended'):
            continue
        variable = 'hdn_xmlrpc_allow_' + hashlib.sha256(site['key'].encode()).hexdigest()[:16]
        lines += ['geo $remote_addr $' + variable + ' {', '    default 0;']
        lines += ['    ' + network + ' 1;' for network in networks]
        lines += ['}']
        # Webuzo's canonical site variable covers aliases without trusting Host/XFF.
        allowed_hosts.append('    ' + site.get('domain', site['key'].split('/')[1]) + ' $' + variable + ';')
    lines += ['map $hdn_site $hdn_xmlrpc_site_exempt {', '    default 0;', *allowed_hosts, '}']
    lines += ['map "$hdn_xmlrpc_global_exempt:$hdn_xmlrpc_site_exempt" $hdn_xmlrpc_exempt {',
              '    default 0;', '    ~^(1:[01]|[01]:1)$ 1;', '}']
    return lines + [
        'map $uri $hdn_xmlrpc_disabled_path {', '    default 0;', '    ' + pattern(PATH) + ' 1;', '}',
        'map "$hdn_mode:$hdn_xmlrpc_disabled_site:$hdn_xmlrpc_disabled_path:$hdn_xmlrpc_exempt" $hdn_xmlrpc_disabled {',
        '    default 0;', '    ~^(observe|enforce):1:1:0$ 1;', '}']
