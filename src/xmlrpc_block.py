"""Explicit per-site XML-RPC rejection, separate from request rate limits."""

DEFAULT = {'enabled': False, 'targets': []}
PATH = r'^/(?:[^/]+/)*xmlrpc\.php(?:/.*)?$'


def validate(settings, target):
    if (not isinstance(settings, dict) or set(settings) != set(DEFAULT)
            or type(settings['enabled']) is not bool or not isinstance(settings['targets'], list)):
        raise ValueError('Invalid XML-RPC disable settings')
    settings['targets'] = list(dict.fromkeys(target(value) for value in settings['targets']))


def compile_maps(settings, sites, scope_map, pattern):
    # An empty selection means no sites, never an implicit server-wide block.
    selected = [site for site in sites if site['key'] in settings['targets'] and site.get('kind') != 'mail']
    return scope_map('hdn_xmlrpc_disabled_site', settings, selected) + [
        'map $uri $hdn_xmlrpc_disabled_path {', '    default 0;', '    ' + pattern(PATH) + ' 1;', '}',
        'map "$hdn_mode:$hdn_xmlrpc_disabled_site:$hdn_xmlrpc_disabled_path" $hdn_xmlrpc_disabled {',
        '    default 0;', '    ~^(observe|enforce):1:1$ 1;', '}']
