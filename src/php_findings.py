"""Independent path characteristics and evidence-based review priorities."""
import re
from urllib.parse import unquote
import probe_rules

TAGS = {'probe': 'Suggested probe pattern', 'configuration': 'Configuration / diagnostics',
        'repeated': 'Repeated directories', 'application': 'Application-shaped route',
        'unexpected': 'Unexpected PHP location', 'cross_domain': 'Multiple domains',
        'client_sweep': 'Client scanning multiple paths', 'encoded': 'Encoded / unusual URL',
        'unknown': 'Unclassified PHP path'}


def family(path):
    # Preserve leading slashes/encoding; grouping is never a ban pattern.
    prefix = path[:len(path) - len(path.lstrip('/'))]
    parts = path[len(prefix):].split('/')
    result = []
    for part in parts[:-1]:
        if not result or not part or part != result[-1]:
            result.append(part)
    return prefix + '/'.join([*result, parts[-1]])


def describe(path, candidate, evidence=None):
    evidence = evidence or {}
    decoded = unquote(path).lower()
    filename = decoded.rsplit('/', 1)[-1]
    tags, reasons, priority = [], [], 'normal'
    reserved = bool(re.search(r'/(?:wp-content|wp-includes)(?:/|$)', decoded))
    app = bool(re.fullmatch(r'/(?:[^/.][^/]*/)*(?:index|wp-login|xmlrpc|wp-cron|wp-signup)\.php', decoded)) and not reserved and '/wp-admin/' not in decoded
    app |= bool(re.fullmatch(r'/(?:[^/.][^/]*/)*wp-admin/(?:admin-ajax|admin-post|install|upgrade)\.php', decoded)) and not reserved
    if app:
        tags.append('application')
        reasons.append('Application-shaped URL, including possible subdirectory installs. The installed application and request context still need checking.')
    if candidate in probe_rules.FILES:
        tags.append('probe')
        reasons.append('This exact path is in the bundled suggestions; that list is not a malware verdict.')
    if filename in ('phpinfo.php', '_phpinfo.php', 'php-info.php', 'info.php', 'debug.php', 'wp-config.php', 'configuration.php', 'config.php', 'env.php', 'settings.php', 'config.inc.php'):
        tags.append('configuration')
        reasons.append('The name resembles a configuration or diagnostic file.')
    if family(path) != path:
        tags.append('repeated')
        reasons.append('Consecutive directory names repeat; this can come from generated probes or broken relative links.')
    if (not app and filename in ('wp-login.php', 'wp-cron.php', 'xmlrpc.php', 'admin-ajax.php')) or re.search(r'/wp-content/(?:uploads|wflogs)/.+\.php$', decoded):
        tags.append('unexpected')
        reasons.append('PHP is being requested in an unexpected location for this endpoint.')
    if '%' in path or '//' in path or '/./' in path:
        tags.append('encoded')
        reasons.append('The URL contains encoding, extra slashes or dot segments. Original URLs remain separate.')
    if not tags:
        tags.append('unknown'); reasons.append('No bundled path characteristic identifies this request. Review its context.')
    domains = len(evidence.get('domains', []))
    if domains > 1:
        tags.append('cross_domain'); reasons.append('Observed on %d domains.' % domains)
    sweeps, cross = evidence.get('multi_path_clients', 0), evidence.get('cross_domain_clients', 0)
    if sweeps:
        tags.append('client_sweep'); reasons.append('%d recorded clients also requested other missing PHP paths.' % sweeps)
    if cross:
        reasons.append('%d recorded clients requested this path across multiple domains.' % cross)
    busiest = evidence.get('busiest_client', {})
    if busiest.get('paths', 0) > 1:
        reasons.append('The busiest matching client requested %d different missing PHP paths across %d domains in this review.' % (busiest['paths'], busiest['domains']))
    suspect = any(tag in tags for tag in ('probe', 'configuration', 'repeated', 'unexpected'))
    if (suspect and (sweeps or cross or domains >= 3)) or (cross and domains >= 3): priority = 'high'
    elif app and not any(tag in tags for tag in ('probe', 'unexpected', 'encoded')) and not sweeps and not cross: priority = 'low'
    return dict(label=TAGS[tags[0]], reason=' '.join(reasons), tags=tags, priority=priority,
                priority_label={'high': 'High review priority', 'normal': 'Review context', 'low': 'Lower review priority'}[priority],
                append_reason='' if candidate else 'This path cannot be added as an exact PHP-file rule: it contains traversal, redacted data, invalid encoding or characters that the path validator rejects.')
