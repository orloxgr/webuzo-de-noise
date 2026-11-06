"""Webuzo discovery and journaled changes through native custom includes."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from policy import (DEFAULT, VERSION, SCANNER_AGENTS, CRAWLER_AGENTS, SEARCH_AGENTS, FILTER_AGENTS,
                    account, domain, validate, site_mode, global_config, site_config)
import activity
import agent_catalog
import auto_bans
import ban_history
from presets import RULES
import storage
import probe_rules
import cron_spread
import domain_bans
import wordpress
import enumeration
import log_analysis
import analysis_jobs

REVIEW_ACTIONS = ('log_scan', 'log_scan_start', 'log_scan_status', 'log_scan_cancel', 'activity_start', 'activity_status', 'activity_cancel', 'agents_export') + tuple(kind + '_' + action for kind in ('agents', 'php_files') for action in ('start', 'status', 'cancel'))

import webuzo
import integration
import web_bans
import webmail

STATE = webuzo.STATE
GLOBAL = webuzo.GLOBAL
run = webuzo.run


def collect():
    return webuzo.collect() + [webmail.discover()]


def managed_path(value):
    path = Path(value)
    if path in (GLOBAL, webmail.SNIPPET):
        return path
    if path.parent != webuzo.SNIPPETS or not path.name.endswith('.conf'):
        raise ValueError('Invalid managed configuration path')
    domain(path.name[:-5])
    return path


def load(name, default):
    raw = storage.read(STATE / name)
    return json.loads(raw) if raw is not None else copy.deepcopy(default)


@contextmanager
def locked():
    import fcntl
    storage.private_directory(STATE)
    fd = os.open(STATE / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_uid != 0:
            raise ValueError('Operation lock must belong to root')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def verify(paths):
    # -T both syntax-checks and proves that the installed snippets are actually
    # included by the running distribution's Nginx configuration structure.
    dump = run(webuzo.NGINX, '-T')
    for path in paths:
        if '# configuration file ' + str(path) + ':' not in dump:
            raise RuntimeError('Nginx does not load the expected include: ' + str(path))


reload_nginx = webuzo.reload_nginx


def restore(record):
    for name, text in record['before'].items():
        path = managed_path(name)
        if not path.parent.exists() and text is None:
            continue
        storage.owned(path)
        storage.replace(path, None if text is None else text.encode(), 0o600)


def recover():
    record = load('transaction.json', None)
    if record is None:
        return
    if record.get('schema') != 1 or not isinstance(record.get('before'), dict):
        raise ValueError('Invalid pending transaction; refusing unsafe recovery')
    integration.write(record.get('custom_changes', []), restore=True)
    restore(record)
    run(webuzo.NGINX, '-t')
    reload_nginx()
    if record.get('mail_touched'):
        run(webmail.BINARY, '-t')
        webmail.reload()
    enumeration.apply(record.get('enumeration_changes', []), reverse=True)
    for name in ('policy.json', 'manifest.json', 'custom-manifest.json', web_bans.APPLIED, domain_bans.APPLIED, enumeration.MANIFEST, webmail.HISTORY):
        if name not in record:
            continue  # Recovery journals from an older installed generation.
        old = record[name]
        storage.replace(STATE / name, None if old is None else storage.json_bytes(old), 0o600)
    storage.replace(STATE / 'transaction.json', None)


def apply(policy, sites, remove=False, global_blocks=None):
    policy = validate(policy)
    if not remove:
        known = {site['key'] for site in sites}
        policy['overrides'] = {key: mode for key, mode in policy['overrides'].items() if key in known}
        policy['static_exceptions'] = {key: paths for key, paths in policy['static_exceptions'].items() if key in known}
        policy['domain_bans']['sites'] = {key: value for key, value in policy['domain_bans']['sites'].items() if key in known}
        for kind in ('files', 'queries'):
            policy['probe_exceptions'][kind] = {key: paths for key, paths in policy['probe_exceptions'][kind].items() if key in known}
    mail_site = next((site for site in sites if site.get('shared_webmail')), None)
    mail_profile = webmail.profile(policy) if not remove else dict(mode='off', agents=[], scanners=False)
    mail_enabled = bool(mail_site and mail_profile['mode'] != 'off')
    if mail_enabled and not mail_site['supported']:
        raise ValueError(mail_site['reason'])
    custom_manifest, custom_changes = integration.prepare(sites, load('custom-manifest.json', {}),
                                                        remove=remove, mail=mail_enabled)
    if global_blocks is None:
        global_blocks = load(web_bans.APPLIED, [])
    global_blocks = sorted(set(global_blocks)) if not remove else []
    desired = {}
    sites, companion_manifest, companion_changes = enumeration.prepare(
        policy, sites, load(enumeration.MANIFEST, {}), site_mode, remove=remove)
    domain_blocks = domain_bans.desired(policy, sites, STATE) if not remove else {}
    if not remove:
        desired[str(GLOBAL)] = global_config(policy, [s for s in sites if not s.get('shared_webmail')], domain_blocks, global_blocks)
        for site in sites:
            if site.get('shared_webmail'):
                if mail_enabled:
                    desired[str(webmail.SNIPPET)] = webmail.compile(mail_profile)
                continue
            site['global_bans'] = bool(global_blocks)
            if site['supported'] and (site.get('kind') != 'mail' or policy['mail_protection']):
                for path in site['paths']:
                    desired[path] = site_config(policy, site, site.get('roots', {}).get(path))
    manifest = load('manifest.json', [])
    old_paths = {str(managed_path(name)) for name in manifest}
    before, changes = {}, {}
    for name in sorted(old_paths | set(desired)):
        path = managed_path(name)
        if not path.parent.exists() and name not in desired:
            continue  # A domain deleted through Webuzo is authoritative.
        current = storage.owned(path)
        text = None if current is None else current.decode()
        next_text = desired.get(name)
        if text != next_text:
            before[name] = text
            changes[name] = next_text
    # Preserve policy + ownership manifest in the same recovery journal. A
    # crash after reload but before state commit restores the old policy too.
    mail_touched = str(webmail.SNIPPET) in changes or any(row['path'] == str(webmail.CUSTOM) for row in custom_changes)
    record = {'schema': 1, 'before': before, 'mail_touched': mail_touched,
              webmail.HISTORY: load(webmail.HISTORY, None),
              'policy.json': load('policy.json', None), 'manifest.json': load('manifest.json', None),
              domain_bans.APPLIED: load(domain_bans.APPLIED, None),
              enumeration.MANIFEST: load(enumeration.MANIFEST, None),
              'enumeration_changes': companion_changes, 'custom_changes': custom_changes,
              web_bans.APPLIED: load(web_bans.APPLIED, None),
              'custom-manifest.json': load('custom-manifest.json', None)}
    storage.replace(STATE / 'transaction.json', storage.json_bytes(record), 0o600)
    try:
        enumeration.apply(companion_changes)
        for name, text in changes.items():
            storage.replace(name, None if text is None else text.encode(), 0o600)
        integration.write(custom_changes)
        verify([path for path in desired if path != str(webmail.SNIPPET)])
        if mail_enabled:
            webmail.verify()
        elif mail_touched:
            run(webmail.BINARY, '-t')
        web_touched = any(path != str(webmail.SNIPPET) for path in changes) or any(row['path'] != str(webmail.CUSTOM) for row in custom_changes)
        if web_touched:
            reload_nginx()
        if mail_touched:
            webmail.reload()
        if mail_site or mail_touched:
            webmail.remember(STATE, mail_profile, mail_site.get('native_logs', []) if mail_site else [])
        changed_roots = {row['root'] for row in companion_changes if row['after'] is not None}
        for site in sites:
            entry = companion_manifest.get(site['key'])
            if entry and entry['root'] in changed_roots and site.get('template', '').startswith('caching'):
                webuzo.cli('clear_cache', users=site['owner'])
        for entry in companion_manifest.values():
            entry['fingerprint'] = enumeration.fingerprint(entry['root'])
        storage.replace(STATE / 'custom-manifest.json', storage.json_bytes(custom_manifest), 0o600)
        storage.replace(STATE / web_bans.APPLIED, storage.json_bytes(global_blocks), 0o600)
        storage.replace(STATE / 'manifest.json', storage.json_bytes(sorted(desired)), 0o600)
        storage.replace(STATE / 'policy.json', storage.json_bytes(policy), 0o600)
        storage.replace(STATE / domain_bans.APPLIED, storage.json_bytes(domain_blocks), 0o600)
        storage.replace(STATE / enumeration.MANIFEST, storage.json_bytes(companion_manifest), 0o600)
        storage.replace(STATE / 'transaction.json', None)
    except Exception as error:
        try:
            recover()
        except Exception as rollback:
            raise RuntimeError(str(error) + '\nRecovery also failed: ' + str(rollback) +
                               '\nThe recovery journal has been retained.') from error
        raise
    return {'changed_files': len(changes), 'sites': len(sites),
            'supported_sites': sum(s['supported'] for s in sites)}


def synchronize(policy, sites, remove=False, disable_wordpress=False):
    health = copy.deepcopy(load('maintenance.json', {}))
    health.update(last_attempt=time.time(), error='')
    try:
        if remove:
            auto_bans.cleanup(policy, sites, STATE, auto_bans.Native(webuzo.HOME, run, STATE))
        else:
            domain_bans.synchronize(policy, sites, STATE, auto_bans.Native(webuzo.HOME, run, STATE))
        result = apply(policy, sites, remove=remove)
        if disable_wordpress and wordpress.read_json(STATE, wordpress.RECEIPT) is not None:
            wordpress.apply(STATE, {**wordpress.settings(STATE), 'enabled': False}, run)
        if not remove:
            bans = auto_bans.synchronize(policy, sites, STATE, auto_bans.Native(webuzo.HOME, run, STATE))
            if bans.get('error'):
                raise RuntimeError('HTTP rules synchronized; automatic web bans failed: ' + bans['error'])
            result['bans'] = {key: value for key, value in bans.items() if key != 'rows'}
        health.update(last_success=time.time(), error='')
    except Exception as error:
        health['error'] = str(error)
        storage.replace(STATE / 'maintenance.json', storage.json_bytes(health), 0o600)
        raise
    storage.replace(STATE / 'maintenance.json', storage.json_bytes(health), 0o600)
    return result


def snapshot(policy, sites, owner=None, wordpress_live=False, listing=None):
    listing = listing or {}
    rows = []
    for site in sites:
        if owner is not None and site['owner'] != owner:
            continue
        rows.append({**{key: site[key] for key in ('key', 'owner', 'domain', 'template', 'aliases',
                                                   'suspended', 'supported', 'reason')},
                     'kind': site.get('kind', 'web'), 'mode': site_mode(policy, site),
                     'override': policy['overrides'].get(site['key'], 'inherit')})
    metrics = {'available': False, 'on_demand': True}
    ban_status = {}
    if owner is None:
        try:
            ban_status = auto_bans.report(STATE, policy['bans']['enabled'],
                listing.get('bans_page', 1), listing.get('bans_view', 'active'))
        except (OSError, ValueError) as error:
            ban_status = {'error': str(error)}
    try:
        scoped = domain_bans.report(policy, sites, STATE, owner,
            page=listing.get('domain_page', 1), view=listing.get('domain_view', 'active'))
    except (OSError, ValueError) as error:
        scoped = {'active': 0, 'pending': 0, 'rows': [], 'error': str(error)}
    visible_keys = {row['key'] for row in rows}
    scoped['preferences'] = {key: value for key, value in policy['domain_bans']['sites'].items() if key in visible_keys}
    scoped['can_edit'] = owner is None or policy['domain_bans']['allow_users']
    scoped['limits'] = {key: {name: policy['bans'][key][name] for name in ('maxretry', 'findtime', 'duration_days')}
                       for key in ('missing_files', 'suspicious_queries', 'any_404')}
    wordpress_status = None
    if owner is None:
        try:
            wordpress_status = wordpress.snapshot(STATE, run, live=wordpress_live, page=listing.get('wordpress_page', 1))
        except (OSError, ValueError) as error:
            wordpress_status = {'settings': wordpress.DEFAULT, 'loaded': wordpress_live, 'error': str(error)}
    maintenance = load('maintenance.json', {}) if owner is None else {}
    if maintenance.get('last_success'):
        maintenance['stale'] = time.time() - maintenance['last_success'] > 180
    return {'ok': True, 'version': VERSION, 'policy': policy if owner is None else {'mode': policy['mode']},
            'sites': rows, 'activity': metrics,
            'bans': ban_status,
            'domain_bans': scoped,
            'history': ban_history.settings(STATE),
            'maintenance': maintenance,
            'wordpress': wordpress_status,
            'cron': cron_spread.public(load('cron-spread.json', None)) if owner is None else None,
            'presets': {'scanners': SCANNER_AGENTS, 'crawlers': CRAWLER_AGENTS, 'search_crawlers': SEARCH_AGENTS,
                        'agent_categories': agent_catalog.CATEGORIES,
                        'filter_agents': FILTER_AGENTS, 'rules': RULES,
                        'probe_files': probe_rules.FILES, 'probe_queries': probe_rules.QUERY_TARGETS,
                        'probe_parameters': probe_rules.QUERY_PARAMETERS} if owner is None else {}}


def authorize(request):
    actor = account(request.get('actor'))
    admin = actor == 'root'
    if not admin:
        user = webuzo.users().get(actor)
        if user is None or user['suspended']:
            raise PermissionError('Account is suspended or unavailable')
    owner = account(request.get('owner', actor))
    if not admin and owner != actor:
        raise PermissionError('Another account cannot be selected')
    if request.get('action') not in ('status', 'domain_bans_save', 'history_clear', 'activity_start', 'activity_status', 'activity_cancel') and not admin:
        raise PermissionError('Only an administrator can change De-Noise settings')
    return admin, owner


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError('Expected a JSON object')
    if request.get('action') in REVIEW_ACTIONS:
        admin, owner = authorize(request)
        if request['action'].startswith('activity_'):
            if set(request) - {'actor', 'owner', 'action', 'minutes', 'job', 'page', 'listing'}:
                raise ValueError('Only activity selections can be submitted')
            scope = None if admin and owner == request['actor'] else owner
            arguments = dict(kind='activity', owner=scope)
            if request['action'] == 'activity_start':
                job = analysis_jobs.start(STATE, None, request['actor'], 'all', request.get('minutes'), **arguments)
            elif request['action'] == 'activity_status':
                job = analysis_jobs.status(STATE, request.get('job'), request['actor'], request.get('page', 1), **arguments)
            else:
                job = analysis_jobs.cancel(STATE, request.get('job'), request['actor'], **arguments)
            return {'ok': True, 'job': job}
        if not admin or owner != request['actor']:
            raise PermissionError('Log analysis requires the administrator context')
        if set(request) - {'actor', 'owner', 'action', 'target', 'minutes', 'verify_google', 'listing', 'job', 'page', 'offset'}:
            raise ValueError('Only log-analysis selections can be submitted')
        for kind in ('agents', 'php_files'):
            if not request['action'].startswith(kind + '_'):
                continue
            operation = request['action'][len(kind) + 1:]
            if kind == 'agents' and operation == 'export':
                return {'ok': True, 'export': analysis_jobs.export_agents(STATE, request.get('job'),
                    request['actor'], request.get('offset', 0))}
            if operation == 'start':
                job = analysis_jobs.start(STATE, None, request['actor'], request.get('target'),
                    request.get('minutes'), kind=kind)
            elif operation == 'status':
                job = analysis_jobs.status(STATE, request.get('job'), request['actor'], request.get('page', 1), kind=kind)
            else:
                job = analysis_jobs.cancel(STATE, request.get('job'), request['actor'], kind=kind)
            return {'ok': True, 'job': job}
        if request['action'] == 'log_scan_start':
            return {'ok': True, 'job': analysis_jobs.start(STATE, None, request['actor'],
                request.get('target'), request.get('minutes'), request.get('verify_google', False))}
        if request['action'] == 'log_scan_status':
            return {'ok': True, 'job': analysis_jobs.status(STATE, request.get('job'), request['actor'], request.get('page', 1))}
        if request['action'] == 'log_scan_cancel':
            return {'ok': True, 'job': analysis_jobs.cancel(STATE, request.get('job'), request['actor'])}
        return {'ok': True, 'analysis': log_analysis.review(collect(), request.get('target'),
                request.get('minutes'), STATE, request.get('verify_google', False))}
    admin, owner = authorize(request)
    action = request.get('action')
    policy = validate(load('policy.json', DEFAULT))
    sites = collect()
    listing = request.get('listing', {})
    if (not isinstance(listing, dict) or set(listing) - {'bans_page','bans_view','domain_page','domain_view','wordpress_page'}):
        raise ValueError('Invalid IP-list selection')
    for scope in ('bans', 'domain'):
        ban_history.selection(listing.get(scope + '_page', 1), listing.get(scope + '_view', 'active'))
    ban_history.selection(listing.get('wordpress_page', 1))
    if action == 'history_clear':
        scope = request.get('scope')
        if scope not in ('global', 'domain') or (scope == 'global' and not (admin and owner == request['actor'])):
            raise PermissionError('Only domain history for your account can be cleared')
        with auto_bans.database(STATE, create=False) as db:
            if db is not None:
                ban_history.clear(db, scope, owner=None if admin and owner == request['actor'] else owner)
    elif action == 'history_settings_save':
        ban_history.configure(STATE, request.get('days'))
        with auto_bans.database(STATE, create=False) as db:
            if db is not None:
                ban_history.maintain(STATE, db, force=True)
    elif action == 'wordpress_save':
        if set(request) - {'actor', 'owner', 'action', 'settings', 'listing'}:
            raise ValueError('Only WordPress protection settings can be submitted')
        wordpress.apply(STATE, request.get('settings'), run)
    elif action == 'wordpress_unban':
        wordpress.unban(STATE, request.get('ips'), run)
    elif action == 'wordpress_status':
        pass
    elif action == 'domain_bans_save':
        if set(request) - {'actor', 'owner', 'action', 'preferences', 'listing'}:
            raise ValueError('Only domain trigger selections can be submitted')
        if not admin and not policy['domain_bans']['allow_users']:
            raise PermissionError('Domain automatic-ban editing is disabled by the administrator')
        preferences = request.get('preferences')
        if not isinstance(preferences, dict) or not preferences:
            raise ValueError('Select existing domain automatic-ban settings')
        known = {site['key']: site for site in sites if site.get('kind') != 'mail'}
        for key, flags in preferences.items():
            if (key not in known or (not (admin and owner == request['actor']) and known[key]['owner'] != owner)):
                raise PermissionError('This domain does not belong to the selected account')
            if not known[key]['supported'] or known[key]['suspended']:
                raise ValueError('This domain is suspended or unsupported')
            if isinstance(flags, dict) and set(flags) == {'missing_files', 'suspicious_queries'}:
                # An already-open 0.5 panel cannot clear a newer switch.
                flags['any_404'] = policy['domain_bans']['sites'].get(key, {}).get('any_404', False)
            if (not isinstance(flags, dict) or set(flags) != {'missing_files', 'suspicious_queries', 'any_404'}
                    or any(type(value) is not bool for value in flags.values())):
                raise ValueError('Only domain trigger switches can be changed')
        for key, flags in preferences.items():
            if any(flags.values()):
                policy['domain_bans']['sites'][key] = flags
            else:
                policy['domain_bans']['sites'].pop(key, None)
        apply(policy, sites)
    elif action == 'cron_preview':
        plan = cron_spread.preview(webuzo.cron_metadata, request.get('minimum', 5), request.get('maximum', 15))
        storage.replace(STATE / 'cron-spread.json', storage.json_bytes(plan), 0o600)
    elif action == 'cron_apply':
        plan = load('cron-spread.json', None)
        if not plan or request.get('plan_id') != plan['id']:
            raise ValueError('Cron preview is missing or changed. Generate a new preview.')
        cron_spread.apply(plan, request.get('jobs'), webuzo.cron_metadata,
            webuzo.change_cron,
            lambda value: storage.replace(STATE / 'cron-spread.json', storage.json_bytes(value), 0o600),
            restore=request.get('restore') is True)
    elif action == 'save':
        # Keep overrides server-side; the global form cannot overwrite them.
        incoming = request.get('policy')
        if not isinstance(incoming, dict):
            raise ValueError('Expected policy settings')
        previous = policy
        if incoming.get('schema') in (6, 7, 8, 9, 10):
            if not isinstance(incoming.get('domain_bans'), dict):
                raise ValueError('Invalid domain automatic-ban policy')
            incoming = {**incoming, 'domain_bans': {**incoming.get('domain_bans', {}),
                'sites': previous['domain_bans']['sites'] if incoming.get('schema') in (7, 8, 9, 10) else {}}}
        policy = validate({**incoming, 'overrides': previous['overrides']})
        if incoming.get('schema') not in (9, 10):
            policy['enumeration'] = previous['enumeration']
        if incoming.get('schema') not in (8, 9, 10):
            for key in ('log_rejections', 'mail_protection'):
                policy[key] = previous[key]
            for key in ('exclude_static', 'min_distinct_paths'):
                policy['bans']['any_404'][key] = previous['bans']['any_404'][key]
        if incoming.get('schema') in (1, 2, 3, 4, 5, 6):
            policy['bans']['any_404'] = previous['bans']['any_404']
        if incoming.get('schema') == 6:
            policy['domain_bans']['sites'] = previous['domain_bans']['sites']
        if incoming.get('schema') in (1, 2, 3, 4, 5):
            policy['domain_bans'] = previous['domain_bans']
        if incoming.get('schema') in (1, 2):
            policy['static_exceptions'] = previous['static_exceptions']
        if incoming.get('schema') in (1, 2, 3):
            policy['bans'] = previous['bans']
            policy['tool_agents_enabled'] = previous['tool_agents_enabled']
            policy['agents_enabled'] = previous['agents_enabled']
        if incoming.get('schema') in (1, 2, 3, 4):
            for key in ('missing_files', 'suspicious_queries'):
                policy['bans'][key] = previous['bans'][key]
            policy['probe_exceptions'] = previous['probe_exceptions']
        if policy['bans']['enabled']:
            auto_bans.Native(webuzo.HOME, run, STATE).available()
        apply(policy, sites)
    elif action == 'bulk':
        selection = request.get('targets')
        mode = request.get('mode')
        known = {s['key'] for s in sites}
        if (not isinstance(selection, list) or not selection or
                any(not isinstance(x, str) or x not in known for x in selection) or
                mode not in ('inherit', 'off', 'observe', 'enforce')):
            raise ValueError('Select existing domains and a valid mode')
        for key in selection:
            if mode == 'inherit':
                policy['overrides'].pop(key, None)
            else:
                policy['overrides'][key] = mode
        apply(policy, sites)
    elif action == 'disable':
        policy['mode'] = 'off'; policy['overrides'] = {}
        apply(policy, sites)
        if wordpress.read_json(STATE, wordpress.RECEIPT) is not None:
            wordpress.apply(STATE, {**wordpress.settings(STATE), 'enabled': False}, run)
    elif action == 'sync':
        synchronize(policy, sites)
    elif action == 'unban':
        auto_bans.unban(STATE, auto_bans.Native(webuzo.HOME, run, STATE), request.get('ips'))
        result = auto_bans.synchronize(policy, sites, STATE, auto_bans.Native(webuzo.HOME, run, STATE), read_events=False)
        if result.get('error'):
            raise RuntimeError('Unban is pending; native web-ban operation failed: ' + result['error'])
    elif action != 'status':
        raise ValueError('Unsupported operation')
    return snapshot(policy, sites, None if admin and owner == request['actor'] else owner,
                    wordpress_live=action in ('wordpress_status', 'wordpress_save', 'wordpress_unban'), listing=listing)


def main():
    if os.geteuid() != 0:
        raise PermissionError('Invoke this command as root or through the Webuzo panel')
    request = None
    if len(sys.argv) == 3 and sys.argv[1] == '--request':
        import transport
        request = transport.read(sys.argv[2])
        sys.argv = sys.argv[:1]
    if not sys.argv[1:]:
        if request is None:
            raw = sys.stdin.buffer.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('Request exceeds the safe transport size')
            request = json.loads(raw)
        # An explicit read-only review has its own queued scan lock. It
        # must not hold the protection/recovery lock or run mutation recovery.
        if isinstance(request, dict) and request.get('action') in REVIEW_ACTIONS:
            if load('active.json', {}).get('active') is not True:
                raise RuntimeError('De-Noise is not active')
            return dispatch(request)
    with locked():
        recover()
        wordpress.recover(STATE, run)
        if sys.argv[1:] != ['status'] and load('active.json', {}).get('active') is not True:
            raise RuntimeError('De-Noise is not active')
        if sys.argv[1:]:
            action = sys.argv[1:]
            if action not in (['sync'], ['disable'], ['status'], ['remove-rules']):
                raise ValueError('Commands: status, sync, disable, remove-rules')
            policy = validate(load('policy.json', DEFAULT))
            sites = collect()
            if action == ['disable']:
                policy['mode'] = 'off'; policy['overrides'] = {}
            if action != ['status']:
                result = synchronize(policy, sites, remove=action == ['remove-rules'], disable_wordpress=action == ['disable'])
            else:
                result = snapshot(policy, sites)
        else:
            result = dispatch(request)
    return {'ok': True, **result}
