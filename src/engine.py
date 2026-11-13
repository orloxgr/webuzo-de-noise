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
                    account, domain, target, validate, site_mode, global_config, site_config)
import activity
import agent_catalog
import auto_bans
import ban_history
import listing as list_sizes
from presets import RULES
import storage
import probe_rules
import cron_spread
import host_protection
import f2b_install
import wordpress
import enumeration
import log_analysis
import analysis_jobs
import access_protection
import captcha_runtime
import country_database

REVIEW_ACTIONS = ('review_mark', 'review_export', 'log_scan', 'log_scan_start', 'log_scan_status', 'log_scan_cancel', 'activity_start', 'activity_status', 'activity_cancel', 'agents_export', 'agents_candidates', 'fail2ban_install_status') + tuple(kind + '_' + action for kind in ('agents', 'php_files') for action in ('start', 'status', 'cancel'))

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
    if path.parent == access_protection.DIRECTORY and (re.fullmatch(r'[0-9a-f]{24}\.(?:htpasswd|captcha\.conf)', path.name) or path.name == captcha_runtime.CONFIG_NAME):
        return path
    if path.parent == STATE and re.fullmatch(r'country-[0-9a-f]{64}\.geo', path.name):
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
        if str(path).endswith('.htpasswd') or Path(path) == access_protection.DIRECTORY / captcha_runtime.CONFIG_NAME:
            continue
        if '# configuration file ' + str(path) + ':' not in dump:
            raise RuntimeError('Nginx does not load the expected include: ' + str(path))


reload_nginx = webuzo.reload_nginx


def replace_rule(path, text):
    path = Path(path)
    password = path.parent == access_protection.DIRECTORY and path.name.endswith('.htpasswd')
    mode = 0o640 if password else (0o644 if path == access_protection.DIRECTORY / captcha_runtime.CONFIG_NAME else 0o600)
    gid = 0
    if password:
        import grp
        gid = grp.getgrnam(captcha_runtime.worker_group()).gr_gid
    storage.replace(path, None if text is None else text.encode(), mode, gid=gid)


def access_settings():
    raw = storage.read(STATE / access_protection.SETTINGS) if STATE.exists() else None
    return access_protection.validate(json.loads(raw) if raw else access_protection.defaults(), target)



def geo_metadata():
    raw = storage.read(STATE / country_database.METADATA) if STATE.exists() else None
    return json.loads(raw) if raw else {}



def refresh_countries(policy, sites):
    """Scheduled download only; serving requests never calls an external service."""
    settings = access_settings()
    if not any(s.get('kind') != 'mail' and s.get('supported') and not s.get('suspended')
               and access_protection.effective(settings, s['key'])['country']['enabled']
               and site_mode(policy, s) != 'off' for s in sites):
        return
    raw = storage.read(STATE / country_database.CONFIG)
    config = json.loads(raw) if raw else {}
    metadata = geo_metadata()
    if not config.get('automatic') or time.time() - metadata.get('last_attempt', metadata.get('updated', 0)) < 86400:
        return
    if not metadata.get('error') and time.time() - metadata.get('updated', 0) < 7 * 86400:
        return
    metadata['last_attempt'] = time.time()
    try:
        geography = country_database.download(config)
        apply(policy, sites, geography=geography)
    except Exception as error:
        metadata['error'] = str(error)
        # Keep the last working country data and rules, while exposing the failure.
        storage.replace(STATE / country_database.METADATA, storage.json_bytes(metadata), 0o600)



def restore(record):
    for name, text in record['before'].items():
        path = managed_path(name)
        if not path.parent.exists() and text is None:
            continue
        storage.owned(path)
        replace_rule(path, text)


def recover():
    record = load('transaction.json', None)
    if record is None:
        return
    if record.get('schema') != 1 or not isinstance(record.get('before'), dict):
        raise ValueError('Invalid pending transaction; refusing unsafe recovery')
    captcha_config = str(access_protection.DIRECTORY / captcha_runtime.CONFIG_NAME)
    captcha_before = record.get('captcha_enabled_before')
    if 'captcha_enabled_before' in record and type(captcha_before) is not bool:
        raise ValueError('Invalid CAPTCHA recovery state')
    if captcha_before is None and (captcha_config in record['before'] or captcha_config in (record.get('manifest.json') or [])):
        # The same journal already carries the previous manifest and file
        # contents, including transactions made before runtime state was saved.
        captcha_before = captcha_config in (record.get('manifest.json') or [])
    integration.write(record.get('custom_changes', []), restore=True)
    restore(record)
    if captcha_before is True:
        captcha_runtime.install(run)
        captcha_runtime.enable(run)
    run(webuzo.NGINX, '-t')
    reload_nginx()
    if record.get('mail_touched'):
        run(webmail.BINARY, '-t')
        webmail.reload()
    enumeration.apply(record.get('enumeration_changes', []), reverse=True)
    for name in ('policy.json', 'manifest.json', 'custom-manifest.json', web_bans.APPLIED, 'domain-ban-applied.json', enumeration.MANIFEST, webmail.HISTORY, access_protection.SETTINGS, country_database.METADATA):
        if name not in record:
            continue  # Recovery journals from an older installed generation.
        old = record[name]
        storage.replace(STATE / name, None if old is None else storage.json_bytes(old), 0o600)
    if captcha_before is False:
        captcha_runtime.disable(run)
    storage.replace(STATE / 'transaction.json', None)


def apply(policy, sites, remove=False, global_blocks=None, access=None, geography=None):
    policy = validate(policy)
    access = access_settings() if access is None else access_protection.validate(access, target)
    metadata = geography[1] if geography else geo_metadata()
    geo_path = country_database.path(STATE, metadata)
    if geography:
        storage.replace(geo_path, geography[0], 0o600)
    if not remove:
        known = {site['key'] for site in sites}
        policy['overrides'] = {key: mode for key, mode in policy['overrides'].items() if key in known}
        policy['static_exceptions'] = {key: paths for key, paths in policy['static_exceptions'].items() if key in known}
        for kind in ('files', 'queries'):
            policy['probe_exceptions'][kind] = {key: paths for key, paths in policy['probe_exceptions'][kind].items() if key in known}
    mail_site = next((site for site in sites if site.get('shared_webmail')), None)
    mail_profile = webmail.profile(policy) if not remove else dict(mode='off', agents=[], scanners=False)
    mail_enabled = bool(mail_site and mail_profile['mode'] != 'off')
    if mail_enabled and not mail_site['supported']:
        raise ValueError(mail_site['reason'])
    custom_manifest, custom_changes = integration.prepare(sites, load('custom-manifest.json', {}),
                                                        remove=remove, mail=mail_enabled, access=access, site_mode=lambda site: site_mode(policy, site))
    if global_blocks is None:
        global_blocks = load(web_bans.APPLIED, [])
    global_blocks = sorted(set(global_blocks)) if not remove else []
    desired = {}
    sites, companion_manifest, companion_changes = enumeration.prepare(
        policy, sites, load(enumeration.MANIFEST, {}), site_mode, remove=remove)
    if not remove:
        desired[str(GLOBAL)] = global_config(policy, [s for s in sites if not s.get('shared_webmail')], global_blocks, access, geo_path)
        for site in sites:
            if site.get('shared_webmail'):
                if mail_enabled:
                    desired[str(webmail.SNIPPET)] = webmail.compile(mail_profile)
                continue
            site['global_bans'] = bool(global_blocks)
            if site['supported'] and (site.get('kind') != 'mail' or policy['mail_protection']):
                for path in site['paths']:
                    desired[path] = site_config(policy, site, site.get('roots', {}).get(path), access)
                entry = access_protection.effective(access, site['key'])
                if entry['enabled'] and entry['method'] == 'basic' and not site.get('suspended') and site_mode(policy, site) != 'off':
                    directory = access_protection.DIRECTORY
                    directory.mkdir(mode=0o755, exist_ok=True)
                    with storage.parent(directory / '.check'):
                        pass
                    filename = directory / (access_protection.identifier(site['key']) + '.htpasswd')
                    desired[str(filename)] = '# Managed by webuzo-de-noise\n' + entry['username'] + ':' + entry['password_hash'] + '\n'
        if any(s.get('supported') and not s.get('suspended') and s.get('kind') != 'mail'
               and site_mode(policy, s) != 'off' and access_protection.effective(access, s['key'])['country']['enabled'] for s in sites):
            if not geo_path or not geo_path.is_file():
                raise ValueError('Download the country database before enabling a country filter')
    captcha_files, captcha_enabled = captcha_runtime.prepare(STATE, access_protection.DIRECTORY, access, sites, lambda site: site_mode(policy, site)) if not remove else ({}, False)
    desired.update(captcha_files)
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
    if captcha_enabled:
        # Native ZIP updates need not invoke the activation hook. Provision
        # the runtime as a normal prerequisite of applying CAPTCHA, before
        # journaling or switching any website rules. Foreign units are rejected.
        captcha_runtime.install(run)
    # Preserve policy + ownership manifest in the same recovery journal. A
    # crash after reload but before state commit restores the old policy too.
    mail_touched = str(webmail.SNIPPET) in changes or any(row['path'] == str(webmail.CUSTOM) for row in custom_changes)
    record = {'schema': 1, 'before': before, 'mail_touched': mail_touched,
              webmail.HISTORY: load(webmail.HISTORY, None),
              'policy.json': load('policy.json', None), 'manifest.json': load('manifest.json', None),
              'domain-ban-applied.json': load('domain-ban-applied.json', None),
              enumeration.MANIFEST: load(enumeration.MANIFEST, None),
              access_protection.SETTINGS: access_settings(),
              country_database.METADATA: geo_metadata(),
              'enumeration_changes': companion_changes, 'custom_changes': custom_changes,
              web_bans.APPLIED: load(web_bans.APPLIED, None),
              'custom-manifest.json': load('custom-manifest.json', None)}
    if captcha_enabled or str(access_protection.DIRECTORY / captcha_runtime.CONFIG_NAME) in old_paths:
        record['captcha_enabled_before'] = str(access_protection.DIRECTORY / captcha_runtime.CONFIG_NAME) in old_paths
    storage.replace(STATE / 'transaction.json', storage.json_bytes(record), 0o600)
    try:
        enumeration.apply(companion_changes)
        for name, text in changes.items():
            replace_rule(Path(name), text)
        if captcha_enabled:
            captcha_runtime.enable(run)
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
        storage.replace(STATE / enumeration.MANIFEST, storage.json_bytes(companion_manifest), 0o600)
        storage.replace(STATE / access_protection.SETTINGS, storage.json_bytes(access), 0o600)
        if geography:
            storage.replace(STATE / country_database.METADATA, storage.json_bytes(metadata), 0o600)
        if not captcha_enabled and str(access_protection.DIRECTORY / captcha_runtime.CONFIG_NAME) in old_paths:
            captcha_runtime.disable(run)
        storage.replace(STATE / 'transaction.json', None)
        retire_domain_bans()
    except Exception as error:
        try:
            recover()
        except Exception as rollback:
            raise RuntimeError(str(error) + '\nRecovery also failed: ' + str(rollback) +
                               '\nThe recovery journal has been retained.') from error
        raise
    return {'changed_files': len(changes), 'sites': len(sites),
            'supported_sites': sum(s['supported'] for s in sites)}


def synchronize(policy, sites, remove=False):
    health = copy.deepcopy(load('maintenance.json', {}))
    health.update(last_attempt=time.time(), error='')
    try:
        if not remove:
            refresh_countries(policy, sites)
        if remove:
            auto_bans.cleanup(policy, sites, STATE, auto_bans.Native(webuzo.HOME, run, STATE))
        result = apply(policy, sites, remove=remove)
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


def retire_domain_bans():
    """Called only after the replacement Nginx configuration has loaded."""
    with auto_bans.database(STATE, create=False) as db:
        if db is not None:
            for table in ('domain_cursors', 'domain_strikes', 'domain_bans'):
                db.execute('DROP TABLE IF EXISTS ' + table)
            for table in ('ban_history', 'ban_diagnostics', 'strike_evidence'):
                db.execute('DELETE FROM ' + table + " WHERE scope='domain'")
            db.execute("DELETE FROM meta WHERE key LIKE 'domain-%'")
            db.commit()
    storage.replace(STATE / 'domain-ban-applied.json', None)


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
                listing.get('bans_page', 1), listing.get('bans_view', 'active'), per_page=listing.get('bans_per_page',50))
        except (OSError, ValueError) as error:
            ban_status = {'error': str(error)}
    wordpress_status = None
    if owner is None:
        try:
            wordpress_status = wordpress.snapshot(STATE, run, live=wordpress_live, page=listing.get('wordpress_page', 1), per_page=listing.get('wordpress_per_page',50))
        except (OSError, ValueError) as error:
            wordpress_status = {'settings': wordpress.DEFAULT, 'loaded': wordpress_live, 'error': str(error)}
    maintenance = load('maintenance.json', {}) if owner is None else {}
    if maintenance.get('last_success'):
        maintenance['stale'] = time.time() - maintenance['last_success'] > 180
    saved_access = access_settings()
    access = access_protection.public(saved_access, {row['key'] for row in rows if row['kind'] != 'mail'})
    owners = {row['owner'] for row in rows if row['kind'] != 'mail'} | ({owner} if owner is not None else set())
    geography = country_database.status(STATE, storage.read) if STATE.exists() else {'available': False, 'configured': False}
    if owner is not None:
        geography = {k: v for k, v in geography.items() if k not in ('account_id', 'error')}
    return {'ok': True, 'version': VERSION, 'policy': policy if owner is None else {'mode': policy['mode']},
            'sites': rows, 'activity': metrics,
            'bans': ban_status,
            'access': access, 'geography': geography,
            'access_defaults': access_protection.public_profile(saved_access['defaults']) if owner is None else None,
            'access_accounts': access_protection.public_accounts(saved_access, owners),
            'history': ban_history.settings(STATE),
            'maintenance': maintenance,
            'wordpress': wordpress_status,
            'fail2ban': host_protection.snapshot(STATE, run) if owner is None else None,
            'install_job': f2b_install.status(STATE) if owner is None else None,
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
    if request.get('action') not in ('status', 'access_save', 'access_account_save', 'activity_start', 'activity_status', 'activity_cancel', 'review_export') and not admin:
        raise PermissionError('Only an administrator can change De-Noise settings')
    return admin, owner


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError('Expected a JSON object')
    if isinstance(request.get('action'), str) and request['action'].startswith('fail2ban_'):
        admin, owner = authorize(request)
        if not admin or owner != request['actor']:
            raise PermissionError('Fail2ban management requires the administrator context')
        action = request['action']
        permitted = {'fail2ban_status': set(), 'fail2ban_start': set(), 'fail2ban_save': {'settings'},
                     'fail2ban_test': {'service'}, 'fail2ban_unban': {'service', 'ips'},
                     'fail2ban_install_preview': set(), 'fail2ban_install_start': {'plan_token'},
                     'fail2ban_install_status': set()}
        if action not in permitted or set(request) - ({'actor', 'owner', 'action', 'listing'} | permitted.get(action, set())):
            raise ValueError('Unsupported Fail2ban operation or parameters')
        if action == 'fail2ban_install_status':
            return {'ok': True, 'install_job': f2b_install.status(STATE)}
        installation = f2b_install.status(STATE)
        if action == 'fail2ban_status' and installation['state'] in ('queued', 'running'):
            # APT exposes the executable before its conffiles and daemon are ready.
            # Do not query Fail2ban halfway through the package transaction.
            return {'ok': True, 'fail2ban': host_protection.snapshot(STATE, run),
                    'install_job': installation, 'wordpress': wordpress.snapshot(STATE, run)}
        if action not in ('fail2ban_status', 'fail2ban_install_start') and f2b_install.status(STATE)['state'] in ('queued', 'running'):
            raise ValueError('Wait for the Fail2ban installation to finish before changing authentication protection')
        extra = {}
        if action == 'fail2ban_install_preview':
            extra['install_plan'] = f2b_install.preview(STATE, run)
        elif action == 'fail2ban_install_start':
            extra['install_job'] = f2b_install.start(STATE, request.get('plan_token'), run)
            return {'ok': True, **extra}
        elif action == 'fail2ban_save':
            extra['service_result'] = host_protection.apply(STATE, request.get('settings'), run)
        elif action == 'fail2ban_test':
            key = request.get('service')
            host_protection.jail(key)
            extra['filter_test'] = {key: host_protection.test_filter(STATE, key, host_protection.discover(run)[key], run)}
        elif action == 'fail2ban_unban':
            host_protection.unban(STATE, request.get('service'), request.get('ips'), run)
        elif action == 'fail2ban_start':
            host_protection.check_service_start(run)
            run(host_protection.client(), '-t')
            run(host_protection.binary('systemctl') or '/usr/bin/systemctl', 'enable', '--now', 'fail2ban')
        return {'ok': True, 'fail2ban': host_protection.snapshot(STATE, run, live=True),
                'install_job': f2b_install.status(STATE), 'wordpress': wordpress.snapshot(STATE, run), **extra}
    if request.get('action') in REVIEW_ACTIONS:
        admin, owner = authorize(request)
        if request['action'] == 'review_mark':
            if not admin or owner != request['actor']:
                raise PermissionError('Review notes require the administrator context')
            if set(request) - {'actor','owner','action','listing','kind','job','domain','item','mark'}:
                raise ValueError('Only an exact report item can be reviewed')
            return {'ok': True, 'mark': analysis_jobs.mark_review(STATE, request.get('job'), request['actor'],
                request.get('kind'), request.get('domain'), request.get('item'), request.get('mark'))}
        if request['action'] == 'review_export':
            if set(request) - {'actor','owner','action','listing','kind','job','offset','domain','filters'}:
                raise ValueError('Only review export selections can be submitted')
            kind = request.get('kind')
            central = admin and owner == request['actor']
            if not central and kind != 'activity':
                raise PermissionError('Only your own Activity can be exported')
            return {'ok': True, 'export': analysis_jobs.export_review(STATE, request.get('job'), request['actor'],
                kind=kind, owner=None if central else owner, domain=request.get('domain','all'), offset=request.get('offset',0), **({'filters': request['filters']} if 'filters' in request else {}))}
        page_args = {'per_page': request['per_page']} if 'per_page' in request else {}
        if 'filters' in request: page_args['filters'] = request['filters']
        if request['action'].startswith('activity_'):
            if set(request) - {'actor', 'owner', 'action', 'minutes', 'job', 'page', 'listing', 'domain', 'per_page'}:
                raise ValueError('Only activity selections can be submitted')
            scope = None if admin and owner == request['actor'] else owner
            arguments = dict(kind='activity', owner=scope)
            if request['action'] == 'activity_start':
                job = analysis_jobs.start(STATE, None, request['actor'], 'all', request.get('minutes'), **arguments)
            elif request['action'] == 'activity_status':
                job = analysis_jobs.status(STATE, request.get('job'), request['actor'], request.get('page', 1), domain=request.get('domain', 'all'), **arguments, **page_args)
            else:
                job = analysis_jobs.cancel(STATE, request.get('job'), request['actor'], **arguments)
            return {'ok': True, 'job': job}
        if not admin or owner != request['actor']:
            raise PermissionError('Log analysis requires the administrator context')
        if request['action'] == 'agents_candidates':
            if set(request) - {'actor', 'owner', 'action', 'listing', 'job', 'offset', 'category'}:
                raise ValueError('Only agent candidate selections can be submitted')
            return {'ok': True, 'candidates': analysis_jobs.agent_candidates(STATE, request.get('job'),
                request['actor'], request.get('category'), request.get('offset', 0))}
        if set(request) - {'actor', 'owner', 'action', 'target', 'minutes', 'verify_google', 'listing', 'job', 'page', 'offset', 'per_page', 'filters'}:
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
                job = analysis_jobs.status(STATE, request.get('job'), request['actor'], request.get('page', 1), kind=kind, **page_args)
            else:
                job = analysis_jobs.cancel(STATE, request.get('job'), request['actor'], kind=kind)
            return {'ok': True, 'job': job}
        if request['action'] == 'log_scan_start':
            return {'ok': True, 'job': analysis_jobs.start(STATE, None, request['actor'],
                request.get('target'), request.get('minutes'), request.get('verify_google', False))}
        if request['action'] == 'log_scan_status':
            return {'ok': True, 'job': analysis_jobs.status(STATE, request.get('job'), request['actor'], request.get('page', 1), **page_args)}
        if request['action'] == 'log_scan_cancel':
            return {'ok': True, 'job': analysis_jobs.cancel(STATE, request.get('job'), request['actor'])}
        return {'ok': True, 'analysis': log_analysis.review(collect(), request.get('target'),
                request.get('minutes'), STATE, request.get('verify_google', False))}
    admin, owner = authorize(request)
    action = request.get('action')
    policy = validate(load('policy.json', DEFAULT))
    sites = collect()
    listing = request.get('listing', {})
    if (not isinstance(listing, dict) or set(listing) - {'bans_page','bans_view','domain_page','domain_view','wordpress_page','bans_per_page','wordpress_per_page'}):
        raise ValueError('Invalid IP-list selection')
    for scope in ('bans', 'domain'):
        ban_history.selection(listing.get(scope + '_page', 1), listing.get(scope + '_view', 'active'))
    ban_history.selection(listing.get('wordpress_page', 1))
    for scope in ('bans','wordpress'):
        list_sizes.size(listing.get(scope + '_per_page', 50))
    if action in ('access_save', 'access_account_save', 'access_defaults_save'):
        if set(request) - {'actor', 'owner', 'action', 'target', 'settings', 'password', 'listing', 'inherit', 'inherit_password'}:
            raise ValueError('Only domain access controls can be submitted')
        key = request.get('target')
        central = admin and owner == request['actor']
        if action == 'access_defaults_save':
            if not central:
                raise PermissionError('Only the administrator can change central access defaults')
        elif action == 'access_account_save':
            account(key)
            if not central and key != owner:
                raise PermissionError('Another account cannot be selected')
            if central and key != request['actor']:
                user = webuzo.users().get(key)
                if user is None or user['suspended']:
                    raise ValueError('Account is suspended or unavailable')
        else:
            known = {site['key']: site for site in sites if site.get('kind') != 'mail'}
            if key not in known or (not central and known[key]['owner'] != owner):
                raise PermissionError('This domain does not belong to the selected account')
            site = known[key]
            if not site['supported'] or site['suspended']:
                raise ValueError('This domain is suspended or unsupported')
        saved = access_settings()
        for flag in ('inherit', 'inherit_password'):
            if flag in request and type(request[flag]) is not bool:
                raise ValueError('Access inheritance switches must be booleans')
        collection = 'accounts' if action == 'access_account_save' else 'sites'
        if action != 'access_defaults_save' and request.get('inherit'):
            saved[collection].pop(key, None)
        else:
            entry = request.get('settings')
            if not isinstance(entry, dict) or set(entry) != set(access_protection.DEFAULT) - {'password_hash'}:
                raise ValueError('Invalid domain access controls')
            entry = copy.deepcopy(entry)
            previous = saved['defaults'] if action == 'access_defaults_save' else saved[collection].get(key, {})
            entry['password_hash'] = previous.get('password_hash', '')
            if action != 'access_defaults_save' and request.get('inherit_password'):
                entry['password_hash'] = ''
            if request.get('password'):
                entry['password_hash'] = access_protection.password_hash(request['password'])
            elif request.get('password') not in ('', None):
                raise ValueError('Invalid HTTP password')
            if action == 'access_defaults_save':
                saved['defaults'] = entry
            else:
                saved[collection][key] = entry
        apply(policy, sites, access=saved)
    elif action in ('geoip_update', 'geoip_save'):
        if not (admin and owner == request['actor']):
            raise PermissionError('Country database management requires the administrator context')
        if set(request) - {'actor', 'owner', 'action', 'account_id', 'license_key', 'automatic', 'listing'}:
            raise ValueError('Only country database settings can be submitted')
        raw = storage.read(STATE / country_database.CONFIG)
        config = json.loads(raw) if raw else {}
        config['account_id'] = request.get('account_id', '')
        if request.get('license_key'):
            config['license_key'] = request['license_key']
        if type(request.get('automatic')) is not bool:
            raise ValueError('Select the automatic country database update setting')
        config['automatic'] = request['automatic']
        config.setdefault('license_key', '')
        country_database.validate_config(config)
        if action == 'geoip_update':
            geography = country_database.download(config)
            apply(policy, sites, geography=geography)
        storage.replace(STATE / country_database.CONFIG, storage.json_bytes(config), 0o600)
    elif action == 'history_clear':
        scope = request.get('scope')
        if scope != 'global' or not (admin and owner == request['actor']):
            raise PermissionError('Only the administrator can clear global ban history')
        with auto_bans.database(STATE, create=False) as db:
            if db is not None:
                ban_history.clear(db, scope, owner=None if admin and owner == request['actor'] else owner)
    elif action == 'history_settings_save':
        ban_history.configure(STATE, request.get('days'))
        with auto_bans.database(STATE, create=False) as db:
            if db is not None:
                ban_history.maintain(STATE, db, force=True)
    elif action == 'wordpress_save':
        host_protection.client()
        if f2b_install.status(STATE)['state'] in ('queued', 'running'):
            raise ValueError('Wait for the Fail2ban installation to finish')
        if set(request) - {'actor', 'owner', 'action', 'settings', 'listing'}:
            raise ValueError('Only WordPress protection settings can be submitted')
        wordpress.apply(STATE, request.get('settings'), run)
    elif action == 'wordpress_unban':
        wordpress.unban(STATE, request.get('ips'), run)
    elif action == 'wordpress_status':
        pass
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
        policy = validate({**incoming, 'overrides': previous['overrides']})
        if incoming.get('schema') not in (9, 10, 11):
            policy['enumeration'] = previous['enumeration']
        if incoming.get('schema') not in (8, 9, 10, 11):
            for key in ('log_rejections', 'mail_protection'):
                policy[key] = previous[key]
            for key in ('exclude_static', 'min_distinct_paths'):
                policy['bans']['any_404'][key] = previous['bans']['any_404'][key]
        if incoming.get('schema') in (1, 2, 3, 4, 5, 6):
            policy['bans']['any_404'] = previous['bans']['any_404']
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
        host_protection.recover(STATE, run)
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
                result = synchronize(policy, sites, remove=action == ['remove-rules'])
            else:
                result = snapshot(policy, sites)
        else:
            result = dispatch(request)
    return {'ok': True, **result}
