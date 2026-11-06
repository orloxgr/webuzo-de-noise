"""Domain-only automatic bans. No native firewall mutation or user exceptions."""
import ipaddress
import json
from pathlib import Path
import time
from itertools import chain
import not_found
import ban_evidence
import ban_history

import auto_bans
from policy import site_mode
from probe_rules import token
import storage

APPLIED = 'domain-ban-applied.json'
CATEGORIES = {'domain-file': 'missing_files', 'domain-query': 'suspicious_queries', 'domain-404': 'any_404'}


def eligible(policy, sites):
    preferences = policy['domain_bans']['sites']
    return {site['key']: site for site in sites if site.get('kind') != 'mail' and site.get('supported') and not site.get('suspended')
            and site_mode(policy, site) == 'enforce' and any(preferences.get(site['key'], {}).values())}


def tables(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS domain_cursors (device INTEGER, inode INTEGER, offset INTEGER NOT NULL, PRIMARY KEY(device,inode));
        CREATE TABLE IF NOT EXISTS domain_strikes (site TEXT, ip TEXT, reason TEXT, token TEXT, stamp REAL);
        CREATE INDEX IF NOT EXISTS domain_strikes_lookup ON domain_strikes(site,ip,reason,stamp);
        CREATE TABLE IF NOT EXISTS domain_bans (site TEXT, ip TEXT, reason TEXT, created REAL, expires REAL,
            PRIMARY KEY(site,ip));
    ''')


def rows(state):
    with auto_bans.database(state, create=False) as db:
        if db is None or not db.execute("SELECT name FROM sqlite_master WHERE name='domain_bans'").fetchone():
            return []
        return [dict(row) for row in db.execute('SELECT * FROM domain_bans')]


def desired(policy, sites, state, now=None):
    now = time.time() if now is None else now
    known = eligible(policy, sites); result = {}
    for row in rows(state):
        key = row['site']; category = CATEGORIES.get(row['reason'])
        if (key not in known or not category or not policy['domain_bans']['sites'][key].get(category)
                or (row['expires'] and row['expires'] <= now)):
            continue
        address = str(ipaddress.ip_address(row['ip']))
        result.setdefault(key, {})[address] = {name: row[name] for name in ('reason', 'created', 'expires')}
    return result


def applied(state):
    raw = storage.read(Path(state) / APPLIED)
    return json.loads(raw) if raw is not None else {}


def report(policy, sites, state, owner=None, now=None, page=1, view='active'):
    ban_history.selection(page, view)
    now = time.time() if now is None else now
    known = {site['key'] for site in sites if owner is None or site['owner'] == owner}
    with auto_bans.database(state, create=False) as db:
        if db is None:
            return {'active': 0, 'pending': 0, 'rows': [], 'pagination': ban_history.pagination(0, page, view)}
        tables(db)
        # Configuration still needs all applied rules. Display rows/evidence are
        # selected in SQL with LIMIT; no Python list of every current ban.
        db.execute('CREATE TEMP TABLE hdn_applied (site TEXT,ip TEXT,reason TEXT,created REAL,expires REAL,PRIMARY KEY(site,ip))')
        for key, entries in applied(state).items():
            if key in known:
                db.executemany('INSERT INTO hdn_applied VALUES (?,?,?,?,?)',
                    ((key, ip, data['reason'], data['created'], data['expires']) for ip, data in entries.items()))
        db.execute('CREATE TEMP TABLE hdn_allowed (site TEXT PRIMARY KEY,missing_files INTEGER,suspicious_queries INTEGER,any_404 INTEGER)')
        eligible_keys = eligible(policy, sites)
        db.executemany('INSERT INTO hdn_allowed VALUES (?,?,?,?)',
            ((key, *(policy['domain_bans']['sites'][key].get(flag, False) for flag in ('missing_files','suspicious_queries','any_404')))
             for key in known if key in eligible_keys))
        cte = '''WITH wanted AS (
            SELECT b.* FROM domain_bans b JOIN hdn_allowed p ON p.site=b.site
            WHERE (b.expires=0 OR b.expires>?) AND
              ((b.reason='domain-file' AND p.missing_files) OR
               (b.reason='domain-query' AND p.suspicious_queries) OR (b.reason='domain-404' AND p.any_404))
        ), current AS (
            SELECT w.*,CASE WHEN EXISTS(SELECT 1 FROM hdn_applied a WHERE a.site=w.site AND a.ip=w.ip)
                THEN 'active' ELSE 'pending' END AS status FROM wanted w
            UNION ALL SELECT a.*,'removing' AS status FROM hdn_applied a
                WHERE NOT EXISTS(SELECT 1 FROM wanted w WHERE w.site=a.site AND w.ip=a.ip)
        ) '''
        counts = dict(db.execute(cte + 'SELECT status,COUNT(*) FROM current GROUP BY status', (now,)).fetchall())
        if view == 'history':
            visible, meta = ban_history.page(db, 'domain', owner=owner, number=page)
        else:
            meta = ban_history.pagination(sum(counts.values()), page)
            visible = [dict(row) for row in db.execute(cte + 'SELECT * FROM current ORDER BY created DESC,site,ip LIMIT ? OFFSET ?',
                       (now, ban_history.PAGE_SIZE, (meta['page'] - 1) * ban_history.PAGE_SIZE))]
            for row in visible:
                row['domain'] = row['site'].split('/', 1)[1]
                row['diagnostics'] = ban_evidence.lookup(db, row['ip'], row['created'], site=row['site'])
                if row['diagnostics'] is None and row['status'] == 'removing':
                    row['diagnostics'] = ban_history.pending_evidence(db, row['ip'], row['site'], row['created'])
    return {'active': counts.get('active', 0), 'pending': counts.get('pending', 0) + counts.get('removing', 0),
            'rows': visible, 'pagination': meta}


def synchronize(policy, sites, state, native, now=None):
    """Consume its own cursor; native global bans consume the same log separately."""
    now = time.time() if now is None else now
    known = eligible(policy, sites)
    if not known and not (Path(state) / 'bans.sqlite').exists():
        return
    by_domain = {site['domain']: key for key, site in known.items()}
    settings = policy['bans']; preferences = policy['domain_bans']['sites']
    with auto_bans.database(state) as db:
        tables(db)
        ban_history.finish_domains(db, applied(state), now)
        shared_rules = {name: settings[name] for name in CATEGORIES.values()}
        for key in known:
            signature = json.dumps([preferences[key], shared_rules], sort_keys=True)
            if auto_bans.get(db, 'domain-rules:'+key) != signature:
                db.execute('DELETE FROM domain_strikes WHERE site=?', (key,))
                auto_bans.put(db, 'domain-rules:'+key, signature)
        if known:
            db.execute('DELETE FROM domain_strikes WHERE site NOT IN ('+','.join('?' for _ in known)+')', tuple(known))
        else:
            db.execute('DELETE FROM domain_strikes')
        cutoff = now - max(settings[name]['findtime'] for name in CATEGORIES.values())
        db.execute('DELETE FROM domain_strikes WHERE stamp<?', (cutoff,))
        for row in db.execute('SELECT * FROM domain_bans').fetchall():
            category = CATEGORIES[row['reason']]
            if (row['site'] not in known or not preferences.get(row['site'], {}).get(category)
                    or (row['expires'] and row['expires'] <= now)):
                ban_history.stage(db, row, site=row['site'])
                db.execute('DELETE FROM domain_bans WHERE site=? AND ip=?', (row['site'], row['ip']))
        ignored = [ipaddress.ip_network(value) for value in settings['ignore_ips']]
        ignored.extend(native.exclusions() if known else [])
        own = native.own_ips() if known else set()

        def exempt(ip):
            return (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local
                    or str(ip) in own or any(ip in network for network in ignored))

        for row in db.execute('SELECT * FROM domain_bans').fetchall():
            if exempt(ipaddress.ip_address(row['ip'])):
                ban_history.stage(db, row, site=row['site'])
                db.execute('DELETE FROM domain_bans WHERE site=? AND ip=?', (row['site'], row['ip']))
        valid = {'domain-file': {token('f', value) for value in settings['missing_files']['paths']},
                 'domain-query': {token('q', value) for value in settings['suspicious_queries']['targets']},
                 'domain-404': {'-'}}
        sources = chain(auto_bans.events(db, 'domain_cursors'), not_found.events(db,
            [site for key, site in known.items() if preferences[key].get('any_404')], 'domain'))
        for stamp, address, host, reason, event_token, path, method in sources:
            if reason == 'not-found':
                reason = 'domain-404'
            key = by_domain.get(host); category = CATEGORIES.get(reason)
            if not key or not category or not preferences[key][category] or event_token not in valid[reason]:
                continue
            try:
                ip = ipaddress.ip_address(address); stamp = float(stamp)
            except ValueError:
                continue
            rule = settings[category]
            if not now-rule['findtime'] <= stamp <= now+5 or exempt(ip):
                continue
            if reason == 'domain-404':
                if not not_found.countable(rule, path):
                    continue
                event_token = token('n', not_found.normal_path(path))
            address = str(ip)
            if db.execute('SELECT ip FROM domain_bans WHERE site=? AND ip=?', (key, address)).fetchone():
                continue
            strike = db.execute('INSERT INTO domain_strikes (site,ip,reason,token,stamp) VALUES (?,?,?,?,?)',
                                (key, address, reason, event_token, stamp))
            ban_evidence.remember(db, 'domain', strike.lastrowid, address, key, reason, stamp, path, method)
            expression = 'COUNT(DISTINCT token)' if reason == 'domain-file' else 'COUNT(*)'
            if reason == 'domain-404':expression += ',COUNT(DISTINCT token)'
            counts = db.execute('SELECT '+expression+' FROM domain_strikes WHERE site=? AND ip=? AND reason=? AND stamp>=?',
                                (key, address, reason, now-rule['findtime'])).fetchone()
            count = counts[0]
            diverse = reason != 'domain-404' or counts[1] >= rule['min_distinct_paths']
            if count >= rule['maxretry'] and diverse:
                duration = rule['duration_days']
                evidence = ban_evidence.capture(db, address, reason, rule, count, now, site=key)
                db.execute('INSERT OR REPLACE INTO domain_bans (site,ip,reason,created,expires) VALUES (?,?,?,?,?)',
                           (key, address, reason, now, now+duration*86400 if duration else 0))
                ban_evidence.store(db, address, now, evidence, site=key)
                db.execute('DELETE FROM domain_strikes WHERE site=? AND ip=?', (key, address))
        ban_evidence.prune(db, domain=True)
        ban_history.maintain(state, db, now)
        # Store independent lifetimes for this scope, preserving creation time.
        for reason, category in CATEGORIES.items():
            duration = settings[category]['duration_days']
            if auto_bans.get(db, 'domain-duration:'+reason) != str(duration):
                db.execute('UPDATE domain_bans SET expires=CASE WHEN ?=0 THEN 0 ELSE created+? END WHERE reason=?',
                           (duration, duration*86400, reason))
                auto_bans.put(db, 'domain-duration:'+reason, duration)
        db.commit()
