"""Bounded log consumption and native Webuzo bans in the existing sync job."""
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from itertools import chain
import not_found
import ban_evidence
import ban_history
import storage
import log_files

from policy import site_mode
from probe_rules import reason_settings, token

CHAIN = 'DENOISE'
LOG = Path('/var/log/webuzo-de-noise/ban-events.log')


class DatabaseConnection(sqlite3.Connection):
    """Wait for real SQLite lock contention, without abandoning valid work."""
    def retry(self, method, *args, **kwargs):
        while True:
            try:
                return method(*args, **kwargs)
            except sqlite3.OperationalError as error:
                code = getattr(error, 'sqlite_errorcode', None)
                # Older supported distro Python versions expose the message
                # only. Extended SQLite result codes retain their primary
                # BUSY/LOCKED result in the low byte.
                busy = (code & 255 in (5, 6)) if isinstance(code, int) else str(error) in (
                    'database is locked', 'database table is locked', 'database schema is locked')
                if not busy:
                    raise
                time.sleep(.05)

    def execute(self, *args, **kwargs):
        return self.retry(super().execute, *args, **kwargs)

    def executescript(self, *args, **kwargs):
        return self.retry(super().executescript, *args, **kwargs)

    def commit(self):
        return self.retry(super().commit)


from web_bans import Native


@contextmanager
def database(state, create=True):
    path = Path(state) / 'bans.sqlite'
    if not create and not path.exists():
        yield None
        return
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Automatic-ban database must be a root-private regular file')
    finally:
        os.close(fd)
    connection = sqlite3.connect(path, timeout=0, factory=DatabaseConnection)
    connection.row_factory = sqlite3.Row
    try:
        app = connection.execute('PRAGMA application_id').fetchone()[0]
        if app not in (0, 0x48444E31) or (app == 0 and connection.execute('SELECT name FROM sqlite_master').fetchone()):
            raise ValueError('Refusing an unmanaged ban database')
        connection.executescript('''
            PRAGMA application_id=1212436017;
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cursors (device INTEGER, inode INTEGER, offset INTEGER NOT NULL, PRIMARY KEY(device,inode));
            CREATE TABLE IF NOT EXISTS strikes (ip TEXT, domain TEXT, reason TEXT, stamp REAL);
            CREATE INDEX IF NOT EXISTS strikes_time ON strikes(stamp);
            CREATE INDEX IF NOT EXISTS strikes_ip ON strikes(ip);
            CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, domain TEXT, reason TEXT,
                created REAL, expires REAL, status TEXT, error TEXT NOT NULL DEFAULT '');
        ''')
        if 'token' not in {row[1] for row in connection.execute('PRAGMA table_info(strikes)')}:
            connection.execute("ALTER TABLE strikes ADD COLUMN token TEXT NOT NULL DEFAULT ''")
        ban_evidence.tables(connection)
        ban_history.tables(connection)
        yield connection
        connection.commit()
    finally:
        connection.close()


def get(db, key, default=''):
    row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return row[0] if row else default


def put(db, key, value):
    db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, str(value)))


def events(db, cursor_table='cursors'):
    if cursor_table not in ('cursors', 'domain_cursors'):
        raise ValueError('Invalid event cursor namespace')
    for path in log_files.rotations(LOG):
        try:
            context = log_files.opened(path)
            stream, raw_stream = context.__enter__()
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(raw_stream.fileno())
            old = db.execute('SELECT offset FROM ' + cursor_table + ' WHERE device=? AND inode=?', (info.st_dev, info.st_ino)).fetchone()
            offset = old[0] if old and (log_files.compressed(path) or old[0] <= info.st_size) else 0
            stream.seek(offset)
            end = offset
            for raw in stream:
                if not log_files.compressed(path) and end + len(raw) > info.st_size:
                    break  # Appended data remains for the next cursor pass.
                if not raw.endswith(b'\n'):
                    break  # Leave an in-progress writer's line for the next pass.
                end += len(raw)
                record = ban_evidence.event(raw.decode('utf-8', errors='replace').rstrip('\r\n'))
                if record is not None:
                    yield record
            db.execute('INSERT OR REPLACE INTO ' + cursor_table + ' VALUES (?,?,?)', (info.st_dev, info.st_ino, end))
        finally:
            context.__exit__(None, None, None)


def report(state, enabled=False, page=1, view='active'):
    ban_history.selection(page, view)
    with database(state, create=False) as db:
        if db is None:
            return {'enabled': enabled, 'active': 0, 'pending': 0, 'rows': [], 'error': '', 'last_sync': '', 'unsupported_ipv6': 0,
                    'pagination': ban_history.pagination(0, page, view)}
        counts = dict(db.execute('SELECT status, COUNT(*) FROM bans GROUP BY status').fetchall())
        if view == 'history':
            rows, meta = ban_history.page(db, 'global', number=page)
        else:
            total = sum(counts.get(key, 0) for key in ('active', 'pending', 'removing'))
            meta = ban_history.pagination(total, page)
            rows = [dict(row) for row in db.execute("SELECT * FROM bans WHERE status IN ('active','pending','removing') ORDER BY created DESC,ip LIMIT ? OFFSET ?",
                    (ban_history.PAGE_SIZE, (meta['page'] - 1) * ban_history.PAGE_SIZE))]
            for row in rows:
                row['diagnostics'] = ban_evidence.lookup(db, row['ip'], row['created'])
                if row['diagnostics'] is None and row['status'] == 'removing':
                    row['diagnostics'] = ban_history.pending_evidence(db, row['ip'])
        return {'enabled': enabled, 'active': counts.get('active', 0),
                'pending': counts.get('pending', 0) + counts.get('removing', 0),
                'rows': rows,
                'error': get(db, 'error'), 'last_sync': get(db, 'last_sync'),
                'unsupported_ipv6': 0, 'previously_skipped_ipv6': int(get(db, 'ipv6', '0')), 'pagination': meta}


def synchronize(policy, sites, state, native, now=None, remove=False, read_events=True):
    now = time.time() if now is None else now
    settings = policy['bans']
    eligible = {site['domain'] for site in sites if site.get('supported') and not site.get('suspended') and
                site_mode(policy, site) == 'enforce' and (not settings['targets'] or site['key'] in settings['targets'])}
    enabled = settings['enabled'] and bool(eligible) and not remove
    if not enabled and not (Path(state) / 'bans.sqlite').exists():
        return report(state)
    if not enabled:
        skip_native = False
        with database(state, create=False) as db:
            if (db is not None and not get(db, 'chain_owned') and not db.execute(
                    "SELECT ip FROM bans WHERE status IN ('active','pending','removing') LIMIT 1").fetchone()):
                # Domain-only bans share storage, not the firewall backend.
                # Do not require iptables when no native work is owned/queued.
                for _ in events(db):
                    pass
                skip_native = True
        if skip_native:
            return report(state, False)
    with database(state) as db:
        try:
            with native.locked():
                exists, records, active = native.inspect()
                owned = get(db, 'chain_owned')
                if (exists or records) and not owned:
                    raise ValueError('DENOISE web-ban backend is not owned by this addon')
                ignored = [ipaddress.ip_network(value) for value in settings['ignore_ips']]
                ignored.extend(native.exclusions())
                self_ips = native.own_ips() if enabled else set()

                def exempt(address):
                    ip = ipaddress.ip_address(address)
                    return ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or address in self_ips or any(ip in network for network in ignored)

                # Reconcile native panel unbans before accepting new events.
                for row in db.execute("SELECT * FROM bans WHERE status='active'").fetchall():
                    if row['ip'] not in records and row['ip'] not in active:
                        ban_history.release(db, row, now)
                        db.execute("UPDATE bans SET status='released',created=?,error='' WHERE ip=?", (now, row['ip']))
                    elif ipaddress.ip_address(row['ip']).version == 6 and row['ip'] in records and row['ip'] not in active:
                        db.execute("UPDATE bans SET status='pending',error='' WHERE ip=?", (row['ip'],))
                    elif row['ip'] not in records or row['ip'] not in active:
                        raise ValueError('Native ban record and firewall disagree for ' + row['ip'])
                rules = reason_settings(settings)
                for reason, rule in rules.items():
                    duration = rule['duration_days']
                    if get(db, 'duration:' + reason) != str(duration):
                        db.execute("UPDATE bans SET expires=CASE WHEN ?=0 THEN 0 ELSE created+? END WHERE reason=? AND status IN ('active','pending')", (duration, duration * 86400, reason))
                        put(db, 'duration:' + reason, duration)
                # Do not let stale strikes from a removed rule/scope create a ban.
                fingerprint = json.dumps([rules, sorted(eligible)], sort_keys=True)
                if get(db, 'rules') != fingerprint:
                    db.execute('DELETE FROM strikes'); put(db, 'rules', fingerprint)
                if enabled:
                    cutoff = now - max([rule['findtime'] for rule in rules.values()] or [settings['findtime']])
                    db.execute('DELETE FROM strikes WHERE stamp<?', (cutoff,))
                    db.execute('DELETE FROM strikes WHERE domain NOT IN (' + ','.join('?' for _ in eligible) + ')', tuple(eligible))
                    valid_tokens = {'missing-file': {token('f', value) for value in settings['missing_files']['paths']},
                                    'suspicious-query': {token('q', value) for value in settings['suspicious_queries']['targets']}}
                    sources = chain(events(db), not_found.events(db,
                        [site for site in sites if site['domain'] in eligible and site.get('kind') != 'mail'], 'native')
                        if settings['any_404']['enabled'] else []) if read_events else []
                    for stamp, address, domain, reason, event_token, path, method in sources:
                        try:
                            stamp, ip = float(stamp), ipaddress.ip_address(address)
                        except ValueError:
                            continue
                        rule = rules.get(reason)
                        if (not rule or not now - rule['findtime'] <= stamp <= now + 5
                                or domain not in eligible or exempt(str(ip))
                                or (reason in valid_tokens and event_token not in valid_tokens[reason])):
                            continue
                        if reason == 'not-found':
                            if any(site.get('kind') == 'mail' and site['domain'] == domain for site in sites):
                                continue
                            if not not_found.countable(rule, path):
                                continue
                            event_token = token('n', not_found.normal_path(path))
                        address = str(ip)
                        previous = db.execute('SELECT * FROM bans WHERE ip=?', (address,)).fetchone()
                        if previous and (previous['status'] in ('active', 'pending', 'removing') or previous['created'] >= stamp):
                            continue
                        strike = db.execute('INSERT INTO strikes (ip,domain,reason,stamp,token) VALUES (?,?,?,?,?)',
                                            (address, domain, reason, stamp, event_token))
                        ban_evidence.remember(db, 'global', strike.lastrowid, address, domain, reason, stamp, path, method)
                        diverse = True
                        if reason == 'not-found':
                            count, paths = db.execute('SELECT COUNT(*),COUNT(DISTINCT token) FROM strikes WHERE ip=? AND reason=? AND stamp>=?',
                                (address, reason, now-rule['findtime'])).fetchone()
                            diverse = paths >= rule['min_distinct_paths']
                        elif reason == 'missing-file':
                            count = db.execute('SELECT COUNT(DISTINCT token) FROM strikes WHERE ip=? AND reason=? AND stamp>=?',
                                               (address, reason, now-rule['findtime'])).fetchone()[0]
                        elif reason == 'suspicious-query':
                            count = db.execute('SELECT COUNT(*) FROM strikes WHERE ip=? AND reason=? AND stamp>=?',
                                               (address, reason, now-rule['findtime'])).fetchone()[0]
                        else:
                            count = db.execute("SELECT COUNT(*) FROM strikes WHERE ip=? AND reason IN ('private-file','repository') AND stamp>=?",
                                               (address, now-rule['findtime'])).fetchone()[0]
                        if count >= rule['maxretry'] and diverse:
                            duration = rule['duration_days']
                            evidence = ban_evidence.capture(db, address, reason, rule, count, now)
                            db.execute('INSERT OR REPLACE INTO bans (ip,domain,reason,created,expires,status,error) VALUES (?,?,?,?,?,?,?)',
                                       (address, domain, reason, now, now + duration * 86400 if duration else 0, 'pending', ''))
                            ban_evidence.store(db, address, now, evidence)
                            db.execute('DELETE FROM strikes WHERE ip=?', (address,))
                else:
                    for _ in events(db):
                        pass
                    db.execute('DELETE FROM strikes')
                ban_evidence.prune(db)
                put(db, 'enabled', int(enabled))
                for row in db.execute("SELECT * FROM bans WHERE status IN ('active','pending')").fetchall():
                    if not enabled or row['reason'] not in rules or row['domain'] not in eligible or exempt(row['ip']) or (row['expires'] and row['expires'] <= now):
                        if row['ip'] not in records and row['ip'] not in active:
                            ban_history.release(db, row, now)
                        db.execute("UPDATE bans SET status=?,error='' WHERE ip=?", ('removing' if row['ip'] in records or row['ip'] in active else 'released', row['ip']))
                db.commit()  # Native mutations remain resumable after interruption.
                pending = db.execute("SELECT * FROM bans WHERE status IN ('pending','removing') ORDER BY status DESC,created").fetchall()
                if any(row['status'] == 'pending' for row in pending) and not exists:
                    put(db, 'chain_owned', 'creating'); db.commit()
                    native.create()
                    exists, records, active = native.inspect()
                    if not exists:
                        raise RuntimeError('Webuzo did not create the web-ban backend')
                    put(db, 'chain_owned', '1'); db.commit()
                failures = []
                for row in pending:
                    address = row['ip']
                    try:
                        if row['status'] == 'pending':
                            if address not in records or address not in active:
                                native.add(address)
                            _, records, active = native.inspect()
                            if address not in records or address not in active:
                                raise RuntimeError('Webuzo did not apply the web ban')
                            db.execute("UPDATE bans SET status='active',error='' WHERE ip=?", (address,))
                        else:
                            if address in records or address in active:
                                native.remove(address)
                            _, records, active = native.inspect()
                            if address in records or address in active:
                                raise RuntimeError('Webuzo did not remove the web ban')
                            ban_history.release(db, row, now)
                            db.execute("UPDATE bans SET status='released',created=?,error='' WHERE ip=?", (now, address))
                        db.commit()
                    except Exception as error:
                        db.execute('UPDATE bans SET error=? WHERE ip=?', (str(error), address)); db.commit()
                        failures.append(address + ': ' + str(error))
                        # Other independent bans must still be attempted.
                        continue
                if remove and owned:
                    if records or active:
                        remaining = db.execute("SELECT COUNT(*) FROM bans WHERE status IN ('active','pending','removing')").fetchone()[0]
                        if not remaining:
                            raise RuntimeError('Untracked bans remain in the native DENOISE chain; refusing to delete them')
                    else:
                        native.drop_chain()
                        put(db, 'chain_owned', '')
                put(db, 'error', '\n'.join(failures))
                put(db, 'last_sync', now)
                ban_history.maintain(state, db, now)
                db.commit()
        except Exception as error:
            put(db, 'error', str(error)); db.commit()
    return report(state, enabled)


def unban(state, native, addresses, now=None):
    now = time.time() if now is None else now
    with database(state, create=False) as db:
        if db is None:
            return
        selected = [row[0] for row in db.execute("SELECT ip FROM bans WHERE status IN ('active','pending','removing')")] if addresses == 'all' else addresses
        if not isinstance(selected, list):
            raise ValueError('Select valid addon-owned IP bans')
        if addresses != 'all' and not selected:
            raise ValueError('Select at least one De-Noise IP to unban')
        for value in selected:
            ipaddress.ip_address(value)
            if not db.execute("SELECT ip FROM bans WHERE ip=? AND status IN ('active','pending','removing')", (value,)).fetchone():
                raise ValueError('This IP is not an active De-Noise ban: ' + value)
        if selected and not get(db, 'chain_owned'):
            raise ValueError('De-Noise does not own this web-ban backend')
        for address in selected:
            ban_history.stage(db, db.execute('SELECT * FROM bans WHERE ip=?', (address,)).fetchone())
            db.execute("UPDATE bans SET status='removing',created=? WHERE ip=?", (now, address))
            db.execute('DELETE FROM strikes WHERE ip=?', (address,))
        db.commit()


def cleanup(policy, sites, state, native, timeout=None):
    while True:
        result = synchronize(policy, sites, state, native, remove=True, read_events=False)
        if result.get('error'):
            raise RuntimeError('Could not remove addon web bans: ' + result['error'])
        if not result['active'] and not result['pending']:
            return result
