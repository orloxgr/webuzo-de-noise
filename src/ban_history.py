"""Paged ban history, independent of live firewall rules and strike counters."""
import json
import math
from pathlib import Path
import time

import ban_evidence
import storage
import listing

PAGE_SIZE = 50
SETTINGS = 'history-settings.json'


def settings(state):
    raw = storage.read(Path(state) / SETTINGS)
    value = json.loads(raw) if raw is not None else {'days': 30}
    if not isinstance(value, dict) or set(value) != {'days'} or type(value['days']) is not int or not value['days'] >= 1:
        raise ValueError('History retention must be a positive number of days')
    return value


def configure(state, days):
    if type(days) is not int or not days >= 1:
        raise ValueError('History retention must be a positive number of days')
    storage.replace(Path(state) / SETTINGS, storage.json_bytes({'days': days}), 0o600)


def tables(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS ban_history (
            id INTEGER PRIMARY KEY, scope TEXT NOT NULL, scope_key TEXT NOT NULL,
            ip TEXT NOT NULL, domain TEXT NOT NULL, reason TEXT NOT NULL,
            created REAL NOT NULL, expires REAL NOT NULL, ended REAL,
            details TEXT, UNIQUE(scope,scope_key,ip,created));
        CREATE INDEX IF NOT EXISTS ban_history_scope_time ON ban_history(scope,ended DESC,id DESC);
        CREATE INDEX IF NOT EXISTS ban_history_owner_time ON ban_history(scope,scope_key,ended DESC);
        CREATE INDEX IF NOT EXISTS bans_status_created ON bans(status,created DESC,ip);
    ''')
    # Seed old completed rows once; clearing history must not rediscover them.
    if not db.execute("SELECT 1 FROM meta WHERE key='history-seeded'").fetchone():
        db.execute('''INSERT OR IGNORE INTO ban_history
            (scope,scope_key,ip,domain,reason,created,expires,ended)
            SELECT 'global','',ip,domain,reason,created,expires,created FROM bans WHERE status='released' ''')
        db.execute("INSERT INTO meta VALUES ('history-seeded','1')")


def stage(db, row, site=None):
    """Keep original timestamps/evidence before live removal mutates its record."""
    scope, key = ('global', '') if site is None else ('domain', site)
    row = dict(row)
    if site is None and db.execute("SELECT 1 FROM ban_history WHERE scope='global' AND ip=? AND ended IS NULL", (row['ip'],)).fetchone():
        return
    details = ban_evidence.lookup(db, row['ip'], row['created'], site=site)
    db.execute('''INSERT OR IGNORE INTO ban_history
        (scope,scope_key,ip,domain,reason,created,expires,details) VALUES (?,?,?,?,?,?,?,?)''',
        (scope, key, row['ip'], key.split('/', 1)[1] if site is not None else row['domain'],
         row['reason'], row['created'], row['expires'], json.dumps(details) if details else None))


def release(db, row, now):
    # Explicit unban changes the core timestamp to suppress replay. Its staged
    # record retains the real creation time; leave the core behavior unchanged.
    pending = db.execute("SELECT id FROM ban_history WHERE scope='global' AND ip=? AND ended IS NULL",
                         (row['ip'],)).fetchone()
    if pending is None:
        stage(db, row)
    db.execute("UPDATE ban_history SET ended=? WHERE scope='global' AND ip=? AND ended IS NULL", (now, row['ip']))


def pending_evidence(db, address, site=None, created=None):
    scope, key = ('global', '') if site is None else ('domain', site)
    where, args = 'scope=? AND scope_key=? AND ip=? AND ended IS NULL', [scope, key, address]
    if site is not None:
        where += ' AND created=?'; args.append(created)
    row = db.execute('SELECT details FROM ban_history WHERE '+where+' ORDER BY id DESC LIMIT 1', args).fetchone()
    return ban_evidence.decoded(row[0]) if row else None


def finish_domains(db, applied, now):
    for row in db.execute("SELECT id,scope_key,ip,created FROM ban_history WHERE scope='domain' AND ended IS NULL").fetchall():
        live = applied.get(row['scope_key'], {}).get(row['ip'])
        if not live or live['created'] != row['created']:
            db.execute('UPDATE ban_history SET ended=? WHERE id=?', (now, row['id']))


def maintain(state, db, now=None, force=False):
    now = time.time() if now is None else now
    last = db.execute("SELECT value FROM meta WHERE key='history-pruned'").fetchone()
    if not force and last and now - float(last[0]) < 86400:
        return
    cutoff = now - settings(state)['days'] * 86400
    db.execute('DELETE FROM ban_history WHERE ended IS NOT NULL AND ended<?', (cutoff,))
    # Finished core rows are replay barriers, not live bans. Retain at least the
    # largest supported strike window (one day), even with short UI retention.
    db.execute("DELETE FROM bans WHERE status='released' AND created<?", (min(cutoff, now - 86400),))
    ban_evidence.prune(db)
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='domain_bans'").fetchone():
        ban_evidence.prune(db, domain=True)
    db.execute("INSERT OR REPLACE INTO meta VALUES ('history-pruned',?)", (str(now),))


def selection(page=1, view='active'):
    if type(page) is not int or not page >= 1 or view not in ('active', 'history'):
        raise ValueError('Invalid IP-list page or view')
    return page, view


def pagination(total, page=1, view='active', per_page=PAGE_SIZE):
    selection(page, view)
    return {**listing.pagination(total, page, per_page), 'view': view}


def page(db, scope, owner=None, number=1, per_page=PAGE_SIZE):
    selection(number, 'history')
    where, args = 'scope=? AND ended IS NOT NULL', [scope]
    if owner is not None:
        if scope != 'domain':
            raise PermissionError('Global ban history is administrator-only')
        where += ' AND scope_key GLOB ?'; args.append(owner + '/*')
    total = db.execute('SELECT COUNT(*) FROM ban_history WHERE ' + where, args).fetchone()[0]
    meta = pagination(total, number, 'history', per_page)
    rows = []
    for item in db.execute('SELECT * FROM ban_history WHERE ' + where + ' ORDER BY ended DESC,id DESC LIMIT ? OFFSET ?',
                           (*args, *listing.bounds(meta))):
        row = dict(item)
        row.update(site=row['scope_key'], status='released', error='', diagnostics=ban_evidence.decoded(row.pop('details')))
        rows.append(row)
    return rows, meta


def clear(db, scope, owner=None):
    if scope not in ('global', 'domain') or (owner is not None and scope != 'domain'):
        raise PermissionError('Invalid history scope')
    where, args = 'scope=? AND ended IS NOT NULL', [scope]
    if owner is not None:
        where += ' AND scope_key GLOB ?'; args.append(owner + '/*')
    # Open removal records, live bans, evidence, counters, cursors and the
    # independent Fail2ban repeat-offender database are deliberately untouched.
    return db.execute('DELETE FROM ban_history WHERE ' + where, args).rowcount
