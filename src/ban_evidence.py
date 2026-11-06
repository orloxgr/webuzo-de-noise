"""Bounded ban evidence, with paths only and no query/header/cookie storage."""
import json
import re
from urllib.parse import urlsplit



def path_only(value):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return ''
    value = value.split('?', 1)[0].split('#', 1)[0]
    if value.startswith(('http://', 'https://')):
        try:
            value = urlsplit(value).path
        except ValueError:
            return ''
    return value if value.startswith('/') else ''


def method_only(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Z]{1,16}', value) else ''


def event(line):
    """Read both new escaped JSON records and the four/five-field legacy log."""
    if line.startswith('{'):
        try:
            row = json.loads(line)
            if not isinstance(row, dict) or row.get('v') != 1:
                return None
            values = [row.get(k) for k in ('ts', 'ip', 'domain', 'reason', 'token')]
            if any(not isinstance(v, str) for v in values):
                return None
            return (*values, path_only(row.get('path')), method_only(row.get('method')))
        except ValueError:
            return None
    values = line.split()
    if len(values) in (4, 5):
        return (*(values if len(values) == 5 else values + ['-']), '', '')
    return None


def tables(db):
    # Keep old table shapes intact: previous releases insert positional rows.
    # An installer rollback must still be able to run the previous code.
    db.executescript('''
        CREATE TABLE IF NOT EXISTS strike_evidence (
            scope TEXT, row_id INTEGER, ip TEXT, stamp REAL, domain TEXT, reason TEXT,
            path TEXT, method TEXT, PRIMARY KEY(scope,row_id));
        CREATE TABLE IF NOT EXISTS ban_diagnostics (
            scope TEXT, scope_key TEXT, ip TEXT, created REAL, details TEXT,
            PRIMARY KEY(scope,scope_key,ip));
    ''')


def remember(db, scope, row_id, ip, domain, reason, stamp, path, method):
    db.execute('INSERT OR REPLACE INTO strike_evidence VALUES (?,?,?,?,?,?,?,?)',
               (scope, row_id, ip, stamp, domain, reason, path_only(path), method_only(method)))


def store(db, address, created, raw, site=None):
    db.execute('INSERT OR REPLACE INTO ban_diagnostics VALUES (?,?,?,?,?)',
               ('domain' if site is not None else 'global', site or '', address, created, raw))


def lookup(db, address, created, site=None):
    row = db.execute('SELECT details FROM ban_diagnostics WHERE scope=? AND scope_key=? AND ip=? AND created=?',
                     ('domain' if site is not None else 'global', site or '', address, created)).fetchone()
    return decoded(row[0]) if row else None


def prune(db, domain=False):
    scope = 'domain' if domain else 'global'
    strikes = 'domain_strikes' if domain else 'strikes'
    bans = 'domain_bans' if domain else 'bans'
    key = 's.site' if domain else 's.domain'
    db.execute('DELETE FROM strike_evidence WHERE scope=? AND NOT EXISTS (SELECT 1 FROM ' + strikes +
               ' s WHERE s.rowid=strike_evidence.row_id AND s.ip=strike_evidence.ip AND s.stamp=strike_evidence.stamp AND ' +
               key + '=strike_evidence.domain AND s.reason=strike_evidence.reason)', (scope,))
    key_match = ' AND b.site=ban_diagnostics.scope_key' if domain else ''
    db.execute('DELETE FROM ban_diagnostics WHERE scope=? AND NOT EXISTS (SELECT 1 FROM ' + bans +
               ' b WHERE b.ip=ban_diagnostics.ip AND b.created=ban_diagnostics.created' + key_match + ')', (scope,))


def capture(db, address, reason, rule, count, now, site=None):
    table = 'domain_strikes' if site is not None else 'strikes'
    where = 's.ip=? AND s.stamp>=?'
    args = [address, now - rule['findtime']]
    if site is not None:
        where += ' AND s.site=?'; args.append(site)
    if reason in ('private-file', 'repository'):
        where += " AND s.reason IN ('private-file','repository')"
    else:
        where += ' AND s.reason=?'; args.append(reason)
    domain = 'site' if site is not None else 'domain'
    rows = db.execute('SELECT s.stamp,s.' + domain + ',s.reason,e.path,e.method FROM ' + table +
                      ' s LEFT JOIN strike_evidence e ON e.scope=? AND e.row_id=s.rowid AND e.ip=s.ip'
                      ' AND e.stamp=s.stamp AND e.domain=s.' + domain + ' AND e.reason=s.reason'
                      ' WHERE ' + where + ' ORDER BY s.stamp DESC,s.rowid DESC',
                      ('domain' if site is not None else 'global', *args, )).fetchall()
    samples = [dict(at=r[0], domain=r[1].split('/', 1)[1] if site is not None else r[1],
                    reason=r[2], path=path_only(r[3]), method=method_only(r[4])) for r in reversed(rows)]
    details = dict(v=1, count=count, maxretry=rule['maxretry'], findtime=rule['findtime'],
                   duration_days=rule['duration_days'], samples=samples)
    if reason in ('not-found', 'domain-404'):
        details.update(min_distinct_paths=rule['min_distinct_paths'], exclude_static=rule['exclude_static'])
    return json.dumps(details, separators=(',', ':'))


def decoded(raw):
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('v') != 1:
            return None
        if any(type(data.get(k)) is not int for k in ('count', 'maxretry', 'findtime', 'duration_days')):
            return None
        samples = data.get('samples')
        if not isinstance(samples, list):
            return None
        for sample in samples:
            if not isinstance(sample, dict):
                return None
            sample['path'] = path_only(sample.get('path'))
            sample['method'] = method_only(sample.get('method'))
        return data
    except (TypeError, ValueError):
        return None
