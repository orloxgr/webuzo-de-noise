"""Exact administrator-selected paths: ban only after a real final HTTP 404."""
import hashlib
import json
import math
from urllib.parse import unquote

DEFAULT = dict(enabled=False, paths=[], targets=[], duration_seconds=86400, maxretry=1, findtime=300)
REASON = 'endpoint-404-list'


def validate(settings, target):
    if not isinstance(settings, dict) or set(settings) != set(DEFAULT):
        raise ValueError('Invalid selected endpoint 404 settings')
    if type(settings['enabled']) is not bool or type(settings['duration_seconds']) is not int or settings['duration_seconds'] < 0:
        raise ValueError('Selected 404 ban duration must be nonnegative; 0 = permanent')
    if any(type(settings[k]) is not int or settings[k] < 1 for k in ('maxretry', 'findtime')):
        raise ValueError('Selected 404 attempts and counting window must be positive whole numbers')
    if not isinstance(settings['paths'], list) or not isinstance(settings['targets'], list):
        raise ValueError('Use an exact path list and domain selections')
    for path in settings['paths']:
        if (not isinstance(path, str) or not path.startswith('/') or '?' in path or '#' in path
                or any(ord(c) < 32 or ord(c) == 127 for c in unquote(path))):
            raise ValueError('404 selections must be exact paths without query strings or control characters')
    settings['paths'] = list(dict.fromkeys(settings['paths']))
    settings['targets'] = list(dict.fromkeys(target(value) for value in settings['targets']))


def fingerprint(settings, domains):
    return hashlib.sha256(json.dumps([settings['enabled'], settings['paths'], sorted(domains), settings.get('maxretry', 1), settings.get('findtime', 300)]).encode()).hexdigest() if domains else ''


def prepare_counts(db, now, window, reset=False):
    # Both log layers can record the same request. Keep source multiplicities,
    # rather than counting their sum or collapsing real same-second repeats.
    db.execute('CREATE TABLE IF NOT EXISTS selected404_sources (key TEXT PRIMARY KEY, stamp INTEGER, structured INTEGER, native INTEGER, counted INTEGER)')
    db.execute('DELETE FROM selected404_sources' if reset else 'DELETE FROM selected404_sources WHERE stamp<?',
               () if reset else (int(now-window),))


def count_once(db, row, source):
    stamp, address, domain, reason, token, path, method = row
    second = int(float(stamp))
    key = hashlib.sha256(json.dumps([second,address,domain,unquote(path),method], ensure_ascii=False).encode()).hexdigest()
    current = db.execute('SELECT structured,native,counted FROM selected404_sources WHERE key=?', (key,)).fetchone()
    structured, native, counted = tuple(current) if current else (0,0,0)
    if source == 'structured': structured += 1
    else: native += 1
    total = max(structured, native)
    db.execute('INSERT OR REPLACE INTO selected404_sources VALUES (?,?,?,?,?)', (key,second,structured,native,total))
    return total > counted


def expand(records, settings, domains, start, db=None):
    selected = {unquote(path) for path in settings['paths']}
    for row in records:
        stamp, address, domain, reason, token, path, method = row
        try: recent = math.isfinite(float(stamp)) and float(stamp) >= start
        except (ValueError, TypeError): recent = False
        matches = domain in domains and unquote(path) in selected and recent
        if reason == REASON:
            if matches and (db is None or count_once(db, row, 'structured')): yield row
            continue
        if reason == 'not-found' and matches:
            if db is None or count_once(db, row, 'native'):
                yield stamp, address, domain, REASON, 'selected-404', path, method
        yield row


def compile_maps(settings, sites, scope_map, exact_uri_pattern, event_format):
    lines = scope_map('hdn_endpoint404_site', settings, sites)
    lines += ['map $uri $hdn_endpoint404_path {', '    default 0;']
    for path in settings['paths']:
        lines += ['    ' + exact_uri_pattern(unquote(path)) + ' 1;']
    lines += ['}', 'map "$hdn_mode:$hdn_endpoint404_site:$hdn_endpoint404_path:$status" $hdn_endpoint404_log {',
              '    default 0;', '    enforce:1:1:404 1;', '}',
              event_format('hdn_endpoint404_bans', REASON, 'selected-404')]
    return lines
