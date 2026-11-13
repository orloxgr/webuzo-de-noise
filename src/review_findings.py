"""Report filters and root-private review notes, independent of protection policy."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import php_findings
import storage

FEATURES = {**php_findings.TAGS, 'security': 'Secret-file probe', 'errors': 'Server errors',
            'rejected': 'Rejected requests', 'technical': 'Technical task',
            'frontend': 'Frontend diagnostics', 'crawl': 'Crawl / URL parameters',
            'asset': 'Missing asset', 'activity': 'Application activity'}
DEFAULTS = dict(domain='all', priority='all', feature='all', review='visible', query='', min_hits=0, min_domains=0, group_rejected=True)


def filters(value=None):
    if value is None:
        return dict(DEFAULTS)
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError('Invalid finding filters')
    result = {**DEFAULTS, **value}
    for key, allowed in [('priority', ('all', 'high', 'normal', 'low')),
                         ('feature', ('all', *FEATURES)),
                         ('review', ('visible', 'all', 'open', 'reviewed', 'ignored'))]:
        if not isinstance(result[key], str) or result[key] not in allowed:
            raise ValueError('Invalid finding ' + key + ' filter')
    from policy import domain
    if result['domain'] != 'all':
        domain(result['domain'])
    if not isinstance(result['query'], str) or len(result['query']) > 2048 or any(ord(c) < 32 for c in result['query']):
        raise ValueError('Invalid path search')
    for key in ('min_hits', 'min_domains'):
        if type(result[key]) is not int or result[key] < 0:
            raise ValueError('Choose a nonnegative ' + key.replace('_', ' '))
    if type(result['group_rejected']) is not bool:
        raise ValueError('Invalid rejected-probe grouping selection')
    return result


def identity(kind, domain, path):
    return hashlib.sha256(json.dumps([kind, domain, path], ensure_ascii=True).encode()).hexdigest()


def notes(state):
    raw = storage.read(Path(state) / 'review-notes.json')
    data = json.loads(raw) if raw else {}
    if not isinstance(data, dict):
        raise ValueError('Invalid saved review notes')
    return data


@contextmanager
def note_lock(state):
    import fcntl
    path = Path(state) / 'review-notes.lock'
    with storage.parent(path) as parent:
        fd = os.open(path.name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o077:
            raise ValueError('Untrusted review notes lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def mark(state, actor, kind, domain, path, value):
    if kind not in ('scan', 'php_files') or value not in ('open', 'reviewed', 'ignored'):
        raise ValueError('Invalid review note')
    with note_lock(state):
        data = notes(state)
        key = identity(kind, domain, path)
        if value == 'open':
            data.pop(key, None)
        else:
            data[key] = dict(state=value, actor=actor, time=time.time())
        storage.replace(Path(state) / 'review-notes.json', storage.json_bytes(data), 0o600)


def scan_info(row):
    tags, priority, reasons = [], 'normal', []
    statuses, count, path = row.get('statuses', {}), row.get('count', 0), row.get('path', '')
    if row.get('kind') == 'security':
        tags.append('security'); priority = 'high'
        reasons.append('A secret-file probe signature matched. A status code alone does not show whether contents were exposed.')
    if any(str(code).startswith('5') and n for code, n in statuses.items()):
        tags.append('errors'); priority = 'high'
        reasons.append('Server errors were recorded. Application protection can also generate these statuses; correlate error logs.')
    rejected = sum(statuses.get(code, 0) for code in ('401', '403', '429'))
    if rejected:
        tags.append('rejected')
        reasons.append('%d rejected responses recorded; the HTTP status does not identify which protection produced them.' % rejected)
    if 'author' in row.get('parameters', []):
        reasons.append('Author-ID discovery requests: check enumeration protection before diagnosing a homepage failure.')
    if re.search(r'/(?:wp-cron\.php|wp-json/ultracache/v1/media/background-worker)$', path): tags.append('technical')
    if path.rstrip('/') == '/wp-json/ultracache/v1/errors/frontend':
        tags.append('frontend')
        reasons.append('HTTP 200 means a browser diagnostic was accepted, not that the page worked correctly.')
    if row.get('kind') == 'crawl': tags.append('crawl')
    if 'asset' in row.get('title', '').lower(): tags.append('asset')
    if not tags: tags.append('activity')
    if statuses and rejected == count and 'errors' not in tags: priority = 'low'
    elif 'technical' in tags and priority != 'high': priority = 'low'
    return dict(priority=priority, priority_label={'high': 'High review priority', 'normal': 'Review context', 'low': 'Lower review priority'}[priority],
                tags=tags, reason=' '.join(reasons) or 'Review the route, declared agents and application work.')


def prepare(row, kind):
    row = copy.deepcopy(row)
    if kind == 'php_files':
        if row.get('members'):
            row['members'] = [prepare(r, kind) for r in row['members']]
            row['php_info'] = dict(label='Repeated directory path group', reason='Open exact paths to review each interpretation. Grouping never creates a wildcard rule.')
        else:
            row['php_info'] = php_findings.describe(row['value'], row.get('candidate'), row)
        row['review_info'] = row['php_info']
    else:
        row['review_info'] = scan_info(row)
    return row


def domains(row, kind):
    return row.get('domains', []) if kind == 'php_files' else [dict(domain=row['domain'], count=row.get('count', 0))]


def view(row, kind, chosen, saved):
    """Filter exact members/domain contributions before grouping or pagination."""
    row = prepare(row, kind)
    if kind == 'php_files' and row.get('members'):
        members = [value for r in row['members'] if (value := view(r, kind, chosen, saved)) is not None]
        if not members: return None
        row['members'] = members
        row['count'] = sum(r['count'] for r in members)
        from collections import Counter
        totals = Counter()
        for r in members:
            for d in r['domains']: totals[d['domain']] += d['count']
        row['domains'] = [dict(domain=d, count=n) for d,n in sorted(totals.items(), key=lambda x: (-x[1], x[0]))]
        row['review_info'] = dict(priority=min((r['review_info']['priority'] for r in members), key=lambda x: ('high','normal','low').index(x)),
                                 priority_label='Exact paths have individual priorities', tags=sorted({t for r in members for t in r['review_info']['tags']}),
                                 reason='The group contains only exact paths matching the current filters.')
        row.pop('agents', None); row.pop('clients', None)
        return row
    path = row['value'] if kind == 'php_files' else row['path']
    contributions, marks = [], []
    for d in domains(row, kind):
        if chosen['domain'] != 'all' and d['domain'] != chosen['domain']: continue
        state = saved.get(identity(kind, d['domain'], path), {}).get('state', 'open')
        if chosen['review'] == 'visible' and state == 'ignored': continue
        if chosen['review'] not in ('all', 'visible') and state != chosen['review']: continue
        contributions.append(d); marks.append(dict(domain=d['domain'], state=state))
    if not contributions: return None
    info = row['review_info']
    if chosen['priority'] != 'all' and info.get('priority') != chosen['priority']: return None
    if chosen['feature'] != 'all' and chosen['feature'] not in info.get('tags', []): return None
    if chosen['query'].casefold() not in path.casefold(): return None
    if sum(d['count'] for d in contributions) < chosen['min_hits'] or len(contributions) < chosen['min_domains']: return None
    row['review_marks'] = marks
    if kind == 'php_files':
        row['domains'] = contributions; row['count'] = sum(d['count'] for d in contributions)
        row['evidence_scope'] = 'Client and agent evidence covers this exact path across the original reviewed domains.'
    return row
