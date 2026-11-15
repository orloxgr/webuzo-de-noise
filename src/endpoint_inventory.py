"""Read-only, disk-backed evidence for endpoint suggestions, including successes."""
import hashlib
import json
import re
import secrets
import sqlite3
import tempfile
from pathlib import Path
from urllib.parse import unquote

import agent_catalog
from collections import Counter

# Candidate discovery only. These expressions never become active protection.
BACKUP = re.compile(r'\.(?:sql|sqlite3?)(?:\.(?:gz|zip|zst|bz2|xz))?$|'
                    r'(?:^|/)(?:bak|backup|dump|database|db|site|www|web|public_html|wp-content|wp-config)'
                    r'(?:[-_.][^/]*)?\.(?:zip|tar(?:\.(?:gz|bz2|xz|zst))?|tgz|gz|zst|7z|rar|bak|old)$', re.I)
SECRET = re.compile(r'(?:^|/)\.(?:env(?:[./]|$)|git(?:/|$)|svn(?:/|$)|hg(?:/|$))', re.I)


def family(path):
    if re.search(r'(?:^|/)wp-config(?:\.php)?\.(?:old|bak|backup|orig|save|swp)$', path, re.I):
        return 'WordPress configuration backup'
    if SECRET.search(path):
        return 'Secret / repository path'
    if re.search(r'\.(?:sql|sqlite3?)(?:\.(?:gz|zip|zst|bz2|xz))?$', path, re.I):
        return 'Database dump filename'
    if BACKUP.search(path):
        return 'Backup archive filename'
    if re.search(r'\.(?:m?js|cjs)$', path, re.I): return 'JavaScript'
    if re.search(r'\.css$', path, re.I): return 'Stylesheet'
    if re.search(r'\.php(?:/|$)', path, re.I): return 'PHP path'
    from log_analysis import ASSET
    return 'Other static file' if ASSET.search(path) else 'Application / other path'


def decorate(row):
    """A specific next action, without treating a 404 or a browser string as proof."""
    row = dict(row)
    path = unquote(row['path']); category = family(path); statuses = row['statuses']
    missing = statuses.get('404', 0)
    successful = sum(n for code,n in statuses.items() if code.startswith(('2','3')))
    errors = sum(n for code,n in statuses.items() if code.startswith('5'))
    security = category in ('WordPress configuration backup','Secret / repository path','Database dump filename','Backup archive filename')
    asset = category in ('JavaScript','Stylesheet','Other static file')
    # Missing application files are evidence for investigation, not ban suggestions.
    # In particular, real WP core/plugin/theme paths can themselves return 404.
    eligible_404 = bool(security and missing and set(statuses) == {'404'} and row.get('candidate') is not None)
    eligible_block = eligible_404 and category in ('WordPress configuration backup','Secret / repository path')
    action, title, detail, priority = 'keep', 'Keep normal routing', 'Successful application/file requests do not justify a block.', 'low'
    if errors:
        action,title,detail,priority = 'repair','Investigate the failing response',f'{errors} server-error responses for this exact path. Check the application/upstream error log at the recorded times.', 'high'
    elif security and successful:
        action,title,detail,priority = 'review','Check the successful response before blocking',f'{successful} successful/redirected responses for {path}. Check the returned content: intentional download, redirect, soft 404 or exposed backup. Remove any exposed backup and block its public URL.', 'high'
    elif security and missing:
        action,title,detail,priority = 'block','Review missing sensitive / backup filenames',f'{missing} actual 404 responses for a {category.lower()}. Check that this domain does not intentionally publish this URL. Only paths with exclusively 404 responses are offered for the 404 list; a missing file alone does not prove abuse.', 'normal'
    elif asset and missing and row.get('domains_404', 1) > 1:
        action,title,detail,priority = 'review','Review cross-domain missing-file requests',f'This exact path returned 404 on {row["domains_404"]} domains. Check site references and the source requests to distinguish a missing dependency from an unrelated application fingerprint. No block or ban rule is suggested for an ordinary asset.', 'normal'
    elif asset and missing:
        action,title,detail,priority = 'repair','Identify the missing asset request',f'{missing} 404 responses for this {category.lower()}. Check site references. Restore the referenced file or fix the theme/plugin/generated HTML and refresh the affected cached HTML. No block or ban rule is suggested.', 'normal'
    elif category == 'PHP path' and missing:
        action,title,detail,priority = 'review','Review missing PHP path',f'{missing} 404 responses for {path}. This may be a core, plugin, theme or application route. Inspect the site and source requests; no block or ban rule is suggested from its filename or 404 status.', 'normal'
    elif missing:
        action,title,detail,priority = 'repair','Check the missing route / file',f'{missing} 404 responses for {path}. Check internal links and application routing. No block or ban rule is suggested.', 'normal'
    elif asset and successful:
        detail = f'{successful} successful/redirected {category.lower()} requests. This is normal asset delivery; the hit count does not establish bot activity or PHP work.'
    elif statuses and all(code in ('401','403','429') for code in statuses):
        title, detail = 'Keep the existing rejection', 'All recorded requests were already rejected. Review the responsible protection before adding another rule.'
    tags = ['security' if security else 'asset' if asset else 'application' if category == 'PHP path' else 'activity']
    if errors: tags.append('errors')
    if missing: tags.append('unexpected')
    row.update(category=category, successful=successful, missing=missing, advice=detail,
               eligible_404=eligible_404, eligible_block=eligible_block,
               can_append=row.get('candidate') is not None,
               can_append_404=bool(missing and row.get('candidate') is not None),
               recommendation=dict(action=action,title=title,detail=detail),
               review_info=dict(priority=priority,priority_label={'high':'High review priority','normal':'Review context','low':'Lower review priority'}[priority],tags=tags,reason=detail))
    return row


def proposals(rows):
    groups = {}
    for raw in rows:
        row = decorate(raw)
        action = row['recommendation']['action']
        key = row['site'], row['category'], action
        group = groups.setdefault(key,dict(site=row['site'],domain=row['domain'],category=row['category'],
            action=action,title=row['recommendation']['title'],paths=[],missing_paths=[],block_paths=[],count=0,statuses=Counter()))
        group['count'] += row['count']; group['statuses'].update(row['statuses'])
        if row.get('candidate') is not None:
            group['paths'].append(row['candidate'])
            if row['can_append_404']: group['missing_paths'].append(row['candidate'])
            if row['eligible_block']: group['block_paths'].append(row['candidate'])
    for group in groups.values():
        paths = sorted(set(group['paths'])); group['paths'] = paths
        group['missing_paths'] = sorted(set(group['missing_paths']))
        group['block_paths'] = sorted(set(group['block_paths']))
        group['statuses'] = dict(group['statuses'])
        # Each observed path becomes its own exact rule, never an oversized PCRE token.
        group['pattern'] = group['block_paths'][0] if len(group['block_paths']) == 1 else None
        group['type'] = 'exact'
        group['detail'] = ('Review missing sensitive/backup filenames and intentional downloads. Manual append actions are available independently of this recommendation.' if group['action'] == 'block' else
                           'Inspect these recorded URLs and their responses; keep normal asset/application routing. No block or ban is suggested.' if group['action'] == 'review' else
                           'Successful application/file delivery does not justify a block. Manual append remains available if you choose to create a rule.' if group['action'] == 'keep' else
                           'Restore the missing files or correct the links/generated HTML for the listed paths. Investigate server errors in the application logs.')
    return sorted(groups.values(),key=lambda g:(g['action'] not in ('review','block','review_block'),-g['count'],g['domain'],g['category']))


class Inventory:
    def __init__(self, kind='endpoints', path=None):
        self.salt = secrets.token_bytes(16)
        self.directory = tempfile.TemporaryDirectory(prefix='hdn-endpoints-') if path is None else None
        if path is None:
            path = Path(self.directory.name) / 'report.sqlite'
        else:
            import storage
            storage.replace(path, b'', 0o600)
        self.db = sqlite3.connect(path)
        self.db.executescript('''
            CREATE TABLE counts (site TEXT, domain TEXT, path TEXT, category TEXT,
                count INTEGER, first REAL, last REAL, PRIMARY KEY(site,path));
            CREATE TABLE evidence (site TEXT, path TEXT, kind TEXT, value BLOB, count INTEGER,
                PRIMARY KEY(site,path,kind,value));
            CREATE INDEX evidence_paths ON evidence(path,kind,value,site);
            CREATE TABLE findings (rank INTEGER, count INTEGER, site TEXT, path TEXT, payload TEXT);
            CREATE INDEX finding_order ON findings(rank,count DESC,site,path);
        ''')

    def observe(self, site, path, status, agent, stamp, address=None, method=''):
        normalized = unquote(path)
        from log_analysis import IMAGE
        if IMAGE.search(normalized): return
        category = family(normalized)
        self.db.execute('''INSERT INTO counts VALUES (?,?,?,?,1,?,?) ON CONFLICT(site,path)
            DO UPDATE SET count=count+1,first=min(first,excluded.first),last=max(last,excluded.last)''',
            (site['key'], site['domain'], path, category, stamp, stamp))
        values = [('status', status), ('method', method), ('agent', agent_catalog.observed(agent)[0])]
        if address is not None:
            values.append(('client', hashlib.blake2s(address.encode(), key=self.salt, digest_size=16).digest()))
        for kind, value in values:
            self.db.execute('''INSERT INTO evidence VALUES (?,?,?,?,1) ON CONFLICT(site,path,kind,value)
                DO UPDATE SET count=count+1''', (site['key'], path, kind, value))

    def finish(self, persist):
        self.paths_total = self.db.execute('SELECT COUNT(*) FROM counts').fetchone()[0]
        for site, domain, path, category, count, first, last in self.db.execute('SELECT * FROM counts'):
            evidence = lambda kind: dict(self.db.execute('''SELECT value,count FROM evidence
                WHERE site=? AND path=? AND kind=? ORDER BY count DESC,value''', (site, path, kind)))
            statuses = evidence('status')
            success = sum(n for code, n in statuses.items() if code.startswith(('2', '3')))
            candidate = path if '[redacted-' not in path else None
            row = decorate(dict(site=site, domain=domain, path=path, candidate=candidate, category=category,
                       count=count, first=first, last=last, statuses=statuses, methods=evidence('method'),
                       agents=evidence('agent'), clients=len(evidence('client')), successful=success,
                       advice=('Successful / redirected responses exist. Check downloads, redirects and application routes before considering a block.' if success else
                               'Filename resembles a probe target. Verify that this domain does not publish it intentionally. A 404 or agent name alone does not establish abuse.')))
            if statuses.get('404'):
                row['domains_404'] = self.db.execute("SELECT COUNT(DISTINCT site) FROM evidence WHERE path=? AND kind='status' AND value='404'", (path,)).fetchone()[0]
                row = decorate(row)
            priority = {'high':0,'normal':1,'low':2}[row['review_info']['priority']]
            self.db.execute('INSERT INTO findings VALUES (?,?,?,?,?)',
                            (priority, count, site, path, json.dumps(row, separators=(',', ':'))))
        self.db.commit()
        rows = [] if persist else [json.loads(r[0]) for r in self.db.execute('SELECT payload FROM findings ORDER BY rank,count DESC,site,path')]
        return rows, self.paths_total

    def close(self):
        self.db.close()
        if self.directory:
            self.directory.cleanup()
