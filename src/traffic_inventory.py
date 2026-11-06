"""Exact, disk-backed counts of observed agent declarations or PHP-path 404s."""
import json
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import unquote

import agent_catalog
from policy import exception_path, validate_agents


class Inventory:
    def __init__(self, kind, path=None):
        self.kind = kind
        self.directory = tempfile.TemporaryDirectory(prefix='hdn-inventory-') if path is None else None
        if path is None:
            path = Path(self.directory.name) / 'report.sqlite'
        else:
            import storage
            storage.replace(path, b'', 0o600)
        self.db = sqlite3.connect(path)
        self.db.executescript('''
            CREATE TABLE counts (id TEXT PRIMARY KEY, value TEXT, category TEXT,
                candidate TEXT, count INTEGER, first REAL, last REAL);
            CREATE TABLE domains (id TEXT, domain TEXT, count INTEGER,
                PRIMARY KEY(id,domain));
            CREATE TABLE findings (rank INTEGER, count INTEGER, site TEXT, path TEXT, payload TEXT);
            CREATE INDEX finding_order ON findings(rank,count DESC,site,path);
        ''')

    def observe(self, site, path, status, agent, stamp):
        if self.kind == 'agents':
            value, category = agent_catalog.observed(agent)
            try:
                candidate = validate_agents([value])[0] if value not in ('', '-') else None
            except ValueError:
                candidate = None
            # Matching is case-insensitive, so case-only declarations share a row.
            ident = value.casefold()
        else:
            if status != '404' or not unquote(path).lower().endswith('.php'):
                return
            value, category, candidate = path, '', None
            try:
                candidate = exception_path(path)
                if '[redacted-' in path:
                    candidate = None
            except ValueError:
                pass
            ident = candidate or value
        self.db.execute('''INSERT INTO counts VALUES (?,?,?,?,1,?,?) ON CONFLICT(id)
            DO UPDATE SET count=count+1, first=min(first,excluded.first), last=max(last,excluded.last)''',
            (ident, value, category, candidate, stamp, stamp))
        self.db.execute('''INSERT INTO domains VALUES (?,?,1) ON CONFLICT(id,domain)
            DO UPDATE SET count=count+1''', (ident, site['domain']))

    def finish(self, persist):
        for ident, value, category, candidate, count, first, last in self.db.execute(
                'SELECT id,value,category,candidate,count,first,last FROM counts'):
            domains = [dict(domain=domain, count=hits) for domain, hits in self.db.execute(
                'SELECT domain,count FROM domains WHERE id=? ORDER BY count DESC,domain', (ident,))]
            row = dict(value=value, category=category, candidate=candidate, count=count,
                       domains=domains, first=first, last=last)
            self.db.execute('INSERT INTO findings VALUES (0,?,?,?,?)',
                (count, '', value, json.dumps(row, separators=(',', ':'))))
        self.db.commit()
        total = self.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
        findings = [] if persist else [json.loads(row[0]) for row in self.db.execute(
            'SELECT payload FROM findings ORDER BY rank,count DESC,site,path')]
        return findings, total

    def close(self):
        self.db.close()
        if self.directory:
            self.directory.cleanup()
