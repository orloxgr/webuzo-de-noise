"""Exact, disk-backed counts of observed agent declarations or PHP-path 404s."""
import json
import hashlib
import secrets
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import unquote

import agent_catalog
import php_findings
from policy import exception_path, validate_agents


class Inventory:
    def __init__(self, kind, path=None):
        self.kind = kind
        self.salt = secrets.token_bytes(16)
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
            CREATE INDEX count_family ON counts(category);
            CREATE TABLE evidence (id TEXT, kind TEXT, value BLOB, count INTEGER,
                PRIMARY KEY(id,kind,value));
            CREATE TABLE client_routes (client BLOB, domain TEXT, id TEXT,
                PRIMARY KEY(client,domain,id));
            CREATE INDEX routes_by_path ON client_routes(id,client);
        ''')

    def observe(self, site, path, status, agent, stamp, address=None):
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
            value, category, candidate = path, php_findings.family(path), None
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
        if self.kind == 'php_files':
            evidence = [('agent', agent_catalog.observed(agent)[0])]
            if address is not None:
                client = hashlib.blake2s(address.encode(), key=self.salt, digest_size=16).digest()
                evidence.append(('client', client))
                self.db.execute('INSERT OR IGNORE INTO client_routes VALUES (?,?,?)', (client, site['domain'], ident))
            for kind, value in evidence:
                self.db.execute('''INSERT INTO evidence VALUES (?,?,?,1)
                    ON CONFLICT(id,kind,value) DO UPDATE SET count=count+1''', (ident, kind, value))

    def finish(self, persist):
        self.paths_total = self.db.execute('SELECT COUNT(*) FROM counts').fetchone()[0]
        if self.kind == 'php_files':
            self.finish_php()
        else:
            self.finish_agents()
        self.db.commit()
        total = self.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
        findings = [] if persist else [json.loads(row[0]) for row in self.db.execute(
            'SELECT payload FROM findings ORDER BY rank,count DESC,site,path')]
        return findings, total

    def finish_agents(self):
        for ident, value, category, candidate, count, first, last in self.db.execute(
                'SELECT id,value,category,candidate,count,first,last FROM counts'):
            domains = [dict(domain=domain, count=hits) for domain, hits in self.db.execute(
                'SELECT domain,count FROM domains WHERE id=? ORDER BY count DESC,domain', (ident,))]
            row = dict(value=value, category=category, candidate=candidate, count=count,
                       domains=domains, first=first, last=last)
            self.db.execute('INSERT INTO findings VALUES (0,?,?,?,?)',
                (count, '', value, json.dumps(row, separators=(',', ':'))))

    def finish_php(self):
        for (family,) in self.db.execute('SELECT DISTINCT category FROM counts'):
            members = []
            for ident, value, candidate, count, first, last in self.db.execute(
                    'SELECT id,value,candidate,count,first,last FROM counts WHERE category=? ORDER BY count DESC,value', (family,)):
                domains = [dict(domain=d, count=n) for d, n in self.db.execute(
                    'SELECT domain,count FROM domains WHERE id=? ORDER BY count DESC,domain', (ident,))]
                agents = [dict(agent=a, count=n) for a,n in self.db.execute(
                    "SELECT value,count FROM evidence WHERE id=? AND kind='agent' ORDER BY count DESC,value", (ident,))]
                clients = self.db.execute("SELECT COUNT(*) FROM evidence WHERE id=? AND kind='client'", (ident,)).fetchone()[0]
                cross = self.db.execute('SELECT COUNT(*) FROM (SELECT client FROM client_routes WHERE id=? GROUP BY client HAVING COUNT(DISTINCT domain)>1)', (ident,)).fetchone()[0]
                sweeps = self.db.execute('''SELECT COUNT(DISTINCT a.client) FROM client_routes a WHERE a.id=?
                    AND EXISTS(SELECT 1 FROM client_routes b WHERE b.client=a.client AND b.id!=a.id)''', (ident,)).fetchone()[0]
                member = dict(value=value, candidate=candidate, count=count, first=first, last=last,
                              domains=domains, clients=clients, agents=agents,
                              cross_domain_clients=cross, multi_path_clients=sweeps)
                busiest = self.db.execute('''SELECT COUNT(DISTINCT id),COUNT(DISTINCT domain) FROM client_routes
                    WHERE client IN (SELECT client FROM client_routes WHERE id=?) GROUP BY client
                    ORDER BY COUNT(DISTINCT id) DESC,COUNT(DISTINCT domain) DESC LIMIT 1''', (ident,)).fetchone()
                if busiest:
                    member['busiest_client'] = dict(paths=busiest[0], domains=busiest[1])
                member['php_info'] = php_findings.describe(value, candidate, member)
                members.append(member)
            domains = [dict(domain=d, count=n) for d, n in self.db.execute(
                '''SELECT domain,SUM(count) n FROM domains WHERE id IN
                   (SELECT id FROM counts WHERE category=?) GROUP BY domain ORDER BY n DESC,domain''', (family,))]
            agents = [dict(agent=a, count=n) for a, n in self.db.execute(
                '''SELECT value,SUM(count) n FROM evidence WHERE kind='agent' AND id IN
                   (SELECT id FROM counts WHERE category=?) GROUP BY value ORDER BY n DESC,value''', (family,))]
            clients = self.db.execute('''SELECT COUNT(DISTINCT value) FROM evidence WHERE kind='client'
                AND id IN (SELECT id FROM counts WHERE category=?)''', (family,)).fetchone()[0]
            count = sum(m['count'] for m in members)
            row = dict(value=members[0]['value'] if len(members)==1 else family,
                       candidate=members[0]['candidate'] if len(members)==1 else None, category='', count=count,
                       domains=domains, first=min(m['first'] for m in members), last=max(m['last'] for m in members),
                       clients=clients, agents=agents, members=members if len(members)>1 else [],
                       php_info=php_findings.describe(members[0]['value'], members[0]['candidate']))
            if len(members) > 1:
                row['php_info'] = dict(label='Repeated directory path group', reason='These paths differ only by consecutive repeated directories. Review each exact path before appending; the group label is not a block pattern.', append_reason='Open the exact paths to select individual rules.')
            else:
                row.update(members[0])
                row['members'] = []
            self.db.execute('INSERT INTO findings VALUES (0,?,?,?,?)', (count, '', family, json.dumps(row, separators=(',', ':'))))

    def close(self):
        self.db.close()
        if self.directory:
            self.directory.cleanup()
