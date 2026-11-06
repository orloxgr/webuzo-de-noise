"""Disk-backed exact aggregation; working-cache eviction never drops groups."""
from collections import Counter, OrderedDict
import json
import sqlite3
import tempfile
from pathlib import Path


class Groups:
    def __init__(self, path=None):
        self.directory = tempfile.TemporaryDirectory(prefix='hdn-analysis-') if path is None else None
        if path is None:
            path = Path(self.directory.name) / 'groups.sqlite'
        else:
            import storage
            storage.replace(path, b'', 0o600)
        self.db = sqlite3.connect(path)
        self.db.executescript('''
            CREATE TABLE groups (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE distinct_values (id TEXT, kind TEXT, value BLOB,
                PRIMARY KEY(id,kind,value));
            CREATE TABLE findings (rank INTEGER, count INTEGER, site TEXT, path TEXT, payload TEXT);
            CREATE INDEX finding_order ON findings(rank,count DESC,site,path);
        ''')
        self.cache = OrderedDict()

    @staticmethod
    def identity(key):
        return json.dumps(key, separators=(',', ':'))

    @staticmethod
    def encode(value):
        return json.dumps({k: v for k, v in value.items() if k not in ('clients', 'combinations')}, separators=(',', ':'))

    @staticmethod
    def decode(raw):
        value = json.loads(raw)
        for key in ('statuses', 'methods', 'agents', 'minutes', 'cache'):
            value[key] = Counter(value[key])
        value['minutes'] = Counter({int(k): v for k, v in value['minutes'].items()})
        return value

    def __contains__(self, key):
        ident = self.identity(key)
        return ident in self.cache or self.db.execute('SELECT 1 FROM groups WHERE id=?', (ident,)).fetchone() is not None

    def __getitem__(self, key):
        ident = self.identity(key)
        if ident in self.cache:
            self.cache.move_to_end(ident)
            return self.cache[ident]
        value = self.decode(self.db.execute('SELECT payload FROM groups WHERE id=?', (ident,)).fetchone()[0])
        self._cache(ident, value)
        return value

    def _cache(self, ident, value):
        self.cache[ident] = value
        # A working buffer, not an analysis limit: every evicted group is saved.
        if len(self.cache) > 128:
            old, payload = self.cache.popitem(last=False)
            self.db.execute('UPDATE groups SET payload=? WHERE id=?', (self.encode(payload), old))

    def __setitem__(self, key, value):
        ident = self.identity(key)
        self.db.execute('INSERT INTO groups VALUES (?,?)', (ident, self.encode(value)))
        self._cache(ident, value)

    def track(self, key, client, combination):
        ident = self.identity(key)
        for kind, value in (('clients', client), ('combinations', combination)):
            if value is not None:
                self.db.execute('INSERT OR IGNORE INTO distinct_values VALUES (?,?,?)', (ident, kind, value))

    def values(self):
        for ident, payload in self.cache.items():
            self.db.execute('UPDATE groups SET payload=? WHERE id=?', (self.encode(payload), ident))
        for ident, raw in self.db.execute('SELECT id,payload FROM groups'):
            group = self.decode(raw)
            for kind in ('clients', 'combinations'):
                count = self.db.execute('SELECT COUNT(*) FROM distinct_values WHERE id=? AND kind=?', (ident, kind)).fetchone()[0]
                group[kind] = range(count)
            yield group

    def close(self):
        self.db.commit()
        self.db.close()
        if self.directory:
            self.directory.cleanup()

    def suggest(self, row):
        rank = {'security': 0, 'site': 1, 'crawl': 2, 'investigate': 3}[row['kind']]
        self.db.execute('INSERT INTO findings VALUES (?,?,?,?,?)',
            (rank, row['count'], row['site'], row['path'], json.dumps(row, separators=(',', ':'))))

    def suggestion_count(self):
        return self.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]

    def suggestions(self):
        for row in self.db.execute('SELECT payload FROM findings ORDER BY rank,count DESC,site,path'):
            yield json.loads(row[0])
