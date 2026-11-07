import copy
import datetime
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import auto_bans
import ban_evidence
import not_found
from policy import DEFAULT
from test_auto_bans import FakeNative


class EventPrivacyTests(unittest.TestCase):
    def test_json_and_legacy_events_do_not_retain_queries_headers_or_control_characters(self):
        row = dict(v=1, ts='1000', ip='198.51.100.9', domain='one.test', reason='not-found',
                   token='-', path='/assets/a%22.map?password=private#fragment', method='GET',
                   cookie='private-cookie', authorization='private-header')
        event = ban_evidence.event(json.dumps(row))
        self.assertEqual(event[-2:], ('/assets/a%22.map', 'GET'))
        self.assertNotIn('private', repr(event))
        self.assertEqual(ban_evidence.event('1000 198.51.100.9 one.test private-file')[-2:], ('', ''))
        self.assertEqual(ban_evidence.path_only('https://user:password@one.test/path?key=private'), '/path')
        self.assertEqual(ban_evidence.path_only('/bad\nforged'), '')
        self.assertEqual(len(ban_evidence.path_only('/' + 'a'*5000)), 5001)
        self.assertIsNone(ban_evidence.event('{"v":1}'))


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Private Linux ban databases')
class EvidenceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.log = self.root/'ban-events.log'; self.log.write_text('')
        self.patches = [patch.object(auto_bans, 'LOG', self.log), patch.object(not_found, 'LOG_ROOT', self.root)]
        for item in self.patches: item.start()
        self.policy = copy.deepcopy(DEFAULT); self.policy['mode'] = 'enforce'
        self.policy['bans']['enabled'] = True
        self.policy['bans']['any_404'].update(enabled=True, maxretry=2, findtime=300, exclude_static=False, min_distinct_paths=1)
        self.sites = [dict(domain='one.test', key='alice/one.test', owner='alice', supported=True),
                      dict(domain='two.test', key='bob/two.test', owner='bob', supported=True)]
        self.native = FakeNative()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def event(self, stamp, domain, path, reason='not-found', ip='198.51.100.9'):
        with self.log.open('a') as stream:
            stream.write(json.dumps(dict(v=1, ts=str(stamp), ip=ip, domain=domain,
                reason=reason, token='-', path=path, method='GET'))+'\n')

    def sync(self, now=1002):
        return auto_bans.synchronize(self.policy, self.sites, self.root, self.native, now)

    def test_early_nginx_and_native_404_capture_cross_domain_paths_and_trigger_policy(self):
        self.event(1000, 'one.test', '/assets/app.js.map?secret=private')
        date = datetime.datetime.fromtimestamp(1001, datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        (self.root/'two.test.log').write_text('198.51.100.9 - - ['+date+'] "GET /missing.css?key=private HTTP/1.1" 404 0 "-" "Browser"\n')
        row = self.sync()['rows'][0]; details = row['diagnostics']
        self.assertEqual((details['count'], details['maxretry'], details['findtime']), (2, 2, 300))
        self.assertEqual([(s['domain'], s['path']) for s in details['samples']],
                         [('one.test', '/assets/app.js.map'), ('two.test', '/missing.css')])
        self.assertNotIn('private', json.dumps(details))
        self.assertEqual(self.sync()['active'], 1)
        self.policy['bans']['any_404'].update(maxretry=9, findtime=600)
        self.assertEqual(self.sync(1003)['rows'][0]['diagnostics'], details)


    def test_existing_bans_counters_and_log_cursors_survive_schema_upgrade(self):
        path=self.root/'bans.sqlite';db=sqlite3.connect(path)
        db.executescript('''
            PRAGMA application_id=1212436017;
            CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE cursors(device INTEGER,inode INTEGER,offset INTEGER NOT NULL,PRIMARY KEY(device,inode));
            CREATE TABLE strikes(ip TEXT,domain TEXT,reason TEXT,stamp REAL,token TEXT NOT NULL DEFAULT '');
            CREATE TABLE bans(ip TEXT PRIMARY KEY,domain TEXT,reason TEXT,created REAL,expires REAL,status TEXT,error TEXT NOT NULL DEFAULT '');
            INSERT INTO cursors VALUES(1,2,1234);
            INSERT INTO strikes VALUES('198.51.100.8','one.test','not-found',1000,'-');
            INSERT INTO bans VALUES('198.51.100.9','one.test','not-found',990,9999,'active','');
        ''');db.commit();db.close();path.chmod(0o600)
        report=auto_bans.report(self.root,True)
        self.assertEqual(report['active'],1);self.assertIsNone(report['rows'][0]['diagnostics'])
        self.assertEqual(report['rows'][0]['created'],990)
        with auto_bans.database(self.root) as db:
            self.assertEqual(tuple(db.execute('SELECT * FROM cursors').fetchone()),(1,2,1234))
            strike=db.execute('SELECT * FROM strikes').fetchone()
            self.assertEqual(strike['stamp'],1000)
            self.assertEqual(len(strike),5)
            # Positional writes from the previous release remain compatible.
            db.execute("INSERT OR REPLACE INTO bans VALUES ('198.51.100.10','one.test','not-found',991,9999,'active','')")
            db.execute("INSERT INTO strikes VALUES ('198.51.100.10','one.test','not-found',1000,'-')")

    def test_all_triggering_evidence_is_retained_and_legacy_lines_do_not_disable_bans(self):
        self.policy['bans']['any_404']['maxretry']=11
        with self.log.open('a') as stream:
            stream.write('1000 198.51.100.9 one.test not-found -\n')
        for i in range(11):self.event(1000+i/100,'one.test','/file'+str(i)+'?secret=private')
        details=self.sync()['rows'][0]['diagnostics']
        self.assertEqual(details['count'],11)
        self.assertEqual(len(details['samples']),11)
        self.assertNotIn('private',json.dumps(details))
