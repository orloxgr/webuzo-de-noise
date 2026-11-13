import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import auto_bans
import ban_history
import engine
from policy import DEFAULT
from test_auto_bans import FakeNative


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-private Linux storage')
class BanHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.state = Path(self.temp.name)
        self.log = self.state / 'events.log'; self.log.write_text('')
        self.logs = patch.object(auto_bans, 'LOG', self.log); self.logs.start()
        self.native = FakeNative()
        self.policy = copy.deepcopy(DEFAULT); self.policy['mode'] = 'enforce'; self.policy['bans']['enabled'] = True
        self.sites = [dict(key=owner+'/'+owner+'.test', owner=owner, domain=owner+'.test', supported=True, suspended=False)
                      for owner in ('alice','bob')]

    def tearDown(self):
        self.logs.stop(); self.temp.cleanup()

    def event(self, stamp=1000):
        with self.log.open('a') as log:
            log.write(json.dumps(dict(v=1,ts=str(stamp),ip='198.51.100.7',domain='alice.test',
                reason='private-file',token='-',path='/.env?secret=not-stored',method='GET'))+'\n')

    def sync(self, now):
        return auto_bans.synchronize(self.policy,self.sites,self.state,self.native,now)

    def test_native_release_preserves_original_time_and_evidence_across_rebans(self):
        self.event(); self.sync(1001)
        auto_bans.unban(self.state,self.native,['198.51.100.7'],1003)
        self.assertEqual(auto_bans.report(self.state)['rows'][0]['diagnostics']['samples'][0]['path'],'/.env')
        self.sync(1004)
        rows=auto_bans.report(self.state,view='history')['rows']
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['created'],1001); self.assertEqual(rows[0]['ended'],1004)
        self.assertEqual(rows[0]['diagnostics']['samples'][0]['path'],'/.env')
        self.assertNotIn('not-stored',json.dumps(rows))
        self.event(1005); self.sync(1006)
        auto_bans.unban(self.state,self.native,['198.51.100.7'],1007); self.sync(1008)
        rows=auto_bans.report(self.state,view='history')['rows']
        self.assertEqual([r['created'] for r in rows],[1006,1001])
        self.assertEqual([r['ended'] for r in rows],[1008,1004])

    def test_global_pages_are_bounded_disjoint_and_keep_full_counts(self):
        with auto_bans.database(self.state) as db:
            db.executemany('INSERT INTO bans VALUES (?,?,?,?,?,?,?)',
                ((f'198.51.{i//256}.{i%256}','alice.test','not-found',1000,0,'active','') for i in range(123)))
        first=auto_bans.report(self.state,page=1); second=auto_bans.report(self.state,page=2); last=auto_bans.report(self.state,page=100)
        self.assertEqual(first['pagination'],dict(page=1,pages=3,total=123,per_page=50,view='active'))
        self.assertEqual(len(first['rows']),50); self.assertEqual(len(second['rows']),50); self.assertEqual(len(last['rows']),23)
        self.assertEqual(last['pagination']['page'],3)
        self.assertFalse({r['ip'] for r in first['rows']} & {r['ip'] for r in second['rows']})
        self.assertEqual(second['active'],123)
        for number in [0,-1,True,'1']:
            with self.assertRaises(ValueError):auto_bans.report(self.state,page=number)




    def test_active_and_history_all_read_more_than_five_hundred_records(self):
        with auto_bans.database(self.state) as db:
            for n in range(607):
                ip='198.18.'+str(n//256)+'.'+str(n%256)
                db.execute("INSERT INTO bans VALUES (?, 'alice.test','private-file',1000,0,'active','')",(ip,))
                db.execute("INSERT INTO ban_history (scope,scope_key,ip,domain,reason,created,expires,ended) VALUES ('global','',?,'alice.test','private-file',1000,0,1001)",(ip,))
        for view in ('active','history'):
            result=auto_bans.report(self.state,view=view,per_page='all')
            self.assertEqual(len(result['rows']),607)
            self.assertEqual(result['pagination']['pages'],1)
            for size in (20,50,100,500):
                self.assertEqual(len(auto_bans.report(self.state,view=view,per_page=size)['rows']),size)

    def test_retention_and_clear_preserve_live_bans_counters_cursors_and_other_owners(self):
        now=4000000
        with auto_bans.database(self.state) as db:
            db.execute("INSERT INTO bans VALUES ('198.51.100.1','alice.test','private-file',1000,0,'active','')")
            db.execute("INSERT INTO strikes VALUES ('198.51.100.2','alice.test','not-found',3999999,'-')")
            db.execute('INSERT INTO cursors VALUES (1,2,300)')
            for scope,key,ip,ended in [('global','','198.51.100.3',1000),('global','','198.51.100.4',now),
                ('domain','alice/alice.test','198.51.100.5',now),('domain','bob/bob.test','198.51.100.6',now),
                ('domain','alice2/alice2.test','198.51.100.7',now)]:
                db.execute('INSERT INTO ban_history (scope,scope_key,ip,domain,reason,created,expires,ended) VALUES (?,?,?,?,?,?,?,?)',
                    (scope,key,ip,'alice.test','private-file',1000,0,ended))
            original_strikes=db.execute('SELECT * FROM strikes').fetchall();original_cursors=db.execute('SELECT * FROM cursors').fetchall()
            ban_history.maintain(self.state,db,now,force=True)
            self.assertEqual(ban_history.page(db,'global')[1]['total'],1)
            self.assertEqual(ban_history.clear(db,'domain','alice'),1)
            self.assertEqual(ban_history.page(db,'domain','bob')[1]['total'],1)
            self.assertEqual(ban_history.page(db,'domain','alice2')[1]['total'],1)
            ban_history.clear(db,'global')
            self.assertEqual(db.execute('SELECT status FROM bans').fetchone()[0],'active')
            self.assertEqual(db.execute('SELECT * FROM strikes').fetchall(),original_strikes)
            self.assertEqual(db.execute('SELECT * FROM cursors').fetchall(),original_cursors)
        self.assertEqual(self.native.calls,[])

    def test_clear_never_reimports_old_released_core_rows(self):
        with auto_bans.database(self.state) as db:
            db.execute("INSERT INTO bans VALUES ('198.51.100.1','alice.test','private-file',1000,0,'active','')")
            ban_history.release(db,db.execute('SELECT * FROM bans').fetchone(),1001)
            db.execute("UPDATE bans SET status='released'")
            self.assertEqual(ban_history.clear(db,'global'),1)
        self.assertEqual(auto_bans.report(self.state,view='history')['rows'],[])

    def test_user_cannot_clear_global_history_or_change_retention(self):
        with patch.object(engine,'STATE',self.state), patch.object(engine,'authorize',return_value=(False,'alice')), \
             patch.object(engine,'load',return_value=self.policy),patch.object(engine,'collect',return_value=self.sites):
            with self.assertRaises(PermissionError):engine.dispatch(dict(actor='alice',action='history_clear',scope='global'))
        with patch.object(engine.webuzo,'users',return_value={'alice':{'suspended':False}}):
            with self.assertRaises(PermissionError):engine.authorize(dict(actor='alice',action='history_settings_save'))
        for days in [0,True,'30',-1]:
            with self.assertRaises(ValueError):ban_history.configure(self.state,days)
        ban_history.configure(self.state,60)
        self.assertEqual(ban_history.settings(self.state),{'days':60})
        self.assertEqual((self.state/ban_history.SETTINGS).stat().st_mode & 0o777,0o600)
