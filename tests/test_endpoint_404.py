import copy
import datetime
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import auto_bans
import endpoint_inventory
import endpoint_404
import engine
import not_found
from policy import DEFAULT, validate
from test_auto_bans import FakeNative


class Selections(unittest.TestCase):
    def test_webuzo_old_panels_preserve_new_list_and_attempt_controls(self):
        saved=copy.deepcopy(DEFAULT);saved['endpoint_404'].update(paths=['/probe.js'],maxretry=3,findtime=600)
        for schema in (11,12):
            old=copy.deepcopy(DEFAULT);old.pop('endpoint_404');old['schema']=schema
            if schema==11: old.pop('custom_endpoints')
            self.assertEqual(validate(old)['endpoint_404'],endpoint_404.DEFAULT)
            with patch.object(engine,'authorize',return_value=(True,'root')),patch.object(engine,'load',return_value=saved),patch.object(engine,'collect',return_value=[]),patch.object(engine,'snapshot',return_value={}),patch.object(engine,'apply') as apply:
                engine.dispatch(dict(action='save',actor='root',policy=old))
            self.assertEqual(apply.call_args.args[0]['endpoint_404'],saved['endpoint_404'])
        for key in ('maxretry','findtime'):
            for bad in (0,-1,True,1.5):
                invalid=copy.deepcopy(DEFAULT);invalid['endpoint_404'][key]=bad
                with self.assertRaises(ValueError):validate(invalid)

    def test_any_extension_exact_list_and_nonnegative_duration(self):
        p=copy.deepcopy(DEFAULT);p['endpoint_404']['paths']=['/probe.js','/db.sql.gz','/route','/styles.css','/probe.js']
        self.assertEqual(len(validate(p)['endpoint_404']['paths']),4)
        for value in ('bad.js','/a?x=1','/a\nfile'):
            with self.assertRaises(ValueError): validate({**p,'endpoint_404':{**p['endpoint_404'],'paths':[value]}})

    def test_specific_proposals_keep_observed_scope_and_do_not_expand_extensions(self):
        rows=[dict(site='alice/one.test',domain='one.test',path=p,candidate=p,count=1,statuses={'404':1}) for p in ('/backup.zip','/backup.rar','/missing.js')]
        groups=endpoint_inventory.proposals(rows)
        backup=next(g for g in groups if g['category']=='Backup archive filename')
        self.assertEqual(backup['site'],'alice/one.test')
        self.assertEqual(backup['missing_paths'],['/backup.rar','/backup.zip'])
        self.assertEqual(backup['block_paths'],[])
        self.assertIsNone(backup['pattern'])
        self.assertEqual(next(g for g in groups if g['category']=='JavaScript')['action'],'repair')
        probe=endpoint_inventory.decorate({**rows[-1],'domains_404':5})
        self.assertEqual(probe['recommendation']['action'],'review')
        self.assertFalse(probe['eligible_404'])
        self.assertTrue(probe['can_append_404'])
        self.assertIn('5 domains',probe['advice'])

    def test_common_application_paths_never_become_suggested_bans(self):
        paths=['/wp-blog-header.php','/wp-trackback.php','/user.php','/upload/upload.php',
               '/wp-content/themes/twentysixteen/content-index.php','/media/system/js/core.js','/missing.css']
        rows=[dict(site='alice/one.test',domain='one.test',path=p,candidate=p,count=4,statuses={'404':4},domains_404=33) for p in paths]
        for row in rows:
            decorated=endpoint_inventory.decorate(row)
            self.assertFalse(decorated['eligible_404'],row['path'])
            self.assertFalse(decorated['eligible_block'],row['path'])
            self.assertTrue(decorated['can_append'],row['path'])
            self.assertTrue(decorated['can_append_404'],row['path'])
        for group in endpoint_inventory.proposals(rows):
            self.assertEqual(group['block_paths'],[])
            self.assertEqual(group['missing_paths'],group['paths'])
            self.assertIsNone(group['pattern'])

    def test_sensitive_recommendations_require_only_404_but_manual_append_does_not(self):
        paths=['/wp-config.old','/wp-config.php.bak','/.env','/.git/config','/backup.zip']
        base=dict(site='alice/one.test',domain='one.test',count=1)
        for path in paths:
            row=dict(base,path=path,candidate=path,statuses={'404':1})
            self.assertTrue(endpoint_inventory.decorate(row)['eligible_404'])
            for statuses in ({'404':1,'200':1},{'404':1,'302':1},{'404':1,'500':1},{'403':1}):
                result=endpoint_inventory.decorate(dict(row,statuses=statuses))
                self.assertFalse(result['eligible_404'])
                self.assertFalse(result['eligible_block'])
                self.assertTrue(result['can_append'])
                self.assertEqual(result['can_append_404'],'404' in statuses)
        rows=[dict(base,path=f'/private/{i}/wp-config.old',candidate=f'/private/{i}/wp-config.old',statuses={'404':1}) for i in range(300)]
        group=endpoint_inventory.proposals(rows)[0]
        self.assertEqual(len(group['block_paths']),300)
        self.assertIsNone(group['pattern'])
        self.assertEqual(group['type'],'exact')

    def test_append_available_for_successful_and_mixed_status_findings_without_changing_advice(self):
        base=dict(site='alice/one.test',domain='one.test',count=2)
        for path in ['/working.js','/missing.css','/wp-blog-header.php','/application/route']:
            for statuses in ({'200':2},{'404':1,'200':1},{'404':2}):
                row=endpoint_inventory.decorate(dict(base,path=path,candidate=path,statuses=statuses))
                self.assertTrue(row['can_append'])
                self.assertEqual(row['can_append_404'],'404' in statuses)
                group=endpoint_inventory.proposals([row])[0]
                self.assertEqual(group['paths'],[path])
                self.assertEqual(group['missing_paths'],[path] if '404' in statuses else [])
                self.assertFalse(row['eligible_block'])
        redacted=endpoint_inventory.decorate(dict(base,path='/[redacted-path]',candidate=None,statuses={'404':2}))
        self.assertFalse(redacted['can_append'])
        self.assertFalse(redacted['can_append_404'])



@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Root-private Linux state')
class Final404(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.events=self.root/'events';self.events.write_text('')
        self.logs=self.root/'logs';self.logs.mkdir()
        self.native=FakeNative();self.policy=copy.deepcopy(DEFAULT);self.policy['mode']='enforce'
        self.policy['endpoint_404']=dict(enabled=True,paths=['/probe.js','/db.sql.gz'],targets=['alice/one.test'],duration_seconds=120,maxretry=1,findtime=300)
        self.sites=[dict(key='alice/'+d,domain=d,supported=True,suspended=False) for d in ('one.test','two.test')]
        for module,field,value in ((auto_bans,'LOG',self.events),(not_found,'LOG_ROOT',self.logs)):
            p=patch.object(module,field,value);p.start();self.addCleanup(p.stop)
        self.sync(900)  # Activation records the start; history is not a new offense.

    def sync(self,now): return auto_bans.synchronize(self.policy,self.sites,self.root,self.native,now=now)

    def request(self,path='/probe.js',status=404,at=1000,ip='198.51.100.7',domain='one.test'):
        date=datetime.datetime.fromtimestamp(at,datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        with (self.logs/(domain+'.log')).open('a') as f:f.write(f'{ip} - - [{date}] "GET {path} HTTP/1.1" {status} 0 "-" "Browser"\n')

    def test_real_404_first_hit_works_with_general_bans_off_and_assets_excluded_there(self):
        self.request(status=200);self.request(path='/not-selected.js',ip='198.51.100.8')
        self.assertEqual(self.sync(1001)['active'],0)
        self.request(path='/probe.js?token=do-not-store',at=1002)
        report=self.sync(1003)
        self.assertEqual(report['active'],1);self.assertEqual(report['error'],'')
        self.assertEqual(report['rows'][0]['expires'],1122)
        self.assertEqual(report['rows'][0]['diagnostics']['samples'][0]['path'],'/probe.js')
        self.assertNotIn('do-not-store',json.dumps(report))
        self.assertEqual(self.sync(1004)['active'],1)
        self.assertIn('198.51.100.7',self.native.active)
        self.assertEqual(self.sync(1123)['active'],0)

    def test_history_scope_exemptions_and_observe_are_not_banned(self):
        self.request(at=899)
        self.request(domain='two.test',ip='198.51.100.8')
        self.request(ip='192.0.2.1');self.request(ip='127.0.0.1')
        self.policy['bans']['ignore_ips']=['198.51.100.9/32'];self.request(ip='198.51.100.9')
        self.assertEqual(self.sync(1001)['active'],0)
        self.policy['mode']='observe';self.sync(1002);self.request(at=1003)
        self.policy['mode']='enforce';self.sync(1004)
        self.assertEqual(self.native.active,set())
        self.request(at=1005);self.assertEqual(self.sync(1006)['active'],1)

    def test_structured_final404_and_native_duplicate_create_only_one_ban(self):
        self.request()
        with self.events.open('a') as f:
            f.write(json.dumps(dict(v=1,ts='1000',ip='198.51.100.7',domain='one.test',reason=endpoint_404.REASON,
                token='selected-404',path='/probe.js',method='GET'))+'\n')
        self.assertEqual(self.sync(1001)['active'],1)
        self.assertEqual(self.native.calls.count(('add','198.51.100.7')),1)

    def threshold(self, attempts=3, window=60):
        self.policy['endpoint_404'].update(maxretry=attempts,findtime=window)
        self.sync(950)

    def structured(self, at, path='/probe.js'):
        with self.events.open('a') as f:
            f.write(json.dumps(dict(v=1,ts=str(at),ip='198.51.100.7',domain='one.test',reason=endpoint_404.REASON,
                token='selected-404',path=path,method='GET'))+'\n')

    def test_attempt_threshold_counts_real_404s_across_selected_paths_only(self):
        self.threshold()
        self.request(at=1000);self.assertEqual(self.sync(1001)['active'],0)
        self.request(at=1002,path='/db.sql.gz');self.assertEqual(self.sync(1003)['active'],0)
        self.request(at=1004,status=200);self.request(at=1004,path='/unselected.js')
        self.assertEqual(self.sync(1005)['active'],0)
        self.request(at=1006);result=self.sync(1007)
        self.assertEqual(result['active'],1)
        details=result['rows'][0]['diagnostics']
        self.assertEqual((details['count'],details['maxretry'],details['findtime']),(3,3,60))
        self.assertEqual(len(details['samples']),3)

    def test_counting_window_can_exceed_ban_duration_when_processing_backlog(self):
        self.threshold(3,300)
        self.request(at=1000);self.request(at=1190);self.request(at=1192)
        result=self.sync(1193)
        self.assertEqual(result['active'],1)
        self.assertEqual(result['rows'][0]['diagnostics']['count'],3)
        self.assertEqual(result['rows'][0]['expires'],1312)

    def test_expired_attempts_do_not_complete_the_threshold(self):
        self.threshold(2,30)
        self.request(at=1000);self.assertEqual(self.sync(1001)['active'],0)
        self.request(at=1040);self.assertEqual(self.sync(1041)['active'],0)
        self.request(at=1042);self.assertEqual(self.sync(1043)['active'],1)

    def test_log_layer_duplicates_do_not_count_twice_even_across_maintenance_runs(self):
        self.threshold()
        self.structured(1000.25);self.assertEqual(self.sync(1001)['active'],0)
        self.request(at=1000);self.assertEqual(self.sync(1002)['active'],0)
        self.request(at=1003);self.structured(1003.5)
        self.assertEqual(self.sync(1004)['active'],0)
        self.request(at=1005);self.assertEqual(self.sync(1006)['active'],1)

    def test_genuine_same_second_repeats_count_without_summing_log_layers(self):
        self.threshold()
        self.request(at=1000);self.request(at=1000)
        self.structured(1000.1);self.structured(1000.2)
        self.assertEqual(self.sync(1001)['active'],0)
        self.request(at=1000)
        self.assertEqual(self.sync(1002)['active'],1)

    def test_counter_change_starts_fresh_without_retroactive_ban(self):
        self.threshold()
        self.request(at=1000);self.assertEqual(self.sync(1001)['active'],0)
        self.policy['endpoint_404']['maxretry']=1
        self.assertEqual(self.sync(1002)['active'],0)
        self.request(at=1003);self.assertEqual(self.sync(1004)['active'],1)

    def test_complete_webuzo_log_is_authoritative_over_legacy_structured_records(self):
        self.threshold(3, 60)
        self.sites[0]['native_access_logging'] = True
        self.structured(1000.1)
        self.structured(1000.2)
        self.structured(1000.3)
        self.request(at=1000)
        self.assertEqual(self.sync(1001)['active'], 0)
        self.request(at=1002)
        self.assertEqual(self.sync(1003)['active'], 0)
        self.request(at=1004)
        result = self.sync(1005)
        self.assertEqual(result['active'], 1)
        self.assertEqual(result['rows'][0]['diagnostics']['count'], 3)


if __name__=='__main__':unittest.main()
