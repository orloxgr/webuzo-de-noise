import copy
import datetime
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import analysis_jobs
import auto_bans
import endpoints
import engine
import log_analysis
import endpoint_inventory
from policy import DEFAULT, validate
from test_auto_bans import FakeNative


def rule(**changes):
    result = dict(id='backups', name='Backup scans', enabled=True, type='regex',
                  pattern=r'^/bak\.sql\.(?:gz|zip|zst)$', targets=['alice/one.test'],
                  also_ban=True, duration_seconds=7200)
    return {**result, **changes}


class EndpointPolicy(unittest.TestCase):
    def test_endpoint_review_requires_administrator_scope_before_discovery(self):
        for role in ((False,'alice'),(True,'alice')):
            with patch.object(engine,'authorize',return_value=role),patch.object(engine,'collect') as collect:
                with self.assertRaises(PermissionError):
                    engine.dispatch(dict(action='endpoints_start',actor='root',target='all',minutes=1440))
                collect.assert_not_called()

    def test_old_open_panel_preserves_saved_endpoints_and_new_panel_can_remove_them(self):
        saved=copy.deepcopy(DEFAULT); saved['custom_endpoints']=[rule(enabled=False)]
        for schema in (11,12):
            incoming=copy.deepcopy(DEFAULT); incoming['schema']=schema
            incoming.pop('endpoint_404'); incoming.pop('xmlrpc_block')
            if schema==11: incoming.pop('custom_endpoints')
            with patch.object(engine,'authorize',return_value=(True,'root')), patch.object(engine,'load',return_value=saved), \
                 patch.object(engine,'collect',return_value=[]),patch.object(engine,'snapshot',return_value={}),patch.object(engine,'apply') as apply:
                engine.dispatch(dict(action='save',actor='root',policy=incoming))
            self.assertEqual(apply.call_args.args[0]['custom_endpoints'], saved['custom_endpoints'] if schema==11 else [])

    def test_webuzo_schema11_migration_has_no_active_new_rules(self):
        old = copy.deepcopy(DEFAULT); old.pop('custom_endpoints'); old.pop('endpoint_404'); old.pop('xmlrpc_block'); old['schema'] = 11
        old['mode'] = 'enforce'; old['bans']['ignore_ips'] = ['198.51.100.2']
        current = validate(old)
        self.assertEqual(current['schema'], 14)
        self.assertEqual(current['custom_endpoints'], [])
        self.assertEqual(current['bans']['ignore_ips'], ['198.51.100.2/32'])
        self.assertEqual(current['mode'], 'enforce')

    def test_exact_metacharacters_and_pcre_syntax_are_not_artificially_rejected(self):
        policy = copy.deepcopy(DEFAULT)
        policy['custom_endpoints'] = [rule(type='exact', pattern='/back[up]+$.zip'),
                                      rule(id='native', pattern=r'(?i)^/back(?|up|ups)\.sql$')]
        self.assertEqual(len(validate(policy)['custom_endpoints']), 2)
        for update in (dict(pattern='x\n}'), dict(type='exact',pattern='/a?b'),
                       dict(duration_seconds=-1), dict(also_ban='yes'), dict(targets=['../one.test'])):
            with self.subTest(update=update), self.assertRaises(ValueError):
                validate({**policy, 'custom_endpoints':[rule(**update)]})


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-private Linux logs/firewall state')
class EndpointBans(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.log = self.root/'events.log'; self.log.write_text('')
        self.patcher = patch.object(auto_bans, 'LOG', self.log); self.patcher.start(); self.addCleanup(self.patcher.stop)
        self.policy = copy.deepcopy(DEFAULT); self.policy['mode'] = 'enforce'
        self.row = rule(); self.policy['custom_endpoints'] = [self.row]
        self.sites = [dict(key='alice/'+host,domain=host,supported=True,suspended=False) for host in ('one.test','two.test')]
        self.native = FakeNative()

    def event(self, ip='198.51.100.7', domain='one.test', token=None, reason=None, stamp=1000):
        with self.log.open('a') as stream:
            stream.write(json.dumps(dict(v=1, ts=str(stamp), ip=ip, domain=domain,
                reason=reason or endpoints.reason(self.row), token=token or endpoints.event_token(self.row),
                path='/bak.sql.zip?password=never-store', method='GET'))+'\n')

    def sync(self, now=1001):
        return auto_bans.synchronize(self.policy,self.sites,self.root,self.native,now=now)

    def test_first_match_works_with_global_bans_off_and_preserves_evidence(self):
        self.event()
        self.event(ip='198.51.100.8',reason='private-file')
        result = self.sync()
        self.assertEqual(result['error'],'')
        self.assertEqual(self.native.active, {'198.51.100.7'})
        row = result['rows'][0]
        self.assertEqual(row['expires'],8200)
        self.assertEqual(row['diagnostics']['duration_seconds'],7200)
        self.assertEqual(row['diagnostics']['rule_name'],'Backup scans')
        self.assertEqual(row['diagnostics']['samples'][0]['path'],'/bak.sql.zip')
        self.assertNotIn('never-store',json.dumps(row))

    def test_scope_exemptions_tokens_and_observe_do_not_ban(self):
        for ip in ('127.0.0.1','192.0.2.1','198.51.100.99'): self.event(ip=ip)
        self.policy['bans']['ignore_ips']=['198.51.100.99/32']
        self.event(ip='198.51.100.2',domain='two.test')
        self.event(ip='198.51.100.3',token='e0000000000000000')
        self.assertEqual(self.sync()['active'],0)
        self.policy['overrides']['alice/one.test']='observe'; self.event(stamp=1002)
        self.assertEqual(self.sync(1003)['active'],0)

    def test_expiry_duration_change_persistent_web_ban_and_manual_unban(self):
        self.row['duration_seconds']=120; self.event(); self.sync()
        # Webuzo bans live in its persisted Nginx map, not a volatile Hestia firewall chain.
        self.assertEqual(self.sync(1002)['active'],1)
        self.assertIn('198.51.100.7',self.native.active)
        self.row['duration_seconds']=180
        self.assertEqual(self.sync(1003)['rows'][0]['expires'],1180)
        self.assertEqual(self.sync(1181)['active'],0)
        self.event(stamp=1182); self.sync(1183)
        self.native.active.clear(); self.native.records.clear()
        self.assertEqual(self.sync(1184)['active'],0)
        self.assertEqual(self.sync(1185)['active'],0)

    def test_disabling_custom_ban_removes_it_without_switching_off_global_rules(self):
        self.policy['bans']['enabled']=True; self.policy['bans']['targets']=['alice/two.test']
        self.event(); self.event(ip='198.51.100.8',domain='two.test',reason='private-file')
        self.assertEqual(self.sync()['active'],2)
        self.row['also_ban']=False
        self.assertEqual(self.sync(1002)['active'],1)
        self.assertEqual(self.native.active,{'198.51.100.8'})

    def test_no_arbitrary_scan_window_and_no_expired_backlog_ban(self):
        self.row['duration_seconds']=86400
        self.event(stamp=100)
        self.assertEqual(self.sync(3600)['active'],1)
        self.event(ip='198.51.100.8',stamp=1)
        self.assertEqual(self.sync(90000)['active'],0)


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-private Linux analysis reports')
class EndpointAnalysis(unittest.TestCase):
    def test_all_file_types_actions_and_cross_domain_404_context(self):
        inventory=endpoint_inventory.Inventory()
        try:
            one=dict(key='alice/one.test',domain='one.test');two=dict(key='alice/two.test',domain='two.test')
            for path,status in [('/working.js','200'),('/style.css','200'),('/missing.php','404'),('/app/','200'),('/photo.jpg','404'),('/media/core.js','404')]:
                inventory.observe(one,path,status,'Browser',1000,address='198.51.100.1',method='GET')
            inventory.observe(two,'/media/core.js','404','Browser',1000,address='198.51.100.1',method='GET')
            rows,total=inventory.finish(False);by_path={r['path']:r for r in rows}
            self.assertEqual(total,6);self.assertNotIn('/photo.jpg',by_path)
            self.assertEqual(by_path['/working.js']['recommendation']['action'],'keep')
            self.assertEqual(by_path['/style.css']['recommendation']['action'],'keep')
            self.assertEqual(by_path['/missing.php']['recommendation']['action'],'review')
            self.assertEqual(by_path['/media/core.js']['domains_404'],2)
            self.assertEqual(by_path['/media/core.js']['recommendation']['action'],'review')
        finally: inventory.close()

    def test_all_statuses_rotations_privacy_paging_export_and_owner_checks(self):
        import gzip
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); logs=root/'logs'; logs.mkdir()
            at=datetime.datetime.fromtimestamp(1000,datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
            def line(path,status='404'):
                return f'198.51.100.1 - - [{at}] "GET {path}?token=private-value HTTP/1.1" {status} 0 "-" "sqlmap/1.0"\n'
            (logs/'one.test.log').write_text(line('/backup.sql','200')+line('/backup.sql')+line('/photo.jpg')+line('/catalogue/'))
            with gzip.open(logs/'one.test.log.1.gz','wt') as stream:
                stream.write(''.join(line(f'/backup-{i}.zip') for i in range(25)))
            sites=[dict(key='alice/one.test',domain='one.test')]
            with patch.object(log_analysis,'LOG_ROOTS',(logs,)), patch.object(analysis_jobs,'launch_worker',return_value=99999999):
                job=analysis_jobs.start(root,sites,'admin','all',60,kind='endpoints')['id']
                path=analysis_jobs.directory(root,job)
                result=log_analysis.scan(sites,'all',60,root,now=1001,report_path=path/'report.sqlite',inventory_kind='endpoints')
            analysis_jobs.write(path,'result.json',result); analysis_jobs.write(path,'status.json',dict(state='complete'))
            page=analysis_jobs.status(root,job,'admin',kind='endpoints')['analysis']
            self.assertEqual(page['findings_total'],27)
            self.assertEqual(len(page['findings']),20)
            first=page['findings'][0]
            self.assertEqual(first['statuses'],{'200':1,'404':1})
            self.assertEqual(first['successful'],1)
            self.assertEqual(first['clients'],1)
            self.assertEqual(first['methods'],{'GET':2})
            self.assertEqual(first['agents'],{'sqlmap':2})
            filtered=analysis_jobs.status(root,job,'admin',kind='endpoints',filters={'query':'.sql'})['analysis']
            self.assertEqual(filtered['findings_total'],1)
            self.assertEqual(filtered['findings'][0]['path'],'/backup.sql')
            self.assertIn('suggestions',filtered)
            export=analysis_jobs.export_review(root,job,'admin',kind='endpoints')
            self.assertEqual(len(export['rows']),27)
            successful_backup=next(row for row in export['rows'] if row[1]=='/backup.sql')
            self.assertEqual(successful_backup[9:11],['',''])
            self.assertEqual(successful_backup[12],'/backup.sql')
            self.assertNotIn('private-value',json.dumps([page,export]))
            self.assertNotIn('198.51.100.1',json.dumps([page,export]))
            with self.assertRaises(PermissionError): analysis_jobs.status(root,job,'other',kind='endpoints')
            self.assertFalse((root/'policy.json').exists())


if __name__ == '__main__': unittest.main()
