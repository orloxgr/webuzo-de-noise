import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import analysis_jobs
import engine
import log_analysis


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-private Linux jobs')
class Jobs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def prepared(self):
        with patch.object(analysis_jobs, 'launch_worker') as launch:
            launch.return_value = 99999999
            result = analysis_jobs.start(self.root, [], 'admin', 'all', 17)
        return result['id'], analysis_jobs.directory(self.root, result['id'])

    def test_installed_isolated_python_worker_runs_without_a_global_operation_lock(self):
        job, path = self.prepared()
        result = subprocess.run([sys.executable, '-I', str(Path(analysis_jobs.__file__).resolve()), str(self.root), job], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        value = analysis_jobs.status(self.root, job, 'admin')
        self.assertEqual(value['state'], 'complete')
        self.assertEqual(value['analysis']['domains'], 0)
        self.assertEqual(value['selection'], dict(target='all', minutes=17, verify_google=False))
        self.assertFalse((self.root / 'operation.lock').exists())
        self.assertEqual((path / 'result.json').stat().st_mode & 0o777, 0o600)

    def test_reports_are_complete_on_disk_and_pages_are_disjoint(self):
        job, path = self.prepared()
        logs = self.root / 'logs'; logs.mkdir()
        source = logs / 'one.test.log'
        import time,datetime
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        source.write_text(''.join('198.51.100.1 - - [' + stamp + '] "GET /.git/probe' + str(i) + ' HTTP/1.1" 403 0 "-" "Googlebot"\n' for i in range(65)))
        sites = [dict(key='alice/one.test',domain='one.test')]
        with patch.object(log_analysis, 'LOG_ROOTS', (logs,)):
            result = log_analysis.scan(sites, 'all', 17, self.root, now=time.time()+1, report_path=path/'report.sqlite')
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['findings_total'], 65)
        analysis_jobs.write(path, 'result.json', result)
        analysis_jobs.write(path, 'status.json', {'state':'complete'})
        pages = [analysis_jobs.status(self.root,job,'admin',page)['analysis'] for page in (1,2,3,4)]
        self.assertEqual([len(page['findings']) for page in pages], [20,20,20,5])
        self.assertEqual(len({item['path'] for page in pages for item in page['findings']}),65)

    def test_job_identity_and_administrator_ownership_are_enforced(self):
        job, path = self.prepared()
        for name in ('../../etc/passwd', '', '/tmp'):
            with self.assertRaises(ValueError): analysis_jobs.directory(self.root,name)
        with self.assertRaises(PermissionError):analysis_jobs.status(self.root,job,'otheradmin')
        with self.assertRaises(PermissionError):analysis_jobs.cancel(self.root,job,'otheradmin')

    def test_start_returns_before_inventory_and_never_runs_protection_recovery(self):
        with patch.object(engine,'authorize',return_value=(True,'admin')), patch.object(engine,'collect') as inventory, \
             patch.object(engine,'STATE',self.root), patch.object(analysis_jobs,'launch_worker') as launch, \
             patch.object(engine,'synchronize') as sync:
            launch.return_value=99999999
            result=engine.dispatch(dict(action='log_scan_start',actor='admin',target='all',minutes=17))
        self.assertEqual(result['job']['state'],'queued')
        inventory.assert_not_called();sync.assert_not_called()

    def test_explicit_cancel_is_recorded_and_latest_job_can_be_resumed(self):
        job, path = self.prepared()
        self.assertEqual(analysis_jobs.status(self.root,None,'admin')['id'],job)
        analysis_jobs.write(path, 'status.json', {'state':'queued','progress':{}})
        analysis_jobs.cancel(self.root,job,'admin')
        self.assertTrue((path/'cancel.json').exists())

    def test_rotated_compressed_logs_and_long_records_are_not_dropped(self):
        import gzip,datetime,time
        logs=self.root/'logs';logs.mkdir()
        stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        query='&'.join('parameter'+str(i)+'='+str(i) for i in range(80))
        line=f'198.51.100.1 - - [{stamp}] "GET /.git/config?{query}&padding=' + 'p'*20000 + ' HTTP/1.1" 403 0 "-" "Googlebot"\n'
        with gzip.open(logs/'one.test.log.7.gz','wt') as stream:stream.write(line)
        with patch.object(log_analysis,'LOG_ROOTS',(logs,)):
            result=log_analysis.scan([dict(key='alice/one.test',domain='one.test')],'all',17,self.root,now=time.time()+1)
        self.assertEqual(result['totals']['requests'],1)
        self.assertEqual(len(result['findings'][0]['parameters']),81)
        self.assertNotIn('p'*100,json.dumps(result))

    def test_activity_reports_preserve_complete_pages_and_account_context(self):
        import activity, time, datetime
        with patch.object(analysis_jobs, 'launch_worker') as launch:
            launch.return_value=99999999
            job=analysis_jobs.start(self.root, [], 'admin', 'all', 17, kind='activity', owner='alice')['id']
        path=analysis_jobs.directory(self.root, job)
        log=self.root/'matches.log'
        stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        log.write_text(''.join(f'{stamp} alice.test agent - 403 enforce\n' for _ in range(67)) + f'{stamp} bob.test agent - 403 enforce\n')
        with patch.object(activity, 'LOG', log):
            result=activity.summary({'alice.test'}, time.time()+1, minutes=17, report_path=path/'report.sqlite')
        analysis_jobs.write(path, 'result.json', result)
        analysis_jobs.write(path, 'status.json', dict(state='complete'))
        pages=[analysis_jobs.status(self.root, job, 'admin', page, kind='activity', owner='alice')['analysis'] for page in range(1,5)]
        self.assertEqual([len(row['findings']) for row in pages], [20,20,20,7])
        self.assertEqual(result['total'], 67)
        with self.assertRaises(PermissionError):analysis_jobs.status(self.root,job,'admin',kind='activity',owner='bob')
        with self.assertRaises(PermissionError):analysis_jobs.status(self.root,job,'admin')

    def test_activity_start_preserves_owner_scope_and_defers_inventory(self):
        with patch.object(engine,'authorize',return_value=(True,'alice')), patch.object(engine,'collect') as inventory, \
             patch.object(engine,'STATE',self.root), patch.object(analysis_jobs,'launch_worker') as launch:
            launch.return_value=99999999
            result=engine.dispatch(dict(action='activity_start',actor='admin',owner='alice',minutes=17))
        inventory.assert_not_called()
        request=analysis_jobs.read(analysis_jobs.directory(self.root,result['job']['id']),'request.json')
        self.assertEqual(request['owner'],'alice')
        self.assertEqual(request['kind'],'activity')

    def test_shared_mail_logs_require_the_discovered_administrator_service_scope(self):
        import activity
        sites = [dict(key='alice/webmail', owner='alice', domain='webmail', kind='web'),
                 dict(key='root/webmail', owner='root', domain='webmail', kind='mail', shared_webmail=True)]
        for owner, actor, expected in [('alice', 'alice', False), (None, 'root', True)]:
            with patch.object(analysis_jobs, 'launch_worker', return_value=99999999):
                job = analysis_jobs.start(self.root, sites, actor, 'all', 17, kind='activity', owner=owner)['id']
            with patch.object(analysis_jobs.os, 'nice'), patch.object(analysis_jobs.signal, 'signal'), \
                    patch.object(activity, 'summary', return_value={}) as summary:
                analysis_jobs.worker(self.root, job)
            self.assertEqual(summary.call_args.kwargs['include_webmail'], expected)
            self.assertEqual(analysis_jobs.read(analysis_jobs.directory(self.root, job), 'status.json')['state'], 'complete')

    def test_cancellation_before_worker_handler_is_loaded_stays_cancelled(self):
        job,path=self.prepared()
        analysis_jobs.cancel(self.root,job,'admin')
        self.assertEqual(analysis_jobs.status(self.root,job,'admin')['state'],'cancelled')

    def test_report_retention_never_removes_active_work(self):
        import time
        first,path=self.prepared()
        request=analysis_jobs.read(path,'request.json');request['requested_at']=time.time()-40*86400
        analysis_jobs.write(path,'request.json',request)
        analysis_jobs.write(path,'status.json',dict(state='complete'))
        second,active=self.prepared()
        self.assertFalse(path.exists())
        request=analysis_jobs.read(active,'request.json');request['requested_at']=time.time()-40*86400
        analysis_jobs.write(active,'request.json',request)
        analysis_jobs.cleanup(self.root)
        self.assertTrue(active.exists())

    def test_real_background_worker_can_be_cancelled_while_waiting_for_scan_lock(self):
        with log_analysis.scan_lock(self.root):
            result=analysis_jobs.start(self.root, [], 'admin', 'all', 17)
            path=analysis_jobs.directory(self.root,result['id'])
            pid=analysis_jobs.read(path,'process.json')['pid']
            analysis_jobs.cancel(self.root,result['id'],'admin')
        # Only our own child; releasing the lock also covers cancellation before
        # exec/handler setup, when the persistent marker is the stop request.
        os.waitpid(pid,0)
        self.assertEqual(analysis_jobs.status(self.root,result['id'],'admin')['state'],'cancelled')
        self.assertFalse((path/'result.json').exists())
