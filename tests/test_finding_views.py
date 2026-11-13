"""Contextual priorities, immutable filtered reports and policy-independent review notes."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import analysis_jobs
import engine
import log_analysis
import php_findings
import review_findings


class InterpretationTests(unittest.TestCase):
    def test_application_paths_include_subdirectory_installs_but_not_fake_core_locations(self):
        for path in ('/index.php','/shop/wp-login.php','/site/wp-admin/admin-ajax.php'):
            self.assertIn('application', php_findings.describe(path,path)['tags'])
        for path in ('/wp-content/themes/example/wp-login.php','/wp-includes/js/xmlrpc.php','/wp-admin/wp-cron.php'):
            info = php_findings.describe(path,path)
            self.assertNotIn('application', info['tags'])
            self.assertIn('unexpected', info['tags'])

    def test_repetition_and_suspicion_are_independent(self):
        path = '/images/images/cache.php'
        simple = php_findings.describe(path,path)
        self.assertIn('repeated',simple['tags'])
        self.assertEqual(simple['priority'],'normal')
        evidence = dict(domains=[dict(domain=str(n)+'.test') for n in range(3)],multi_path_clients=2)
        high = php_findings.describe(path,path,evidence)
        self.assertEqual(high['priority'],'high')
        self.assertIn('2 recorded clients',high['reason'])
        self.assertNotIn('repeated',php_findings.describe('//tmp/probe.php','/tmp/probe.php')['tags'])
        self.assertEqual(php_findings.family('/x/x/y/y/a.php'),'/x/y/a.php')

    def test_known_basenames_do_not_imply_malware_or_safe_traffic(self):
        self.assertEqual(php_findings.describe('/phpinfo.php','/phpinfo.php')['priority'],'normal')
        self.assertIn('not a malware verdict',php_findings.describe('/phpinfo.php','/phpinfo.php')['reason'])
        row = dict(path='/',kind='site',count=4,statuses={'500':4},parameters=['author'])
        self.assertIn('enumeration protection',review_findings.scan_info(row)['reason'])
        row.update(path='/wp-json/ultracache/v1/errors/frontend',statuses={'200':4})
        self.assertIn('not that the page worked',review_findings.scan_info(row)['reason'])

    def test_technical_tokens_and_agent_products_are_recognized_without_query_values(self):
        names,_,_ = log_analysis.params('/wp-cron.php?doing_wp_cron=private-token&no-cache=secret')
        self.assertEqual(names,[])
        self.assertEqual(log_analysis.claim('Mozilla (compatible; Amzn-SearchBot/1.0)'),'Amzn-SearchBot')
        self.assertEqual(log_analysis.claim('Amzn-User/1.0'),'Amzn-User')
        self.assertEqual(log_analysis.claim('MyGooglebotFake'),'Other / browser-like (unverified)')
        self.assertEqual(log_analysis.endpoint('/', '/?wc-ajax=get_refreshed_fragments&token=secret'),'WooCommerce cart fragments')
        self.assertNotIn('secret',log_analysis.endpoint('/', '/?wc-ajax=secret'))

    def test_filter_validation_rejects_bad_types_and_unknown_fields(self):
        for bad in ({'priority':[]},{'domain':[]},{'query':'a\n'},{'min_hits':True},{'min_hits':-1},{'unknown':1}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):review_findings.filters(bad)


@unittest.skipUnless(os.name == 'posix' and getattr(os,'geteuid',lambda:1)()==0,'Root-private Linux report tests')
class FindingViewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.logs = self.root/'logs';self.logs.mkdir()
        self.now = 1700000000
        self.sites = [dict(key='alice/one.test',domain='one.test'),dict(key='bob/two.test',domain='two.test')]
        self.patches = [patch.object(log_analysis,'LOG_ROOTS',(self.logs,)),patch.object(analysis_jobs,'launch_worker',return_value=99999999)]
        for p in self.patches:p.start()
        stamp=datetime.datetime.fromtimestamp(self.now,datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        self.line=lambda path,ip='192.0.2.1': f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" 404 0 "-" "TestAgent"\n'
        (self.logs/'one.test.log').write_text(self.line('/images/images/a.php')*3+self.line('/images/images/images/a.php')+self.line('/index.php'))
        (self.logs/'two.test.log').write_text(self.line('/images/images/a.php')*2)

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()

    def job(self,kind='php_files'):
        job=analysis_jobs.start(self.root,self.sites,'root','all',30,kind=kind)['id']
        directory=analysis_jobs.directory(self.root,job)
        result=log_analysis.scan(self.sites,'all',30,self.root,now=self.now,inventory_kind=kind if kind=='php_files' else None,report_path=directory/'report.sqlite')
        analysis_jobs.write(directory,'result.json',result);analysis_jobs.write(directory,'status.json',{'state':'complete'})
        return job,directory

    def test_group_filters_apply_before_pagination_and_csv_uses_exact_same_subset(self):
        job,directory=self.job()
        before=(directory/'report.sqlite').read_bytes()
        chosen=dict(domain='one.test',query='/images/',min_hits=2)
        page=analysis_jobs.status(self.root,job,'root',kind='php_files',filters=chosen)['analysis']
        self.assertEqual(page['findings_total'],1)
        group=page['findings'][0]
        self.assertEqual(group['count'],3)
        self.assertEqual(len(group['members']),1)
        self.assertEqual(group['members'][0]['clients'],1)
        exported=analysis_jobs.export_review(self.root,job,'root',kind='php_files',filters=chosen)
        self.assertEqual(len(exported['rows']),1)
        self.assertEqual(exported['rows'][0][1],3)
        self.assertIn('one.test: 3',exported['rows'][0][2])
        self.assertNotIn('two.test',json.dumps(exported['rows']))
        self.assertEqual(before,(directory/'report.sqlite').read_bytes())
        self.assertFalse((self.root/'policy.json').exists())

    def test_review_notes_survive_new_jobs_and_are_domain_specific_and_reversible(self):
        job,directory=self.job()
        analysis_jobs.mark_review(self.root,job,'root','php_files','one.test','/images/images/a.php','ignored')
        page=analysis_jobs.status(self.root,job,'root',kind='php_files')['analysis']
        group=next(r for r in page['findings'] if r.get('members'))
        self.assertEqual(group['count'],3) # one other variant plus two.test's contributions
        ignored=analysis_jobs.status(self.root,job,'root',kind='php_files',filters={'review':'ignored'})['analysis']
        self.assertEqual(ignored['findings'][0]['count'],3)
        revision=ignored['view_revision']
        newer,_=self.job()
        self.assertEqual(analysis_jobs.status(self.root,newer,'root',kind='php_files',filters={'review':'ignored'})['analysis']['findings_total'],1)
        analysis_jobs.mark_review(self.root,newer,'root','php_files','one.test','/images/images/a.php','open')
        self.assertNotEqual(revision,analysis_jobs.status(self.root,newer,'root',kind='php_files',filters={'review':'ignored'})['analysis']['view_revision'])
        self.assertEqual(analysis_jobs.status(self.root,newer,'root',kind='php_files',filters={'review':'ignored'})['analysis']['findings_total'],0)
        self.assertFalse((self.root/'policy.json').exists())

    def test_review_cannot_target_foreign_job_domain_path_or_policy(self):
        job,_=self.job()
        for actor,kind,domain,item in [('other','php_files','one.test','/index.php'),('root','scan','one.test','/index.php'),('root','php_files','foreign.test','/index.php'),('root','php_files','one.test','/not-in-report.php')]:
            with self.subTest(actor=actor,domain=domain,item=item),self.assertRaises((ValueError,PermissionError)):
                analysis_jobs.mark_review(self.root,job,actor,kind,domain,item,'ignored')
        self.assertFalse((self.root/'review-notes.json').exists())
        for extra in ({'policy':{}},{'filters':{}},{'owner':'alice'}):
            with self.assertRaises((PermissionError,ValueError)):
                engine.dispatch(dict(actor='root',action='review_mark',kind='php_files',job=job,domain='one.test',item='/index.php',mark='reviewed',**extra))

    def test_client_correlation_preserves_counts_without_retaining_addresses(self):
        job,directory=self.job()
        page=analysis_jobs.status(self.root,job,'root',kind='php_files',per_page='all')['analysis']
        group=next(r for r in page['findings'] if r.get('members'))
        member=next(r for r in group['members'] if r['value']=='/images/images/a.php')
        self.assertEqual(member['cross_domain_clients'],1)
        self.assertEqual(member['multi_path_clients'],1)
        self.assertEqual(member['busiest_client'],dict(paths=3,domains=2))
        self.assertEqual(member['review_info']['priority'],'high')
        self.assertNotIn('192.0.2.1',json.dumps(page))
        self.assertNotIn(b'192.0.2.1',(directory/'report.sqlite').read_bytes())

    def test_notes_refuse_symlink_and_filter_validation_does_not_change_report(self):
        job,_=self.job()
        target=self.root/'target';target.write_text('unchanged')
        (self.root/'review-notes.json').symlink_to(target)
        with self.assertRaises(OSError):analysis_jobs.mark_review(self.root,job,'root','php_files','one.test','/index.php','ignored')
        self.assertEqual(target.read_text(),'unchanged')

    def test_rejected_secret_probes_group_for_display_but_csv_and_notes_keep_exact_paths(self):
        (self.logs/'one.test.log').write_text((self.line('/.env')*2+self.line('/.git/config')*3).replace('" 404 ', '" 403 '))
        (self.logs/'two.test.log').write_text('')
        job,_=self.job('scan')
        page=analysis_jobs.status(self.root,job,'root')['analysis']
        self.assertEqual(page['findings_total'],1)
        self.assertEqual(page['findings'][0]['count'],5)
        self.assertEqual(page['findings'][0]['review_info']['priority'],'low')
        self.assertEqual(len(page['findings'][0]['grouped_probes']),2)
        exported=analysis_jobs.export_review(self.root,job,'root')
        self.assertEqual(len(exported['rows']),2)
        self.assertEqual({r[1] for r in exported['rows']},{'/.env','/.git/config'})
        expanded=analysis_jobs.status(self.root,job,'root',filters={'group_rejected':False})['analysis']
        self.assertEqual(expanded['findings_total'],2)
        with self.assertRaises(ValueError):analysis_jobs.mark_review(self.root,job,'root','scan','one.test','Rejected secret-file probes','ignored')

    def test_saved_reports_without_new_evidence_are_read_without_rewriting_or_invented_clients(self):
        job,directory=self.job()
        with sqlite3.connect(directory/'report.sqlite') as db:
            old=dict(value='/wp-content/themes/example/wp-login.php',candidate='/wp-content/themes/example/wp-login.php',count=2,domains=[dict(domain='one.test',count=2)])
            db.execute('DELETE FROM findings')
            db.execute('INSERT INTO findings VALUES (0,2,?, ?,?)',('',old['value'],json.dumps(old)))
        before=(directory/'report.sqlite').read_bytes()
        page=analysis_jobs.status(self.root,job,'root',kind='php_files')['analysis']
        row=page['findings'][0]
        self.assertIn('unexpected',row['review_info']['tags'])
        self.assertNotIn('clients',row)
        self.assertEqual(before,(directory/'report.sqlite').read_bytes())
