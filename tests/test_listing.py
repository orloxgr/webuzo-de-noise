import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import listing
import traffic_inventory
import analysis_jobs
import engine


class ListingTests(unittest.TestCase):
    def test_every_size_and_all_have_no_hidden_record_cap(self):
        for count in (20,50,100,500,'all'):
            meta = listing.pagination(1508, 999, count)
            self.assertEqual(meta['total'],1508)
            self.assertEqual(listing.bounds(meta),(-1,0) if count=='all' else (count,(meta['page']-1)*count))
        for invalid in (True,0,-1,'50',1000,None):
            with self.assertRaises(ValueError): listing.size(invalid)

    def test_php_groups_preserve_exact_paths_evidence_counts_and_safe_append_candidates(self):
        inventory = traffic_inventory.Inventory('php_files')
        self.addCleanup(inventory.close)
        for site, path, agent, ip in [('a.test','/images/cache.php','PathScanner','198.51.100.1'),
                                     ('b.test','/images/images/cache.php','PathScanner','198.51.100.1'),
                                     ('a.test','/images/images/images/cache.php','OtherAgent','198.51.100.2'),
                                     ('a.test','/index.php','UserAgent','198.51.100.3'),
                                     ('a.test','/%2e%2e/evil.php','UserAgent','198.51.100.3')]:
            inventory.observe({'domain':site},path,'404',agent,1234,ip)
        rows, total = inventory.finish(False)
        self.assertEqual((total,inventory.paths_total),(3,5))
        group = next(row for row in rows if row['members'])
        self.assertEqual((group['count'],group['clients']),(3,2))
        self.assertEqual(group['domains'],[{'domain':'a.test','count':2},{'domain':'b.test','count':1}])
        self.assertIsNone(group['candidate'])
        self.assertEqual([m['value'] for m in group['members']],['/images/cache.php','/images/images/cache.php','/images/images/images/cache.php'])
        self.assertEqual(sum(a['count'] for a in group['agents']),3)
        self.assertIn('not a block pattern',group['php_info']['reason'])
        index = next(row for row in rows if row['value']=='/index.php')
        self.assertIn('Application',index['php_info']['label'])
        protected = next(row for row in rows if row['value']=='/%2e%2e/evil.php')
        self.assertIsNone(protected['candidate'])
        self.assertIn('traversal',protected['php_info']['append_reason'])
        self.assertNotIn('198.51.100.',json.dumps(rows))
        self.assertNotIn('198.51.100.',str(inventory.db.execute('SELECT * FROM evidence').fetchall()))


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-private native reports')
class ReviewExportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name)

    def job(self, kind, owner=None):
        with patch.object(analysis_jobs,'launch_worker',return_value=99999999):
            job=analysis_jobs.start(self.state, [], 'root','all',30,kind=kind,owner=owner)['id']
        return job, analysis_jobs.directory(self.state,job)

    def test_php_exports_every_exact_path_in_chunks_and_all_exposes_every_group(self):
        job, path = self.job('php_files')
        inventory=traffic_inventory.Inventory('php_files',path/'report.sqlite')
        for n in range(1007): inventory.observe({'domain':'a.test'},'/probe'+str(n)+'.php','404','Scanner',1234,'198.51.100.1')
        for p in ('/images/cache.php','/images/images/cache.php'): inventory.observe({'domain':'a.test'},p,'404','Scanner',1234,'198.51.100.1')
        _,total=inventory.finish(True);inventory.close()
        analysis_jobs.write(path,'result.json',dict(findings_database=True, findings_total=total))
        analysis_jobs.write(path,'status.json',dict(state='complete'))
        all_rows=analysis_jobs.status(self.state,job,'root',kind='php_files',per_page='all')['analysis']['findings']
        self.assertEqual(len(all_rows),1008)
        chunks=[analysis_jobs.export_review(self.state,job,'root',kind='php_files',offset=n) for n in (0,500,1000)]
        self.assertEqual([c['scanned'] for c in chunks],[500,500,8])
        self.assertEqual([c['next_offset'] for c in chunks],[500,1000,None])
        rows=[r for c in chunks for r in c['rows']]
        self.assertEqual(len(rows),1009)
        self.assertEqual(len({row[0] for row in rows}),1009)
        self.assertFalse((self.state/'policy.json').exists())
        with self.assertRaises(PermissionError): analysis_jobs.export_review(self.state,job,'another',kind='php_files')
        with self.assertRaises(PermissionError): analysis_jobs.export_review(self.state,job,'root',kind='scan')

    def test_owner_export_cannot_cross_kind_or_account_and_accepts_no_policy_fields(self):
        with patch.object(engine,'authorize',return_value=(False,'alice')), patch.object(analysis_jobs,'export_review',return_value={}) as export:
            result=engine.dispatch(dict(action='review_export',actor='alice',kind='activity',job='x',domain='a.test'))
            self.assertTrue(result['ok'])
            export.assert_called_once_with(engine.STATE,'x','alice',kind='activity',owner='alice',domain='a.test',offset=0)
            for kind in ('scan','php_files','agents'):
                with self.assertRaises(PermissionError): engine.dispatch(dict(action='review_export',actor='alice',kind=kind))
            with self.assertRaises(ValueError): engine.dispatch(dict(action='review_export',actor='alice',kind='activity',policy={}))
