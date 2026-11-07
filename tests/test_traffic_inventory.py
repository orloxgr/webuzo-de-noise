"""Purpose lists and observational inventories preserve explicit rule choices."""
import copy
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import agent_catalog
import analysis_jobs
import engine
import log_analysis
import policy
import webmail


class Categories(unittest.TestCase):
    def test_empty_defaults_and_disjoint_suggestions(self):
        all_names = []
        for field, category in agent_catalog.CATEGORIES.items():
            self.assertEqual(policy.DEFAULT[field], [])
            all_names += category['entries']
        self.assertEqual(len(all_names), len(set(name.casefold() for name in all_names)))
        self.assertNotIn('meta-webindexer', agent_catalog.AI)
        self.assertIn('meta-webindexer', agent_catalog.SEARCH)

    def test_v9_migration_preserves_active_substrings_and_disabled_choices(self):
        for enabled in (True, False):
            old = {key: copy.deepcopy(policy.DEFAULT[key]) if key in policy.DEFAULT else {'allow_users':True,'sites':{}} for key in policy.V9_KEYS}
            old.update(schema=9, agents=['GPTBot', 'meta-webindexer', 'AhrefsBot',
                                        'MyCrawler', 'GoogleOther', 'Claude'], agents_enabled=enabled)
            result = policy.validate(old)
            self.assertEqual(result['ai_agents'], ['GPTBot'])
            self.assertEqual(result['search_agents'], ['meta-webindexer'])
            self.assertEqual(result['seo_agents'], ['AhrefsBot'])
            self.assertEqual(result['agents'], ['MyCrawler', 'GoogleOther', 'Claude'])
            for field in ('ai_agents', 'search_agents', 'seo_agents'):
                self.assertIs(result[field + '_enabled'], enabled)
            self.assertEqual(set(agent_catalog.enabled(result)), set(old['agents']) if enabled else set())
            self.assertEqual(policy.validate(result), result)

    def test_independent_switches_apply_to_website_and_shared_webmail(self):
        value = copy.deepcopy(policy.DEFAULT)
        value.update(mail_protection=True, mode='enforce')
        for field in agent_catalog.CATEGORIES:
            value[field] = ['Test-' + field]
        for selected in agent_catalog.CATEGORIES:
            for field in agent_catalog.CATEGORIES:
                value[field + '_enabled'] = field == selected
            valid = policy.validate(value)
            self.assertEqual(agent_catalog.enabled(valid), ['Test-' + selected])
            compiled = policy.global_config(valid, [])
            self.assertIn(policy.literal_regex('Test-' + selected), compiled)
            for other in agent_catalog.CATEGORIES:
                if other != selected:
                    self.assertNotIn(policy.literal_regex('Test-' + other), compiled)
            self.assertEqual(webmail.profile(valid)['agents'], ['Test-' + selected])

    def test_declared_training_search_and_fetch_names_remain_distinct(self):
        for name, expected in [('ClaudeBot', 'ai_agents'), ('Claude-SearchBot', 'search_agents'),
                               ('OAI-SearchBot', 'search_agents'), ('ChatGPT-User', 'agents'),
                               ('Amzn-SearchBot', 'search_agents'), ('AhrefsBot', 'seo_agents')]:
            self.assertEqual(agent_catalog.observed('Mozilla/5.0 (compatible; ' + name + '/1.0)')[1], expected)
        self.assertEqual(agent_catalog.observed('NotGPTBot/1.0'), ('NotGPTBot/1.0', 'agents'))


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Trusted native Linux log files')
class Inventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / 'logs'; self.logs.mkdir()
        self.now = datetime.datetime.now(datetime.timezone.utc).timestamp() + 1
        self.sites = [dict(key='alice/one.test', domain='one.test', owner='alice'),
                      dict(key='bob/two.test', domain='two.test', owner='bob')]
        self.stamp = datetime.datetime.fromtimestamp(self.now - 2, datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')

    def line(self, path='/', status=200, agent='TestCrawler/1.0', stamp=None):
        return f'198.51.100.1 - - [{stamp or self.stamp}] "GET {path} HTTP/1.1" {status} 0 "-" "{agent}"\n'

    def scan(self, kind, **extra):
        with patch.object(log_analysis, 'LOG_ROOTS', (self.logs,)):
            return log_analysis.scan(self.sites, extra.pop('target', 'all'), 30, self.root,
                                     now=self.now, inventory_kind=kind, **extra)

    def test_agent_counts_include_assets_rotations_and_unknowns_without_query_values(self):
        (self.logs / 'one.test.log').write_text(self.line('/a.png', agent='GPTBot/1.0') +
            self.line('/x?token=private-query', agent='GPTBot/2.0') + self.line(agent='Unknown <tag>') +
            self.line(agent='OAI-SearchBot/1.0'))
        with gzip.open(self.logs / 'two.test.log.1.gz', 'wt') as stream:
            stream.write(self.line('/a.css', agent='gptbot/1.0'))
        result = self.scan('agents')
        rows = {row['value']: row for row in result['findings']}
        self.assertEqual(result['totals']['requests'], 5)
        self.assertEqual(rows['GPTBot']['count'], 3)
        self.assertEqual(len(rows['GPTBot']['domains']), 2)
        self.assertEqual(rows['Unknown <tag>']['category'], 'agents')
        self.assertEqual(rows['OAI-SearchBot']['category'], 'search_agents')
        self.assertNotIn('private-query', json.dumps(result))
        self.assertFalse((self.root / 'policy.json').exists())

    def test_php_counts_only_404_and_keeps_domains_exact_paths_and_safe_candidates(self):
        (self.logs / 'one.test.log').write_text(self.line('/probe.php?a=secret', 404) * 3 +
            self.line('/probe.php', 200) + self.line('/image.png', 404) +
            self.line('/other%2ephp', 404) + self.line('/%2e%2e/evil.php', 404))
        (self.logs / 'two.test.log').write_text(self.line('/probe.php', 404))
        result = self.scan('php_files')
        rows = {row['value']: row for row in result['findings']}
        self.assertEqual(rows['/probe.php']['count'], 4)
        self.assertEqual([d['count'] for d in rows['/probe.php']['domains']], [3, 1])
        self.assertEqual(rows['/other%2ephp']['candidate'], '/other.php')
        self.assertIsNone(rows['/%2e%2e/evil.php']['candidate'])
        self.assertNotIn('/image.png', rows)
        self.assertNotIn('secret', json.dumps(result))
        for row in rows.values():
            if row['candidate']:
                data = copy.deepcopy(policy.DEFAULT)
                data['bans']['missing_files']['paths'] = [row['candidate']]
                policy.validate(data)

    def test_domain_selection_and_time_window_are_enforced(self):
        old = datetime.datetime.fromtimestamp(self.now - 86400, datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        (self.logs / 'one.test.log').write_text(self.line(agent='OwnBot') + self.line(agent='OldBot', stamp=old))
        (self.logs / 'two.test.log').write_text(self.line(agent='ForeignBot'))
        result = self.scan('agents', target='alice/one.test')
        self.assertEqual([row['value'] for row in result['findings']], ['OwnBot'])

    def test_complete_inventory_pages_and_kind_ownership_cannot_be_crossed(self):
        with patch.object(analysis_jobs, 'launch_worker', return_value=99999999):
            job = analysis_jobs.start(self.root, self.sites, 'root', 'all', 30, kind='agents')['id']
        directory = analysis_jobs.directory(self.root, job)
        (self.logs / 'one.test.log').write_text(''.join(self.line(agent='Unknown' + str(n)) for n in range(47)))
        result = self.scan('agents', report_path=directory / 'report.sqlite')
        analysis_jobs.write(directory, 'result.json', result)
        analysis_jobs.write(directory, 'status.json', dict(state='complete'))
        pages = [analysis_jobs.status(self.root, job, 'root', page, kind='agents')['analysis'] for page in (1, 2, 3)]
        self.assertEqual([len(p['findings']) for p in pages], [20, 20, 7])
        self.assertEqual(len({r['value'] for p in pages for r in p['findings']}), 47)
        with self.assertRaises(PermissionError): analysis_jobs.status(self.root, job, 'root', kind='php_files')
        with self.assertRaises(PermissionError): analysis_jobs.status(self.root, job, 'alice', kind='agents')

    def test_new_reviews_require_root_context_and_do_not_discover_sites_in_start_request(self):
        for kind in ('agents', 'php_files'):
            with patch.object(engine.webuzo, 'users', return_value={'alice': dict(suspended=False)}):
                with self.assertRaises(PermissionError):
                    engine.dispatch(dict(action=kind + '_start', actor='alice', target='all', minutes=30))
            with patch.object(engine, 'STATE', self.root), patch.object(engine, 'collect') as collect, \
                    patch.object(analysis_jobs, 'launch_worker', return_value=99999999):
                result = engine.dispatch(dict(action=kind + '_start', actor='root', target='all', minutes=30))
            collect.assert_not_called()
            self.assertEqual(result['job']['state'], 'queued')
            with self.assertRaises(PermissionError):
                engine.dispatch(dict(action=kind + '_status', actor='root', owner='alice', job=result['job']['id']))

    def test_cancelled_inventory_never_creates_a_report_or_policy(self):
        with patch.object(analysis_jobs, 'launch_worker', return_value=99999999):
            job = analysis_jobs.start(self.root, self.sites, 'root', 'all', 30, kind='php_files')['id']
        analysis_jobs.cancel(self.root, job, 'root', kind='php_files')
        with patch.object(analysis_jobs.signal, 'signal'), patch.object(analysis_jobs.os, 'nice'):
            analysis_jobs.worker(self.root, job)
        directory = analysis_jobs.directory(self.root, job)
        self.assertEqual(analysis_jobs.read(directory, 'status.json')['state'], 'cancelled')
        self.assertFalse((directory / 'report.sqlite').exists())
        self.assertFalse((self.root / 'policy.json').exists())

    def export_job(self, kind='agents', complete=True):
        with patch.object(analysis_jobs, 'launch_worker', return_value=99999999):
            job = analysis_jobs.start(self.root, self.sites, 'root', 'all', 30, kind=kind)['id']
        directory = analysis_jobs.directory(self.root, job)
        result = self.scan(kind, report_path=directory / 'report.sqlite')
        analysis_jobs.write(directory, 'result.json', result)
        analysis_jobs.write(directory, 'status.json', dict(state='complete' if complete else 'running'))
        return job, directory

    def test_csv_export_reads_all_rows_across_transfer_chunks_without_scanning_or_writing(self):
        (self.logs / 'one.test.log').write_text(''.join(self.line(agent='Agent-' + str(n)) for n in range(1507)) +
            self.line(agent='TopBot') * 3)
        job, directory = self.export_job()
        database = directory / 'report.sqlite'
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        rows, offset, chunks = [], 0, []
        with patch.object(log_analysis, 'scan') as scan:
            while offset is not None:
                value = analysis_jobs.export_agents(self.root, job, 'root', offset)
                self.assertEqual(value['total'], 1508)
                rows.extend(value['rows']); chunks.append(len(value['rows']))
                offset = value['next_offset']
        scan.assert_not_called()
        self.assertEqual(chunks, [500, 500, 500, 8])
        self.assertEqual(rows[0], ['TopBot', 3])
        self.assertEqual(len({row[0] for row in rows}), 1508)
        self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
        self.assertFalse((self.root / 'policy.json').exists())

    def test_export_rejects_foreign_jobs_incomplete_reports_offsets_and_untrusted_database(self):
        job, directory = self.export_job()
        with self.assertRaises(PermissionError): analysis_jobs.export_agents(self.root, job, 'alice')
        for offset in (-1, True, '0', 1):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                analysis_jobs.export_agents(self.root, job, 'root', offset)
        other, _ = self.export_job(kind='php_files')
        with self.assertRaises(PermissionError): analysis_jobs.export_agents(self.root, other, 'root')
        analysis_jobs.write(directory, 'status.json', dict(state='running'))
        with self.assertRaises(ValueError): analysis_jobs.export_agents(self.root, job, 'root')
        analysis_jobs.write(directory, 'status.json', dict(state='complete'))
        (directory / 'report.sqlite').chmod(0o644)
        with self.assertRaises(ValueError): analysis_jobs.export_agents(self.root, job, 'root')

    def test_empty_completed_export_is_valid(self):
        job, _ = self.export_job()
        self.assertEqual(analysis_jobs.export_agents(self.root, job, 'root'), dict(rows=[], total=0, next_offset=None))

    def test_export_endpoint_requires_root_scope_and_never_discovers_or_changes_sites(self):
        with patch.object(engine.webuzo, 'users', return_value={'alice': dict(suspended=False)}):
            with self.assertRaises(PermissionError):
                engine.dispatch(dict(actor='alice', action='agents_export', job='a' * 32))
        with self.assertRaises(PermissionError):
            engine.dispatch(dict(actor='root', owner='alice', action='agents_export', job='a' * 32))
        with patch.object(engine, 'collect') as collect, patch.object(analysis_jobs, 'export_agents',
                return_value=dict(rows=[['GPTBot', 10]], total=1, next_offset=None)) as export:
            result = engine.dispatch(dict(actor='root', action='agents_export', job='a' * 32, offset=0))
        collect.assert_not_called()
        self.assertTrue(result['ok'])
        export.assert_called_once_with(engine.STATE, 'a' * 32, 'root', 0)
