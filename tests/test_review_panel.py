"""Escaping and legacy compatibility for visible diagnostic recommendations/agents."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'PHP CLI for report rendering')
class ReviewPanelTests(unittest.TestCase):
    def test_direct_template_access_stops_before_rendering_or_processing_requests(self):
        program = 'register_shutdown_function(function(){echo http_response_code();});require $argv[1];'
        files = list((ROOT / 'panel').glob('*.php')) + [ROOT / 'webuzo-de-noise.php']
        for source in files:
            with self.subTest(file=source.name):
                result = subprocess.run(['php', '-r', program, str(source)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, '')
                self.assertEqual(result.stdout, '403')

    def render(self, template, analysis):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'fixture.json').write_text(json.dumps(analysis))
            (path/'render.php').write_text('''<?php
                define('SOFTACULOUS', true);
                $data=['analysis'=>json_decode(file_get_contents($argv[1]),true)];
                $escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
                require $argv[2];
            ''')
            result = subprocess.run(['php', str(path/'render.php'), str(path/'fixture.json'),
                str(ROOT/'panel'/template)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout

    def test_agents_are_escaped_and_old_and_empty_headers_are_distinguishable(self):
        agents = ['Crawler <script>alert(1)</script>', None, '']
        rows = [dict(domain='one.test',rule='agent',outcome='blocked',count=1,
            time='2026-11-04T01:00:00+00:00',status=403,agent=agent) for agent in agents]
        del rows[1]['agent']  # Previously saved report.
        body = self.render('activity-output.php', dict(window_minutes=15,total=3,rows=rows,findings=rows))
        self.assertIn('User-Agent', body)
        self.assertIn('Crawler &lt;script&gt;', body)
        self.assertNotIn('<script>alert', body)
        self.assertIn('Not recorded', body)
        self.assertIn('Not sent', body)

    def test_filter_candidate_is_read_only_scoped_and_escaped(self):
        finding = dict(kind='crawl',title='Many combinations of URL parameters',domain='one.test',
            path='/<script>alert(1)</script>/',parameters=['season'],count=35,peak_per_minute=2,
            clients=2,combinations=35,statuses={'200':35},agents={'Applebot':35},verified_google=0,
            unconfirmed_google=0,mean_request_ms=None,mean_upstream_ms=None,cache={},advice='Review filters',
            recommendations=[dict(title='Fix crawl space at the site',detail='Review generated links')],
            filter_candidate=dict(domain='one.test',path='/<script>alert(1)</script>/',parameters=['season'],observed_crawlers=['Applebot']))
        body = self.render('analysis-output.php', dict(minutes=360,totals={'requests':35,'image_records_excluded':0},
            domains=1,bytes_read=100,elapsed_seconds=1,findings=[finding],findings_total=1,verification='Not requested',note='Report only'))
        self.assertIn('Filter candidate for review', body)
        self.assertIn('Suggested next steps', body)
        self.assertIn('No rule has been created', body)
        self.assertIn('&lt;script&gt;', body)
        self.assertNotIn('<script>alert', body)
        self.assertNotIn('<form', body)
        self.assertIn('360 minutes', body)

    def test_inventory_values_and_append_attributes_are_escaped(self):
        value = 'Unknown"><script>alert(1)</script>'
        for kind in ('agents', 'php_files'):
            analysis = dict(inventory_kind=kind, minutes=30, totals={'requests':3}, domains=1,
                findings_total=1, bytes_read=100, note='Observed traffic',
                categories={'agents':'Other'}, findings=[dict(value=value, candidate=value,
                    category='agents', count=3, domains=[dict(domain='<img src=x>', count=3)])])
            body = self.render('inventory-output.php', analysis)
            self.assertIn('&lt;script&gt;', body)
            self.assertNotIn('<script>alert', body)
            self.assertNotIn('<img src=x>', body)
            self.assertIn('Append selected to lists', body)
            self.assertNotIn('form="hdn-settings"', body)
            self.assertEqual('Bot information' in body, kind == 'agents')

    def test_bot_information_escapes_metadata_and_allows_only_https_source_links(self):
        info = dict(operator='Operator <script>bad</script>', purpose='Purpose <img src=x>',
                    usefulness='Shop & SEO <b>advice</b>', url='https://example.test/docs?a=1&b=2')
        row = dict(value='TestBot', candidate='TestBot', category='agents', count=3,
                   domains=[dict(domain='one.test', count=3)], bot_info=info)
        analysis = dict(inventory_kind='agents', minutes=30, totals={'requests':3}, domains=1,
            findings_total=1, bytes_read=100, note='Observed traffic', categories={'agents':'Other'}, findings=[row])
        body = self.render('inventory-output.php', analysis)
        self.assertIn('<th>Bot information</th>', body)
        self.assertIn('<strong>Useful for:</strong>', body)
        self.assertIn('Operator &lt;script&gt;', body)
        self.assertIn('Purpose &lt;img src=x&gt;', body)
        self.assertIn('Shop &amp; SEO &lt;b&gt;advice&lt;/b&gt;', body)
        self.assertNotIn('<script>bad', body)
        self.assertIn('https://example.test/docs?a=1&amp;b=2', body)
        self.assertIn('rel="noopener noreferrer"', body)
        info['url'] = 'javascript:alert(1)'
        body = self.render('inventory-output.php', analysis)
        self.assertNotIn('javascript:', body)
        self.assertNotIn('>Source</a>', body)

    def test_activity_groups_outcomes_and_shows_saved_absolute_window(self):
        rows=[dict(domain='one.test',rule='filter-limit-one',agent='Mozilla/5.0 Applebot/0.1',outcome=outcome,count=count)
              for outcome,count in (('blocked',105),('matched',75))]
        body=self.render('activity-output.php',dict(window_minutes=15,total=180,rows=rows,findings=[],
            window_start='2026-11-04T06:17:52+02:00',window_end='2026-11-04T06:32:52+02:00',selected_domain='one.test'))
        self.assertEqual(body.count('Applebot (declared)'),1)
        self.assertIn('2026-11-04T06:17:52+02:00',body)
        self.assertIn('2026-11-04T06:32:52+02:00',body)
        self.assertIn('Blocked by De-Noise',body)
        self.assertIn('No block recorded',body)
        self.assertIn('Filtered URL rate limit',body)
        self.assertNotIn('last 15 minutes',body)
        self.assertIn('does not by itself mean an IP ban',body)
        self.assertIn('<strong>105</strong>',body)
        self.assertIn('<strong>75</strong>',body)

    def test_php_groups_explain_evidence_and_select_only_escaped_exact_members(self):
        member=dict(value='/images/images/cache.php', candidate='/images/images/cache.php', count=2,
                    domains=[dict(domain='a.test',count=2)], php_info=dict(append_reason=''))
        row=dict(value='/images/cache.php',candidate=None,category='',count=2,domains=member['domains'],
                 clients=1, first=1000,last=1002, agents=[dict(agent='Scanner <script>bad</script>',count=2)],
                 php_info=dict(label='Repeated directory path group',reason='Review exact paths.'),members=[member])
        report=self.render('inventory-output.php',dict(inventory_kind='php_files',minutes=30,totals={'requests':2},domains=1,
            findings_total=1,paths_total=1,bytes_read=100,note='Observed',findings=[row],per_page='all'))
        self.assertIn('Interpretation / evidence',report)
        self.assertIn('Distinct clients: 1',report)
        self.assertIn('Scanner &lt;script&gt;',report)
        self.assertNotIn('<script>bad',report)
        self.assertIn('data-hdn-inventory-value="/images/images/cache.php"',report)
        self.assertIn('data-hdn-inventory-value="" disabled',report)
        self.assertIn('value="all" selected',report)
        self.assertIn('data-hdn-export-review',report)
        for size in (20,50,100,500): self.assertIn('value="'+str(size)+'"',report)
