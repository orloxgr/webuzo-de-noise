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
    def render(self, template, analysis):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'fixture.json').write_text(json.dumps(analysis))
            (path/'render.php').write_text('''<?php
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
