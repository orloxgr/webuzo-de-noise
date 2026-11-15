"""Exercise the actual native save parser, including an already open older form."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'PHP CLI for native save parsing')
class SaveParser(unittest.TestCase):
    def parse(self, post):
        program = r'''
            $source = file_get_contents($argv[1]);
            $begin = strpos($source, '$agents = is_string(');
            $end = strpos($source, '} elseif ($request[\'action\'] === \'review_mark\')', $begin);
            if ($begin === false || $end === false) throw new RuntimeException('Missing save parser');
            $_POST = json_decode($argv[2], true, 512, JSON_THROW_ON_ERROR);
            $request = []; $submitted = null;
            eval(substr($source, $begin, $end - $begin));
            echo json_encode($request['policy'], JSON_THROW_ON_ERROR);
        '''
        return subprocess.run(['php', '-r', program, str(ROOT/'panel/index.php'), json.dumps(post)],
                              capture_output=True, text=True)

    def test_existing_open_webuzo_form_keeps_its_schema_and_does_not_erase_endpoints(self):
        result = self.parse(dict(mode='observe'))
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads(result.stdout)
        self.assertEqual(policy['schema'], 11)
        self.assertNotIn('custom_endpoints', policy)
        self.assertNotIn('endpoint_404', policy)

    def test_current_form_parses_attempt_window_exact_seconds_and_empty_rule_deletion(self):
        result = self.parse(dict(endpoint_settings_schema='13', mode='enforce', endpoint404_enabled='on',
            endpoint404_paths='/probe.js\n/route', endpoint404_targets=['alice/one.test'],
            endpoint404_maxretry='3', endpoint404_findtime='600', endpoint404_duration='2', endpoint404_unit='hours'))
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads(result.stdout)
        self.assertEqual(policy['schema'], 13)
        self.assertEqual(policy['custom_endpoints'], [])
        self.assertEqual(policy['endpoint_404'], dict(enabled=True, paths=['/probe.js', '/route'],
            targets=['alice/one.test'], maxretry=3, findtime=600, duration_seconds=7200))

    def test_current_form_preserves_native_pcre_and_encodes_duration(self):
        result = self.parse(dict(endpoint_settings_schema='13', endpoint404_duration='0', endpoint404_unit='days',
            endpoint404_maxretry='1', endpoint404_findtime='300', custom_endpoints=[dict(id='test', name='Exact rule',
            enabled='on', type='regex', pattern=r'(?i)^/a(?:b|c)\.sql$', targets=['alice/one.test'],
            also_ban='on', duration='90', duration_unit='seconds')]))
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads(result.stdout)
        self.assertEqual(policy['custom_endpoints'][0]['pattern'], r'(?i)^/a(?:b|c)\.sql$')
        self.assertEqual(policy['custom_endpoints'][0]['duration_seconds'], 90)
        self.assertTrue(policy['custom_endpoints'][0]['also_ban'])
        self.assertEqual(policy['endpoint_404']['duration_seconds'], 0)

    def test_malformed_or_overflowing_duration_never_becomes_zero_or_permanent(self):
        for duration in ('-1', '1.5', '99999999999999999999999999'):
            with self.subTest(duration=duration):
                result = self.parse(dict(endpoint_settings_schema='13', endpoint404_duration=duration, endpoint404_unit='days'))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('"endpoint_404"', result.stdout)


if __name__ == '__main__':
    unittest.main()
