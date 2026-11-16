"""Exercise the actual native save parser, including an already open older form."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'PHP CLI for native save parsing')
class SaveParser(unittest.TestCase):
    def test_jetpack_lookup_uses_native_admin_csrf_gate_and_returns_json(self):
        program = r'''
            define('SOFTACULOUS', true);
            $_GET = [];
            $_SERVER['REQUEST_METHOD'] = 'POST';
            $_SERVER['HTTP_X_HDN_ANALYSIS'] = '1';
            $_POST = ['action'=>'xmlrpc_jetpack_ips', 'token'=>$argv[2]];
            $actor = $owner = 'root'; $isAdmin = $argv[3] === '1';
            $read_only = $argv[4] === '1'; $csrf = 'fixture-token';
            $escape = static fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
            $bridge = static function ($request) {
                return ['ok'=>true, 'ips'=>['192.0.2.1/32'], 'request'=>$request];
            };
            require $argv[1];
        '''
        for token, admin, readonly, allowed in (('fixture-token', '1', '0', True),
                ('invalid', '1', '0', False), ('fixture-token', '0', '0', False),
                ('fixture-token', '1', '1', False)):
            with self.subTest(token=token, admin=admin, readonly=readonly):
                result = subprocess.run(['php', '-r', program, str(ROOT/'panel/index.php'),
                    token, admin, readonly], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(result.stdout)
                self.assertEqual(data['ok'], allowed)
                if allowed:
                    self.assertEqual(data['request']['action'], 'xmlrpc_jetpack_ips')
                    self.assertEqual(data['request']['actor'], 'root')
                    self.assertEqual(data['ips'], ['192.0.2.1/32'])
                else:
                    self.assertNotIn('request', data)

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

    def test_xmlrpc_site_checkboxes_parse_without_an_implicit_all_sites_scope(self):
        for enabled, targets in ((True, ['alice/one.test']), (True, []), (False, [])):
            post = dict(endpoint_settings_schema='13', endpoint404_duration='1', endpoint404_unit='days',
                        endpoint404_maxretry='1', endpoint404_findtime='300', xmlrpc_block_present='1',
                        xmlrpc_block_targets=targets)
            if enabled:
                post['xmlrpc_block_enabled'] = 'on'
            result = self.parse(post)
            self.assertEqual(result.returncode, 0, result.stderr)
            policy = json.loads(result.stdout)
            self.assertEqual(policy['schema'], 14)
            self.assertEqual(policy['xmlrpc_block'], dict(enabled=enabled, targets=targets))


    def test_new_form_parses_per_site_networks_and_can_clear_all_exceptions(self):
        for posted, expected in (({'alice/one.test':'192.0.2.1\n2001:db8::/32', 'bob/two.test':''},
                                  {'alice/one.test':['192.0.2.1','2001:db8::/32']}), ({}, {})):
            result=self.parse(dict(xmlrpc_block_present='1',xmlrpc_exceptions_present='1',
                                   xmlrpc_block_exceptions=posted))
            self.assertEqual(result.returncode,0,result.stderr)
            policy=json.loads(result.stdout)
            self.assertEqual(policy['schema'],15)
            self.assertEqual(policy['xmlrpc_block'],dict(enabled=False,targets=[],exceptions=expected,global_exceptions=[],**{'global':False}))
        for invalid in ('192.0.2.1', {'alice/one.test':['192.0.2.1']}):
            result=self.parse(dict(xmlrpc_block_present='1',xmlrpc_exceptions_present='1',
                                   xmlrpc_block_exceptions=invalid))
            self.assertNotEqual(result.returncode,0)

    def test_global_checkbox_and_exceptions_have_their_own_save_fields(self):
        result = self.parse(dict(xmlrpc_block_present='1', xmlrpc_exceptions_present='1',
            xmlrpc_block_enabled='on', xmlrpc_block_global='on',
            xmlrpc_block_global_exceptions='192.0.2.1\n2001:db8::/32',
            xmlrpc_block_exceptions={'alice/one.test':'198.51.100.1'}))
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads(result.stdout)
        self.assertEqual(policy['xmlrpc_block'], {'enabled':True, 'global':True, 'targets':[],
            'global_exceptions':['192.0.2.1','2001:db8::/32'], 'exceptions':{'alice/one.test':['198.51.100.1']}})
        result = self.parse(dict(xmlrpc_block_present='1', xmlrpc_exceptions_present='1',
            xmlrpc_block_global_exceptions=['192.0.2.1']))
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
