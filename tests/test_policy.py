import copy
import sys
from pathlib import Path
import unittest
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from policy import DEFAULT, LEGACY_KEYS, validate, domain, target, site_mode, global_config, site_config


class PolicyTests(unittest.TestCase):
    def test_v6_upgrade_expands_only_unchanged_preset_and_keeps_new_bans_off(self):
        old = json.loads((Path(__file__).parent/'fixtures/policy-v6.json').read_text())
        saved = validate(old)
        self.assertEqual(len(old['bans']['missing_files']['paths']),138)
        self.assertIn('/admin/phpinfo.php', saved['bans']['missing_files']['paths'])
        self.assertFalse(saved['bans']['any_404']['enabled'])
        self.assertEqual(saved['bans']['any_404']['maxretry'],10)
        self.assertEqual(saved['bans']['any_404']['findtime'],300)
        self.assertFalse(saved['domain_bans']['sites']['alice/example.test']['any_404'])
        old['bans']['missing_files']['paths']=['/custom.php']
        self.assertEqual(validate(old)['bans']['missing_files']['paths'],['/custom.php'])
        saved['bans']['any_404']['maxretry']=False
        with self.assertRaises(ValueError):validate(saved)

    def test_v4_upgrade_preserves_existing_bans_and_does_not_enable_new_categories(self):
        old = copy.deepcopy(DEFAULT)
        old['schema'] = 4
        old.pop('enumeration')
        old.pop('probe_exceptions')
        old.pop('domain_bans')
        for key in ('missing_files', 'suspicious_queries', 'any_404'): old['bans'].pop(key)
        old['bans'].update(enabled=True, maxretry=1, duration_days=0)
        saved = validate(old)
        self.assertEqual(saved['schema'], 9)
        self.assertEqual(saved['bans']['duration_days'], 0)
        for key in ('missing_files', 'suspicious_queries'):
            self.assertFalse(saved['bans'][key]['enabled'])
            self.assertEqual(saved['bans'][key]['maxretry'], 2)
            self.assertEqual(saved['bans'][key]['duration_days'], 3)

    def test_probe_input_is_literal_and_category_controls_are_validated(self):
        for candidate in ['/auth.php; return 200', '/../../auth.php', '/not-php.txt']:
            policy = copy.deepcopy(DEFAULT); policy['bans']['missing_files']['paths'] = [candidate]
            with self.assertRaises(ValueError): validate(policy)
        for candidate in ['/etc/passwd|.*', '../etc/passwd', '$request_uri']:
            policy = copy.deepcopy(DEFAULT); policy['bans']['suspicious_queries']['targets'] = [candidate]
            with self.assertRaises(ValueError): validate(policy)
        policy = copy.deepcopy(DEFAULT); policy['bans']['missing_files']['maxretry'] = 0
        with self.assertRaises(ValueError): validate(policy)

    def test_install_defaults_do_not_deny_anything(self):
        policy = validate(DEFAULT)
        self.assertEqual(policy['mode'], 'observe')
        self.assertFalse(policy['agents'])
        self.assertFalse(policy['login']['enabled'])
        self.assertFalse(policy['xmlrpc']['enabled'])
        self.assertFalse(policy['scanners'])

    def test_normalization_and_invalid_inputs(self):
        policy = copy.deepcopy(DEFAULT)
        policy['agents'] = ['Crawler', ' crawler ', 'Other']
        self.assertEqual(validate(policy)['agents'], ['Crawler', 'Other'])
        for text in ['a\nreturn 403;', 'a\rfoo', 'agent\x00x', '' ]:
            with self.subTest(text=text):
                policy['agents'] = [text]
                with self.assertRaises(ValueError):
                    validate(policy)
        for name in ['../test', '*.test', 'x;return403', 'x..test', 'x.-test', 'TEST.example']:
            with self.assertRaises(ValueError):
                domain(name)
        with self.assertRaises(ValueError):
            target('owner/../../etc')

    def test_different_site_and_alias_scope(self):
        policy = copy.deepcopy(DEFAULT)
        policy['mode'] = 'enforce'
        policy['overrides'] = {'alice/one.test': 'off'}
        site = {'key': 'alice/one.test', 'suspended': False}
        self.assertEqual(site_mode(policy, site), 'off')
        self.assertEqual(site_mode(policy, {'key': 'alice/two.test'}), 'enforce')
        self.assertEqual(site_mode(policy, {'key': 'bob/one.test'}), 'enforce')
        self.assertEqual(site_mode(policy, {'key': 'bob/one.test', 'suspended': True}), 'off')

    def test_rates_never_intercept_general_rest_or_ajax(self):
        policy = copy.deepcopy(DEFAULT)
        policy['login']['enabled'] = True
        policy['xmlrpc']['enabled'] = True
        text = global_config(policy, [])
        self.assertIn(':POST:/wp-login', text)
        self.assertIn(':POST:/xmlrpc', text)
        self.assertNotIn('wp-admin', text)
        self.assertNotIn('wp-json', text)
        self.assertNotIn('$args', text)
        self.assertNotIn('$http_x_forwarded_for', text)
        self.assertIn('$server_name:$binary_remote_addr', text)

    def test_off_cannot_deny_requests(self):
        policy = copy.deepcopy(DEFAULT)
        policy['mode'] = 'off'
        policy['agents'] = ['Crawler']
        text = site_config(policy, {'key': 'alice/one.test'})
        self.assertNotIn('return 403', text)
        self.assertIn('set $hdn_mode off;', text)

    def test_upgrade_keeps_old_policy_without_adding_restrictions(self):
        old = {key: copy.deepcopy(value) for key, value in DEFAULT.items() if key in LEGACY_KEYS}
        old.update(schema=1, mode='enforce', agents=['ExistingBot'])
        old['overrides'] = {'alice/one.test': 'off'}
        upgraded = validate(old)
        self.assertEqual(upgraded['agents'], old['agents'])
        self.assertEqual(upgraded['overrides'], old['overrides'])
        self.assertEqual(upgraded['mode'], 'enforce')
        self.assertEqual(upgraded['filters'], [])
        self.assertEqual(upgraded['static'], [])
        self.assertEqual(upgraded['static_exceptions'], {})
        old2 = {key: copy.deepcopy(value) for key, value in DEFAULT.items() if key in LEGACY_KEYS | {'filters', 'static'}}
        old2['schema'] = 2
        old2['static'] = [{'id': 'maps', 'enabled': True, 'path': '/wp-content/', 'extensions': ['map'], 'targets': []}]
        upgraded2 = validate(old2)
        self.assertEqual(upgraded2['static'], old2['static'])
        self.assertEqual(upgraded2['static_exceptions'], {})
        old3 = {key: copy.deepcopy(value) for key, value in DEFAULT.items() if key in LEGACY_KEYS | {'filters', 'static', 'static_exceptions'}}
        old3.update(schema=3, agents=['TLM-Audit-Scanner', 'GoogleOther', 'CustomAgent'])
        upgraded3 = validate(old3)
        self.assertEqual(upgraded3['tool_agents'], ['TLM-Audit-Scanner'])
        self.assertEqual(upgraded3['agents'], ['GoogleOther', 'CustomAgent'])
        self.assertFalse(upgraded3['bans']['enabled'])

    def test_static_exceptions_are_exact_paths_with_idempotent_encoding(self):
        policy = copy.deepcopy(DEFAULT)
        policy['static_exceptions'] = {'alice/one.test': ['/wp-content/a b.map', '/wp-content/a%20b.map', '/wp-content/a%25name.map']}
        validated = validate(policy)
        self.assertEqual(validated['static_exceptions']['alice/one.test'], ['/wp-content/a%20b.map', '/wp-content/a%25name.map'])
        self.assertEqual(validate(validated), validated)
        for path in ['https://one.test/x.map', '/x/../y.map', '/%2e%2e/y.map', '/folder/', '/x.map?ver=1',
                     '/x.map#fragment', '/bad%ZZ.map', '/bad%00.map', '/bad%FF.map', '/wild*.map']:
            policy['static_exceptions'] = {'alice/one.test': [path]}
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate(policy)

    def test_bundled_rule_presets_are_valid_together_and_do_not_modify_defaults(self):
        from presets import RULES
        candidate = copy.deepcopy(DEFAULT)
        for module, presets in RULES.items():
            candidate[module] = [copy.deepcopy(rule) for preset in presets for rule in preset['rules']]
        validate(candidate)
        self.assertEqual(DEFAULT['filters'], [])
        self.assertEqual(DEFAULT['static'], [])

    def test_rule_config_injection_and_unsafe_static_root_are_rejected(self):
        policy = copy.deepcopy(DEFAULT)
        policy['filters'] = [{'id': 'facets', 'enabled': True, 'path': '/shop/',
                              'parameters': ['orderby'], 'agents': ['Applebot'],
                              'action': 'limit', 'rate': 30, 'burst': 5, 'targets': []}]
        self.assertEqual(validate(policy)['filters'][0]['agents'], ['applebot'])
        for key, value in [('id', 'x;return'), ('path', '/x/../y/'),
                           ('parameters', ['a;return']), ('targets', ['alice/../x']), ('rate', True)]:
            invalid = copy.deepcopy(policy)
            invalid['filters'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(invalid)
        policy['static'] = [{'id': 'maps', 'enabled': True, 'path': '/wp-content/', 'extensions': ['map'], 'targets': []}]
        with self.assertRaisesRegex(ValueError, 'document root'):
            site_config(policy, {'key': 'alice/one.test'})


if __name__ == '__main__':
    unittest.main()
