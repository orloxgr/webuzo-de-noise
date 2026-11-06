import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import webuzo
from policy import V9_KEYS, DEFAULT, LEGACY_KEYS, MARKER


def fixture_read(path):
    path = Path(path)
    return path.read_bytes() if path.exists() else None


def fixture_replace(path, data, mode=0o644, gid=None):
    path = Path(path)
    if data is None:
        path.unlink(missing_ok=True)
    else:
        path.write_bytes(data)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.state = self.directory / 'state'; self.state.mkdir()
        self.global_file = self.directory / '00-de-noise.conf'
        self.snippets = self.directory / 'snippets'; self.snippets.mkdir()
        self.custom = self.directory / 'custom'; self.custom.mkdir()
        self.domain_file = self.snippets / 'example.test.conf'
        self.patches = [patch.object(engine, 'STATE', self.state),
                        patch.object(engine, 'GLOBAL', self.global_file),
                        patch.object(webuzo, 'GLOBAL', self.global_file),
                        patch.object(webuzo, 'GLOBAL_CUSTOM', self.directory / 'native-global-custom.conf'),
                        patch.object(webuzo, 'CUSTOM', self.custom),
                        patch.object(webuzo, 'SNIPPETS', self.snippets),
                        patch.object(engine, 'reload_nginx'),
                        patch.object(engine, 'managed_path', side_effect=lambda p: Path(p)),
                        patch.object(engine.storage, 'read', side_effect=fixture_read),
                        patch.object(engine.storage, 'replace', side_effect=fixture_replace)]
        for item in self.patches: item.start()
        self.site = {'key': 'alice/example.test', 'domain': 'example.test', 'owner': 'alice', 'supported': True,
                     'paths': [str(self.domain_file)]}

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def test_failed_candidate_restores_files_and_policy(self):
        policy = copy.deepcopy(DEFAULT)
        old = (MARKER + '\n# Previous active configuration\n').encode()
        self.global_file.write_bytes(old)
        (self.state / 'policy.json').write_text(json.dumps(policy))
        (self.state / 'manifest.json').write_text(json.dumps([str(self.global_file)]))
        candidate = copy.deepcopy(policy); candidate['mode'] = 'enforce'
        with patch.object(engine, 'verify', side_effect=RuntimeError('nginx: unknown directive')), \
                patch.object(engine, 'run', return_value='') as command:
            with self.assertRaisesRegex(RuntimeError, 'unknown directive'):
                engine.apply(candidate, [self.site])
        self.assertEqual(self.global_file.read_bytes(), old)
        self.assertFalse(self.domain_file.exists())
        self.assertEqual(json.loads((self.state / 'policy.json').read_text()), policy)
        self.assertFalse((self.state / 'transaction.json').exists())
        self.assertIn((webuzo.NGINX, '-t'), [c.args for c in command.call_args_list])

    def test_success_then_noop_never_reload_again(self):
        with patch.object(engine, 'verify'), patch.object(engine, 'reload_nginx') as reload:
            first = engine.apply(DEFAULT, [self.site])
            second = engine.apply(DEFAULT, [self.site])
        self.assertEqual(first['changed_files'], 2)
        self.assertEqual(second['changed_files'], 0)
        self.assertEqual(reload.call_count, 1)

    def test_interrupted_apply_recovers_previous_state(self):
        self.global_file.write_bytes((MARKER + '\n# Partial candidate\n').encode())
        record = {'schema': 1, 'before': {str(self.global_file): None},
                  'policy.json': None, 'manifest.json': None}
        (self.state / 'transaction.json').write_text(json.dumps(record))
        with patch.object(engine, 'run', return_value=''):
            engine.recover()
        self.assertFalse(self.global_file.exists())
        self.assertFalse((self.state / 'transaction.json').exists())

    def test_collision_does_not_overwrite_unmanaged_file(self):
        self.domain_file.write_text('# Other addon\n')
        with self.assertRaisesRegex(ValueError, 'not owned'):
            engine.apply(DEFAULT, [self.site])
        self.assertEqual(self.domain_file.read_text(), '# Other addon\n')

    def test_uninstall_keeps_unrelated_files(self):
        neighbor = self.directory / 'nginx.conf_other'; neighbor.write_text('unrelated')
        with patch.object(engine, 'verify'), patch.object(engine, 'run', return_value=''):
            engine.apply(DEFAULT, [self.site])
            engine.apply(DEFAULT, [], remove=True)
        self.assertFalse(self.domain_file.exists())
        self.assertFalse(self.global_file.exists())
        self.assertEqual(neighbor.read_text(), 'unrelated')

    def test_failed_panel_reload_restores_both_native_instances_and_policy_history(self):
        mail = dict(key='root/webmail', domain='webmail', owner='root', kind='mail', shared_webmail=True,
                    supported=True, native_logs=['/var/log/native-panel.log'])
        snippet = self.directory / 'webmail.conf'
        custom = self.directory / 'panel-custom.conf'
        with patch.object(engine.webmail, 'SNIPPET', snippet), patch.object(engine.webmail, 'CUSTOM', custom), \
                patch.object(engine, 'verify'), patch.object(engine.webmail, 'verify'), \
                patch.object(engine, 'run', return_value=''), patch.object(engine.webmail, 'reload') as reload:
            engine.apply(DEFAULT, [self.site, mail])
            old = self.global_file.read_bytes()
            candidate = copy.deepcopy(DEFAULT)
            candidate.update(mode='enforce', mail_protection=True, agents=['Scanner'])
            reload.side_effect = [RuntimeError('Panel reload failed'), None]
            with self.assertRaisesRegex(RuntimeError, 'Panel reload failed'):
                engine.apply(candidate, [self.site, mail])
            self.assertEqual(reload.call_count, 2)
            self.assertEqual(self.global_file.read_bytes(), old)
            self.assertFalse(snippet.exists())
            self.assertFalse(custom.exists())
            self.assertFalse((self.state / engine.webmail.HISTORY).exists())
            self.assertFalse((self.state / 'transaction.json').exists())
            self.assertEqual(json.loads((self.state / 'policy.json').read_text()), DEFAULT)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(engine.ban_history, 'settings', return_value={'days': 30}))

    def test_stale_v6_save_preserves_general_404_and_domain_switches(self):
        incoming=json.loads((Path(__file__).parent/'fixtures/policy-v6.json').read_text())
        incoming['domain_bans']['allow_users']=False
        saved=copy.deepcopy(DEFAULT)
        saved['bans']['any_404'].update(enabled=True,maxretry=13)
        saved['domain_bans']['sites']={'alice/example.test':dict(missing_files=False,suspicious_queries=False,any_404=True)}
        with patch.object(engine,'authorize',return_value=(True,'admin')), \
             patch.object(engine,'load',return_value=saved),patch.object(engine,'collect',return_value=[]), \
             patch.object(engine,'apply') as apply,patch.object(engine,'snapshot',return_value={}):
            engine.dispatch({'actor':'admin','action':'save','policy':incoming})
            actual=apply.call_args.args[0]
            self.assertEqual(actual['bans']['any_404'],saved['bans']['any_404'])
            self.assertEqual(actual['domain_bans']['sites'],saved['domain_bans']['sites'])
            self.assertFalse(actual['domain_bans']['allow_users'])

    def test_native_ban_failure_is_not_reported_as_a_successful_sync(self):
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'load', return_value=DEFAULT), \
                patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine, 'apply'), \
                patch.object(engine.storage, 'replace'), \
                patch.object(engine.auto_bans, 'synchronize', return_value={'error': 'native failure'}):
            with self.assertRaisesRegex(RuntimeError, 'automatic web bans failed: native failure'):
                engine.dispatch({'actor': 'admin', 'action': 'sync'})

    def test_old_panel_save_preserves_exceptions_but_new_panel_can_clear_them(self):
        saved = copy.deepcopy(DEFAULT)
        saved['static_exceptions'] = {'alice/example.test': ['/wp-content/dynamic.map']}
        old = {key: copy.deepcopy(value) for key, value in DEFAULT.items() if key in LEGACY_KEYS | {'filters', 'static'}}
        old['schema'] = 2
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'load', return_value=saved), \
                patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine, 'apply') as apply, \
                patch.object(engine.activity, 'summary', return_value={}):
            engine.dispatch({'actor': 'admin', 'action': 'save', 'policy': old})
            self.assertEqual(apply.call_args.args[0]['static_exceptions'], saved['static_exceptions'])
            engine.dispatch({'actor': 'admin', 'action': 'save', 'policy': copy.deepcopy(DEFAULT)})
            self.assertEqual(apply.call_args.args[0]['static_exceptions'], {})

    def test_stale_v4_panel_preserves_new_probe_settings_and_exceptions(self):
        saved = copy.deepcopy(DEFAULT)
        saved['bans']['missing_files'].update(enabled=True, maxretry=4)
        saved['probe_exceptions']['queries'] = {'alice/example.test': ['/manager.php']}
        incoming = {key: copy.deepcopy(DEFAULT[key]) for key in V9_KEYS}; incoming['schema'] = 4; incoming.pop('probe_exceptions'); incoming.pop('domain_bans')
        incoming.pop('enumeration')
        for key in ('missing_files', 'suspicious_queries', 'any_404'): incoming['bans'].pop(key)
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'load', return_value=saved), \
                patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine, 'apply') as apply, \
                patch.object(engine.activity, 'summary', return_value={}):
            engine.dispatch({'actor': 'admin', 'action': 'save', 'policy': incoming})
            actual = apply.call_args.args[0]
            self.assertEqual(actual['bans']['missing_files'], saved['bans']['missing_files'])
            self.assertEqual(actual['probe_exceptions'], saved['probe_exceptions'])

    def test_user_cannot_change_global_policy_or_select_another_owner(self):
        with patch.object(webuzo, 'users', return_value={'alice': {'suspended': False}}):
            for request in [{'actor': 'alice', 'owner': 'bob', 'action': 'status'},
                            {'actor': 'alice', 'action': 'save'},
                            {'actor': 'alice', 'action': 'unban'},
                            {'actor': 'alice', 'action': 'bulk'}]:
                with self.assertRaises(PermissionError):
                    engine.authorize(request)

    def test_user_status_contains_only_own_domains_and_no_global_agent_policy(self):
        sites = [{'key': owner + '/example.test', 'owner': owner, 'domain': 'example.test',
                  'template': 'default', 'aliases': '', 'suspended': False,
                  'supported': True, 'reason': ''} for owner in ('alice', 'bob')]
        data = engine.snapshot(DEFAULT, sites, 'alice')
        self.assertEqual([s['owner'] for s in data['sites']], ['alice'])
        self.assertNotIn('agents', data['policy'])

    def test_admin_viewing_an_owner_gets_the_owner_activity_scope(self):
        sites = [{'key': owner + '/' + owner + '.test', 'owner': owner, 'domain': owner + '.test',
                  'template': 'default', 'aliases': '', 'suspended': False,
                  'supported': True, 'reason': ''} for owner in ('alice', 'bob')]
        with patch.object(engine, 'authorize', return_value=(True, 'alice')), \
                patch.object(engine, 'load', return_value=DEFAULT), \
                patch.object(engine, 'collect', return_value=sites), \
                patch.object(engine.activity, 'summary', return_value={}) as summary:
            data = engine.dispatch({'actor': 'admin', 'owner': 'alice', 'action': 'status'})
            self.assertEqual([s['owner'] for s in data['sites']], ['alice'])
            summary.assert_not_called()
            self.assertTrue(data['activity']['on_demand'])


if __name__ == '__main__':
    unittest.main()
