"""Native-jail settings, recovery and scope; never inspect WordPress."""
import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import wordpress
import engine
from test_engine import fixture_read, fixture_replace


class WordPressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'; self.state.mkdir()
        self.etc = self.root / 'etc'
        for folder in ['filter.d', 'action.d', 'jail.d', 'fail2ban.d']:
            (self.etc / folder).mkdir(parents=True)
        self.patches = [patch.object(wordpress, 'ETC', self.etc),
                        patch.object(wordpress, 'log_source', return_value='backend = auto\nlogpath = /var/log/auth.log tail\n'),
                        patch.object(wordpress.storage, 'read', side_effect=fixture_read),
                        patch.object(wordpress.storage, 'replace', side_effect=fixture_replace)]
        for p in self.patches: p.start()
        self.run = Mock(return_value='OK')
        self.run.side_effect = lambda *args: '86400seconds' if args[1:] == ('get', 'dbpurgeage') else self.run.return_value

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def test_fresh_install_stays_off_and_calls_no_external_commands(self):
        self.assertEqual(wordpress.install(self.state, self.run), {'managed': False})
        status = wordpress.snapshot(self.state, self.run)
        self.assertFalse(status['settings']['enabled'])
        self.assertFalse(status['loaded'])
        self.run.assert_not_called()

    def test_apply_validate_reload_and_namespace_with_exact_duration_seconds(self):
        value = {**copy.deepcopy(wordpress.DEFAULT), 'enabled': True}
        wordpress.apply(self.state, value, self.run)
        jail = (self.etc / 'jail.d/webuzo-denoise-wordpress.local').read_text()
        self.assertIn('ExactBanUnit', jail)
        self.assertIn('bantime.multipliers = 300 259200 -1', jail)
        self.assertIn('filter = wdn-wordpress-login', jail)
        self.assertIn('actname=webuzo-denoise-wordpress', jail)
        self.assertEqual([c.args for c in self.run.call_args_list],
                         [(wordpress.CLIENT, 'get', 'dbpurgeage'), (wordpress.CLIENT, '-t'), (wordpress.CLIENT, 'reload')])
        self.run.reset_mock()
        wordpress.apply(self.state, value, self.run)
        self.run.assert_called_once_with(wordpress.CLIENT, 'get', 'dbpurgeage')

    def test_csf_blocks_service_jails_but_wordpress_protection_remains_available(self):
        host = engine.host_protection
        config = self.root / 'csf.conf'; config.write_text('Existing CSF settings')
        with patch.object(host, 'COMPETING_PROTECTION', {'CSF': (str(config),)}):
            self.assertEqual(host.service_blockers(), ['CSF'])
            wordpress.apply(self.state, {**wordpress.DEFAULT, 'enabled': True}, self.run)
        self.assertIn('enabled = true', (self.etc / 'jail.d/webuzo-denoise-wordpress.local').read_text())
        self.assertEqual(config.read_text(), 'Existing CSF settings')

    def test_candidate_failure_restores_previous_jail_settings_and_other_files(self):
        initial = {**copy.deepcopy(wordpress.DEFAULT), 'enabled': True}
        wordpress.apply(self.state, initial, self.run)
        before = wordpress.capture(wordpress.paths(self.state))
        unrelated = self.etc / 'jail.d/other-service.local'
        unrelated.write_text('[other]\nenabled = true\n')
        failing = Mock(side_effect=['86400seconds', RuntimeError('configuration rejected')])
        with self.assertRaisesRegex(RuntimeError, 'configuration rejected'):
            wordpress.apply(self.state, {**initial, 'maxretry': 4}, failing)
        self.assertEqual(before, wordpress.capture(wordpress.paths(self.state)))
        self.assertEqual(unrelated.read_text(), '[other]\nenabled = true\n')
        self.assertFalse((self.state / wordpress.JOURNAL).exists())

    def test_reload_failure_restores_and_reloads_previous_configuration(self):
        initial = copy.deepcopy(wordpress.DEFAULT)
        wordpress.apply(self.state, initial, self.run)
        before = wordpress.capture(wordpress.paths(self.state))
        command = Mock(side_effect=['86400seconds', 'OK', RuntimeError('reload failed'), 'OK', 'OK'])
        with self.assertRaisesRegex(RuntimeError, 'reload failed'):
            wordpress.apply(self.state, {**initial, 'enabled': True}, command)
        self.assertEqual(before, wordpress.capture(wordpress.paths(self.state)))
        self.assertEqual(command.call_count, 5)

    def test_journal_cannot_restore_an_arbitrary_path(self):
        journal = {'before': {str(self.root / 'unrelated'): base64.b64encode(b'bad').decode()},
                   'reload_started': False, 'receipt_created': False}
        (self.state / wordpress.JOURNAL).write_text(json.dumps(journal))
        with self.assertRaisesRegex(ValueError, 'recovery paths'):
            wordpress.recover(self.state, self.run)
        self.assertFalse((self.root / 'unrelated').exists())

    def test_existing_unowned_file_is_not_replaced(self):
        path = self.etc / 'jail.d/webuzo-denoise-wordpress.local'
        path.write_text('[wordpress-login]\nenabled = true\n')
        with self.assertRaisesRegex(ValueError, 'not owned'):
            wordpress.apply(self.state, wordpress.DEFAULT, self.run)
        self.assertEqual(path.read_text(), '[wordpress-login]\nenabled = true\n')
        self.run.assert_not_called()

    def test_existing_generic_jail_is_preserved_through_our_full_lifecycle(self):
        generic = self.etc / 'jail.d/wordpress-login.local'
        original = b'[wordpress-login]\nenabled = false\nfilter = administrator-custom\n'
        generic.write_bytes(original)
        wordpress.install(self.state, self.run)
        self.run.assert_not_called()
        self.assertFalse(wordpress.settings(self.state)['enabled'])
        wordpress.apply(self.state, {**wordpress.DEFAULT, 'enabled': True}, self.run)
        self.assertEqual(generic.read_bytes(), original)
        wordpress.uninstall(self.state, self.run)
        self.assertEqual(generic.read_bytes(), original)
        self.assertFalse((self.etc / 'jail.d/webuzo-denoise-wordpress.local').exists())
        self.assertFalse((self.etc / 'filter.d/wdn-wordpress-login.conf').exists())
        self.assertFalse((self.state / wordpress.RECEIPT).exists())

    def test_status_reads_only_fail2ban_when_explicitly_requested(self):
        self.run.side_effect = ['Status\n`- Jail list: ssh-iptables, ' + wordpress.JAIL,
                                '192.0.2.5 2001:db8::5']
        data = wordpress.snapshot(self.state, self.run, live=True)
        self.assertTrue(data['active'])
        self.assertEqual(data['ips'], ['192.0.2.5', '2001:db8::5'])
        self.assertTrue(all(c.args[0] == wordpress.CLIENT for c in self.run.call_args_list))

    def test_ip_pagination_keeps_total_and_does_not_poll_when_not_requested(self):
        self.run.side_effect = ['Jail list: ' + wordpress.JAIL, ' '.join(f'198.51.100.{i}' for i in range(123))]
        data = wordpress.snapshot(self.state,self.run,live=True,page=3)
        self.assertEqual(len(data['ips']),23)
        self.assertEqual(data['pagination'],dict(page=3,pages=3,total=123,per_page=50,view='active'))
        self.assertEqual(self.run.call_count,2)
        self.run.reset_mock()
        self.assertEqual(wordpress.snapshot(self.state,self.run,page=3)['ips'],[])
        self.run.assert_not_called()

    def test_unban_only_accepts_ips_belonging_to_wordpress_jail(self):
        wordpress.apply(self.state, wordpress.DEFAULT, self.run)
        self.run.reset_mock(); self.run.return_value = '192.0.2.5'
        with self.assertRaisesRegex(ValueError, 'existing WordPress bans'):
            wordpress.unban(self.state, ['192.0.2.7'], self.run)
        self.assertEqual(self.run.call_count, 1)
        self.run.reset_mock()
        wordpress.unban(self.state, ['192.0.2.5'], self.run)
        self.assertEqual(self.run.call_args.args,
                         (wordpress.CLIENT, 'set', wordpress.JAIL, 'unbanip', '192.0.2.5'))

    def test_unban_all_completes_every_ip_beyond_old_five_hundred_limit(self):
        import ipaddress
        wordpress.apply(self.state,wordpress.DEFAULT,self.run)
        self.run.reset_mock()
        values=[str(ipaddress.ip_address('198.18.0.1')+number) for number in range(650)]
        self.run.return_value=' '.join(values)
        wordpress.unban(self.state,'all',self.run)
        self.assertEqual(self.run.call_count,651)
        self.assertEqual({call.args[-1] for call in self.run.call_args_list[1:]}, set(values))

    def test_users_cannot_invoke_wordpress_actions(self):
        for action in ['wordpress_status', 'wordpress_save', 'wordpress_unban']:
            with patch.object(engine.webuzo, 'users', return_value={'alice': {'suspended': False}}):
                with self.assertRaises(PermissionError):
                    engine.authorize({'actor': 'alice', 'owner': 'alice', 'action': action})

    def test_http_disable_does_not_change_authentication_protection(self):
        from policy import DEFAULT
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'load', return_value=copy.deepcopy(DEFAULT)), \
                patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine, 'apply') as http_apply, \
                patch.object(wordpress, 'read_json', return_value={}), \
                patch.object(wordpress, 'settings', return_value=wordpress.DEFAULT), \
                patch.object(wordpress, 'apply', side_effect=AssertionError('Must not change authentication jails')) as authentication, \
                patch.object(engine, 'snapshot', return_value={}):
            engine.dispatch({'actor': 'admin', 'owner': 'admin', 'action': 'disable'})
            authentication.assert_not_called()
        self.assertEqual(http_apply.call_args.args[0]['mode'], 'off')

    def test_longer_administrator_history_retention_is_never_reduced(self):
        self.run.side_effect = lambda *args: 'Current database purge age is:\n`- 7776000seconds' if args[1:] == ('get', 'dbpurgeage') else 'OK'
        wordpress.apply(self.state, {**wordpress.DEFAULT, 'enabled': True}, self.run)
        history = self.etc / 'fail2ban.d/webuzo-denoise-history.local'
        self.assertIn('dbpurgeage = 7776000', history.read_text())
        wordpress.apply(self.state, wordpress.DEFAULT, self.run)
        self.assertFalse(history.exists())

    def test_unreadable_native_retention_fails_before_any_write(self):
        self.run.side_effect = None
        with self.assertRaisesRegex(ValueError, 'history retention'):
            wordpress.apply(self.state, {**wordpress.DEFAULT, 'enabled': True}, self.run)
        self.assertFalse((self.state / wordpress.JOURNAL).exists())
        self.assertFalse((self.etc / 'jail.d/webuzo-denoise-wordpress.local').exists())

    def test_invalid_policy_cannot_reach_fail2ban(self):
        for update in [{'maxretry': True}, {'findtime': 0}, {'enabled': 'true'},
                       {'durations': [300, 60, -1]}, {'durations': [300, 259200, 0]}]:
            with self.assertRaises(ValueError):
                wordpress.apply(self.state, {**wordpress.DEFAULT, **update}, self.run)
        self.run.assert_not_called()

    def test_arbitrary_durations_preserve_exact_permanent_sentinel_without_float_scaling(self):
        value={**wordpress.DEFAULT, 'durations':[4020,259200,-1]}
        wordpress.validate(value)
        text=next(body.decode() for path,body in wordpress.render(value,self.state).items() if path.name=='webuzo-denoise-wordpress.local')
        self.assertIn('ExactBanUnit',text)
        self.assertIn('bantime.multipliers = 4020 259200 -1',text)
        self.assertNotIn('bantime.factor = 1/',text)



class NativeLogSourceTests(unittest.TestCase):
    def test_journal_backend_includes_hosting_user_events(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(wordpress, 'JOURNAL_DIRECTORY', Path(folder)), \
                    patch.object(wordpress.importlib.util, 'find_spec', return_value=object()):
                source = wordpress.log_source()
        self.assertIn('systemd[journalflags=1]', source)
        self.assertIn('_TRANSPORT=syslog', source)
        self.assertNotIn('logpath', source)

    def test_native_file_fallback_and_missing_prerequisite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); log = root / 'secure'; log.write_text('')
            with patch.object(wordpress, 'JOURNAL_DIRECTORY', root / 'absent'), \
                    patch.object(wordpress, 'AUTH_LOGS', (log,)):
                self.assertIn(str(log), wordpress.log_source())
                log.unlink()
                with self.assertRaisesRegex(ValueError, 'authentication log'):
                    wordpress.log_source()
                with patch.object(wordpress, 'log_source', side_effect=AssertionError('disabled protection needs no log service')):
                    wordpress.render(wordpress.DEFAULT, root)


if __name__ == '__main__':
    unittest.main()
