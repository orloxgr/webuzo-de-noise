"""Authentication isolation, real native-filter tests, and reversible jail changes."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import f2b_install
import host_protection as host
import storage
import webuzo
from policy import DEFAULT, global_config, site_config, validate
from test_engine import fixture_read, fixture_replace


class InputTests(unittest.TestCase):
    def test_csf_and_lfd_installations_are_detected_even_without_a_running_service(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root / 'csf.conf'; unit = root / 'lfd.service'
            with patch.object(host, 'COMPETING_PROTECTION', {'CSF': (str(config),), 'LFD': (str(unit),)}):
                self.assertEqual(host.service_blockers(), [])
                config.write_text('TESTING="0"')
                self.assertEqual(host.service_blockers(), ['CSF'])
                unit.write_text('[Unit]\nDescription=Existing LFD\n')
                self.assertEqual(host.service_blockers(), ['CSF', 'LFD'])

    def test_only_supported_services_and_valid_ips_and_numbers_are_accepted(self):
        for key, value in [('maxretry', True), ('findtime', 0), ('bantime', -1),
                           ('enabled', 'yes'), ('ignore_ips', ['1.2.3.4\naction=bad'])]:
            candidate = copy.deepcopy(host.DEFAULT); candidate['ssh'][key] = value
            with self.assertRaises(ValueError): host.validate(candidate)
        candidate = copy.deepcopy(host.DEFAULT); candidate['ssh']['command'] = 'bad'
        with self.assertRaises(ValueError): host.validate(candidate)
        with self.assertRaises(ValueError): host.jail('../sshd')
        candidate = copy.deepcopy(host.DEFAULT); candidate['imap']['ignore_ips'] = ['192.0.2.5/24', '192.0.2.0/24', '2001:db8::1']
        self.assertEqual(host.validate(candidate)['imap']['ignore_ips'], ['192.0.2.0/24', '2001:db8::1/128'])

    def test_ports_are_taken_from_matching_processes_and_not_default_service_numbers(self):
        output = '\n'.join([
            'LISTEN 0 100 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=4))',
            'LISTEN 0 100 [::]:2587 [::]:* users:(("exim",pid=2,fd=5))',
            'LISTEN 0 100 0.0.0.0:22 0.0.0.0:* users:(("unrelated",pid=3,fd=6))',
            'LISTEN 0 100 0.0.0.0:993 0.0.0.0:* users:(("dovecot",pid=4,fd=7))'])
        ports = host.listeners(output)
        self.assertEqual(ports['ssh'], [2222]); self.assertEqual(ports['smtp'], [2587])
        self.assertEqual(ports['imap'], [993]); self.assertEqual(ports['ftp'], [])

    def test_account_and_impersonated_contexts_cannot_manage_or_install_fail2ban(self):
        actions = ['fail2ban_status', 'fail2ban_start', 'fail2ban_save', 'fail2ban_unban',
                   'fail2ban_test', 'fail2ban_install_preview', 'fail2ban_install_start', 'fail2ban_install_status',
                   'domain_bans_save']
        with patch.object(engine.webuzo, 'users', return_value={'alice': {'suspended': False}}):
            for action in actions:
                with self.subTest(action=action), self.assertRaises(PermissionError):
                    engine.dispatch(dict(actor='alice', owner='alice', action=action))
        with self.assertRaises(PermissionError):
            engine.dispatch(dict(actor='root', owner='alice', action='fail2ban_status'))
        with self.assertRaises(ValueError):
            engine.dispatch(dict(actor='root', action='fail2ban_start', command='bad'))

    def test_legacy_preferences_are_retired_without_changing_global_rules(self):
        old = copy.deepcopy(DEFAULT); old['schema'] = 10
        old['domain_bans'] = dict(allow_users=True, sites={'alice/one.test': dict(missing_files=True, suspicious_queries=True, any_404=True)})
        old.update(mode='enforce', agents=['MyBot'])
        old['bans']['enabled'] = True
        value = validate(old)
        self.assertNotIn('domain_bans', value)
        self.assertEqual(value['bans'], old['bans']); self.assertEqual(value['agents'], ['MyBot'])
        self.assertEqual(value['mode'], 'enforce')
        text = global_config(value, [dict(key='alice/one.test')]) + site_config(value, dict(key='alice/one.test'))
        self.assertNotIn('hdn_domain_', text); self.assertNotIn('hdn_local_', text)
        self.assertIn('global-ban', text); self.assertIn('hdn_agent', text)

    def test_service_status_does_not_query_partially_unpacked_fail2ban(self):
        for stage in ('queued', 'running'):
            with self.subTest(stage=stage), \
                    patch.object(f2b_install, 'status', return_value={'state': stage}), \
                    patch.object(host, 'binary', return_value='/usr/bin/fail2ban-client'), \
                    patch.object(host, 'settings', return_value=copy.deepcopy(host.DEFAULT)), \
                    patch.object(engine.wordpress, 'snapshot', return_value={}), \
                    patch.object(engine, 'run') as run:
                result = engine.dispatch(dict(actor='root', owner='root', action='fail2ban_status'))
                self.assertEqual(result['install_job']['state'], stage)
                self.assertTrue(result['fail2ban']['installed'])
                self.assertFalse(result['fail2ban']['loaded'])
                self.assertNotIn('error', result['fail2ban'])
                run.assert_not_called()

    def test_service_status_resumes_live_checks_after_installation_finishes(self):
        for stage in ('idle', 'complete', 'failed'):
            with self.subTest(stage=stage), \
                    patch.object(f2b_install, 'status', return_value={'state': stage}), \
                    patch.object(host, 'snapshot', return_value={}) as snapshot, \
                    patch.object(engine.wordpress, 'snapshot', return_value={}):
                engine.dispatch(dict(actor='root', owner='root', action='fail2ban_status'))
                snapshot.assert_called_once_with(engine.STATE, engine.run, live=True)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.state = self.root / 'state'; self.state.mkdir()
        self.etc = self.root / 'etc'; (self.etc / 'jail.d').mkdir(parents=True)
        (self.etc / 'filter.d').mkdir()
        self.enterContext(patch.object(host, 'ETC', self.etc))
        self.enterContext(patch.object(storage, 'read', side_effect=fixture_read))
        self.enterContext(patch.object(storage, 'replace', side_effect=fixture_replace))
        self.enterContext(patch.object(host, 'client', return_value='/usr/bin/fail2ban-client'))
        self.enterContext(patch.object(host, 'firewall_action', return_value='nftables-multiport'))
        self.enterContext(patch.object(host, 'inherited_exclusions', return_value=False))
        self.detected = {key: dict(ready=True, ports=[2222] if key == 'ssh' else [993],
                         title=spec['title'], source=dict(backend='auto', logpath=spec['logs'][0]))
                         for key, spec in host.SERVICES.items()}
        self.enterContext(patch.object(host, 'discover', return_value=self.detected))
        self.enterContext(patch.object(host, 'test_filter', return_value=dict(lines=3, matches=1)))
        self.enterContext(patch.object(host, 'duplicates', return_value=[]))
        self.enabled = copy.deepcopy(host.DEFAULT); self.enabled['imap']['enabled'] = True
        self.run = Mock(return_value='OK')

    def test_csf_appearing_after_page_load_blocks_every_forged_service_enable_before_writes(self):
        csf = self.root / 'csf.conf'
        with patch.object(host, 'COMPETING_PROTECTION', {'CSF': (str(csf),)}), \
                patch.object(engine, 'STATE', self.state), patch.object(engine, 'run', self.run):
            self.assertFalse(host.snapshot(self.state, self.run)['service_activation_blocked'])
            csf.write_text('TESTING = "0"\nLF_SSHD = "5"\n')
            for key in host.SERVICES:
                value = copy.deepcopy(host.DEFAULT); value[key]['enabled'] = True
                with self.subTest(service=key), self.assertRaisesRegex(ValueError, 'cannot be enabled'):
                    engine.dispatch(dict(actor='root', owner='root', action='fail2ban_save', settings=value))
            self.run.assert_not_called()
            self.assertEqual(list(self.state.iterdir()), [])
            self.assertFalse((self.etc / host.CONFIG).exists())
            self.assertEqual(csf.read_text(), 'TESTING = "0"\nLF_SSHD = "5"\n')

    def test_csf_detection_allows_disabling_our_existing_jails_without_changing_other_protection(self):
        csf = self.root / 'csf.conf'
        other = self.etc / 'jail.d/other.local'; other.write_bytes(b'[other]\nenabled=true\n')
        with patch.object(host, 'COMPETING_PROTECTION', {'CSF': (str(csf),)}):
            with patch.object(host, 'active_jails', side_effect=[[], [host.jail('imap')]]):
                host.apply(self.state, self.enabled, self.run)
            csf.write_text('unchanged CSF settings')
            self.assertTrue(host.settings(self.state)['imap']['enabled'])
            status = host.snapshot(self.state, self.run)
            self.assertTrue(status['service_activation_blocked'])
            self.assertEqual(status['service_blockers'], ['CSF'])
            with patch.object(host, 'active_jails', side_effect=[[host.jail('imap')], []]):
                host.apply(self.state, copy.deepcopy(host.DEFAULT), self.run)
            self.assertFalse(any(rule['enabled'] for rule in host.settings(self.state).values()))
            self.assertEqual(other.read_bytes(), b'[other]\nenabled=true\n')
            self.assertEqual(csf.read_text(), 'unchanged CSF settings')

    def test_unverifiable_csf_inspection_blocks_activation_without_writes(self):
        with patch.object(host, 'service_blockers', side_effect=PermissionError('inspection denied')):
            with self.assertRaises(PermissionError): host.apply(self.state, self.enabled, self.run)
            status = host.snapshot(self.state, self.run)
        self.assertTrue(status['service_activation_blocked'])
        self.run.assert_not_called()
        self.assertEqual(list(self.state.iterdir()), [])

    def test_apply_changes_only_our_files_and_uses_service_ports_with_native_action(self):
        other = self.etc / 'jail.d/other.local'; other.write_bytes(b'[other]\nenabled=true\n')
        with patch.object(host, 'active_jails', side_effect=[['sshd'], ['sshd', host.jail('imap')]]):
            host.apply(self.state, self.enabled, self.run)
        text = (self.etc / host.CONFIG).read_text()
        self.assertIn('filter = wdn-dovecot-auth[mode=normal]', text)
        self.assertIn('port="993"', text); self.assertNotIn('allports', text)
        self.assertIn('ignoreself = true', text)
        self.assertNotIn('ignoreip =', text)
        self.assertEqual(other.read_bytes(), b'[other]\nenabled=true\n')
        self.assertEqual([call.args[1:] for call in self.run.call_args_list], [('-t',), ('reload',)])
        host.uninstall(self.state, self.run)
        self.assertFalse((self.etc / host.CONFIG).exists()); self.assertEqual(other.read_bytes(), b'[other]\nenabled=true\n')

    def test_rejected_candidate_restores_files_and_has_no_reload(self):
        self.run.side_effect = RuntimeError('bad candidate')
        with patch.object(host, 'active_jails', return_value=[]), self.assertRaisesRegex(RuntimeError, 'bad candidate'):
            host.apply(self.state, self.enabled, self.run)
        self.assertFalse((self.etc / host.CONFIG).exists()); self.assertFalse((self.state / host.RECEIPT).exists())
        self.assertEqual(self.run.call_count, 1)

    def test_reload_failure_restores_previous_configuration_and_reloads_it(self):
        self.run.side_effect = ['OK', RuntimeError('reload failed'), 'OK', 'OK']
        with patch.object(host, 'active_jails', return_value=[]), self.assertRaisesRegex(RuntimeError, 'reload failed'):
            host.apply(self.state, self.enabled, self.run)
        self.assertFalse((self.etc / host.CONFIG).exists()); self.assertFalse((self.state / host.JOURNAL).exists())
        self.assertEqual(self.run.call_count, 4)

    def test_reload_reporting_success_with_missing_jail_is_rolled_back(self):
        with patch.object(host, 'active_jails', return_value=[]), self.assertRaisesRegex(RuntimeError, 'did not apply'):
            host.apply(self.state, self.enabled, self.run)
        self.assertFalse((self.etc / host.CONFIG).exists()); self.assertEqual(self.run.call_count, 4)

    def test_existing_native_jail_and_unowned_file_are_never_replaced(self):
        with patch.object(host, 'active_jails', return_value=['sshd']), \
             patch.object(host, 'duplicates', return_value=['dovecot']), self.assertRaisesRegex(ValueError, 'Existing protection'):
            host.apply(self.state, self.enabled, self.run)
        self.run.assert_not_called()
        (self.etc / host.CONFIG).write_bytes(b'# administrator\n')
        with patch.object(host, 'active_jails', return_value=[]), self.assertRaises(ValueError):
            host.apply(self.state, self.enabled, self.run)
        self.assertEqual((self.etc / host.CONFIG).read_bytes(), b'# administrator\n')

    def test_recovery_cannot_target_an_arbitrary_file(self):
        (self.state / host.JOURNAL).write_text(json.dumps(dict(before={str(self.root / 'foreign'): None}, reload_started=False, receipt_created=False)))
        with self.assertRaisesRegex(ValueError, 'recovery paths'): host.recover(self.state, self.run)

    def test_unban_can_only_remove_an_existing_managed_service_ip(self):
        (self.state / host.RECEIPT).write_text('{}')
        self.run.return_value = '192.0.2.5'
        with self.assertRaises(ValueError): host.unban(self.state, 'imap', ['192.0.2.6'], self.run)
        host.unban(self.state, 'imap', ['192.0.2.5'], self.run)
        self.assertEqual(self.run.call_args.args[1:], ('set', host.jail('imap'), 'unbanip', '192.0.2.5'))


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-owned Linux service storage')
class NativeTests(unittest.TestCase):
    def test_authentication_reader_rejects_links_fifos_and_customer_owned_logs(self):
        with tempfile.TemporaryDirectory(dir="/root") as temp:
            root = Path(temp); path = root / 'auth.log'
            spec = {'test': dict(logs=[str(path)])}
            with patch.object(host, 'SERVICES', spec):
                path.write_text('native authentication log')
                with host.log_stream(path) as stream: self.assertEqual(stream.read(), b'native authentication log')
                path.chmod(0o666)
                with self.assertRaises(ValueError):
                    with host.log_stream(path): pass
                path.chmod(0o600); os.chown(path, 65534, 65534)
                with self.assertRaises(ValueError):
                    with host.log_stream(path): pass
                path.unlink(); target = root / 'other'; target.write_text('secret')
                path.symlink_to(target)
                with self.assertRaises(OSError):
                    with host.log_stream(path): pass
                path.unlink(); os.mkfifo(path)
                with self.assertRaises(ValueError):
                    with host.log_stream(path): pass

    def test_dovecot_24_counts_authentication_failures_only_and_rejects_injected_usernames(self):
        prefix = 'Nov  7 12:00:00 imap-login: Info: Login aborted: Logged out '
        messages = [
            '(auth failed, 1 attempts in 2 secs) (auth_failed): user=<invalid>, method=PLAIN, rip=192.0.2.25, lip=192.0.2.26, secured, session=<abc123>',
            '(auth failed, 1 attempts in 2 secs) (auth_failed): user=<invalid>, method=PLAIN, rip=2001:db8::25, lip=2001:db8::26, TLS, session=<abc123>',
            '(no auth attempts in 0 secs) (no_auth_attempts): user=<>, rip=192.0.2.25, lip=192.0.2.26, secured, session=<abc123>',
            '(disconnected during TLS handshake) (tls_handshake_not_finished): user=<>, rip=192.0.2.25, lip=192.0.2.26, secured, session=<abc123>',
            '(auth failed, 1 attempts in 2 secs) (auth_failed): user=<evil>, method=PLAIN, rip=192.0.2.99, lip=192.0.2.26, secured, session=<abc123>fake>, method=PLAIN, rip=192.0.2.25, lip=192.0.2.26, secured, session=<abc123>']
        with tempfile.TemporaryDirectory() as temp, patch.object(host, 'sample', return_value=('\n'.join(prefix + message for message in messages) + '\n').encode()):
            result = host.test_filter(Path(temp), 'imap', dict(ready=True), webuzo.run)
            self.assertEqual(result['matches'], 2)

    def test_regex_tests_native_patterns_and_removes_private_samples(self):
        fixtures = {
            'ssh': 'Nov  7 12:00:00 host sshd[123]: Failed password for invalid user test from 192.0.2.25 port 12345 ssh2\n',
            'imap': 'Nov  7 12:00:00 host dovecot: imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<invalid>, method=PLAIN, rip=192.0.2.25, lip=192.0.2.26, TLS\n',
            'smtp': '2026-11-07 12:00:00 plain authenticator failed for host.example [192.0.2.25]: 535 Incorrect authentication data\n',
            'ftp': 'Nov  7 12:00:00 host pure-ftpd[123]: (?@192.0.2.25) [WARNING] Authentication failed for user [test]\n'}
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp); state.chmod(0o700)
            for key, text in fixtures.items():
                with self.subTest(service=key), patch.object(host, 'sample', return_value=text.encode()):
                    result = host.test_filter(state, key, dict(ready=True), webuzo.run)
                    self.assertEqual(result['matches'], 1)
                    self.assertEqual(list(state.iterdir()), [])

    def test_retirement_removes_only_obsolete_domain_state_and_preserves_global_bans(self):
        import auto_bans
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp); state.chmod(0o700)
            with auto_bans.database(state) as db:
                db.execute('CREATE TABLE domain_bans (site TEXT,ip TEXT)')
                db.execute("INSERT INTO domain_bans VALUES ('alice/one.test','192.0.2.5')")
                db.execute("INSERT INTO bans VALUES ('192.0.2.6','one.test','private-file',1000,0,'active','')")
            with patch.object(engine, 'STATE', state): engine.retire_domain_bans()
            with auto_bans.database(state) as db:
                self.assertFalse(db.execute("SELECT 1 FROM sqlite_master WHERE name='domain_bans'").fetchone())
                self.assertEqual(db.execute('SELECT ip FROM bans').fetchone()[0], '192.0.2.6')
