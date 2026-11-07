"""Installer accepts only a fresh reviewed OS package plan, never HTTP commands."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

import f2b_install as installer
import host_protection as host
import storage
from test_engine import fixture_read, fixture_replace


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.enterContext(patch.object(storage, 'read', side_effect=fixture_read))
        self.enterContext(patch.object(storage, 'replace', side_effect=fixture_replace))
        self.os = self.state / 'os-release'; self.os.write_text('ID=ubuntu\nPRETTY_NAME="Ubuntu test"\n')
        self.enterContext(patch.object(installer, 'OS_RELEASE', self.os))
        self.enterContext(patch.object(host, 'binary', side_effect=lambda name: None if name == 'fail2ban-client' else '/usr/bin/' + name))
        self.enterContext(patch.object(host, 'service_blockers', return_value=[]))
        self.run = Mock(side_effect=self.command)
        self.origins = [{'origin': 'Ubuntu', 'trusted': True}]
        self.simulation = 'Inst fail2ban (1.0.2 Ubuntu:24.04/noble [all])\nConf fail2ban\n'

    def command(self, *argv, **kwargs):
        if argv[1:3] == ('policy', 'fail2ban'):
            return 'fail2ban:\n  Candidate: 1.0.2\n'
        if argv[0] == '/usr/bin/python3':
            if len(argv) == 5:
                return json.dumps([dict(name=name, origins=self.origins) for name, version in json.loads(argv[-1])])
            return json.dumps(dict(version='1.0.2', origins=self.origins))
        if '-s' in argv:
            return self.simulation
        return 'OK'

    def test_preview_is_read_only_and_uses_fixed_package_with_verified_origin(self):
        value = installer.preview(self.state, self.run)
        self.assertEqual(value['package'], 'fail2ban'); self.assertEqual(len(value['token']), 64)
        self.assertEqual(value['command'][-1], 'fail2ban=1.0.2')
        self.assertIn('DEBIAN_FRONTEND=noninteractive', value['command'])
        self.assertTrue(all('-y' not in call.args for call in self.run.call_args_list))
        self.assertFalse((self.state / installer.JOB).exists())

    def test_csf_blocks_installation_preview_without_commands_or_plan(self):
        with patch.object(host, 'service_blockers', return_value=['CSF']):
            with self.assertRaisesRegex(ValueError, 'package scripts'):
                installer.preview(self.state, self.run)
        self.run.assert_not_called()
        self.assertFalse((self.state / installer.PLAN).exists())

    def test_csf_appearing_after_preview_blocks_start_without_spawn(self):
        value = installer.preview(self.state, self.run)
        self.run.reset_mock()
        with patch.object(host, 'service_blockers', return_value=['LFD']), \
                patch.object(installer.os, 'posix_spawn', create=True) as spawn:
            with self.assertRaisesRegex(ValueError, 'automatic Fail2ban installation'):
                installer.start(self.state, value['token'], self.run)
        self.run.assert_not_called(); spawn.assert_not_called()
        self.assertFalse((self.state / installer.JOB).exists())

    def test_worker_rechecks_csf_before_package_commands_even_after_a_valid_preview(self):
        plan = installer.preview(self.state, self.run)
        job = dict(id='a' * 32, state='queued', created=plan['created'], version=plan['version'])
        (self.state / installer.JOB).write_text(json.dumps(job))
        self.run.reset_mock()
        with patch.object(host, 'service_blockers', return_value=['CSF']):
            installer.worker(self.state, job['id'], self.run)
        self.run.assert_not_called()
        self.assertEqual(installer.status(self.state)['state'], 'failed')
        self.assertIn('package scripts', installer.status(self.state)['error'])

    def test_worker_rechecks_csf_after_package_planning_and_before_install(self):
        plan = installer.preview(self.state, self.run)
        job = dict(id='b' * 32, state='queued', created=plan['created'], version=plan['version'])
        (self.state / installer.JOB).write_text(json.dumps(job))
        self.run.reset_mock()
        with patch.object(host, 'service_blockers', side_effect=[[], ['CSF']]):
            installer.worker(self.state, job['id'], self.run)
        self.assertTrue(all('-y' not in call.args for call in self.run.call_args_list))
        self.assertEqual(installer.status(self.state)['state'], 'failed')

    def test_third_party_untrusted_and_mixed_origins_are_rejected(self):
        for origins in [[dict(origin='ThirdParty', trusted=True)], [dict(origin='Ubuntu', trusted=False)],
                        [dict(origin='Ubuntu', trusted=True), dict(origin='Other', trusted=True)], []]:
            self.origins = origins
            with self.subTest(origins=origins), self.assertRaisesRegex(ValueError, 'authenticated'):
                installer.preview(self.state, self.run)
        self.assertFalse((self.state / installer.PLAN).exists())

    def test_no_automatic_repository_addition_for_unsupported_os_or_missing_candidate(self):
        self.os.write_text('ID=other\n')
        with self.assertRaisesRegex(ValueError, 'manually'): installer.preview(self.state, self.run)
        self.run.assert_not_called()
        self.os.write_text('ID=ubuntu\n')
        self.run.side_effect = lambda *args: 'Candidate: (none)'
        with self.assertRaisesRegex(ValueError, 'No Fail2ban package'): installer.preview(self.state, self.run)

    def test_removing_existing_packages_is_rejected(self):
        self.simulation += 'Remv unrelated-service [1.0]\n'
        with self.assertRaisesRegex(ValueError, 'removing'): installer.preview(self.state, self.run)

    def test_local_dpkg_status_is_not_mistaken_for_an_untrusted_download(self):
        self.origins.append(dict(origin='', trusted=False, archive='now', site=''))
        # The dependency query in real python-apt excludes this status-only record.
        self.simulation = '0 upgraded, 0 newly installed, 0 to remove\n'
        self.assertEqual(installer.candidate(self.run)['version'], '1.0.2')

    def test_package_preview_omits_unrelated_apt_autoremove_suggestions(self):
        self.simulation = 'Use apt autoremove to remove unrelated packages.\n' + self.simulation
        result = installer.candidate(self.run)
        self.assertIn('Inst fail2ban', result['changes'])
        self.assertNotIn('autoremove', result['changes'])

    def test_start_requires_fresh_matching_plan_and_spawns_only_fixed_worker(self):
        value = installer.preview(self.state, self.run)
        with patch.object(installer.os, 'posix_spawn', create=True) as spawn, \
             patch.object(installer.os, 'POSIX_SPAWN_OPEN', 0, create=True):
            with self.assertRaises(ValueError): installer.start(self.state, '0' * 64, self.run)
            spawn.assert_not_called()
            result = installer.start(self.state, value['token'], self.run)
            args = spawn.call_args.args[1]
            self.assertEqual(args[:3], ['/usr/bin/python3', '-I', '-B'])
            self.assertEqual(args[-2:], ['--worker', result['id']])
            self.assertNotIn(value['token'], args)
            installer.start(self.state, value['token'], self.run)
            spawn.assert_called_once()

    def test_changed_package_plan_does_not_spawn(self):
        value = installer.preview(self.state, self.run)
        self.simulation += 'Inst extra-package (1.0 Ubuntu:24.04/noble [all])\n'
        with patch.object(installer.os, 'posix_spawn', create=True) as spawn:
            with self.assertRaisesRegex(ValueError, 'changed'): installer.start(self.state, value['token'], self.run)
            spawn.assert_not_called()

    def test_worker_rechecks_plan_records_errors_and_never_runs_unreviewed_install(self):
        plan = installer.preview(self.state, self.run)
        job = dict(id='a' * 32, state='queued', created=plan['created'], version=plan['version'])
        (self.state / installer.JOB).write_text(json.dumps(job))
        self.origins = [dict(origin='Other', trusted=True)]
        self.run.reset_mock()
        installer.worker(self.state, job['id'], self.run)
        self.assertEqual(installer.status(self.state)['state'], 'failed')
        self.assertTrue(all('-y' not in call.args for call in self.run.call_args_list))

    def test_successful_worker_installs_checks_starts_and_verifies_daemon(self):
        plan = installer.preview(self.state, self.run)
        job = dict(id='a' * 32, state='queued', created=plan['created'], version=plan['version'])
        (self.state / installer.JOB).write_text(json.dumps(job))
        with patch.object(host, 'client', return_value='/usr/bin/fail2ban-client'), \
             patch.object(host, 'active_jails', return_value=['sshd']):
            installer.worker(self.state, job['id'], self.run)
        self.assertEqual(installer.status(self.state)['state'], 'complete')
        calls = [call.args for call in self.run.call_args_list]
        self.assertIn(tuple(plan['command']), calls)
        self.assertIn(('/usr/bin/fail2ban-client', '-t'), calls)
        self.assertIn(('/usr/bin/systemctl', 'enable', '--now', 'fail2ban'), calls)
        self.assertFalse((self.state / installer.PLAN).exists())

    def test_progress_tracks_package_configuration_and_service_phases(self):
        plan = installer.preview(self.state, self.run)
        job = dict(id='b' * 32, state='queued', created=plan['created'], version=plan['version'])
        (self.state / installer.JOB).write_text(json.dumps(job))
        phases = []
        def command(*argv, **kwargs):
            if '-y' in argv or argv[1:] in [('-t',), ('enable', '--now', 'fail2ban')]:
                current = installer.status(self.state)
                self.assertEqual(current['state'], 'running')
                phases.append(current['message'])
            return self.command(*argv, **kwargs)
        self.run.side_effect = command
        with patch.object(host, 'client', return_value='/usr/bin/fail2ban-client'), \
                patch.object(host, 'active_jails', return_value=['sshd']):
            installer.worker(self.state, job['id'], self.run)
        self.assertEqual(phases, [
            'Installing Fail2ban packages. Service checks will follow when APT finishes.',
            'Packages installed. Checking Fail2ban configuration.',
            'Starting Fail2ban and checking service readiness.'])
        self.assertEqual(installer.status(self.state)['state'], 'complete')
