"""A new Fail2ban install cannot start authentication jails during APT."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import f2b_bootstrap as bootstrap
import host_protection as host
import storage
import wordpress


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux/root fixture')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/var/lib', prefix='wdn-f2b-bootstrap-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.etc = self.root / 'fail2ban'
        self.mask = self.root / 'fail2ban.service'
        self.profile = self.etc / 'jail.d/webuzo-de-noise-bootstrap.local'
        for target, name, value in ((bootstrap, 'MASK', self.mask), (bootstrap, 'PROFILE', self.profile),
                                    (host, 'ETC', self.etc)):
            self.enterContext(patch.object(target, name, value))
        self.enterContext(patch.object(host, 'binary', side_effect=lambda n: '/usr/bin/' + n))
        self.enterContext(patch.object(host, 'client', return_value='/usr/bin/fail2ban-client'))
        self.enterContext(patch.object(bootstrap, 'package_defaults', return_value={'sshd', 'dovecot', 'exim', 'pure-ftpd'}))
        self.run = Mock(side_effect=self.command)

    def command(self, *args, **kwargs):
        if 'show' in args: return 'inactive\n'
        if 'mask' in args: self.mask.symlink_to('/dev/null')
        elif 'unmask' in args: self.mask.unlink()
        elif args[-1:] == ('-d',):
            names = [] if self.profile.exists() else ['sshd']
            return '\n'.join([repr(['set', 'loglevel', 'INFO'])] + [repr(['add', n, 'auto']) for n in names])
        return 'OK'

    def installed_directories(self):
        (self.etc / 'jail.d').mkdir(parents=True, exist_ok=True)

    def test_package_start_is_masked_until_new_default_jails_are_disabled(self):
        bootstrap.prepare(self.state, self.run)
        self.assertTrue(self.mask.is_symlink())
        self.assertTrue((self.state / bootstrap.GUARD).exists())
        self.installed_directories()
        self.assertTrue(bootstrap.finish(self.state, self.run))
        for name in ('sshd', 'dovecot', 'exim', 'pure-ftpd'):
            self.assertIn('[' + name + ']\nenabled = false', self.profile.read_text())
        self.assertFalse(self.mask.is_symlink())
        self.assertFalse((self.state / bootstrap.GUARD).exists())
        calls = [c.args for c in self.run.call_args_list]
        self.assertLess(calls.index(('/usr/bin/fail2ban-client', '-t')), calls.index(('/usr/bin/systemctl', 'unmask', 'fail2ban.service')))
        self.assertFalse(any('stop' in c or 'restart' in c for c in calls))

    def test_existing_configuration_and_its_enabled_ssh_jail_remain_unchanged(self):
        self.installed_directories()
        original = self.etc / 'jail.local'; original.write_text('[sshd]\nenabled=true\nport=22000\n')
        before = original.read_bytes()
        bootstrap.prepare(self.state, self.run)
        with self.assertRaisesRegex(ValueError, 'existing non-WordPress jails'):
            bootstrap.finish(self.state, self.run)
        self.assertEqual(original.read_bytes(), before)
        self.assertFalse(self.profile.exists())
        self.assertTrue(self.mask.is_symlink())
        self.assertTrue((self.state / bootstrap.GUARD).exists())

    def test_existing_wordpress_only_configuration_can_start_without_rewrites(self):
        self.installed_directories()
        original = self.etc / 'jail.local'; original.write_text('# Existing WordPress configuration\n')
        before = original.read_bytes()
        bootstrap.prepare(self.state, self.run)
        with patch.object(host, 'configured_jails', return_value={wordpress.JAIL}):
            bootstrap.finish(self.state, self.run)
        self.assertEqual(original.read_bytes(), before)
        self.assertFalse(self.profile.exists())
        self.assertFalse(self.mask.is_symlink())

    def test_configuration_failure_keeps_mask_and_resume_retains_disabled_defaults(self):
        bootstrap.prepare(self.state, self.run); self.installed_directories()
        def failing(*args):
            if args[-1:] == ('-t',): raise RuntimeError('Invalid native configuration')
            return self.command(*args)
        with self.assertRaisesRegex(RuntimeError, 'Invalid native'):
            bootstrap.finish(self.state, failing)
        saved = self.profile.read_bytes()
        self.assertTrue(self.mask.is_symlink())
        self.assertTrue((self.state / bootstrap.GUARD).exists())
        # Retry never overwrites the guard with an empty default list.
        bootstrap.finish(self.state, self.run)
        self.assertEqual(self.profile.read_bytes(), saved)
        self.assertFalse(self.mask.is_symlink())

    def test_new_install_with_empty_existing_directories_is_supported(self):
        self.installed_directories()
        bootstrap.prepare(self.state, self.run)
        self.assertFalse(json.loads((self.state / bootstrap.GUARD).read_text())['had_configuration'])
        bootstrap.finish(self.state, self.run)
        self.assertTrue(self.profile.exists())

    def test_administrator_mask_or_unit_is_not_replaced_or_removed(self):
        self.mask.symlink_to('/dev/null')
        with self.assertRaisesRegex(ValueError, 'already masked by the administrator'):
            bootstrap.prepare(self.state, self.run)
        self.mask.unlink(); self.mask.write_text('[Service]\nExecStart=/administrator/fail2ban\n')
        with self.assertRaisesRegex(ValueError, 'independently managed'):
            bootstrap.prepare(self.state, self.run)
        self.assertIn('/administrator/fail2ban', self.mask.read_text())
        self.assertFalse((self.state / bootstrap.GUARD).exists())
        self.run.assert_not_called()

    def test_unmanaged_profile_is_not_overwritten(self):
        bootstrap.prepare(self.state, self.run); self.installed_directories()
        self.profile.write_text('# Administrator file\n')
        with self.assertRaisesRegex(ValueError, 'not owned'):
            bootstrap.finish(self.state, self.run)
        self.assertEqual(self.profile.read_text(), '# Administrator file\n')
        self.assertTrue(self.mask.is_symlink())

    def test_active_service_is_not_masked_or_stopped(self):
        with self.assertRaisesRegex(ValueError, 'existing Fail2ban service is active'):
            bootstrap.prepare(self.state, Mock(return_value='active'))
        self.assertFalse(self.mask.is_symlink())
        self.assertFalse((self.state / bootstrap.GUARD).exists())

    def test_partial_package_failure_can_resume_without_assuming_its_configs_preexisted(self):
        bootstrap.prepare(self.state, self.run)
        self.installed_directories()
        (self.etc / 'jail.conf').write_text('# Newly unpacked package\n')
        bootstrap.prepare(self.state, self.run)
        self.assertFalse(json.loads((self.state / bootstrap.GUARD).read_text())['had_configuration'])
        self.assertEqual(sum('mask' in c.args for c in self.run.call_args_list), 1)
        bootstrap.finish(self.state, self.run)
        self.assertTrue(self.profile.exists())


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0 and shutil.which('fail2ban-client'), 'Native Linux/root Fail2ban')
class NativeBootstrapTests(unittest.TestCase):
    def test_native_config_reader_handles_default_ssh_without_an_auth_log_and_allows_wordpress_only(self):
        with tempfile.TemporaryDirectory(dir='/var/lib', prefix='wdn-f2b-native-') as folder:
            root = Path(folder)
            config = root / 'fail2ban'; shutil.copytree('/etc/fail2ban', config)
            # Test only the fresh package defaults in a private config tree.
            for path in (config / 'jail.d').iterdir():
                path.unlink()
            (config / 'jail.local').unlink(missing_ok=True)
            (config / 'jail.d/defaults-debian.conf').write_text('[sshd]\nenabled=true\nlogpath=/no-such-auth-log\nbackend=polling\n')
            state = root / 'state'; state.mkdir(mode=0o700)
            mask = root / 'fail2ban.service'; mask.symlink_to('/dev/null')
            storage.replace(state / bootstrap.GUARD, storage.json_bytes({'had_configuration': False}), 0o600)
            profile = config / 'jail.d/webuzo-de-noise-bootstrap.local'
            def run(*args):
                if 'unmask' in args: mask.unlink(); return ''
                argv = list(args)
                if Path(argv[0]).name == 'fail2ban-client': argv[1:1] = ['-c', str(config)]
                result = subprocess.run(argv, capture_output=True, text=True)
                if result.returncode: raise RuntimeError(result.stderr + result.stdout)
                return result.stdout
            with patch.object(host, 'ETC', config), patch.object(bootstrap, 'MASK', mask), patch.object(bootstrap, 'PROFILE', profile):
                self.assertIn('sshd', bootstrap.package_defaults(run))
                bootstrap.finish(state, run)
                self.assertEqual(host.configured_jails(run), set())
                self.assertFalse(mask.is_symlink())
                logfile = root / 'wordpress.log'; logfile.touch()
                (config / 'jail.d/webuzo-denoise-wordpress.local').write_text('[' + wordpress.JAIL + ']\nenabled=true\nfilter=sshd\nbackend=polling\nlogpath=' + str(logfile) + '\naction=dummy\n')
                self.assertEqual(host.configured_jails(run), {wordpress.JAIL})
                self.assertIn('[sshd]\nenabled = false', profile.read_text())
                with patch.object(host, 'service_blockers', return_value=['CSF', 'LFD']):
                    host.check_service_start(run)
                # An isolated real daemon: private DB/socket/PID/log, dummy
                # action, no authentication logs or host firewall operations.
                (config / 'fail2ban.local').write_text('[Definition]\ndbfile=' + str(root / 'fail2ban.sqlite3') + '\n')
                sock = root / 'fail2ban.sock'
                output = (root / 'server-output.log').open('w')
                process = subprocess.Popen(['fail2ban-server', '-xf', '-c', str(config), '-s', str(sock),
                    '-p', str(root / 'fail2ban.pid'), '--logtarget', str(root / 'fail2ban.log'), 'start'],
                    stdout=output, stderr=subprocess.STDOUT)
                try:
                    for attempt in range(60):
                        result = subprocess.run(['fail2ban-client', '-s', str(sock), 'ping'], capture_output=True, text=True)
                        if result.returncode == 0: break
                        if process.poll() is not None:
                            logfile = root / 'fail2ban.log'
                            self.fail(logfile.read_text() if logfile.exists() else (root / 'server-output.log').read_text())
                        time.sleep(0.1)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run(['fail2ban-client', '-s', str(sock), 'status'], capture_output=True, text=True, check=True)
                    self.assertIn('Number of jail:\t1', result.stdout)
                    self.assertIn('Jail list:\t' + wordpress.JAIL, result.stdout)
                finally:
                    subprocess.run(['fail2ban-client', '-s', str(sock), 'stop'], capture_output=True)
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
                    output.close()

    @unittest.skipUnless(shutil.which('systemctl') and shutil.which('deb-systemd-helper'), 'Native systemd/package helpers')
    def test_native_systemd_mask_survives_the_distribution_package_unmask_helper(self):
        with tempfile.TemporaryDirectory(dir='/var/lib', prefix='wdn-systemd-root-') as folder:
            root = Path(folder)
            units = root / 'usr/lib/systemd/system'; units.mkdir(parents=True)
            shutil.copyfile('/usr/lib/systemd/system/fail2ban.service', units / 'fail2ban.service')
            masks = root / 'etc/systemd/system'; masks.mkdir(parents=True)
            mask = masks / 'fail2ban.service'
            config = root / 'etc/fail2ban'
            state = root / 'state'; state.mkdir(mode=0o700)
            def run(*args):
                if 'show' in args: return 'inactive'
                result = subprocess.run(['systemctl', '--root=' + str(root), *args[1:]], capture_output=True, text=True)
                if result.returncode: raise RuntimeError(result.stdout + result.stderr)
                return result.stdout
            with patch.object(host, 'ETC', config), patch.object(bootstrap, 'MASK', mask):
                bootstrap.prepare(state, run)
                self.assertTrue(mask.is_symlink())
                environment = {**os.environ, 'DPKG_ROOT': str(root), 'DPKG_MAINTSCRIPT_PACKAGE': 'fail2ban'}
                # The actual Ubuntu postinst calls this helper before starting
                # the service. It must leave our non-helper mask intact.
                subprocess.run(['deb-systemd-helper', 'unmask', 'fail2ban.service'], env=environment, capture_output=True, check=True)
                self.assertEqual(os.readlink(mask), '/dev/null')
                result = subprocess.run(['systemctl', '--root=' + str(root), 'is-enabled', 'fail2ban.service'], capture_output=True, text=True)
                self.assertEqual(result.stdout.strip(), 'masked')
                run('/usr/bin/systemctl', 'unmask', 'fail2ban.service')
                self.assertFalse(mask.is_symlink())


if __name__ == '__main__': unittest.main()
