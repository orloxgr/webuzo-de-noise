"""Native plugin lifecycle using owned temporary configuration destinations."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import lifecycle as installer
import storage
import webuzo


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux native lifecycle fixtures')
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('state', 'etc', 'cron', 'rotate', 'tmpfiles', 'units'):
            (self.root / name).mkdir()
        self.state = self.root / 'state'; self.state.chmod(0o700)
        self.enterContext(patch.object(webuzo, 'STATE', self.state))
        self.enterContext(patch.object(installer.engine, 'STATE', self.state))
        self.enterContext(patch.object(installer, 'CONFIG', self.root / 'etc'))
        self.enterContext(patch.object(webuzo, 'SNIPPETS', self.root / 'etc/domains'))
        self.enterContext(patch.object(installer, 'LOGS', self.root / 'logs'))
        self.enterContext(patch.object(installer.transport, 'DIRECTORY', self.root / 'requests'))
        for name, folder in (('CRON', 'cron'), ('ROTATE', 'rotate'), ('TMPFILES', 'tmpfiles')):
            self.enterContext(patch.object(installer, name, self.root / folder / 'webuzo-de-noise'))
        self.enterContext(patch.object(installer.engine.captcha_runtime, 'UNITS', self.root / 'units'))
        self.enterContext(patch.object(installer.engine.captcha_runtime, 'worker_group', return_value='root'))
        self.commands = self.enterContext(patch.object(webuzo, 'run', return_value=''))
        binary = self.root / 'nginx'; binary.touch()
        self.enterContext(patch.object(webuzo, 'NGINX', binary))
        self.enterContext(patch.object(webuzo, 'collect', return_value=[]))
        self.enterContext(patch.object(installer.engine.webmail, 'discover', return_value={
            'key': 'root/webmail', 'domain': 'webmail', 'owner': 'root', 'kind': 'mail',
            'shared_webmail': True, 'supported': True}))
        self.enterContext(patch.object(installer.engine, 'locked', side_effect=contextlib.nullcontext))
        self.enterContext(patch.object(installer.engine, 'recover'))
        self.apply = self.enterContext(patch.object(installer.engine, 'apply', return_value={'changed_files': 0}))
        self.enterContext(patch.object(installer.wordpress, 'install', return_value={'managed': False}))
        self.enterContext(patch.object(installer.wordpress, 'uninstall'))

    def test_activation_registers_only_owned_native_artifacts_and_stays_observe(self):
        result = installer.install()
        self.assertTrue(result['ok'])
        self.assertEqual(self.apply.call_args.args[0]['mode'], 'observe')
        self.assertIn('* * * * * root ', installer.CRON.read_text())
        self.assertIn('-I -B ', installer.CRON.read_text())
        self.assertIn('0730 root webuzo', installer.TMPFILES.read_text())
        self.assertEqual(json.loads((self.state / 'active.json').read_text()), {'active': True})

    def test_unmanaged_integration_collision_is_not_overwritten(self):
        installer.CRON.write_text('# administrator cron\n')
        with self.assertRaisesRegex(ValueError, 'not owned'):
            installer.install()
        self.apply.assert_not_called()
        self.assertEqual(installer.CRON.read_text(), '# administrator cron\n')
        self.assertFalse((self.state / 'active.json').exists())

    def test_failed_native_apply_does_not_register_a_cron_or_claim_activation(self):
        self.apply.side_effect = RuntimeError('bad candidate')
        with self.assertRaisesRegex(RuntimeError, 'bad candidate'):
            installer.install()
        self.assertFalse(installer.CRON.exists())
        self.assertFalse((self.state / 'active.json').exists())
        self.assertEqual(list((self.root / 'units').iterdir()), [])

    def test_captcha_units_remain_inactive_until_configured_and_foreign_units_are_preserved(self):
        runtime = installer.engine.captcha_runtime
        path = runtime.UNITS / (runtime.NAME + '.socket')
        path.write_text('# Administrator owned\n')
        with self.assertRaisesRegex(ValueError, 'not owned'):
            installer.install()
        self.assertEqual(path.read_text(), '# Administrator owned\n')
        self.apply.assert_not_called()
        path.unlink()
        installer.install()
        self.assertIn('SocketMode=0660', path.read_text())
        service = runtime.UNITS / (runtime.NAME + '.service')
        self.assertIn('DynamicUser=yes', service.read_text())
        self.assertIn('LoadCredential=', service.read_text())
        commands = [call.args for call in self.commands.call_args_list]
        self.assertFalse(any('enable' in command for command in commands))
        self.assertIn(('/usr/bin/systemctl', 'try-restart', runtime.NAME + '.service'), commands)

    def test_failure_after_rules_rolls_back_activation_and_artifacts(self):
        with patch.object(installer.wordpress, 'install', side_effect=RuntimeError('service unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'service unavailable'):
                installer.install()
        self.assertFalse(installer.CRON.exists())
        self.assertFalse((self.state / 'active.json').exists())
        self.assertTrue(self.apply.call_args.kwargs['remove'])

    def test_deactivation_unregisters_owned_artifacts_and_preserves_neighbors(self):
        installer.install()
        neighbor = installer.CRON.with_name('unrelated'); neighbor.write_text('keep')
        with patch.object(installer.engine, 'synchronize', return_value={}) as remove:
            result = installer.remove()
        self.assertEqual(result['state'], 'disabled')
        self.assertTrue(remove.call_args.kwargs['remove'])
        self.assertFalse(installer.CRON.exists())
        self.assertFalse(installer.ROTATE.exists())
        self.assertFalse(installer.TMPFILES.exists())
        self.assertEqual(neighbor.read_text(), 'keep')
        self.assertFalse(json.loads((self.state / 'active.json').read_text())['active'])

    def test_upgrade_removes_only_exact_retired_source_and_preserves_custom_files(self):
        source = self.root / 'source'; (source / 'src').mkdir(parents=True)
        (source / 'panel').mkdir()
        old = b'# retired bundled source\n'
        expected = {name: hashlib.sha256(old).hexdigest() for name in installer.OBSOLETE_SOURCE}
        (source / 'src/domain_bans.py').write_bytes(old.replace(b'\n', b'\r\n'))
        (source / 'panel/domain-bans.php').write_bytes(b'# administrator-customized file\n')
        neighbor = source / 'src/neighbor.py'; neighbor.write_bytes(b'keep')
        with patch.object(installer, 'SOURCE', source), patch.object(installer, 'OBSOLETE_SOURCE', expected):
            result = installer.retire_source()
        self.assertEqual(result, dict(removed=['src/domain_bans.py'], preserved=['panel/domain-bans.php']))
        self.assertFalse((source / 'src/domain_bans.py').exists())
        self.assertEqual((source / 'panel/domain-bans.php').read_bytes(), b'# administrator-customized file\n')
        self.assertEqual(neighbor.read_bytes(), b'keep')

    def test_retired_source_symlink_is_never_followed_or_deleted(self):
        source = self.root / 'source'; (source / 'src').mkdir(parents=True); (source / 'panel').mkdir()
        target = self.root / 'unrelated'; target.write_bytes(b'keep')
        link = source / 'src/domain_bans.py'; link.symlink_to(target)
        with patch.object(installer, 'SOURCE', source):
            result = installer.retire_source()
        self.assertEqual(result['removed'], [])
        self.assertTrue(link.is_symlink()); self.assertEqual(target.read_bytes(), b'keep')
