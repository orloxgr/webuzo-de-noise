"""Native plugin lifecycle using owned temporary configuration destinations."""
import contextlib
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
        for name in ('state', 'etc', 'cron', 'rotate', 'tmpfiles'):
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
