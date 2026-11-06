"""Native panel request transport ownership, bounds and one-time consumption."""
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import transport


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root/panel transport fixtures')
class BridgeTransport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'requests'; self.directory.mkdir()
        self.panel = pwd.getpwnam('webuzo')
        os.chown(self.directory, 0, self.panel.pw_gid); self.directory.chmod(0o730)
        self.enterContext(patch.object(transport, 'DIRECTORY', self.directory))
        self.identity = 'a' * 64; self.path = self.directory / (self.identity + '.json')

    def create(self, payload=b'{"actor":"alice","action":"status"}'):
        self.path.write_bytes(payload)
        os.chown(self.path, self.panel.pw_uid, self.panel.pw_gid); self.path.chmod(0o600)

    def test_native_panel_request_is_consumed_once(self):
        self.create()
        self.assertEqual(transport.read(self.identity)['actor'], 'alice')
        self.assertFalse(self.path.exists())
        with self.assertRaises(FileNotFoundError): transport.read(self.identity)

    def test_path_injection_invalid_json_and_non_object_are_rejected(self):
        for value in ('../etc/passwd', 'a' * 63, 'A' * 64, None):
            with self.subTest(identity=value), self.assertRaises(ValueError): transport.read(value)
        for value in (b'null', b'[]', b'{invalid'):
            self.create(value)
            with self.subTest(payload=value), self.assertRaises(ValueError): transport.read(self.identity)

    def test_symlink_fifo_wrong_owner_and_hardlinks_are_rejected(self):
        target = self.directory / 'foreign'; target.write_text('unchanged')
        self.path.symlink_to(target)
        with self.assertRaises(OSError): transport.read(self.identity)
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaises(ValueError): transport.read(self.identity)
        self.path.unlink(); self.create(); os.chown(self.path, 12345, -1)
        with self.assertRaises(ValueError): transport.read(self.identity)
        self.path.unlink(); self.create(); os.link(self.path, self.directory / 'hardlink')
        with self.assertRaises(ValueError): transport.read(self.identity)
        self.assertEqual(target.read_text(), 'unchanged')

    def test_world_access_and_oversize_requests_are_rejected(self):
        self.create(); self.path.chmod(0o644)
        with self.assertRaises(ValueError): transport.read(self.identity)
        self.path.unlink(); self.create(b' ' * (transport.LIMIT + 1))
        with self.assertRaises(ValueError): transport.read(self.identity)
        self.path.unlink(); self.create(); self.directory.chmod(0o733)
        with self.assertRaises(ValueError): transport.read(self.identity)
