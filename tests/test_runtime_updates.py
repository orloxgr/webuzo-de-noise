"""Native ZIP updates must not execute stale modules with matching metadata."""
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class UpdateTests(unittest.TestCase):
    def test_entry_uses_new_source_when_old_bytecode_has_identical_timestamp_and_size(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            engine = root / 'engine.py'
            old = 'def main(): return {"generation": "old"}\n'
            new = 'def main(): return {"generation": "new"}\n'
            self.assertEqual(len(old), len(new))
            engine.write_text(old)
            os.utime(engine, (1767225600, 1767225600))
            with patch.object(sys, 'pycache_prefix', None):
                cached = Path(py_compile.compile(str(engine), doraise=True,
                    invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
            old_bytecode = cached.read_bytes()
            engine.write_text(new)
            os.utime(engine, (1767225600, 1767225600))
            # Confirm that -B alone still accepts the obsolete timestamp cache.
            baseline = subprocess.run([sys.executable, '-I', '-B', '-c',
                'import sys;sys.path.insert(0,sys.argv[1]);import engine;print(engine.main()["generation"])',
                str(root)], capture_output=True, text=True, check=True)
            self.assertEqual(baseline.stdout.strip(), 'old')
            shutil.copyfile(ROOT / 'src/addon.py', root / 'addon.py')
            actual = subprocess.run([sys.executable, '-I', '-B', str(root / 'addon.py')],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(actual.stdout), {'generation': 'new'})
            self.assertEqual(cached.read_bytes(), old_bytecode)
            self.assertFalse((root / '.bytecode').exists())

    def test_package_epoch_changes_native_source_timestamps_and_stays_reproducible(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / 'tools').mkdir()
            shutil.copyfile(ROOT / 'tools/build.py', root / 'tools/build.py')
            for name in ('webuzo-de-noise.php', 'LICENSE', 'README.md', 'UPSTREAM'):
                (root / name).write_text('fixture')
            (root / 'info.json').write_text('{"version":"0.1.0"}')
            for name in ('src', 'panel', 'wordpress', 'config'):
                (root / name).mkdir()
            dates, archives = [], []
            for epoch in ('1767225600', '1767312000', '1767312000'):
                subprocess.run([sys.executable, '-I', '-B', str(root / 'tools/build.py')],
                    env={**os.environ, 'SOURCE_DATE_EPOCH': epoch}, capture_output=True, check=True)
                archive = root / 'dist/webuzo-de-noise-0.1.0.zip'
                archives.append(archive.read_bytes())
                with zipfile.ZipFile(archive) as source:
                    dates.append(source.getinfo('webuzo-de-noise/webuzo-de-noise.php').date_time)
            self.assertNotEqual(dates[0], dates[1])
            self.assertEqual(archives[1], archives[2])


if __name__ == '__main__':
    unittest.main()
