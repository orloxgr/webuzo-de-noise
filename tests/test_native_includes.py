"""Ownership, preservation and recovery of native Webuzo custom includes."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import integration
import storage
import webuzo


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root-owned configuration fixtures')
class NativeIncludeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.custom = self.root / 'custom'; self.custom.mkdir()
        self.snippets = self.root / 'snippets'; self.snippets.mkdir()
        self.enterContext(patch.object(webuzo, 'CUSTOM', self.custom))
        self.enterContext(patch.object(webuzo, 'SNIPPETS', self.snippets))
        self.path = self.custom / 'example.test.conf'
        self.site = {'domain': 'example.test', 'supported': True}

    def test_existing_custom_settings_survive_install_noop_and_removal(self):
        original = 'add_header X-Existing "kept";'
        self.path.write_text(original)
        manifest, changes = integration.prepare([self.site], {})
        integration.write(changes)
        installed = self.path.read_text()
        self.assertTrue(installed.startswith(original + '\n'))
        self.assertIn(str(self.snippets / 'example.test.conf'), installed)
        self.assertEqual(integration.prepare([self.site], manifest)[1], [])
        _, changes = integration.prepare([], manifest, remove=True)
        integration.write(changes)
        self.assertEqual(self.path.read_text(), original)

    def test_later_administrator_changes_are_preserved_on_remove(self):
        self.path.write_text('# Existing\n')
        manifest, changes = integration.prepare([self.site], {})
        integration.write(changes)
        self.path.write_text(self.path.read_text() + '# Later administrator setting\n')
        _, changes = integration.prepare([], manifest, remove=True)
        integration.write(changes)
        self.assertEqual(self.path.read_text(), '# Existing\n# Later administrator setting\n')

    def test_new_custom_file_is_removed_only_when_no_unrelated_content_remains(self):
        manifest, changes = integration.prepare([self.site], {})
        integration.write(changes)
        _, changes = integration.prepare([], manifest, remove=True)
        integration.write(changes)
        self.assertFalse(self.path.exists())

    def test_modified_or_unregistered_owned_block_is_refused(self):
        self.path.write_text(integration.block('example.test'))
        with self.assertRaisesRegex(ValueError, 'Unregistered'):
            integration.prepare([self.site], {})
        self.path.write_text(integration.BEGIN + 'include /other.conf;\n' + integration.END)
        with self.assertRaisesRegex(ValueError, 'changed'):
            integration.prepare([self.site], {'example.test': {'created': False}})

    def test_deleted_domain_can_release_a_custom_file_already_removed_by_the_panel(self):
        manifest, changes = integration.prepare([self.site], {})
        integration.write(changes)
        self.path.unlink()
        next_manifest, changes = integration.prepare([], manifest)
        self.assertEqual(next_manifest, {})
        self.assertEqual(changes, [])
        with self.assertRaisesRegex(ValueError, 'missing'):
            integration.prepare([self.site], manifest)

    def test_foreign_limiter_is_not_overridden(self):
        for directive in ('limit_req zone=other;', 'limit_req_log_level warn;'):
            self.path.write_text(directive)
            with self.subTest(directive=directive), self.assertRaisesRegex(ValueError, 'request limits'):
                integration.prepare([self.site], {})
            self.assertEqual(self.path.read_text(), directive)

    def test_nested_limits_quoted_directives_and_include_cycles(self):
        included = self.root / 'administrator.conf'
        self.path.write_text('include "' + str(included) + '";\n')
        included.write_text('location /login { limit_req zone=administrator; }\n')
        with self.assertRaisesRegex(ValueError, 'request limits'):
            integration.prepare([self.site], {})
        included.write_text('add_header X-Example "limit_req is text"; # limit_req comment\n')
        self.assertTrue(integration.prepare([self.site], {})[1])
        included.write_text('include ' + str(self.path) + ';\n')
        with self.assertRaisesRegex(ValueError, 'Recursive'):
            integration.prepare([self.site], {})
        self.assertNotIn(integration.BEGIN, self.path.read_text())

    def test_alias_custom_include_can_be_retargeted_and_removed_without_losing_admin_content(self):
        alias = self.custom / 'alias.test.conf'
        original = 'add_header X-Administrator "kept";\n'; alias.write_text(original)
        site = {**self.site, 'custom_domains': ['example.test', 'alias.test']}
        manifest, changes = integration.prepare([site], {})
        integration.write(changes)
        self.assertIn('snippets/example.test.conf', alias.read_text())
        self.assertEqual(manifest['alias.test']['site'], 'example.test')
        retargeted = {'domain': 'other.test', 'supported': True, 'custom_domains': ['alias.test']}
        manifest, changes = integration.prepare([retargeted], manifest)
        integration.write(changes)
        self.assertNotIn('snippets/example.test.conf', alias.read_text())
        self.assertIn('snippets/other.test.conf', alias.read_text())
        self.assertFalse(self.path.exists())
        _, changes = integration.prepare([], manifest, remove=True)
        integration.write(changes)
        self.assertEqual(alias.read_text(), original)

    def test_symlinks_untrusted_owners_and_writable_parent_are_refused(self):
        target = self.root / 'target'; target.write_text('untouched')
        self.path.symlink_to(target)
        with self.assertRaises(OSError): integration.prepare([self.site], {})
        self.path.unlink(); self.path.write_text('untrusted'); os.chown(self.path, 12345, -1)
        with self.assertRaises(ValueError): integration.prepare([self.site], {})
        os.chown(self.path, 0, -1); self.custom.chmod(0o777)
        try:
            with self.assertRaises(ValueError): integration.prepare([self.site], {})
        finally:
            self.custom.chmod(0o755)
        self.assertEqual(target.read_text(), 'untouched')

    def test_recovery_refuses_unrelated_paths_and_concurrent_edits(self):
        with self.assertRaises(ValueError):
            integration.write([{'path': '/etc/passwd', 'before': None, 'after': 'bad'}])
        self.path.write_text('# Original\n')
        _, changes = integration.prepare([self.site], {})
        self.path.write_text('# Concurrent administrator edit\n')
        with self.assertRaisesRegex(ValueError, 'changed during'):
            integration.write(changes)
        self.assertEqual(self.path.read_text(), '# Concurrent administrator edit\n')

    def test_interrupted_change_can_restore_both_written_and_unwritten_steps(self):
        original = '# Original\n'; self.path.write_text(original)
        _, changes = integration.prepare([self.site], {})
        integration.write(changes, restore=True)
        self.assertEqual(self.path.read_text(), original)
        integration.write(changes)
        integration.write(changes, restore=True)
        self.assertEqual(self.path.read_text(), original)
