"""Preset upgrade compatibility without new global crawler blocks or ban resets."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from policy import DEFAULT, SEARCH_AGENTS, validate
from probe_rules import FILES


class PresetUpgradeTests(unittest.TestCase):
    def old_policy(self):
        value = copy.deepcopy(DEFAULT)
        value['bans']['missing_files']['paths'] = (
            Path(__file__).parent / 'fixtures/php-probes-v010.txt').read_text().splitlines()
        value['mode'] = 'enforce'
        value['bans']['enabled'] = True
        value['bans']['missing_files'].update(enabled=True, maxretry=2, findtime=120, duration_days=3)
        value['bans']['any_404'].update(maxretry=30, min_distinct_paths=4)
        value['agents'] = ['ExistingBot']
        value['enumeration']['enabled'] = True
        value['probe_exceptions']['files'] = {'alice/one.test': ['/wp-content/module.php']}
        return value

    def test_current_schema_bundled_upgrade_preserves_all_choices(self):
        old = self.old_policy()
        new = validate(old)
        self.assertEqual(len(old['bans']['missing_files']['paths']), 219)
        self.assertEqual(len(new['bans']['missing_files']['paths']), 265)
        expected = copy.deepcopy(old)
        expected['bans']['missing_files']['paths'] = list(FILES)
        self.assertEqual(new, expected)
        self.assertEqual(validate(new), new)
        self.assertIn('/wp-content/module.php', new['bans']['missing_files']['paths'])
        self.assertIn('/wp-admin/maint/config.php', new['bans']['missing_files']['paths'])

    def test_custom_added_removed_or_empty_lists_are_not_repopulated(self):
        old = self.old_policy()
        for paths in [old['bans']['missing_files']['paths'] + ['/custom.php'],
                      old['bans']['missing_files']['paths'][1:], [], ['/custom.php']]:
            old['bans']['missing_files']['paths'] = paths
            self.assertEqual(validate(old)['bans']['missing_files']['paths'], paths)

    def test_reordered_prior_preset_is_recognized_and_new_groups_stay_optional(self):
        old = self.old_policy()
        old['bans']['missing_files']['paths'].reverse()
        new = validate(old)
        self.assertEqual(new['bans']['missing_files']['paths'], list(FILES))
        self.assertEqual(new['agents'], ['ExistingBot'])
        self.assertFalse(new['mail_protection'])
        self.assertIn('ibou-search', SEARCH_AGENTS)
        self.assertFalse(set(SEARCH_AGENTS) & {'Googlebot', 'bingbot', 'facebookexternalhit'})
        self.assertFalse(DEFAULT['bans']['missing_files']['enabled'])
