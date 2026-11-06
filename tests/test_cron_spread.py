import copy
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import cron_spread


class CronSpreadTests(unittest.TestCase):
    def setUp(self):
        self.jobs = {'alice': {'1': {'MIN': '*/5', 'HOUR': '*', 'DAY': '*', 'MONTH': '*', 'WDAY': '*',
                                  'CMD': '/usr/bin/php -q /home/alice/web/one.test/public_html/wp-cron.php >/dev/null 2>&1', 'SUSPENDED': 'no'},
                               '2': {'MIN': '*/5', 'HOUR': '*', 'DAY': '*', 'MONTH': '*', 'WDAY': '*',
                                  'CMD': 'echo unrelated', 'SUSPENDED': 'no'}}}
        self.calls = []

    def metadata(self, command, owner=None):
        if command == 'accounts': return {'alice': {'SUSPENDED': 'no'}, 'suspended': {'SUSPENDED': 'yes'}}
        self.assertEqual(command, 'cron_jobs')
        return copy.deepcopy(self.jobs[owner])

    def change(self, owner, ident, *values):
        self.calls.append((owner, ident, values))
        self.jobs[owner][ident].update(dict(zip(cron_spread.FIELDS, values)))

    def test_minute_gaps_include_hour_boundary_and_no_extra_command_wrapper(self):
        for seed in range(300):
            values = list(map(int, cron_spread.minutes(5, 15, random.Random(seed)).split(',')))
            self.assertEqual(values, sorted(set(values)))
            gaps = [right-left for left, right in zip(values, values[1:]+[values[0]+60])]
            self.assertTrue(all(5 <= gap <= 15 for gap in gaps), gaps)
        with self.assertRaises(ValueError): cron_spread.minutes(7, 7)

    def test_preview_is_readonly_apply_preserves_command_and_restore_is_native(self):
        plan = cron_spread.preview(self.metadata)
        self.assertEqual(len(plan['rows']), 1); self.assertFalse(self.calls)
        original = copy.deepcopy(self.jobs['alice']['1'])
        exposed = cron_spread.public(plan)
        self.assertNotIn('CMD', repr(exposed)); self.assertNotIn('>/dev/null', repr(exposed))
        saves = []
        cron_spread.apply(plan, ['alice/1'], self.metadata, self.change, lambda p: saves.append(copy.deepcopy(p)))
        self.assertEqual(self.jobs['alice']['1']['CMD'], original['CMD'])
        self.assertEqual(self.jobs['alice']['2']['CMD'], 'echo unrelated')
        self.assertEqual(plan['rows'][0]['state'], 'applied')
        cron_spread.apply(plan, ['alice/1'], self.metadata, self.change, lambda p: None, restore=True)
        self.assertEqual(self.jobs['alice']['1'], original)

    def test_changed_commands_or_suspended_jobs_are_not_overwritten(self):
        plan = cron_spread.preview(self.metadata)
        self.jobs['alice']['1']['CMD'] = 'echo changed in Webuzo'
        with self.assertRaisesRegex(ValueError, 'changed after preview'):
            cron_spread.apply(plan, ['alice/1'], self.metadata, self.change, lambda p: None)
        self.assertFalse(self.calls)
        with self.assertRaises(ValueError):
            cron_spread.apply(plan, ['someone/99'], self.metadata, self.change, lambda p: None)

    def test_public_schedule_uses_intervals_and_keeps_details_available(self):
        self.assertEqual(cron_spread.interval_label('4,11,17,24,31,37,44,51,57'), 'Every 6–7 minutes')
        self.assertEqual(cron_spread.interval_label('*/5'), 'Every 5 minutes')
        self.assertEqual(cron_spread.interval_label('3,13,23,33,43,53'), 'Every 10 minutes')
        self.assertEqual(cron_spread.site_label('/home/alice/web/one.test/public_html/wp-cron.php'), 'one.test')
        self.assertEqual(cron_spread.site_label('/home/alice/one.test/wp-cron.php'), 'one.test')
        result = cron_spread.public(cron_spread.preview(self.metadata))
        self.assertEqual(result['rows'][0]['before_label'], 'Every 5 minutes')
        self.assertEqual(result['rows'][0]['site'], 'one.test')
