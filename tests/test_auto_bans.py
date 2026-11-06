import contextlib
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import auto_bans
from probe_rules import token
from policy import DEFAULT


class FakeNative:
    def __init__(self):
        self.exists = False; self.records = set(); self.active = set(); self.calls = []
        self.fail = False
    def locked(self): return contextlib.nullcontext()
    def own_ips(self): return {'192.0.2.1'}
    def exclusions(self): return []
    def inspect(self): return self.exists, set(self.records), set(self.active)
    def create(self): self.exists = True; self.calls.append(('create',))
    def add(self, ip):
        self.calls.append(('add', ip))
        if self.fail: raise RuntimeError('Synthetic native failure')
        self.records.add(ip); self.active.add(ip)
    def remove(self, ip):
        self.calls.append(('remove', ip)); self.records.discard(ip); self.active.discard(ip)
    def drop_chain(self): self.calls.append(('drop',)); self.exists = False


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-private Linux database and logs')
class BanLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.directory = Path(self.temp.name)
        self.log = self.directory / 'ban-events.log'; self.log.write_text('')
        self.patch = patch.object(auto_bans, 'LOG', self.log); self.patch.start()
        self.policy = copy.deepcopy(DEFAULT)
        self.policy['mode'] = 'enforce'; self.policy['bans']['enabled'] = True
        self.sites = [{'domain': 'one.test', 'key': 'alice/one.test', 'supported': True, 'suspended': False}]
        self.native = FakeNative()

    def tearDown(self): self.patch.stop(); self.temp.cleanup()

    def event(self, ip='198.51.100.7', stamp=1000, domain='one.test', reason='private-file'):
        with self.log.open('a') as stream: stream.write(f'{stamp} {ip} {domain} {reason}\n')

    def sync(self, now=1001, **kwargs):
        return auto_bans.synchronize(self.policy, self.sites, self.directory, self.native, now, **kwargs)

    def test_all_pending_firewall_operations_complete_beyond_old_hundred_limit(self):
        import ipaddress
        for number in range(175):
            self.event(str(ipaddress.ip_address('198.18.0.1') + number))
        result=self.sync()
        self.assertEqual(result['active'],175)
        self.assertEqual(result['pending'],0)
        self.assertEqual(len([call for call in self.native.calls if call[0]=='add']),175)

    def test_one_native_failure_does_not_abandon_other_pending_bans(self):
        self.event('198.18.0.1');self.event('198.18.0.2')
        original=self.native.add
        def apply(address):
            if address=='198.18.0.1':raise RuntimeError('One native operation failed')
            original(address)
        with patch.object(self.native,'add',side_effect=apply):
            report=self.sync()
        self.assertEqual(report['active'],1)
        self.assertEqual(report['pending'],1)
        self.assertIn('198.18.0.2',self.native.active)

    def test_log_cursor_consumes_more_than_two_mib_without_skipping_later_events(self):
        self.log.write_text(('not an event ' + 'x'*1000 + '\n') * 2200)
        self.event()
        self.assertEqual(self.sync()['active'],1)
        with auto_bans.database(self.directory) as db:
            self.assertEqual(db.execute('SELECT offset FROM cursors').fetchone()[0], self.log.stat().st_size)

    def test_first_recent_request_bans_permanently_and_manual_unban_does_not_replay_old_events(self):
        self.event(stamp=950)
        report = self.sync()
        self.assertEqual(report['active'], 1)
        self.assertEqual(report['rows'][0]['expires'], 0)
        self.assertEqual(self.native.calls.count(('add', '198.51.100.7')), 1)
        self.sync(now=1002)
        self.assertEqual(self.native.calls.count(('add', '198.51.100.7')), 1)
        auto_bans.unban(self.directory, self.native, ['198.51.100.7'], now=1003)
        self.assertEqual(self.sync(now=1004, read_events=False)['active'], 0)
        self.assertFalse(self.native.records)
        self.assertEqual(self.sync(now=1005)['active'], 0)
        self.event(stamp=1006)
        self.assertEqual(self.sync(now=1007)['active'], 1)

    def test_native_failure_remains_pending_and_retry_preserves_the_request(self):
        self.native.fail = True; self.event()
        report = self.sync()
        self.assertEqual(report['active'], 0); self.assertEqual(report['pending'], 1)
        self.assertIn('Synthetic native failure', report['error'])
        self.native.fail = False
        report = self.sync(now=1002)
        self.assertEqual(report['active'], 1); self.assertEqual(report['error'], '')

    def test_expiry_disable_and_uninstall_remove_only_owned_bans(self):
        self.policy['bans']['duration_days'] = 1
        self.event(); self.sync()
        self.assertEqual(self.sync(now=87402)['active'], 0)
        self.event(stamp=87403); self.sync(now=87404)
        self.policy['bans']['enabled'] = False
        self.assertEqual(self.sync(now=87405)['active'], 0)
        report = self.sync(now=87406, remove=True)
        self.assertEqual(report['pending'], 0); self.assertFalse(self.native.exists)
        self.assertIn(('drop',), self.native.calls)

    def test_native_panel_unban_is_respected_and_foreign_selections_are_rejected(self):
        self.event(); self.sync()
        with self.assertRaisesRegex(ValueError, 'not an active De-Noise ban'):
            auto_bans.unban(self.directory, self.native, ['198.51.100.7', '198.51.100.99'])
        self.native.records.clear(); self.native.active.clear()
        self.assertEqual(self.sync(now=1002)['active'], 0)
        self.assertEqual(self.native.calls.count(('add', '198.51.100.7')), 1)

    def test_scope_ignore_self_stale_and_ipv6_behavior_are_explicit(self):
        self.policy['bans']['ignore_ips'] = ['198.51.100.0/25']
        for ip, stamp, domain, reason in [('198.51.100.7',1000,'one.test','private-file'),
            ('127.0.0.2',1000,'one.test','private-file'), ('192.0.2.1',1000,'one.test','private-file'),
            ('198.51.100.200',1000,'other.test','private-file'), ('198.51.100.201',1000,'one.test','static-file'),
            ('198.51.100.202',600,'one.test','private-file'), ('2001:db8::1',1000,'one.test','private-file')]:
            self.event(ip, stamp, domain, reason)
        report = self.sync()
        self.assertEqual(report['active'], 1); self.assertEqual(report['unsupported_ipv6'], 0)
        self.assertIn(('add', '2001:db8::1'), self.native.calls)
        self.policy['overrides'] = {'alice/one.test': 'observe'}
        self.event('198.51.100.200',1002)
        self.assertEqual(self.sync(now=1003)['active'], 0)

    def test_configurable_threshold_across_rotation_and_changing_duration(self):
        self.policy['bans']['maxretry'] = 2
        self.event(); self.assertEqual(self.sync()['active'], 0)
        self.log.rename(self.log.with_name(self.log.name + '.1')); self.log.write_text('')
        self.event(stamp=1002)
        self.assertEqual(self.sync(now=1003)['active'], 1)
        self.policy['bans']['duration_days'] = 1
        self.assertEqual(self.sync(now=1004)['rows'][0]['expires'], 1003 + 86400)
        self.policy['bans']['ignore_ips'] = ['198.51.100.7/32']
        self.assertEqual(self.sync(now=1005)['active'], 0)

    def test_unmanaged_chain_and_database_symlinks_are_refused(self):
        self.native.exists = True; self.event()
        self.assertIn('not owned', self.sync()['error'])
        self.assertFalse(self.native.calls)
        other = self.directory / 'other'; other.mkdir()
        (other / 'bans.sqlite').symlink_to(self.directory / 'bans.sqlite')
        with self.assertRaises(OSError):
            auto_bans.report(other)

    def probe(self, reason, value, stamp, domain='one.test', ip='198.51.100.70'):
        with self.log.open('a') as stream:
            stream.write(f'{stamp} {ip} {domain} {reason} {token("f" if reason == "missing-file" else "q", value)}\n')

    def test_two_distinct_missing_files_across_domains_expire_after_three_days(self):
        self.policy['bans']['missing_files']['enabled'] = True
        self.sites.append({'domain': 'two.test', 'key': 'bob/two.test', 'supported': True})
        self.probe('missing-file', '/auth.php', 1000)
        self.assertEqual(self.sync()['active'], 0)
        self.probe('missing-file', '/auth.php', 1002, 'two.test')
        self.assertEqual(self.sync(now=1003)['active'], 0)
        self.probe('missing-file', '/test.php', 1004, 'two.test')
        result = self.sync(now=1005)
        self.assertEqual(result['active'], 1)
        self.assertEqual(result['rows'][0]['reason'], 'missing-file')
        self.assertEqual(result['rows'][0]['expires'], 1005 + 3*86400)
        self.assertEqual(self.sync(now=1005 + 3*86400 + 1)['active'], 0)

    def test_query_counter_is_independent_and_disabled_category_releases_its_bans(self):
        self.policy['bans']['suspicious_queries']['enabled'] = True
        self.policy['bans']['missing_files']['enabled'] = True
        self.probe('missing-file', '/auth.php', 1000)
        self.probe('suspicious-query', '/etc/passwd', 1001)
        self.assertEqual(self.sync(now=1002)['active'], 0)
        self.probe('suspicious-query', '/etc/passwd', 1003)
        result = self.sync(now=1004)
        self.assertEqual(result['active'], 1)
        self.assertEqual(result['rows'][0]['expires'], 1004 + 3*86400)
        self.policy['bans']['suspicious_queries']['enabled'] = False
        self.assertEqual(self.sync(now=1005)['active'], 0)

    def test_unselected_probe_tokens_and_events_outside_window_do_not_count(self):
        self.policy['bans']['missing_files']['enabled'] = True
        self.probe('missing-file', '/not-selected.php', 1000)
        self.probe('missing-file', '/auth.php', 930)
        self.probe('missing-file', '/test.php', 1000)
        self.assertEqual(self.sync(now=1001)['active'], 0)

    def test_uninstall_reports_foreign_native_entries_and_does_not_delete_them(self):
        self.event(); self.sync()
        self.native.records.add('198.51.100.99'); self.native.active.add('198.51.100.99')
        with self.assertRaisesRegex(RuntimeError, 'Untracked bans remain'):
            auto_bans.cleanup(self.policy, self.sites, self.directory, self.native)
        self.assertEqual(self.native.active, {'198.51.100.99'})
        self.assertNotIn(('drop',), self.native.calls)
