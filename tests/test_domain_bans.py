import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import auto_bans
import domain_bans
import engine
from policy import DEFAULT
from probe_rules import token
from test_auto_bans import FakeNative


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-private Linux database/log fixtures')
class ScopedBanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.state = Path(self.temp.name)
        self.log = self.state / 'ban-events.log'; self.log.write_text('')
        self.patch = patch.object(auto_bans, 'LOG', self.log); self.patch.start()
        self.policy = copy.deepcopy(DEFAULT); self.policy['mode'] = 'enforce'
        self.sites = [{'key': owner+'/'+host, 'owner': owner, 'domain': host, 'supported': True,
                       'suspended': False} for owner, host in [('alice','one.test'),('bob','two.test')]]
        self.policy['domain_bans']['sites'] = {site['key']: {'missing_files': True, 'suspicious_queries': True, 'any_404': False} for site in self.sites}
        self.native = FakeNative()

    def tearDown(self): self.patch.stop(); self.temp.cleanup()

    def event(self, path='/auth.php', stamp=1000, host='one.test', ip='198.51.100.7', query=False):
        reason = 'domain-query' if query else 'domain-file'
        with self.log.open('a') as out: out.write(f'{stamp} {ip} {host} {reason} {token("q" if query else "f", path)}\n')

    def sync(self, now=1001):
        domain_bans.synchronize(self.policy, self.sites, self.state, self.native, now)
        return domain_bans.desired(self.policy, self.sites, self.state, now)

    def test_counters_and_bans_are_domain_scoped_and_never_touch_native_firewall(self):
        self.event(); self.event(host='two.test', path='/test.php')
        self.assertEqual(self.sync(), {})
        self.event(path='/test.php', stamp=1002)
        desired = self.sync(1003)
        self.assertEqual(set(desired), {'alice/one.test'})
        self.assertEqual(desired['alice/one.test']['198.51.100.7']['expires'], 1003+3*86400)
        self.assertEqual(self.native.calls, [])
        report = domain_bans.report(self.policy, self.sites, self.state, 'alice', 1004)
        self.assertEqual(report['pending'], 1); self.assertEqual(report['active'], 0)
        (self.state/domain_bans.APPLIED).write_text(json.dumps(desired))
        self.assertEqual(domain_bans.report(self.policy, self.sites, self.state, 'alice', 1005)['active'], 1)
        self.assertEqual(domain_bans.report(self.policy, self.sites, self.state, 'bob', 1005)['rows'], [])
        self.policy['domain_bans']['sites']['alice/one.test']['missing_files'] = False
        self.assertEqual(self.sync(1006), {})
        self.assertEqual(domain_bans.report(self.policy, self.sites, self.state, 'alice', 1006)['rows'][0]['status'], 'removing')

    def test_ipv6_queries_expiry_and_observe_mode(self):
        for stamp in (1000, 1001): self.event('/etc/passwd', stamp, ip='2001:db8::7', query=True)
        desired = self.sync(1002)
        self.assertIn('2001:db8::7', desired['alice/one.test'])
        self.assertEqual(self.sync(1002+3*86400+1), {})
        self.policy['overrides']['alice/one.test'] = 'observe'
        for stamp in (400000, 400001): self.event('/etc/passwd', stamp, ip='2001:db8::8', query=True)
        self.assertEqual(self.sync(400002), {})

    def test_normal_native_signals_do_not_become_domain_bans(self):
        self.log.write_text('1000 198.51.100.7 one.test private-file -\n')
        self.assertEqual(self.sync(), {})
        self.assertEqual(self.native.calls, [])

    def test_domain_only_state_does_not_require_or_modify_native_firewall(self):
        self.event(); self.sync()
        with patch.object(self.native, 'inspect', side_effect=AssertionError('Native firewall must not be used')):
            result = auto_bans.synchronize(self.policy, self.sites, self.state, self.native, 1002)
        self.assertEqual(result['active'], 0)
        self.assertEqual(result['error'], '')
        self.assertEqual(self.native.calls, [])


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.policy = copy.deepcopy(DEFAULT)
        self.sites = [{'key': owner+'/'+owner+'.test', 'owner': owner, 'domain': owner+'.test',
                       'supported': True, 'suspended': False} for owner in ('alice','bob')]

    def request(self, key='alice/alice.test', flags=None):
        return {'actor':'alice','owner':'alice','action':'domain_bans_save',
                'preferences':{key: flags or {'missing_files':True,'suspicious_queries':False}}}

    def test_owner_can_select_own_categories_but_not_foreign_domains_or_exceptions(self):
        with patch.object(engine,'authorize',return_value=(False,'alice')), \
             patch.object(engine,'load',return_value=self.policy), patch.object(engine,'collect',return_value=self.sites), \
             patch.object(engine,'apply') as apply, patch.object(engine,'snapshot',return_value={}):
            engine.dispatch(self.request())
            self.assertTrue(apply.call_args.args[0]['domain_bans']['sites']['alice/alice.test']['missing_files'])
            self.assertEqual(apply.call_args.args[0]['bans'], self.policy['bans'])
            with self.assertRaises(PermissionError): engine.dispatch(self.request('bob/bob.test'))
            with self.assertRaises(ValueError): engine.dispatch(self.request(flags={'missing_files':True,'suspicious_queries':False,'exceptions':['/']}))
            injected = self.request(); injected['policy'] = {'mode':'off'}
            with self.assertRaises(ValueError): engine.dispatch(injected)
            self.policy['domain_bans']['allow_users'] = False
            with self.assertRaises(PermissionError): engine.dispatch(self.request())
