"""Native discovery must be complete, account scoped and independent of alias order."""
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
if os.name == 'posix':
    import webuzo


@unittest.skipUnless(os.name == 'posix', 'Native Unix account discovery')
class NativeDiscovery(unittest.TestCase):
    def test_discovery_expands_native_page_and_accepts_existing_imported_uid(self):
        alice = dict(user='alice', homedir='/home/alice', status='')
        bob = dict(user='bob', homedir='/home/bob', status='suspended')
        responses = [dict(users={'1': alice}, num_res=2), dict(users={'1': alice, '2': bob}, num_res=2)]
        def identity(name):
            return SimpleNamespace(pw_uid=501, pw_dir='/home/' + name)
        with patch.object(webuzo, 'api', side_effect=responses) as api, patch.object(webuzo.pwd, 'getpwnam', side_effect=identity):
            users = webuzo.users()
        self.assertEqual(api.call_args_list[1].kwargs, {'reslen': 2})
        self.assertEqual(set(users), {'alice', 'bob'})
        self.assertFalse(users['alice']['suspended'])
        self.assertTrue(users['bob']['suspended'])

    def test_empty_and_incomplete_responses_are_distinct(self):
        with patch.object(webuzo, 'api', return_value=dict(users=[], num_res=0)):
            self.assertEqual(webuzo.users(), {})
        with patch.object(webuzo, 'api', return_value=dict(users={}, num_res=2)) as api:
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                webuzo.users()
        self.assertEqual(api.call_count, 2)

    def test_alias_before_primary_uses_primary_root_and_all_native_protocol_blocks(self):
        aliases = {'alias.test': dict(path='/home/alice/alias-placeholder'),
                   'one.test': dict(path='/home/alice/public_html')}
        server = dict(names=['one.test', 'alias.test'], roots=[['/home/alice/public_html']],
                      includes=[str(webuzo.CUSTOM / 'one.test.conf')], limits=False, cache=True)
        with patch.object(webuzo, 'users', return_value={'alice': dict(homedir='/home/alice', suspended=False)}), \
                patch.object(webuzo, 'native_list', return_value={name: dict(user='alice', domain=name, **row) for name,row in aliases.items()}), \
                patch.object(webuzo, 'servers', return_value=[server, {**server, 'names': ['one.test']}]):
            sites = webuzo.collect()
        self.assertEqual(len(sites), 1)
        self.assertTrue(sites[0]['supported'], sites[0]['reason'])
        self.assertEqual(sites[0]['domain'], 'one.test')
        self.assertIn('caching', sites[0]['template'])

    def test_location_limits_are_detected_without_parsing_quoted_text_as_code(self):
        text = 'server { server_name one.test; root /home/alice/public_html; location /login { limit_req zone=other; } }'
        with patch.object(webuzo, 'native_read', return_value=text.encode()):
            self.assertTrue(webuzo.servers()[0]['limits'])
        self.assertFalse(webuzo.has_limits(webuzo.directives('add_header X-Text "limit_req zone=literal;";')))

    def test_native_aliases_with_separate_virtual_hosts_share_one_policy_identity(self):
        rows = {'2': dict(user='alice', domain='alias.test', path='/home/alice/public_html', type='alias', alias='one.test'),
                '1': dict(user='alice', domain='one.test', path='/home/alice/public_html', type='primary')}
        servers = [dict(names=[host, 'www.' + host], roots=[['/home/alice/public_html']],
                        includes=[str(webuzo.CUSTOM / (host + '.conf'))], limits=False, cache=True)
                   for host in ('alias.test', 'one.test')]
        with patch.object(webuzo, 'users', return_value={'alice': dict(homedir='/home/alice', suspended=False)}), \
                patch.object(webuzo, 'native_list', return_value=rows), \
                patch.object(webuzo, 'servers', return_value=servers):
            sites = webuzo.collect()
        self.assertEqual(len(sites), 1)
        self.assertTrue(sites[0]['supported'])
        self.assertEqual(sites[0]['key'], 'alice/one.test')
        self.assertEqual(sites[0]['custom_domains'], ['alias.test', 'one.test'])
        self.assertEqual(sites[0]['paths'], [str(webuzo.SNIPPETS / 'one.test.conf')])
        self.assertIn('www.alias.test', sites[0]['aliases'])

    def test_alias_metadata_cannot_point_into_another_account_or_form_a_cycle(self):
        rows = {'1': dict(user='alice', domain='alias.test', path='/home/alice/public_html', type='alias', alias='other.test')}
        with patch.object(webuzo, 'users', return_value={'alice': dict(homedir='/home/alice', suspended=False)}), \
                patch.object(webuzo, 'native_list', return_value=rows), patch.object(webuzo, 'servers', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'does not belong'):
                webuzo.collect()
            rows['1']['alias'] = 'alias.test'
            with self.assertRaisesRegex(ValueError, 'Recursive'):
                webuzo.collect()

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root Nginx process fixtures')
    def test_reload_waits_until_old_workers_stop_accepting_new_connections(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); proc = root / 'proc'
            binary = root / 'nginx'; binary.touch()
            master = proc / '123'; (master / 'task/123').mkdir(parents=True)
            (master / 'exe').symlink_to(binary)
            children = master / 'task/123/children'; children.write_text('456')
            for pid in ('456', '789'):
                (proc / pid).mkdir()
                (proc / pid / 'cmdline').write_bytes(b'nginx: worker process\0')
            def path(value):
                return proc if str(value) == '/proc' else Path(value)
            def signal_master(pid, signal):
                self.assertEqual(pid, 123)
                children.write_text('456 789')
            def graceful_transition(delay):
                self.assertEqual(delay, .05)
                (proc / '456/cmdline').write_bytes(b'nginx: worker process is shutting down\0')
            def native_read(path):
                return b'pid /run/native-test.pid;' if path == webuzo.CONFIG else b'123'
            with patch.object(webuzo, 'Path', side_effect=path), \
                    patch.object(webuzo, 'NGINX', binary), \
                    patch.object(webuzo, 'native_read', side_effect=native_read), \
                    patch.object(webuzo, 'run'), \
                    patch.object(webuzo.os, 'kill', side_effect=signal_master), \
                    patch.object(webuzo.time, 'sleep', side_effect=graceful_transition) as transition:
                webuzo.reload_nginx()
            transition.assert_called_once()
