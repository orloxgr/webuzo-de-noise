"""Native discovery must be complete, account scoped and independent of alias order."""
import os
from pathlib import Path
import sys
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
