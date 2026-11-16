"""XML-RPC disabling is an explicit selected-site choice, independent of limits."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import xmlrpc_block
from policy import DEFAULT, global_config, validate


class XmlrpcBlockTests(unittest.TestCase):
    def test_previous_policy_upgrades_without_enabling_or_selecting_sites(self):
        old = copy.deepcopy(DEFAULT); old.pop('xmlrpc_block'); old['schema'] = 13
        old['mode'] = 'enforce'; old['xmlrpc'].update(enabled=True, rate=7, burst=2)
        new = validate(old)
        self.assertEqual(new['schema'], 14)
        self.assertEqual(new['xmlrpc_block'], dict(enabled=False, targets=[]))
        self.assertEqual(new['xmlrpc'], old['xmlrpc'])

    def test_empty_selection_never_means_all_sites_and_disabled_switch_is_inert(self):
        sites = [dict(key='alice/one.test'), dict(key='bob/two.test')]
        for settings in (dict(enabled=True, targets=[]), dict(enabled=False, targets=['alice/one.test'])):
            policy = copy.deepcopy(DEFAULT); policy['xmlrpc_block'] = settings
            section = global_config(policy, sites).split('map $hdn_site $hdn_xmlrpc_disabled_site {')[1].split('}')[0]
            self.assertNotIn('one.test 1;', section)
            self.assertNotIn('two.test 1;', section)

    def test_scope_excludes_unselected_suspended_unsupported_and_mail_sites(self):
        sites = [dict(key='alice/one.test'), dict(key='bob/two.test'),
                 dict(key='alice/suspended.test', suspended=True), dict(key='alice/bad.test', supported=False),
                 dict(key='alice/mail.test', kind='mail')]
        policy = copy.deepcopy(DEFAULT)
        policy['xmlrpc_block'] = dict(enabled=True, targets=[s['key'] for s in sites if s['key'] != 'bob/two.test'])
        section = global_config(policy, sites).split('map $hdn_site $hdn_xmlrpc_disabled_site {')[1].split('}')[0]
        self.assertIn('one.test 1;', section)
        for name in ('two', 'suspended', 'bad', 'mail'):
            self.assertNotIn(name + '.test 1;', section)

    def test_invalid_settings_are_rejected_and_targets_deduplicated(self):
        policy = copy.deepcopy(DEFAULT)
        policy['xmlrpc_block'] = dict(enabled=True, targets=['alice/one.test', 'alice/one.test'])
        self.assertEqual(validate(policy)['xmlrpc_block']['targets'], ['alice/one.test'])
        for settings in (dict(enabled=1, targets=[]), dict(enabled=True, targets='all'),
                         dict(enabled=True, targets=['../one.test']), dict(enabled=True, targets=[None]),
                         dict(enabled=True, targets=[], all=True)):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                validate({**policy, 'xmlrpc_block': settings})

    def test_older_panel_preserves_saved_choices_and_current_panel_can_clear_them(self):
        saved = copy.deepcopy(DEFAULT)
        saved['xmlrpc_block'] = dict(enabled=True, targets=['alice/one.test'])
        old = copy.deepcopy(DEFAULT); old.pop('xmlrpc_block'); old['schema'] = 13
        for incoming, expected in ((old, saved['xmlrpc_block']), (copy.deepcopy(DEFAULT), xmlrpc_block.DEFAULT)):
            with patch.object(engine, 'authorize', return_value=(True, 'root')), \
                    patch.object(engine, 'load', return_value=saved), patch.object(engine, 'collect', return_value=[]), \
                    patch.object(engine, 'snapshot', return_value={}), patch.object(engine, 'apply') as apply:
                engine.dispatch(dict(action='save', actor='root', policy=incoming))
            self.assertEqual(apply.call_args.args[0]['xmlrpc_block'], expected)


if __name__ == '__main__':
    unittest.main()
