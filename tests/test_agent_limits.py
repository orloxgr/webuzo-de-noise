"""Server-wide budgets, legacy saves and actual native Nginx HTTP behavior."""
import copy
import http.client
from http.server import ThreadingHTTPServer
import json
import os
import shutil
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import agent_catalog
import agent_limits
import activity
import engine
from policy import DEFAULT, validate, validate_agents, global_config, site_config, literal_regex
from test_nginx import Origin
from native_nginx import isolated_config
import test_endpoint_panel as native_parser


def individual(name, rate=1, unit='m', burst=0, enabled=True):
    return dict(agent=name, rate=rate, unit=unit, burst=burst, enabled=enabled)


def configured():
    policy = copy.deepcopy(DEFAULT)
    policy.update(mode='enforce', agents=['GroupA', 'GroupB', 'IndividualBot', 'ExactBot', 'DisabledBot', 'BlockOnly'])
    policy['agent_limits']['tool_agents']['group'].update(enabled=True,
        agents=['GroupA', 'GroupB', 'IndividualBot'], rate=1)
    policy['agent_limits']['ai_agents']['individual'] = [individual('IndividualBot')]
    policy['agent_limits']['search_agents']['individual'] = [individual('ExactBot'),
        individual('ExactBot-Image', burst=3), individual('SecondBot',rate=2,unit='s'), individual('Odd";${literal}#(a)+[b]\\c')]
    policy['agent_limits']['agents']['individual'] = [individual('DisabledBot',enabled=False)]
    policy['agent_limits']['agents']['group'].update(agents=['DisabledBot'],rate=1)
    policy['overrides'] = {'alice/observe.test':'observe', 'alice/off.test':'off'}
    policy['scanners'] = True
    policy['agent_limits']['seo_agents']['group'].update(enabled=True, agents=['GroupA-Specific'], rate=1)
    policy['filters'] = [dict(id='shop', enabled=True, path='/shop/', parameters=['orderby'],
        agents=['IndividualBot'], action='block', rate=1, burst=0, targets=[])]
    return policy


class AgentLimitPolicyTests(unittest.TestCase):
    def test_upgrade_preserves_every_choice_and_adds_only_empty_disabled_controls(self):
        old = copy.deepcopy(DEFAULT); old.pop('agent_limits'); old['schema'] = 15
        old.update(agents=['Custom'], agents_enabled=False, mode='enforce')
        new = validate(old)
        self.assertEqual({k:v for k,v in new.items() if k not in ('schema','agent_limits')},
                         {k:v for k,v in old.items() if k != 'schema'})
        self.assertEqual(new['agent_limits'], agent_limits.DEFAULT)
        self.assertFalse(agent_limits.rules(new['agent_limits']))

    def test_old_open_panel_preserves_new_settings_and_current_panel_can_clear(self):
        saved = validate(configured())
        for current in (False, True):
            incoming = copy.deepcopy(DEFAULT)
            if not current:
                incoming.pop('agent_limits'); incoming['schema'] = 15
            with patch.object(engine, 'authorize', return_value=(True,'root')), \
                 patch.object(engine, 'load', return_value=saved), patch.object(engine, 'collect', return_value=[]), \
                 patch.object(engine, 'snapshot', return_value={}), patch.object(engine, 'apply') as apply:
                engine.dispatch(dict(actor='root', action='save', policy=incoming))
            self.assertEqual(apply.call_args.args[0]['agent_limits'],
                             agent_limits.DEFAULT if current else saved['agent_limits'])

    def test_rate_validation_rejects_injection_invalid_values_and_conflicts(self):
        for field, value in [('rate',0),('rate',True),('rate',None),('burst',-1),('burst',False),
                             ('unit','m;return 200'),('agent','a\nreturn 403')]:
            policy = configured(); policy['agent_limits']['ai_agents']['individual'][0][field] = value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError): validate(policy)
        policy = configured()
        policy['agent_limits']['agents']['individual'] = [individual('individualbot',rate=2)]
        with self.assertRaisesRegex(ValueError, 'Conflicting'): validate(policy)
        policy['agent_limits']['agents']['individual'] = [individual('individualbot',rate=1)]
        self.assertEqual(len([r for r in agent_limits.rules(validate(policy)['agent_limits'])
                              if r.get('agent','').lower() == 'individualbot']),1)
        policy = configured()
        policy['agent_limits']['agents']['group'].update(enabled=True,agents=['groupa'],rate=2)
        with self.assertRaisesRegex(ValueError, 'multiple enabled'): validate(policy)
        policy = configured(); policy['agent_limits']['tool_agents']['group']['agents'] = []
        with self.assertRaisesRegex(ValueError,'at least one'): validate(policy)

    def test_matching_order_is_stable_for_equal_length_groups_and_individuals(self):
        policy = configured()
        policy['agent_limits']['ai_agents']['individual'] += [individual('beta'), individual('alfa')]
        policy['agent_limits']['agents']['group'].update(enabled=True, agents=['zeta'], rate=1)
        policy['agent_limits']['tool_agents']['group']['agents'] += ['yeta']
        text = '\n'.join(agent_limits.compile_maps(validate(policy)['agent_limits'], literal_regex))
        self.assertLess(text.index(literal_regex('alfa')), text.index(literal_regex('beta')))
        self.assertLess(text.index(literal_regex('yeta')), text.index(literal_regex('zeta')))
        # Equivalent duplicate units create only one individual zone.
        policy['agent_limits']['agents']['individual'] = [individual('BETA', rate=60)]
        policy['agent_limits']['ai_agents']['individual'][-2]['unit'] = 's'
        selected = agent_limits.rules(validate(policy)['agent_limits'])
        self.assertEqual(sum(r.get('agent', '').lower() == 'beta' for r in selected), 1)

    def test_webuzo_webmail_remains_in_its_separate_native_nginx(self):
        import webmail
        policy = configured(); policy['mail_protection'] = True
        policy['agents'] = ['GroupA', 'ManualMailBlock']
        profile = webmail.profile(policy)
        self.assertEqual(profile['agents'], ['GroupA', 'ManualMailBlock'])
        self.assertEqual(webmail.match(profile, '/mail/', 'GroupA'), 'agent')
        self.assertNotIn('limit_req', webmail.compile(profile))
        self.assertNotIn('limit_req', site_config(policy, dict(key='root/webmail', kind='mail')))

    def test_precedence_specificity_stable_ids_empty_keys_and_observe_separation(self):
        policy = configured(); text = global_config(policy,[])
        self.assertLess(text.index(literal_regex('ExactBot-Image')),text.index(literal_regex('ExactBot') + ' agent-individual'))
        self.assertIn('~^observe:agent-group-tool_agents$ observe;',text)
        self.assertIn('~^enforce:agent-group-tool_agents$ enforce;',text)
        self.assertNotIn('$remote_addr', '\n'.join(agent_limits.compile_maps(policy['agent_limits'],literal_regex)))
        self.assertNotIn('$server_name', '\n'.join(agent_limits.compile_maps(policy['agent_limits'],literal_regex)))
        before = {r['label']:agent_limits.zone(r) for r in agent_limits.rules(policy['agent_limits'])}
        policy['agent_limits']['search_agents']['individual'].reverse()
        after = {r['label']:agent_limits.zone(r) for r in agent_limits.rules(policy['agent_limits'])}
        self.assertEqual(before,after)
        self.assertNotIn('limit_req ',site_config(policy,{'key':'alice/off.test'}))

    def test_owner_cannot_submit_server_wide_limits(self):
        with patch.object(engine.webuzo,'users',return_value={'alice':{'suspended':False}}):
            with self.assertRaises(PermissionError):
                engine.dispatch(dict(actor='alice',action='save',policy=configured()))

    def test_shapbot_is_optional_search_indexing_suggestion(self):
        self.assertIn('ShapBot',agent_catalog.SEARCH_ADDITIONAL)
        self.assertEqual(agent_catalog.observed('Mozilla/5.0 compatible; ShapBot/0.1.0'),('ShapBot','search_agents'))
        self.assertEqual(agent_catalog.describe('ShapBot')['operator'],'Parallel')
        self.assertNotIn(literal_regex('ShapBot'),global_config(DEFAULT,[]))


@unittest.skipUnless(shutil.which('php'), 'PHP CLI required')
class AgentLimitSaveParserTests(unittest.TestCase):
    parse = native_parser.SaveParser.parse
    base = staticmethod(lambda: dict(endpoint_settings_schema='13', endpoint404_duration='0', endpoint404_unit='days', endpoint404_maxretry='1', endpoint404_findtime='300', mode='observe'))
    def test_agent_form_parses_empty_defaults_manual_names_and_blank_inactive_rate(self):
        post = dict(self.base(), xmlrpc_block_present='1',xmlrpc_exceptions_present='1',
                    xmlrpc_global_present='1',agent_limits_present='1')
        post['agent_groups'] = {field:dict(agents='',rate='',unit='m',burst='0') for field in agent_catalog.CATEGORIES}
        post['agent_groups']['agents'].update(enabled='on',agents='CustomOne\nCustomTwo',rate='5',unit='s',burst='2')
        post['agent_individual'] = {'search_agents':{'9':dict(agent='My manual bot',rate='',unit='m',burst='0')}}
        result = self.parse(post)
        self.assertEqual(result.returncode,0,result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['schema'],16)
        self.assertEqual(data['agent_limits']['agents']['group']['agents'],['CustomOne','CustomTwo'])
        agent_limits.validate(data['agent_limits'], validate_agents)
        self.assertIsNone(data['agent_limits']['search_agents']['individual'][0]['rate'])
        post['agent_groups'].pop('ai_agents')
        self.assertNotEqual(self.parse(post).returncode,0)


@unittest.skipUnless(os.environ.get('HDN_TEST_NGINX'), 'Requires an isolated native Nginx binary')
class NativeAgentLimitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hdn-agent-http-')
        self.directory = Path(self.temp.name); self.directory.chmod(0o755)
        (self.directory/'logs').mkdir()
        self.origin = ThreadingHTTPServer(('127.0.0.1',0),Origin)
        self.thread = threading.Thread(target=self.origin.serve_forever,daemon=True); self.thread.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.origin.server_close)
        self.addCleanup(self.origin.shutdown)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0)); self.port = probe.getsockname()[1]
        policy = configured()
        sites = [dict(key='alice/'+host) for host in ('one.test','two.test','observe.test','off.test')]
        if self._testMethodName == 'test_independent_login_limiter_keeps_its_label_and_overall_rate_status':
            policy['login'].update(enabled=True, rate=1, burst=0)
        (self.directory/'asset.css').write_text('body{}')
        text = 'daemon off; worker_processes 2; pid logs/nginx.pid; error_log logs/error.log notice; events {worker_connections 64;} http {\n'
        text += global_config(policy,sites)
        for site in sites:
            host = site['key'].split('/')[1]
            text += f'server {{ listen 127.0.0.1:{self.port}; server_name {host} www.{host};\n'
            text += site_config(policy,site).replace('/var/log/webuzo-de-noise/matches.log',(self.directory/'matches.log').as_posix())
            text += f'location = /asset.css {{ root {self.directory.as_posix()}; }}\n'
            text += f'location / {{ proxy_pass http://127.0.0.1:{self.origin.server_address[1]}; }} }}\n'
        text += '}\n'
        (self.directory/'nginx.conf').write_text(isolated_config(text,self.directory))
        self.command = [os.environ['HDN_TEST_NGINX'],'-p',self.directory.as_posix()+'/', '-c','nginx.conf']
        check = subprocess.run([*self.command,'-t'],capture_output=True,text=True)
        self.assertEqual(check.returncode,0,check.stderr)
        self.process = subprocess.Popen(self.command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop)
        deadline = time.monotonic()+5
        while True:
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=.1): break
            except OSError:
                if time.monotonic()>deadline: self.fail('Isolated Nginx did not start')
                time.sleep(.02)

    def stop(self):
        subprocess.run([*self.command,'-s','quit'],capture_output=True,timeout=5)
        self.process.wait(timeout=10)

    def request(self,agent,host='one.test',source='127.0.0.1',path='/',method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1',self.port,timeout=3,source_address=(source,0))
        connection.request(method,path,headers={'Host':host,'User-Agent':agent})
        response = connection.getresponse(); status=response.status; response.read(); connection.close()
        return status

    def test_group_shares_all_bots_sites_aliases_ips_assets_and_methods(self):
        before = Origin.hits
        self.assertEqual(self.request('GroupA',path='/image.png'),200)
        self.assertEqual(self.request('GroupB',host='two.test',source='127.0.0.2',path='/style.css',method='POST'),429)
        self.assertEqual(self.request('GroupA',host='www.one.test',source='127.0.0.3'),429)
        self.assertEqual(Origin.hits-before,1)

    def test_longest_group_substring_wins_and_other_group_keeps_its_budget(self):
        self.assertEqual(self.request('GroupA-Specific/1'), 200)
        self.assertEqual(self.request('GroupA-Specific/1'), 429)
        self.assertEqual(self.request('GroupA'), 200)
        self.assertEqual(self.request('GroupB'), 429)
        self.assertIn('agent-group-seo_agents REJECTED', (self.directory/'matches.log').read_text())

    def test_native_static_asset_consumes_the_same_group_budget(self):
        before = Origin.hits
        self.assertEqual(self.request('GroupA', path='/asset.css'), 200)
        self.assertEqual(self.request('GroupB', host='two.test', path='/asset.css'), 429)
        self.assertEqual(Origin.hits, before)

    def test_independent_login_limiter_keeps_its_label_and_overall_rate_status(self):
        self.assertEqual(self.request('ExactBot-Image', path='/wp-login.php', method='POST'), 200)
        self.assertEqual(self.request('ExactBot-Image', path='/wp-login.php', method='POST'), 429)
        self.assertIn(' login REJECTED 429 enforce', (self.directory/'matches.log').read_text())
        self.assertEqual(self.request('ExactBot-Image', path='/image.png'), 200)

    def test_individual_overrides_other_category_group_and_block_without_debiting_group(self):
        self.assertEqual(self.request('IndividualBot'),200)
        self.assertEqual(self.request('IndividualBot',host='two.test',source='127.0.0.2'),429)
        self.assertEqual(self.request('GroupA'),200)
        self.assertEqual(self.request('GroupB'),429)
        log=(self.directory/'matches.log').read_text()
        self.assertIn('agent-individual-ai_agents-',log)
        self.assertIn('agent-group-tool_agents REJECTED 429 enforce',log)

    def test_observe_and_off_do_not_consume_enforce_budget(self):
        for _ in range(4):
            self.assertEqual(self.request('GroupA',host='observe.test'),200)
            self.assertEqual(self.request('IndividualBot',host='observe.test'),200)
            self.assertEqual(self.request('GroupB',host='off.test'),200)
        self.assertEqual(self.request('GroupB'),200)
        self.assertEqual(self.request('IndividualBot'),200)
        self.assertEqual(self.request('GroupA'),429)
        # Enforce exhaustion must not change Observe into a real rejection.
        self.assertEqual(self.request('GroupA',host='observe.test'),200)
        log=(self.directory/'matches.log').read_text()
        self.assertIn('REJECTED_DRY_RUN 200 observe',log)
        self.assertNotIn(' off\t',log)
        with patch.object(activity,'LOG',self.directory/'matches.log'):
            report=activity.summary({'observe.test','one.test'})
        self.assertTrue(any(row['limit']=='REJECTED_DRY_RUN' and row['outcome']=='observed' for row in report['recent']))

    def test_longest_individual_and_burst_literal_escaping_and_unknown_pass(self):
        for _ in range(4): self.assertEqual(self.request('ExactBot-Image/1'),200)
        self.assertEqual(self.request('ExactBot-Image/1'),429)
        self.assertEqual(self.request('ExactBot'),200)
        self.assertEqual(self.request('ExactBot'),429)
        literal='Odd";${literal}#(a)+[b]\\c'
        self.assertEqual(self.request(literal),200)
        self.assertEqual(self.request(literal),429)
        self.assertEqual(self.request('Odd'),200)
        self.assertEqual(self.request('Mozilla/5.0'),200)

    def test_seconds_unit_refills_and_native_reload_accepts_changed_rate(self):
        self.assertEqual(self.request('SecondBot'),200)
        self.assertEqual(self.request('SecondBot'),429)
        time.sleep(.55)
        self.assertEqual(self.request('SecondBot'),200)
        self.assertEqual(self.request('GroupA'),200)
        self.assertEqual(self.request('GroupB'),429)
        config=self.directory/'nginx.conf'
        config.write_text(config.read_text().replace('rate=1r/m;', 'rate=1000r/s;'))
        candidate=subprocess.run([*self.command,'-t'],capture_output=True,text=True)
        self.assertEqual(candidate.returncode,0,candidate.stderr)
        reload=subprocess.run([*self.command,'-s','reload'],capture_output=True,text=True)
        self.assertEqual(reload.returncode,0,reload.stderr)
        deadline=time.monotonic()+3
        while self.request('GroupB') != 200:
            if time.monotonic()>deadline:self.fail('New rate not active after reload')
            time.sleep(.02)

    def test_other_protections_still_block_a_rate_limited_bot(self):
        before=Origin.hits
        self.assertEqual(self.request('DisabledBot'),403)
        self.assertEqual(self.request('BlockOnly'),403)
        self.assertEqual(self.request('IndividualBot',path='/.env'),403)
        self.assertEqual(self.request('IndividualBot',path='/shop/?orderby=price'),403)
        self.assertEqual(Origin.hits,before)


if __name__ == '__main__':
    unittest.main()
