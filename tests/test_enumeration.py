import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import enumeration
from policy import V9_KEYS, DEFAULT, validate, site_mode
import test_engine as engine_tests
import test_nginx as nginx_tests


class EnumerationPolicyTests(unittest.TestCase):
    def test_upgrade_starts_off_and_rejects_injected_scope_or_non_boolean(self):
        old = {key: copy.deepcopy(DEFAULT[key]) if key in DEFAULT else {'allow_users':True,'sites':{}} for key in V9_KEYS}; old.pop('enumeration'); old['schema'] = 8
        upgraded = validate(old)
        self.assertEqual(upgraded['schema'], 11)
        self.assertEqual(upgraded['enumeration'], enumeration.SETTINGS)
        for value in ('yes', 1, None):
            bad = copy.deepcopy(DEFAULT); bad['enumeration']['enabled'] = value
            with self.assertRaises(ValueError): validate(bad)
        bad = copy.deepcopy(DEFAULT); bad['enumeration']['targets'] = ['alice/../etc']
        with self.assertRaises(ValueError): validate(bad)

    def test_stale_panel_save_preserves_new_setting(self):
        saved = copy.deepcopy(DEFAULT); saved['enumeration']['enabled'] = True
        old = {key: copy.deepcopy(DEFAULT[key]) if key in DEFAULT else {'allow_users':True,'sites':{}} for key in V9_KEYS}; old['schema'] = 8; old.pop('enumeration')
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
             patch.object(engine, 'load', return_value=saved), patch.object(engine, 'collect', return_value=[]), \
             patch.object(engine, 'apply') as apply, patch.object(engine, 'snapshot', return_value={}):
            engine.dispatch(dict(actor='admin', action='save', policy=old))
        self.assertEqual(apply.call_args.args[0]['enumeration'], saved['enumeration'])

    def test_unchanged_fingerprint_has_no_website_process_and_observe_does_not_install(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'wp-includes').mkdir(); (root/'wp-load.php').touch(); (root/'wp-includes/version.php').touch()
            site=dict(owner='alice',domain='one.test',key='alice/one.test',supported=True,roots={'nginx':str(root)})
            policy=copy.deepcopy(DEFAULT);policy['mode']='enforce';policy['enumeration']['enabled']=True
            with patch.object(enumeration, 'helper', return_value=dict(wordpress=True,body=None)) as helper:
                prepared, manifest, changes=enumeration.prepare(policy,[site],{},site_mode)
            self.assertTrue(prepared[0]['enumeration_ready']);self.assertEqual(len(changes),1)
            with patch.object(enumeration,'helper') as helper:
                enumeration.prepare(policy,[site],manifest,site_mode)
                helper.assert_not_called()
                policy['mode']='observe'
                prepared,manifest,changes=enumeration.prepare(policy,[site],{},site_mode)
                helper.assert_not_called()
            self.assertTrue(prepared[0]['enumeration_ready']);self.assertEqual(manifest,{});self.assertEqual(changes,[])

    @unittest.skipUnless(shutil.which('php'), 'PHP CLI')
    def test_guard_checks_actual_login_and_leaves_other_api_and_authenticated_reads(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);plugin=root/'plugin.php';plugin.write_text(enumeration.payload(enumeration.SETTINGS))
            script=root/'test.php'
            script.write_text('''<?php
            define('ABSPATH',__DIR__);$filters=[];$logged=false;
            function add_filter($name,$callback,...$args){$GLOBALS['filters'][$name]=$callback;}
            function add_action(...$args){}
            function is_user_logged_in(){return $GLOBALS['logged'];}
            class WP_Error{public function __construct(...$args){}}
            class Request{public $route; public function __construct($route){$this->route=$route;}public function get_method(){return 'GET';}public function get_route(){return $this->route;}}
            require $argv[1];
            foreach(['/wp/v2/users','/wp/v2/users/1','/wp/v2/users/me','/wp/v2/posts','/wc/v3/orders'] as $route){
                foreach([false,true] as $logged){$r=$filters['rest_pre_dispatch'](null,null,new Request($route));
                    echo json_encode([$route,$logged,$r instanceof WP_Error])."\\n";}}
            ''')
            result=subprocess.run(['php',str(script),str(plugin)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        for line in result.stdout.splitlines():
            route,logged,blocked=json.loads(line)
            self.assertEqual(blocked, not logged and route in ('/wp/v2/users','/wp/v2/users/1'))


class EnumerationTransactionTests(engine_tests.TransactionTests):
    def test_enabling_on_native_caching_uses_the_native_account_clear(self):
        site={**self.site,'owner':'alice','domain':'example.test','template':'caching'}
        changes=[dict(owner='alice',root=str(self.directory),before=None,after='owned')]
        manifest={site['key']:dict(owner='alice',root=str(self.directory),digest='fixture')}
        with patch.object(enumeration,'prepare',return_value=([site],manifest,changes)), \
             patch.object(enumeration,'apply'),patch.object(engine,'verify'),patch.object(engine.webuzo,'cli',return_value='') as command:
            engine.apply(DEFAULT,[site])
        command.assert_called_once_with('clear_cache', users='alice')

    def test_companion_and_manifest_roll_back_when_nginx_validation_fails(self):
        changes=[dict(owner='alice',root='/home/alice/web/one.test/public_html',before=None,after='owned')]
        with patch.object(enumeration,'prepare',return_value=([self.site],{'alice/one.test':{}},changes)), \
             patch.object(enumeration,'apply') as apply, patch.object(engine,'verify',side_effect=RuntimeError('bad candidate')), \
             patch.object(engine,'run',return_value=''):
            with self.assertRaisesRegex(RuntimeError,'bad candidate'):engine.apply(DEFAULT,[self.site])
        self.assertEqual(apply.call_args_list[0].args[0],changes)
        self.assertEqual(apply.call_args_list[1].kwargs,{'reverse':True})
        self.assertFalse((self.state/enumeration.MANIFEST).exists())


class EnumerationNginxTests(nginx_tests.NativeNginxTests):
    @classmethod
    def setUpClass(cls):
        # Reuse the native server fixture with protection scoped to one domain.
        from policy import global_config as compile_config
        import test_nginx
        def config(policy,sites,*args):
            policy=copy.deepcopy(policy)
            policy['enumeration'].update(enabled=True,targets=['alice/enforce.test','alice/observe.test'])
            for site in sites:site.update(domain=site['key'].split('/')[1],enumeration_ready=True)
            cls.enumeration_policy=policy
            return compile_config(policy,sites,*args)
        original_site_config=test_nginx.site_config
        def site_config(policy,site,*args):
            return original_site_config(cls.enumeration_policy,site,*args)
        with patch.object(test_nginx,'global_config',side_effect=config),patch.object(test_nginx,'site_config',side_effect=site_config):
            super().setUpClass()

    def test_public_users_variants_block_before_origin_without_banning(self):
        paths=['/wp-json/wp/v2/users','/wp-json/wp/v2/users/1','/wp-json/wp/v2/users/',
               '/wp-json/wp/v2/%75sers','/?rest_route=/wp/v2/users',
               '/?rest_route=%2Fwp%2Fv2%2Fusers%2F1','/?%72est_route=%2fwp%2fv2%2fusers',
               '/?x=1&rest_route=/wp/v2/users','/?author=1','/?x=1&author=1','/index.php?author=123']
        for path in paths:
            with self.subTest(path=path):
                before=nginx_tests.Origin.hits
                self.assertEqual(self.request(path),403)
                self.assertEqual(nginx_tests.Origin.hits,before)
                self.assertEqual(self.request(path,host='other.test'),200)
                self.assertEqual(self.request(path,host='observe.test'),200)
                self.assertEqual(self.request(path,host='off.test'),200)
        self.assertEqual(self.request('/'),200)
        self.assertIn('user-enumeration',(self.directory/'matches.log').read_text())
        self.assertNotIn('user-enumeration',(self.directory/'ban-events.log').read_text())

    def test_unrelated_routes_author_pages_login_resets_and_users_me_work(self):
        for path in ['/wp-json/wp/v2/posts?author=1','/wp-json/wp/v2/users/me','/wp-json/wp/v2/users-example',
                     '/?rest_route=/wp/v2/users/me','/author/public-name/', '/?author_name=public-name',
                     '/wp-admin/users.php','/wp-json/wc/v3/orders','/wp-login.php?action=lostpassword',
                     '/wp-login.php?action=rp&key=example']:
            with self.subTest(path=path):self.assertEqual(self.request(path),200)

    def test_cookie_presence_is_only_passed_to_wordpress_not_accepted_as_authentication(self):
        import http.client
        for headers in [{'Cookie':'wordpress_logged_in_fake=not-a-valid-cookie'},
                        {'Authorization':'Basic invalid'}]:
            connection=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
            connection.request('GET','/wp-json/wp/v2/users',headers={'Host':'enforce.test',**headers})
            response=connection.getresponse();response.read();connection.close()
            # This fixture origin is only a stub. Actual rejection is checked
            # separately against the companion and a real WordPress fixture.
            self.assertEqual(response.status,200)
