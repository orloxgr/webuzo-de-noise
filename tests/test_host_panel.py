"""Native panel layout, separate forms, admin access and AJAX rendering."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

import host_protection as host
from policy import DEFAULT
from test_ban_panel import Forms

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'Native PHP rendering')
class PanelTests(unittest.TestCase):
    def render(self, admin=True, ajax=False):
        data = dict(ok=True, policy=copy.deepcopy(DEFAULT), sites=[], bans={}, history={'days': 30},
                    maintenance={}, presets={}, wordpress={}, cron={},
                    fail2ban=dict(installed=True, loaded=True, running=True, settings=copy.deepcopy(host.DEFAULT),
                                  services={}, active_jails=['sshd'], conflicts=[]))
        for key, spec in host.SERVICES.items():
            data['fail2ban']['services'][key] = dict(title=spec['title'], ready=True, ports=[2222],
                source=dict(backend='auto', logpath='/var/log/<script>.log'), active=False, existing=[], ips=[])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'data.json').write_text(json.dumps(data), encoding='utf-8')
            (path / 'render.php').write_text('''<?php
define('SOFTACULOUS',true);
$install=$argv[1];$fixture=json_decode(file_get_contents($argv[2]),true);
$isAdmin=$argv[3]==='1';$actor=$isAdmin?'root':'alice';$owner=$actor;$csrf='fixture-token';$read_only=false;
$meta=['version'=>'test'];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
$bridge=static fn($request)=>$fixture;
$_SERVER['REQUEST_METHOD']=$argv[4]==='1'?'POST':'GET';$_GET=[];$_POST=[];
if($argv[4]==='1'){$_SERVER['HTTP_X_HDN_ANALYSIS']='1';$_POST=['action'=>'fail2ban_status','token'=>$csrf,'tab'=>'fail2ban'];}
require $install.'/panel/index.php';
''', encoding='utf-8')
            result = subprocess.run(['php', str(path / 'render.php'), str(ROOT), str(path / 'data.json'),
                                     '1' if admin else '0', '1' if ajax else '0'],
                                    capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout

    def test_general_domains_follow_save_and_have_a_separate_bulk_form(self):
        body = self.render()
        general = body[body.index('id="hdn-panel-general"'):body.index('id="hdn-panel-agents"')]
        self.assertLess(general.index('id="hdn-general-save"'), general.index('>Domains</h2>'))
        self.assertIn('value="bulk"', general); self.assertIn('Apply to selected', general)
        self.assertIn('id="hdn-tab-fail2ban"', body)
        self.assertNotIn('id="hdn-tab-domains"', body); self.assertNotIn('Domain automatic bans', body)
        parsed = Forms(); parsed.feed(body)
        self.assertFalse(parsed.nested); self.assertEqual(parsed.depth, 0)

    def test_account_has_no_domain_ban_controls_or_server_services(self):
        body = self.render(admin=False)
        self.assertIn('id="hdn-tab-domains"', body); self.assertIn('id="hdn-tab-activity"', body)
        self.assertNotIn('id="hdn-tab-fail2ban"', body); self.assertNotIn('domain_bans_save', body)
        self.assertNotIn('hdn-settings', body); self.assertNotIn('Apply to selected', body)

    def test_ajax_service_status_has_valid_fields_escaping_and_no_nested_forms(self):
        result = json.loads(self.render(ajax=True))
        self.assertTrue(result['ok']); body = result['report']
        self.assertIn('value="fixture-token"', body); self.assertIn('value="fail2ban_save"', body)
        self.assertIn('form="hdn-services-settings"', body)
        self.assertIn('&lt;script&gt;.log', body); self.assertNotIn('<script>.log', body)
        self.assertIn('password authentication', body)
        parsed = Forms(); parsed.feed(body)
        self.assertFalse(parsed.nested); self.assertEqual(parsed.depth, 0)

    def test_account_cannot_request_admin_ajax_even_when_post_is_forged(self):
        result = json.loads(self.render(admin=False, ajax=True))
        self.assertFalse(result['ok']); self.assertNotIn('report', result)
