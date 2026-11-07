"""Native panel layout, separate forms, admin access and AJAX rendering."""
import copy
import json
import html.parser
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

import host_protection as host
import agent_catalog
from policy import DEFAULT
from test_ban_panel import Forms

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'Native PHP rendering')
class PanelTests(unittest.TestCase):
    def render(self, admin=True, ajax=False, install_state=None, csf=False, services_enabled=False,
               ajax_action='fail2ban_status', token='fixture-token', installed=True):
        data = dict(ok=True, policy=copy.deepcopy(DEFAULT), sites=[], bans={}, history={'days': 30},
                    maintenance={}, presets={'agent_categories': agent_catalog.CATEGORIES}, wordpress={}, cron={},
                    fail2ban=dict(installed=installed, loaded=True, running=True, settings=copy.deepcopy(host.DEFAULT),
                                  services={}, active_jails=['sshd'], conflicts=[]))
        for key, spec in host.SERVICES.items():
            data['fail2ban']['services'][key] = dict(title=spec['title'], ready=True, ports=[2222],
                source=dict(backend='auto', logpath='/var/log/<script>.log'), active=False, existing=[], ips=[])
            data['fail2ban']['settings'][key]['enabled'] = services_enabled
        if csf:
            data['fail2ban'].update(service_blockers=['CSF', 'LFD'], service_activation_blocked=True,
                                   service_activation_error=host.activation_error(['CSF', 'LFD']))
        if install_state:
            data['install_job'] = dict(state=install_state, message='Installing Fail2ban packages.')
            data['fail2ban'].update(running=False, error='Transient missing configuration during unpack')
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'data.json').write_text(json.dumps(data), encoding='utf-8')
            (path / 'render.php').write_text('''<?php
define('SOFTACULOUS',true);
$install=$argv[1];$fixture=json_decode(file_get_contents($argv[2]),true);
$isAdmin=$argv[3]==='1';$actor=$isAdmin?'root':'alice';$owner=$actor;$headerOwner=$owner;$csrf='fixture-token';$read_only=false;
$meta=['version'=>'test'];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
$bridge=static fn($request)=>$request['action']==='agents_candidates'?['ok'=>true,'received'=>$request]:$fixture;
$_SERVER['REQUEST_METHOD']=$argv[4]==='1'?'POST':'GET';$_GET=[];$_POST=[];
if($argv[4]==='1'){$_SERVER['HTTP_X_HDN_ANALYSIS']='1';$_POST=['action'=>$argv[5],'token'=>$argv[6],'tab'=>'fail2ban','analysis_job'=>str_repeat('a',32),'export_offset'=>'500','analysis_category'=>'search_agents'];}
require $install.'/panel/index.php';
''', encoding='utf-8')
            result = subprocess.run(['php', str(path / 'render.php'), str(ROOT), str(path / 'data.json'),
                                     '1' if admin else '0', '1' if ajax else '0', ajax_action, token],
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

    def test_analyzed_append_has_five_buttons_and_authenticated_read_only_transfer(self):
        body = self.render()
        self.assertEqual(body.count('>Append analyzed agents</button>'), 5)
        for category in agent_catalog.CATEGORIES:
            self.assertIn('data-hdn-append-analyzed="' + category + '"', body)
        for admin, token in ((False, 'fixture-token'), (True, 'wrong')):
            result = json.loads(self.render(admin=admin, ajax=True, ajax_action='agents_candidates', token=token))
            self.assertFalse(result['ok']); self.assertNotIn('received', result)
        result = json.loads(self.render(ajax=True, ajax_action='agents_candidates'))
        self.assertTrue(result['ok'])
        self.assertEqual(result['received']['category'], 'search_agents')
        self.assertEqual(result['received']['offset'], 500)
        self.assertEqual(result['received']['job'], 'a' * 32)
        self.assertNotIn('policy', result['received'])

    def test_partial_package_is_shown_as_installing_and_not_as_a_broken_service(self):
        for stage in ('queued', 'running'):
            body = json.loads(self.render(ajax=True, install_state=stage))['report']
            self.assertIn('<strong>Installation:</strong> In progress', body)
            self.assertIn('data-installing="true"', body)
            self.assertIn('refresh automatically', body)
            self.assertNotIn('Not available', body)
            self.assertNotIn('Transient missing configuration', body)
            self.assertNotIn('Enable &amp; start existing', body)
            self.assertNotIn('id="hdn-services-settings"', body)
            parsed = Forms(); parsed.feed(body)
            self.assertFalse(parsed.nested); self.assertEqual(parsed.depth, 0)

    def test_failed_installation_keeps_actual_service_diagnostic_visible(self):
        body = json.loads(self.render(ajax=True, install_state='failed'))['report']
        self.assertIn('Not available', body)
        self.assertIn('Transient missing configuration', body)
        self.assertIn('data-installing="false"', body)

    def test_csf_blocks_service_controls_but_wordpress_controls_remain_available(self):
        class Inputs(html.parser.HTMLParser):
            def __init__(self): super().__init__(); self.inputs = {}
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'input' and attrs.get('type') == 'checkbox': self.inputs[attrs['name']] = attrs
        for enabled in (False, True):
            body = json.loads(self.render(ajax=True, csf=True, services_enabled=enabled))['report']
            fields = Inputs(); fields.feed(body)
            for key in host.SERVICES:
                self.assertEqual('disabled' in fields.inputs['services[' + key + '][enabled]'], not enabled)
            self.assertNotIn('disabled', fields.inputs['wordpress_enabled'])
            self.assertIn('WordPress login protection remains available.', body)
            self.assertLess(body.index('WordPress login protection'), body.index('<h2 class="u-mb20">Fail2ban</h2>'))
            if enabled: self.assertIn('Uncheck all enabled service protections', body)

    def test_csf_blocks_package_preview_instead_of_starting_the_distribution_ssh_jail(self):
        body = json.loads(self.render(ajax=True, csf=True, installed=False))['report']
        self.assertIn('Automatic installation is blocked while CSF/LFD is installed', body)
        self.assertIn('disabled>Preview Fail2ban installation</button>', body)
        self.assertNotIn('value="fail2ban_install_start"', body)
