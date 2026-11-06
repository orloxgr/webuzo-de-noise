import copy
import html.parser
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from policy import DEFAULT

ROOT = Path(__file__).resolve().parents[1]


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.depth = 0; self.nested = False; self.forms = []; self.current = None; self.links = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.nested |= self.depth > 0; self.depth += 1; self.current = {}
        if tag == 'input' and self.current is not None and attrs.get('name'):
            self.current[attrs['name']] = attrs.get('value', '')
        if tag == 'a':self.links.append(attrs)
    def handle_endtag(self, tag):
        if tag == 'form':
            self.depth -= 1; self.forms.append(self.current); self.current = None


@unittest.skipUnless(shutil.which('php'), 'PHP CLI for server-rendered panel components')
class BanPanelTests(unittest.TestCase):
    def test_unavailable_activity_does_not_display_a_zero_measurement(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'activity.php'
            source.write_text('''<?php
                define('SOFTACULOUS', true);
                $data=[];$isAdmin=true;$headerOwner='admin';$install=$argv[1];$fields=static function($action){};
                $escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
                require $argv[1].'/panel/activity.php';
            ''')
            r=subprocess.run(['php',str(source),str(ROOT)],capture_output=True,text=True,timeout=5)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('only when requested',r.stdout)
        self.assertNotIn('0 in the bounded',r.stdout)
        self.assertNotIn('Matched requests',r.stdout)
        self.assertIn('hdn-activity-scan',r.stdout)

    def render(self, view, scope):
        data = dict(policy=copy.deepcopy(DEFAULT),sites=[],history={'days':30},bans={},domain_bans={})
        meta=dict(page=2,pages=4,total=177,per_page=50,view=view)
        row=dict(ip='198.51.100.7',domain='one.test',reason='domain-file' if scope=='domain' else 'private-file',
                 created=1000,expires=0,ended=1100,status='released' if view=='history' else 'active',error='',
                 diagnostics=dict(v=1,count=2,maxretry=2,findtime=60,duration_days=3,
                                  samples=[dict(at=1000,domain='one.test',reason='private-file',method='GET',path='/<img onerror=alert(1)>')]))
        data['bans' if scope=='bans' else 'domain_bans'] = dict(rows=[row],pagination=meta,active=177,pending=0)
        if scope=='wordpress':
            data['wordpress']=dict(loaded=True,available=True,active=True,ips=['198.51.100.7'],pagination=meta)
        fixture={'data':data,'listing':dict(bans_page=2,bans_view=view if scope=='bans' else 'active',
                    domain_page=2,domain_view=view if scope=='domain' else 'active')}
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'render.php';payload=Path(temp)/'data.json'
            payload.write_text(json.dumps(fixture))
            source.write_text('''<?php
                define('SOFTACULOUS', true);
                $fixture=json_decode(file_get_contents($argv[1]),true);
                $install=$argv[2];$data=$fixture['data'];$policy=$data['policy'];$listing=$fixture['listing'];
                $isAdmin=true;$read_only=false;$error='';$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
                $fields=static function($action)use($escape,$listing){echo '<input name="action" value="'.$escape($action).'">';
                    foreach($listing as $k=>$v)echo '<input name="'.$escape($k).'" value="'.$escape($v).'">';};
                require $install.'/panel/'.$argv[3].'.php';
            ''')
            r=subprocess.run(['php',str(source),str(payload),str(ROOT),{'bans':'bans','domain':'domain-bans','wordpress':'wordpress'}[scope]],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stderr,'')
        parsed=Forms();parsed.feed(r.stdout)
        return parsed,r.stdout

    def test_active_and_history_forms_do_not_nest_and_links_preserve_tab_and_scope(self):
        for scope,tab in [('bans','bans'),('domain','domain-bans')]:
            for view in ['active','history']:
                with self.subTest(scope=scope,view=view):
                    parsed,body=self.render(view,scope)
                    self.assertFalse(parsed.nested);self.assertEqual(parsed.depth,0)
                    hrefs=[a.get('href','') for a in parsed.links]
                    self.assertTrue(any('tab='+tab in h and scope+'_page=3' in h and scope+'_view='+view in h for h in hrefs))
                    actions=[f.get('action') for f in parsed.forms]
                    self.assertEqual('history_clear' in actions,view=='history')
                    if scope=='bans':self.assertEqual('unban' in actions,view=='active')
                    self.assertIn('&lt;img onerror=alert(1)&gt;',body);self.assertNotIn('<img onerror=',body)

    def test_wordpress_pager_has_native_refresh_action_and_correct_total(self):
        parsed,body=self.render('active','wordpress')
        self.assertFalse(parsed.nested);self.assertEqual(parsed.depth,0)
        self.assertIn('Banned IPs: 177',body)
        self.assertTrue(any(f.get('action')=='wordpress_status' for f in parsed.forms))
        self.assertIn('name="wordpress_target_page" value="3"',body)
        self.assertNotIn('Empty history',body)
