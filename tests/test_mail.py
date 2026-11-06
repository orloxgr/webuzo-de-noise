"""Native webmail include scope; normal Roundcube paths remain untouched."""
import copy
import http.client
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import engine
from policy import DEFAULT, global_config, site_config, site_mode


class MailDiscoveryTests(unittest.TestCase):
    def test_recovery_can_only_write_owned_snippets_and_global_configuration(self):
        if os.name != 'posix':
            self.skipTest('Native Linux paths')
        expected = engine.webuzo.SNIPPETS / 'webmail.one.test.conf'
        self.assertEqual(engine.managed_path(expected), expected)
        for path in (engine.webuzo.VHOST, engine.webuzo.CONFIG,
                     engine.webuzo.HOME / 'index.php', '/var/lib/roundcube/index.php'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                engine.managed_path(path)

    def test_webmail_is_opt_in_and_never_adds_wordpress_or_general_404_handlers(self):
        site=dict(key='alice/webmail.one.test',owner='alice',domain='webmail.one.test',kind='mail',supported=True)
        policy=copy.deepcopy(DEFAULT);policy['mode']='enforce'
        self.assertEqual(site_mode(policy,site),'off')
        policy['mail_protection']=True;policy['login']['enabled']=True
        policy['bans']['enabled']=True
        policy['bans']['missing_files']['enabled']=True
        policy['bans']['any_404']['enabled']=True
        text=site_config(policy,site)
        self.assertNotIn('limit_req ',text)
        self.assertNotIn('hdn_early_404',text)
        self.assertNotIn('if ($hdn_probe_file',text)
        self.assertIn('if ($hdn_direct_reject)',text)

    def test_independently_managed_native_limiter_is_not_overwritten(self):
        native = engine.webuzo
        custom = native.CUSTOM / 'one.test.conf'
        server = dict(names=['one.test', 'mail.one.test'], roots=[['/home/alice/public_html']],
                      includes=[str(custom)], limits=True, cache=False)
        with patch.object(native, 'users', return_value={'alice': dict(homedir='/home/alice', suspended=False)}), \
                patch.object(native, 'servers', return_value=[server]), \
                patch.object(native, 'native_list', return_value={'1': dict(user='alice', domain='one.test', path='/home/alice/public_html')}):
            result = native.collect()
        self.assertFalse(result[0]['supported'])
        self.assertIn('already defines request limits', result[0]['reason'])
        self.assertEqual(result[0]['paths'], [])


@unittest.skipUnless(os.name=='posix' and os.environ.get('HDN_TEST_NGINX'),'Native Linux Nginx')
class MailRequestsTests(unittest.TestCase):
    def test_private_probes_are_blocked_while_roundcube_login_and_assets_work(self):
        with tempfile.TemporaryDirectory(prefix='hdn-mail-') as temp:
            root=Path(temp);root.chmod(0o755)
            policy=copy.deepcopy(DEFAULT);policy.update(mode='enforce',mail_protection=True,scanners=True)
            policy['agents']=['EvilScanner'];policy['login']['enabled']=True
            policy['bans']['enabled']=True
            policy['bans']['any_404']['enabled']=True
            policy['bans']['missing_files']['enabled']=True
            policy['bans']['suspicious_queries']['enabled']=True
            sites=[dict(key='alice/'+host,domain=host,owner='alice',kind='mail',supported=True,suspended=False)
                   for host in ('webmail.one.test','webmail.two.test')]
            policy['overrides'][sites[1]['key']]='off'
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            conf=root/'nginx.conf'
            text='daemon off; pid '+str(root/'pid')+'; error_log '+str(root/'error')+'; events {} http {\n'
            text+=global_config(policy,sites)
            for site in sites:
                text+='server { listen 127.0.0.1:'+str(port)+'; server_name '+site['domain']+' mail.'+site['domain'].removeprefix('webmail.')+';\n'
                text+=site_config(policy,site).replace('/var/log/webuzo-de-noise/',str(root)+'/')
                text+='location / { return 200 "roundcube"; } }\n'
            conf.write_text(text+'}')
            child=subprocess.Popen([os.environ['HDN_TEST_NGINX'],'-c',str(conf),'-p',str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+5
                while not (root/'pid').exists():
                    if child.poll() is not None:raise RuntimeError(child.stderr.read().decode())
                    if time.monotonic()>deadline:raise RuntimeError('Nginx startup timeout')
                    time.sleep(.02)
                cases=[('webmail.one.test','/','GET','Browser',200),
                       ('mail.one.test','/?_task=login','POST','Browser',200),
                       ('webmail.one.test','/skins/elastic/styles/styles.css','GET','Browser',200),
                       ('webmail.one.test','/auth.php','GET','Browser',200),
                       ('webmail.one.test','/?file=/etc/passwd','GET','Browser',200),
                       ('webmail.one.test','/.env','GET','Browser',403),
                       ('webmail.one.test','/.git/config','GET','Browser',403),
                       ('webmail.one.test','/','GET','EvilScanner',403),
                       ('webmail.two.test','/.env','GET','Browser',200)]
                for host,path,method,agent,status in cases:
                    with self.subTest(host=host,path=path):
                        c=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
                        c.request(method,path,headers={'Host':host,'User-Agent':agent})
                        response=c.getresponse();response.read();c.close();self.assertEqual(response.status,status)
                # The native global HTTP ban mechanism receives secret probes.
                time.sleep(.05)
                events=(root/'ban-events.log').read_text()
                self.assertIn('repository',events);self.assertIn('private-file',events)
                self.assertNotIn('not-found',events)
            finally:
                if child.poll() is None:os.kill(child.pid,signal.SIGQUIT)
                try:child.communicate(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.communicate()
