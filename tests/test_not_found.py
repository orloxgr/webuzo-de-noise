import copy
import datetime
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
import not_found
from policy import DEFAULT
from test_auto_bans import FakeNative
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import subprocess
import threading
from policy import global_config, site_config


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-owned native log fixtures')
class General404Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.log = self.root / 'ban-events.log'; self.log.write_text('')
        self.patches = [patch.object(auto_bans, 'LOG', self.log), patch.object(not_found, 'LOG_ROOT', self.root)]
        for item in self.patches: item.start()
        self.policy = copy.deepcopy(DEFAULT); self.policy['mode'] = 'enforce'
        self.policy['bans']['enabled'] = True; self.policy['bans']['any_404']['enabled'] = True
        self.policy['bans']['any_404'].update(exclude_static=False, min_distinct_paths=1)
        self.sites = [dict(domain=name+'.test', key=owner+'/'+name+'.test', owner=owner,
                           supported=True, suspended=False) for name, owner in [('one','alice'),('two','bob')]]
        self.native = FakeNative()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def event(self, host='one.test', stamp=1000, status=404, ip='198.51.100.7', request='GET /missing.css HTTP/1.1'):
        date = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        with (self.root/(host+'.log')).open('a') as out:
            out.write(f'{ip} - - [{date}] "{request}" {status} 12 "-" "Browser"\n')

    def sync(self, now=1001):
        return auto_bans.synchronize(self.policy, self.sites, self.root, self.native, now)

    def test_static_exclusion_protects_images_in_native_and_early_global_and_domain_counters(self):
        self.policy['bans']['any_404']['exclude_static'] = True
        self.policy['domain_bans']['sites'] = {'alice/one.test':dict(missing_files=False,suspicious_queries=False,any_404=True)}
        for suffix in ('jpg', 'png', 'webp', 'svgz', 'jxl', 'heic', 'heif'):
            for index in range(20):
                self.event(request=f'GET /uploads/missing{index}.{suffix} HTTP/1.1')
        with self.log.open('a') as out:
            for index in range(20):
                out.write(json.dumps(dict(v=1,ts='1000',ip='198.51.100.7',domain='one.test',reason='not-found',
                    token='-',path=f'/uploads/early{index}.webp',method='GET'))+'\n')
        self.assertEqual(self.sync()['active'], 0)
        domain_bans.synchronize(self.policy,self.sites,self.root,self.native,1001)
        self.assertEqual(domain_bans.desired(self.policy,self.sites,self.root,1001), {})

    def test_ten_final_404s_across_domains_ban_once_and_expire_in_three_days(self):
        for _ in range(9): self.event()
        for _ in range(20): self.event(status=200, request='GET /?status=404 HTTP/1.1')
        self.assertEqual(self.sync()['active'], 0)
        self.event(host='two.test', stamp=1002)
        report = self.sync(1003)
        self.assertEqual(report['active'], 1)
        self.assertEqual(report['rows'][0]['reason'], 'not-found')
        self.assertEqual(report['rows'][0]['expires'], 1003+3*86400)
        self.sync(1004)
        self.assertEqual(self.native.calls.count(('add','198.51.100.7')), 1)
        self.assertEqual(self.sync(1003+3*86400+1)['active'], 0)

    def test_rotation_partial_lines_stale_records_exclusions_and_disabled_rule(self):
        for _ in range(9): self.event()
        self.sync()
        (self.root/'one.test.log').rename(self.root/'one.test.log.1')
        self.event(stamp=1002); self.assertEqual(self.sync(1003)['active'], 1)
        self.policy['bans']['any_404']['enabled'] = False
        self.assertEqual(self.sync(1004)['active'], 0)
        self.policy['bans']['any_404']['enabled'] = True
        self.policy['bans']['ignore_ips'] = ['198.51.100.0/24']
        for _ in range(10): self.event(stamp=1005)
        self.assertEqual(self.sync(1006)['active'], 0)
        self.policy['bans']['ignore_ips'] = []
        for _ in range(10): self.event(stamp=100, ip='198.51.100.9')
        self.assertEqual(self.sync(1007)['active'], 0)
        with (self.root/'one.test.log').open('a') as out:out.write('unfinished')
        self.assertEqual(self.sync(1008)['active'], 0)

    def test_early_rejections_and_native_origin_404s_share_one_threshold(self):
        for _ in range(5): self.event()
        with self.log.open('a') as out:
            for _ in range(5): out.write('{"v":1,"ts":"1000","ip":"198.51.100.7","domain":"one.test","reason":"not-found","token":"-","path":"/missing","method":"GET"}\n')
        self.assertEqual(self.sync()['active'], 1)

    def test_owner_scope_accepts_ipv6_and_cannot_block_another_domain(self):
        self.policy['bans']['enabled'] = False
        self.policy['domain_bans']['sites'] = {'alice/one.test':dict(missing_files=False,suspicious_queries=False,any_404=True)}
        for _ in range(9): self.event(ip='2001:db8::7')
        for _ in range(10): self.event(host='two.test',ip='2001:db8::7')
        domain_bans.synchronize(self.policy,self.sites,self.root,self.native,1001)
        self.assertEqual(domain_bans.desired(self.policy,self.sites,self.root,1001),{})
        self.event(stamp=1002,ip='2001:db8::7')
        domain_bans.synchronize(self.policy,self.sites,self.root,self.native,1003)
        result = domain_bans.desired(self.policy,self.sites,self.root,1003)
        self.assertEqual(set(result), {'alice/one.test'})
        self.assertEqual(result['alice/one.test']['2001:db8::7']['reason'],'domain-404')
        self.assertEqual(self.native.calls, [])

    def test_one_owner_changing_switches_does_not_reset_another_domain_counter(self):
        self.policy['bans']['enabled']=False
        self.policy['domain_bans']['sites']={site['key']:dict(missing_files=False,suspicious_queries=False,any_404=True) for site in self.sites}
        for _ in range(9):self.event(host='two.test')
        domain_bans.synchronize(self.policy,self.sites,self.root,self.native,1001)
        self.policy['domain_bans']['sites']['alice/one.test']['any_404']=False
        self.event(host='two.test',stamp=1002)
        domain_bans.synchronize(self.policy,self.sites,self.root,self.native,1003)
        self.assertIn('bob/two.test',domain_bans.desired(self.policy,self.sites,self.root,1003))

    def test_unsafe_native_log_is_refused(self):
        target=self.root/'foreign'; target.write_text('')
        (self.root/'one.test.log').symlink_to(target)
        result=self.sync()
        self.assertTrue(result['error']); self.assertEqual(result['active'],0)

    def test_native_worker_log_is_accepted_but_customer_owned_log_is_refused(self):
        import storage
        for _ in range(9):self.event()
        path=self.root/'one.test.log'
        worker = next(uid for uid in storage.log_uids() if uid != 0)
        os.chown(path,worker,-1)
        self.assertEqual(self.sync()['error'],'')
        self.event(stamp=1002)
        self.assertEqual(self.sync(1003)['active'],1)
        os.chown(path,12345,-1)
        self.assertTrue(self.sync(1004)['error'])

    def test_observe_and_outside_window_requests_do_not_ban(self):
        self.policy['overrides']['alice/one.test']='observe'
        for _ in range(10):self.event()
        self.assertEqual(self.sync()['active'],0)

    @unittest.skipUnless(os.environ.get('HDN_TEST_NGINX'), 'Native Nginx integration')
    def test_native_nginx_and_origin_each_404_is_counted_once(self):
        native = self.root/'one.test.log'
        class Origin(BaseHTTPRequestHandler):
            def do_GET(inner):
                status = 404 if inner.path == '/origin-404' else 200
                with native.open('a') as out:
                    out.write('198.51.100.7 - - ['+datetime.datetime.now(datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')+
                              '] "GET '+inner.path+' HTTP/1.1" '+str(status)+' 0 "-" "Browser"\n')
                inner.send_response(status); inner.send_header('Content-Length','0'); inner.end_headers()
            def log_message(self,*args):pass
        origin=ThreadingHTTPServer(('127.0.0.1',0),Origin)
        thread=threading.Thread(target=origin.serve_forever,daemon=True);thread.start()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        self.root.chmod(0o755)
        self.policy['bans']['missing_files']['enabled']=True
        self.policy['static']=[dict(id='assets',enabled=True,path='/wp-content/',extensions=['js'],targets=[])]
        site=self.sites[0]
        text='worker_processes 1; pid '+str(self.root/'nginx.pid')+'; error_log '+str(self.root/'error.log')+'; events {} http {\n'
        text+=global_config(self.policy,[site])
        text+='server { listen 127.0.0.1:'+str(port)+'; server_name one.test;\n'
        text+=site_config(self.policy,site,str(self.root)).replace('/var/log/webuzo-de-noise/',str(self.root)+'/')
        text+='location = /hidden { return 404; }\nlocation /native-missing/ { root '+str(self.root)+'; try_files $uri =404; access_log '+str(native)+' combined; }\n'
        text+='location / { proxy_pass http://127.0.0.1:'+str(origin.server_address[1])+'; } } }'
        config=self.root/'nginx.conf';config.write_text(text)
        subprocess.run([os.environ['HDN_TEST_NGINX'],'-c',str(config),'-p',str(self.root)],check=True,capture_output=True)
        try:
            for path in ['/origin-404','/native-missing/a.css?key=private','/hidden?password=private','/wp-content/missing.js?token=private','/opsh.php','/ok']:
                connection=http.client.HTTPConnection('127.0.0.1',port)
                connection.request('GET',path,headers={'Host':'one.test'})
                response=connection.getresponse();response.read();connection.close()
                self.assertEqual(response.status,200 if path=='/ok' else 404)
            # Stop flushes native access-log writes before the read-only check.
            subprocess.run([os.environ['HDN_TEST_NGINX'],'-c',str(config),'-p',str(self.root),'-s','quit'],check=True,capture_output=True)
            with auto_bans.database(self.root) as db:
                local=[event for event in auto_bans.events(db) if event[3]=='not-found']
                upstream=list(not_found.events(db,[site],'native'))
            self.assertEqual(len(local),3)
            self.assertEqual(len(upstream),2)
            self.assertEqual(len(local)+len(upstream),5)
            self.assertNotIn('/origin-404',self.log.read_text())
            self.assertNotIn('private',self.log.read_text())
            self.assertEqual({event[5] for event in local},{'/hidden','/wp-content/missing.js','/opsh.php'})
            self.assertEqual({event[5] for event in upstream},{'/origin-404','/native-missing/a.css'})
        finally:
            subprocess.run([os.environ['HDN_TEST_NGINX'],'-c',str(config),'-p',str(self.root),'-s','quit'],capture_output=True)
            origin.shutdown();origin.server_close();thread.join()
