"""Regressions for rotation trust, maintenance failures and 404 false bans."""
import copy
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import activity
import auto_bans
import domain_bans
import engine
import storage
from policy import V9_KEYS, DEFAULT, validate, global_config, site_config
from probe_rules import FILES
from test_auto_bans import FakeNative
from test_installer import installer
import test_not_found


class UpgradeTests(unittest.TestCase):
    def test_v7_keeps_custom_limits_lists_and_adds_guardrails_without_new_blocks(self):
        old = {key: copy.deepcopy(DEFAULT[key]) for key in V9_KEYS}
        old.update(schema=7)
        old.pop('enumeration')
        old.pop('mail_protection'); old.pop('log_rejections')
        old['bans']['any_404'] = dict(enabled=True, maxretry=30, findtime=300, duration_days=3)
        old['agents'] = ['CustomBot']
        old['bans']['missing_files']['paths'] = ['/custom.php']
        new = validate(old)
        self.assertEqual(new['schema'], 10)
        self.assertEqual(new['agents'], ['CustomBot'])
        self.assertEqual(new['bans']['missing_files']['paths'], ['/custom.php'])
        self.assertEqual(new['bans']['any_404'], {**old['bans']['any_404'], 'exclude_static':True, 'min_distinct_paths':3})
        self.assertFalse(new['mail_protection'])
        self.assertFalse(new['log_rejections'])
        self.assertIn('/admin/phpinfo.php', FILES)

    def test_old_panel_cannot_reset_new_controls_or_domain_preferences(self):
        saved=copy.deepcopy(DEFAULT)
        saved.update(mail_protection=True, log_rejections=True)
        saved['bans']['any_404']['min_distinct_paths']=7
        saved['domain_bans']['sites']={'alice/one.test':dict(missing_files=True,suspicious_queries=False,any_404=False)}
        old={key: copy.deepcopy(DEFAULT[key]) for key in V9_KEYS};old.update(schema=7)
        old.pop('enumeration')
        for key in ('mail_protection','log_rejections'):old.pop(key)
        for key in ('exclude_static','min_distinct_paths'):old['bans']['any_404'].pop(key)
        with patch.object(engine,'authorize',return_value=(True,'admin')), patch.object(engine,'load',return_value=saved), \
             patch.object(engine,'collect',return_value=[]),patch.object(engine,'snapshot',return_value={}),patch.object(engine,'apply') as apply:
            engine.dispatch(dict(action='save',actor='admin',policy=old))
        result=apply.call_args.args[0]
        self.assertTrue(result['mail_protection']);self.assertTrue(result['log_rejections'])
        self.assertEqual(result['bans']['any_404']['min_distinct_paths'],7)
        self.assertEqual(result['domain_bans'],saved['domain_bans'])


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux root-owned storage')
class HealthTests(unittest.TestCase):
    def test_failure_before_firewall_sync_is_reported_then_cleared_on_success(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(engine,'STATE',Path(temp)):
            storage.replace(Path(temp)/'maintenance.json',storage.json_bytes(dict(last_success=123)),0o600)
            with patch.object(engine.domain_bans,'synchronize',side_effect=ValueError('untrusted log')), \
                 patch.object(engine.auto_bans,'synchronize') as firewall:
                with self.assertRaisesRegex(ValueError,'untrusted log'):engine.synchronize(DEFAULT,[])
                firewall.assert_not_called()
            failed=json.loads(storage.read(Path(temp)/'maintenance.json'))
            self.assertEqual(failed['last_success'],123)
            self.assertEqual(failed['error'],'untrusted log')
            with patch.object(engine.domain_bans,'synchronize'),patch.object(engine,'apply',return_value={}), \
                 patch.object(engine.auto_bans,'synchronize',return_value={'error':''}):
                engine.synchronize(DEFAULT,[])
            success=json.loads(storage.read(Path(temp)/'maintenance.json'))
            self.assertGreater(success['last_success'],123);self.assertEqual(success['error'],'')


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux log fixtures')
class LogTrustTests(unittest.TestCase):
    def test_installer_and_both_readers_accept_worker_logs_but_reject_foreign_writable_and_symlink_logs(self):
        import pwd
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); logs=root/'logs'
            with patch.object(installer,'LOGS',logs):installer.prepare_logs()
            event=logs/'ban-events.log'; match=logs/'matches.log'
            event.write_text('1000 198.51.100.7 one.test private-file\n')
            match.write_text('2026-01-01T00:00:00+00:00 one.test private-file - 403 enforce\n')
            worker=next(uid for uid in storage.log_uids() if uid != 0)
            with patch.object(auto_bans,'LOG',event),patch.object(activity,'LOG',match),auto_bans.database(root) as db:
                for uid in (0,worker):
                    for path in (event,match):os.chown(path,uid,-1);path.chmod(0o640)
                    with patch.object(installer,'LOGS',logs):installer.prepare_logs()
                    list(auto_bans.events(db));self.assertEqual(activity.summary({'one.test'},1767225601)['total'],1)
                for bad in ('foreign','writable','symlink','fifo','ancestor'):
                    for path in (event,match):
                        if bad=='foreign':os.chown(path,12345,-1)
                        elif bad=='writable':os.chown(path,worker,-1);path.chmod(0o666)
                        elif bad=='symlink':path.rename(path.with_suffix('.saved'));path.symlink_to(path.with_suffix('.saved'))
                        elif bad=='fifo':path.unlink();os.mkfifo(path,0o640)
                    if bad=='ancestor':logs.chmod(0o777)
                    with self.subTest(case=bad):
                        with self.assertRaises((ValueError,OSError)):list(auto_bans.events(db))
                        with self.assertRaises((ValueError,OSError)):activity.summary({'one.test'})
                        with patch.object(installer,'LOGS',logs),self.assertRaises((ValueError,OSError)):installer.prepare_logs()
                    logs.chmod(0o755)
                    for path in (event,match):
                        if bad in ('symlink','fifo'):path.unlink();path.write_text('')
                        os.chown(path,0,-1);path.chmod(0o640)

    @unittest.skipUnless(os.environ.get('HDN_TEST_NGINX'),'Native Nginx reopen')
    def test_actual_nginx_reopen_and_rotation_preserve_readers_installer_and_cursor(self):
        import pwd
        with tempfile.TemporaryDirectory(prefix='hdn-reopen-') as temp:
            root=Path(temp);root.chmod(0o755);logs=root/'logs'
            with patch.object(installer,'LOGS',logs):installer.prepare_logs()
            event=logs/'ban-events.log';match=logs/'matches.log'
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            conf=root/'nginx.conf'
            worker=next(uid for uid in storage.log_uids() if uid != 0)
            from native_nginx import isolated_config
            conf.write_text(isolated_config('user '+pwd.getpwuid(worker).pw_name+'; daemon off; pid '+str(root/'pid')+'; error_log '+str(root/'error')+'; events {} http {\n'+
                'log_format match "$time_iso8601 one.test private-file - $status enforce";\n'+
                'log_format event "$msec 198.51.100.7 one.test private-file -";\n'+
                'server { listen 127.0.0.1:'+str(port)+'; access_log '+str(match)+' match; access_log '+str(event)+' event; return 403; } }', root))
            child=subprocess.Popen([os.environ['HDN_TEST_NGINX'],'-p',str(root),'-c',str(conf)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+5
                while not (root/'pid').exists():
                    if child.poll() is not None:raise RuntimeError(child.stderr.read().decode())
                    if time.monotonic()>deadline:raise RuntimeError('Nginx startup timeout')
                    time.sleep(.02)
                def request():
                    c=http.client.HTTPConnection('127.0.0.1',port,timeout=3);c.request('GET','/synthetic');r=c.getresponse();r.read();c.close()
                    self.assertEqual(r.status,403)
                request();time.sleep(.05)
                with patch.object(auto_bans,'LOG',event),patch.object(activity,'LOG',match),auto_bans.database(root) as db:
                    self.assertEqual(len(list(auto_bans.events(db))),1)
                    event.rename(logs/'ban-events.log.1');match.rename(logs/'matches.log.1')
                    for path in (event,match):path.touch(mode=0o640)
                    os.kill(child.pid,signal.SIGUSR1)
                    deadline=time.monotonic()+5
                    while event.stat().st_uid==0 and time.monotonic()<deadline:time.sleep(.02)
                    self.assertEqual(event.stat().st_uid,worker)
                    self.assertEqual(event.stat().st_mode&0o777,0o640)
                    request();time.sleep(.05)
                    self.assertEqual(len(list(auto_bans.events(db))),1)
                    self.assertEqual(list(auto_bans.events(db)),[])
                    self.assertEqual(activity.summary({'one.test'})['total'],2)
                    with patch.object(installer,'LOGS',logs):installer.prepare_logs()
            finally:
                if child.poll() is None:os.kill(child.pid,signal.SIGQUIT)
                try:child.communicate(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.communicate()


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux native logs and database')
class GuardrailTests(unittest.TestCase):
    setUp = test_not_found.General404Tests.setUp
    tearDown = test_not_found.General404Tests.tearDown
    event = test_not_found.General404Tests.event
    sync = test_not_found.General404Tests.sync
    # Reuse native/event writers, with production-safe defaults for new tests.
    def test_static_exclusion_covers_both_sources_and_security_probe_still_bans(self):
        self.policy['bans']['any_404'].update(exclude_static=True,min_distinct_paths=3)
        paths=['/logo.jpg','/a.css','/a.js.map','/a.woff2','/x%2EPNG']
        for path in paths:
            for _ in range(10):
                self.event(request='GET '+path+'?v=1 HTTP/1.1')
                with self.log.open('a') as out:out.write(json.dumps(dict(v=1,ts='1000',ip='198.51.100.7',domain='one.test',reason='not-found',token='-',path=path,method='GET'))+'\n')
        self.assertEqual(self.sync()['active'],0)
        self.policy['bans']['missing_files']['enabled']=True
        from probe_rules import token
        with self.log.open('a') as out:
            for path in ['/auth.php','/test.php']:
                out.write(json.dumps(dict(v=1,ts='1002',ip='198.51.100.7',domain='one.test',reason='missing-file',token=token('f',path),path=path,method='GET'))+'\n')
        self.assertEqual(self.sync(1003)['rows'][0]['reason'],'missing-file')

    def test_repeated_one_path_and_queries_do_not_meet_diversity_but_scanning_does(self):
        self.policy['bans']['any_404'].update(exclude_static=True,min_distinct_paths=3)
        for i in range(30):self.event(request='GET /missing?v='+str(i)+' HTTP/1.1')
        self.assertEqual(self.sync()['active'],0)
        self.event(request='GET /missing2 HTTP/1.1',stamp=1002)
        self.assertEqual(self.sync(1003)['active'],0)
        self.event(request='GET /missing3 HTTP/1.1',stamp=1004)
        self.assertEqual(self.sync(1005)['active'],1)

    def test_domain_bans_use_same_asset_exclusion_and_diversity(self):
        self.policy['bans']['enabled']=False
        self.policy['bans']['any_404'].update(exclude_static=True,min_distinct_paths=3,maxretry=3)
        self.policy['domain_bans']['sites']={'alice/one.test':dict(missing_files=False,suspicious_queries=False,any_404=True)}
        for _ in range(10):self.event(request='GET /logo.jpg HTTP/1.1')
        for path in ['/bad','/bad2']:
            self.event(request='GET '+path+' HTTP/1.1')
        domain_bans.synchronize(self.policy,self.sites,self.root,self.native,1001)
        self.assertEqual(domain_bans.desired(self.policy,self.sites,self.root,1001),{})
        self.event(request='GET /bad3 HTTP/1.1',stamp=1002)
        domain_bans.synchronize(self.policy,self.sites,self.root,self.native,1003)
        self.assertIn('alice/one.test',domain_bans.desired(self.policy,self.sites,self.root,1003))
