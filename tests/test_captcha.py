"""Real challenge state plus an isolated native Nginx/service/backend flow."""
import copy
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import access_protection as access
import captcha
import captcha_runtime as runtime
import captcha_server as service
import engine
from policy import DEFAULT, target, global_config, site_config, site_mode
from test_access import Origin, ThreadingHTTPServer


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.challenges = captcha.Challenges(b'x' * 32, Path(self.temp.name) / 'state.sqlite')
        self.args = ('site1', 'example.test', 'https', 'revision1')

    def tearDown(self): self.temp.cleanup()

    def new(self): return self.challenges.create(*self.args, '/shop/wp-login.php?action=login')

    def test_single_use_correct_wrong_and_refresh_answers(self):
        for wrong, refresh in [(False, False), (True, False), (False, True)]:
            token, data = self.new()
            answer = '999' if wrong else str(sum(self.challenges.numbers(data['nonce'])))
            valid, previous = self.challenges.consume(token, *self.args, answer, refresh)
            self.assertEqual(valid, not wrong and not refresh)
            self.assertEqual(previous['target'], '/shop/wp-login.php?action=login')
            self.assertFalse(self.challenges.consume(token, *self.args, answer)[0])

    @unittest.skipUnless(os.name == 'posix', 'Native Nginx group lookup')
    def test_worker_group_follows_nginx_directive_and_build_defaults(self):
        import storage, webuzo, grp
        for config, build, expected in [(b'user nobody;', '', 'nobody'),
                                        (b'user nginx workers;', '', 'workers'),
                                        (b'# user ignored;', 'configure arguments: --user=nobody --group=workers', 'workers')]:
            with self.subTest(config=config), patch.object(storage, 'read', return_value=config), \
                    patch.object(webuzo, 'nginx_build', return_value=build), patch.object(grp, 'getgrnam') as lookup:
                self.assertEqual(runtime.worker_group(), expected)
                lookup.assert_called_once_with(expected)

    def test_expiry_tampering_and_other_origin_rejected(self):
        token, data = self.new()
        answer = str(sum(self.challenges.numbers(data['nonce'])))
        for args in [('site2', *self.args[1:]), ('site1', 'alias.test', *self.args[2:]),
                     (*self.args[:2], 'http', 'revision1'), (*self.args[:3], 'revision2')]:
            with self.assertRaises(ValueError): self.challenges.consume(token, *args, answer)
        with self.assertRaises(ValueError): self.challenges.consume(token + 'x', *self.args, answer)
        with patch.object(captcha.time, 'time', return_value=data['expires'] + 1):
            self.assertFalse(self.challenges.consume(token, *self.args, answer)[0])

    def test_redirect_targets_and_rendering(self):
        for value in ('https://evil.test/', '//evil.test/', '/%2fevil.test/', '/%5cevil.test/', '/\r\nX:bad'):
            with self.assertRaises(ValueError): captcha.safe_target(value)
        token, data = self.new()
        body = captcha.page(self.challenges, token, data)
        self.assertIn('data:image/png;base64,', body)
        self.assertNotIn('<script', body)
        self.assertIn('formnovalidate', body)
        self.assertTrue(captcha.picture(1, 9).startswith(b'\x89PNG'))
        complete = captcha.verified_page('/wp-admin/?a=1&b=2')
        self.assertIn('http-equiv="refresh" content="0;url=/wp-admin/?a=1&amp;b=2"', complete)
        self.assertIn('href="/wp-admin/?a=1&amp;b=2"', complete)
        self.assertNotIn('<script', complete)
        with self.assertRaises(ValueError): captcha.verified_page('//evil.test/')

    def test_captcha_needs_no_http_password_and_explicit_off_overrides_defaults(self):
        settings = access.defaults()
        settings['defaults'].update(enabled=True, method='captcha')
        settings = access.validate(settings, target)
        self.assertTrue(access.effective(settings, 'bob/new.test')['enabled'])
        settings['accounts']['bob'] = copy.deepcopy(access.DEFAULT)
        self.assertFalse(access.effective(settings, 'bob/new.test')['enabled'])
        self.assertNotIn('password_hash', json.dumps(access.public(settings, {'bob/new.test'})))

    def test_nginx_proves_private_include_but_service_data_is_not_an_include(self):
        private = access.DIRECTORY / ('a' * 24 + '.captcha.conf')
        config = access.DIRECTORY / runtime.CONFIG_NAME
        with patch.object(engine, 'run', return_value='# configuration file ' + str(private) + ':'):
            engine.verify([private, config])
            with self.assertRaisesRegex(RuntimeError, 'expected include'):
                engine.verify([access.DIRECTORY / ('b' * 24 + '.captcha.conf')])


@unittest.skipUnless(os.environ.get('HDN_TEST_NGINX'), 'Requires isolated native Nginx')
class NativeCaptchaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='hdn-captcha-test-')
        cls.root = Path(cls.temp.name); cls.root.chmod(0o755)
        (cls.root / 'logs').mkdir(); (cls.root / 'keys').mkdir()
        cls.patches = [patch.object(access, 'DIRECTORY', cls.root / 'keys'),
                       patch.object(runtime, 'SOCKET', cls.root / 'captcha.sock'),
                       patch.object(service, 'CONFIG', cls.root / 'keys' / runtime.CONFIG_NAME)]
        for item in cls.patches: item.start()
        cls.sites = [dict(key='alice/' + h, domain=h, supported=True, aliases='www.' + h)
                     for h in ('captcha.test', 'strict.test', 'observe.test', 'off.test', 'second.test')]
        cls.settings = dict(defaults={**copy.deepcopy(access.DEFAULT), 'enabled': True, 'method': 'captcha'}, accounts={}, sites={})
        cls.settings['sites']['alice/strict.test'] = {**copy.deepcopy(cls.settings['defaults']), 'bypass_internal': False}
        cls.policy = copy.deepcopy(DEFAULT); cls.policy.update(mode='enforce', agents=['BlockedBot'])
        cls.policy['overrides'] = {'alice/observe.test': 'observe', 'alice/off.test': 'off'}
        desired, _ = runtime.prepare(cls.root, cls.root / 'keys', cls.settings, cls.sites, lambda s: site_mode(cls.policy, s))
        for path, body in desired.items(): Path(path).write_text(body)
        cls.backend = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        cls.backend_thread = threading.Thread(target=cls.backend.serve_forever, daemon=True); cls.backend_thread.start()
        cls.server = service.Server(str(runtime.SOCKET), service.Handler)
        runtime.SOCKET.chmod(0o777)  # Isolated fixture's Nginx worker; installed socket is root:worker 0660.
        cls.server.challenges = captcha.Challenges((cls.root / 'captcha.key').read_bytes(), cls.root / 'challenges.sqlite')
        cls.service_thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.service_thread.start()
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); cls.port = sock.getsockname()[1]
        text = 'worker_processes 1; pid logs/nginx.pid; error_log logs/error.log notice; events {worker_connections 64;} http {\n'
        text += global_config(cls.policy, cls.sites, access_settings=cls.settings)
        for site in cls.sites:
            text += 'server { listen 127.0.0.1:' + str(cls.port) + '; server_name ' + site['domain'] + ' www.' + site['domain'] + ';\n'
            text += site_config(cls.policy, site, access_settings=cls.settings).replace('/var/log/webuzo-de-noise/matches.log', str(cls.root / 'matches.log'))
            text += 'location / { proxy_pass http://127.0.0.1:' + str(cls.backend.server_address[1]) + '; } }\n'
        (cls.root / 'nginx.conf').write_text(text + '}\n')
        cls.command = [os.environ['HDN_TEST_NGINX'], '-p', str(cls.root) + '/', '-c', 'nginx.conf']
        result = subprocess.run([*cls.command, '-t'], capture_output=True, text=True)
        if result.returncode: raise AssertionError(result.stderr)
        cls.process = subprocess.Popen([*cls.command, '-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.1): break
            except OSError: time.sleep(.02)
        else: raise AssertionError('Isolated CAPTCHA Nginx did not start')

    @classmethod
    def tearDownClass(cls):
        subprocess.run([*cls.command, '-s', 'quit'], capture_output=True); cls.process.wait(timeout=10)
        cls.server.shutdown(); cls.server.server_close(); cls.service_thread.join()
        cls.backend.shutdown(); cls.backend.server_close(); cls.backend_thread.join()
        for item in reversed(cls.patches): item.stop()
        cls.temp.cleanup()

    def request(self, path='/wp-login.php', host='captcha.test', method='GET', body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        connection.request(method, path, body=body, headers={'Host': host, 'User-Agent': 'Captcha test', **(headers or {})})
        response = connection.getresponse(); result = response.status, dict(response.getheaders()), response.read()
        connection.close(); return result

    def solve(self, page, host='captcha.test', **extra):
        token = re.search(rb'name="challenge" value="([^"]+)"', page)[1].decode()
        scope = access.identifier('alice/' + host)
        data = self.server.challenges.decode(token, scope, host, 'http', captcha.revision(self.settings['defaults']))
        answer = str(sum(self.server.challenges.numbers(data['nonce'])))
        return self.request(captcha.PREFIX + 'verify', host=host, method='POST', body=urlencode(dict(challenge=token, answer=answer, **extra)))

    def test_challenge_solve_cookie_and_native_validation_without_service(self):
        before = Origin.hits
        status, headers, page = self.request('/shop/wp-login.php?redirect_to=%2Fshop%2Fwp-admin%2F')
        self.assertEqual(status, 200); self.assertIn(b'A quick check', page)
        # no-referrer turns real browser form POST Origin into null; keep just the origin.
        self.assertEqual(headers['Referrer-Policy'], 'strict-origin')
        self.assertNotIn('WWW-Authenticate', headers); self.assertEqual(Origin.hits, before)
        status, headers, complete = self.solve(page)
        self.assertEqual(status, 200); self.assertEqual(headers['X-HDN-Captcha-Result'], 'verified')
        self.assertNotIn('Location', headers)
        self.assertIn(b'0;url=/shop/wp-login.php?redirect_to=%2Fshop%2Fwp-admin%2F', complete)
        cookie = headers['Set-Cookie'].split(';')[0]
        self.assertIn('HttpOnly', headers['Set-Cookie']); self.assertIn('SameSite=Lax', headers['Set-Cookie'])
        with patch.object(self.server.challenges, 'create', side_effect=AssertionError('Native cookie must not invoke service')):
            self.assertEqual(self.request(headers={'Cookie': cookie})[2], b'OK')
        self.assertIn(b'A quick check', self.request(headers={'Cookie': cookie + '0'})[2])
        self.assertIn(b'A quick check', self.request(host='www.captcha.test', headers={'Cookie': cookie})[2])

    def test_wrong_refresh_replay_expired_cookie_and_cross_origin(self):
        page = self.request()[2]
        status, headers, refreshed = self.solve(page, refresh='1')
        self.assertEqual(status, 200); self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(self.solve(page)[0], 200)  # Spent nonce cannot mint clearance.
        token = re.search(rb'name="challenge" value="([^"]+)"', refreshed)[1].decode()
        status, headers, body = self.request(captcha.PREFIX + 'verify', method='POST', body=urlencode(dict(challenge=token, answer='999')))
        self.assertEqual(status, 200); self.assertIn(b'incorrect', body); self.assertNotIn('Set-Cookie', headers)
        scope = access.identifier('alice/captcha.test'); rev = captcha.revision(self.settings['defaults'])
        value = captcha.clearance(self.server.challenges.secret, scope, rev, 'captcha.test', 'http', int(time.time()) - 1)
        self.assertIn(b'A quick check', self.request(headers={'Cookie': captcha.cookie(scope) + '=' + value})[2])
        status = self.request(captcha.PREFIX + 'verify', method='POST', body=urlencode(dict(challenge=token, answer='1')),
                              headers={'Origin': 'http://evil.test'})[0]
        self.assertEqual(status, 400)

    def test_direct_post_never_forwards_credentials_and_frontend_stays_open(self):
        before = Origin.hits
        result = self.request(method='POST', body='log=private-user&pwd=private-password')
        self.assertIn(b'submit your original form again', result[2]); self.assertEqual(Origin.hits, before)
        for path in ('/my-account/', '/checkout/', '/?wc-ajax=checkout', '/wp-admin/admin-ajax.php',
                     '/wp-admin/admin-post.php', '/wp-admin/js/password-strength-meter.min.js', '/shop/wp-admin/admin-ajax.php'):
            self.assertEqual(self.request(path, method='POST', body='customer=1')[2], b'OK')
            self.assertEqual(Origin.body, b'customer=1')
        self.assertEqual(self.request(headers={'Sec-Fetch-Site': 'same-origin'})[2], b'OK')
        self.assertEqual(self.request(headers={'Referer': 'http://captcha.test/my-account/'})[2], b'OK')
        self.assertIn(b'A quick check', self.request(host='strict.test', headers={'Sec-Fetch-Site': 'same-origin'})[2])

    def test_observe_off_agent_denial_and_event_privacy(self):
        self.assertEqual(self.request(host='observe.test')[2], b'OK')
        self.assertEqual(self.request(host='off.test')[2], b'OK')
        self.assertEqual(self.request(headers={'User-Agent': 'BlockedBot'})[0], 403)
        page = self.request()[2]; self.solve(page)
        time.sleep(.03)
        log = (self.root / 'matches.log').read_text()
        self.assertIn('captcha-check - 200 enforce', log)
        self.assertIn('captcha-verified - 200 enforce', log)
        for private in ('private-password', 'private-user', 'hdn_captcha_', 'challenge='):
            self.assertNotIn(private, log)


if __name__ == '__main__': unittest.main()
