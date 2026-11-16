"""Global XML-RPC scope uses Webuzo identities, including separate alias vhosts."""
import copy
import http.client
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from native_nginx import isolated_config

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from policy import DEFAULT, global_config, site_config

NGINX = os.environ.get('HDN_TEST_NGINX')


@unittest.skipUnless(NGINX, 'Set HDN_TEST_NGINX for native global XML-RPC tests')
class GlobalXmlrpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='wdn-global-xmlrpc-')
        cls.directory = Path(cls.temp.name)
        cls.directory.chmod(0o755)
        (cls.directory / 'logs').mkdir()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            cls.port = probe.getsockname()[1]
        cls.ipv6 = False
        try:
            with socket.socket(socket.AF_INET6) as probe:
                probe.bind(('::1', cls.port))
                cls.ipv6 = True
        except OSError:
            pass
        policy = copy.deepcopy(DEFAULT)
        policy['mode'] = 'enforce'
        policy['agents'] = ['BlockedBot']
        policy['xmlrpc_block'].update(enabled=True, targets=['alice/one.test'],
            global_exceptions=['127.0.0.2', '127.0.0.4/30', '::1'],
            exceptions={'alice/one.test': ['127.0.0.3']}, **{'global': True})
        policy['overrides'] = {'bob/observe.test': 'observe', 'bob/off.test': 'off'}
        # The native ban backend marks sites when a stored IP ban is present.
        sites = [dict(key=key, global_bans=True) for key in ('alice/one.test', 'bob/new.test', 'bob/observe.test', 'bob/off.test')]
        text = 'worker_processes 1; pid logs/nginx.pid; error_log logs/error.log; events { worker_connections 64; } http {\n'
        text += global_config(policy, sites, ['127.0.0.5'])
        for site, hostname in [(s, s['key'].split('/')[1]) for s in sites] + [(sites[1], 'alias-new.test')]:
            text += 'server { listen 127.0.0.1:' + str(cls.port) + '; server_name ' + hostname + ';\n'
            if cls.ipv6:
                text += 'listen [::1]:' + str(cls.port) + ';\n'
            snippet = site_config(policy, site, cls.directory.as_posix())
            snippet = snippet.replace('/var/log/webuzo-de-noise/matches.log', (cls.directory/'matches.log').as_posix())
            snippet = snippet.replace('/var/log/webuzo-de-noise/ban-events.log', (cls.directory/'ban-events.log').as_posix())
            text += snippet + 'location / { return 200 "origin"; }\n}\n'
        text += '}\n'
        (cls.directory/'nginx.conf').write_text(isolated_config(text, cls.directory))
        cls.command = [NGINX, '-p', cls.directory.as_posix()+'/', '-c', 'nginx.conf']
        result = subprocess.run([*cls.command, '-t'], capture_output=True, text=True)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError(result.stderr)
        cls.process = subprocess.Popen([*cls.command, '-g', 'daemon off;'], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        deadline = time.monotonic()+5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    cls.tearDownClass()
                    raise AssertionError('Global XML-RPC test Nginx did not start')
                time.sleep(.05)

    @classmethod
    def tearDownClass(cls):
        subprocess.run([*cls.command, '-s', 'quit'], capture_output=True, timeout=5)
        cls.process.wait(timeout=10)
        cls.temp.cleanup()

    def request(self, host, source='127.0.0.1', path='/xmlrpc.php', headers=None, ipv6=False):
        connection = http.client.HTTPConnection('::1' if ipv6 else '127.0.0.1', self.port, timeout=3,
            source_address=None if ipv6 else (source, 0))
        connection.request('POST', path, headers={'Host': host, **(headers or {})})
        response = connection.getresponse()
        status = response.status
        response.read()
        connection.close()
        return status

    def test_global_covers_unselected_new_sites_and_separate_alias_vhosts(self):
        for host in ('one.test', 'new.test', 'alias-new.test'):
            for path in ('/xmlrpc.php', '/shop/xmlrpc.php/path-info', '/%78mlrpc.php'):
                self.assertEqual(self.request(host, path=path), 403)
                self.assertEqual(self.request(host, '127.0.0.2', path=path), 200)
            self.assertEqual(self.request(host, path='/wp-login.php'), 200)
        self.assertEqual(self.request('new.test', '127.0.0.4'), 200)

    def test_site_exceptions_add_to_global_without_leaking_to_another_site(self):
        self.assertEqual(self.request('one.test', '127.0.0.3'), 200)
        self.assertEqual(self.request('new.test', '127.0.0.3'), 403)

    def test_global_exception_keeps_other_bans_and_rejects_spoofed_ip_headers(self):
        self.assertEqual(self.request('new.test', '127.0.0.5'), 403)
        self.assertEqual(self.request('new.test', '127.0.0.2', headers={'User-Agent':'BlockedBot'}), 403)
        self.assertEqual(self.request('new.test', headers={'X-Forwarded-For':'127.0.0.2',
            'X-Real-IP':'127.0.0.2', 'User-Agent':'Jetpack'}), 403)

    def test_observe_and_off_keep_normal_routing(self):
        self.assertEqual(self.request('observe.test'), 200)
        self.assertEqual(self.request('off.test'), 200)

    def test_global_ipv6_exception(self):
        if not self.ipv6:
            self.skipTest('IPv6 loopback unavailable')
        self.assertEqual(self.request('new.test', ipv6=True), 200)


if __name__ == '__main__':
    unittest.main()
