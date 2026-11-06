"""Shared panel webmail isolation, native log privacy and transactional cleanup."""
import copy
import datetime
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import webmail
import webuzo
import integration
import activity
import storage
from policy import DEFAULT


class DiscoveryTests(unittest.TestCase):
    def test_vendor_configuration_links_are_read_by_the_native_binary(self):
        dump = '# configuration file ' + str(webmail.CONFIG) + ':\nuser root; pid /run/native-panel.pid; events {} http {}\n'
        with patch.object(webuzo, 'run', return_value=dump) as command, \
                patch.object(webuzo, 'reload_instance') as reload:
            webmail.reload()
            self.assertEqual(webmail.worker_uids(), {0})
        self.assertEqual(reload.call_args.args, (webmail.BINARY, webmail.CONFIG))
        self.assertIn(('pid', ['/run/native-panel.pid'], None), reload.call_args.kwargs['nodes'])
        self.assertEqual(command.call_args.args, (webmail.BINARY, '-T'))

    def test_native_include_expansion_uses_the_dump_and_keeps_existing_logs(self):
        dump = ('# configuration file ' + str(webmail.CONFIG) + ':\n'
                'events {} http { access_log /var/log/native.log main; '
                'server { include /usr/local/webuzo/conf/webuzo/emps/enduser_locations*; '
                'include ' + str(webmail.CUSTOM.parent / '*') + '; } }\n'
                '# configuration file /usr/local/webuzo/conf/webuzo/emps/enduser_locations_vendor.conf:\n'
                'location /vendor/ { return 200; }\n')
        with patch.object(webuzo, 'run', return_value=dump), patch.object(webmail.Path, 'is_file', return_value=True):
            found = webmail.discover()
        self.assertTrue(found['supported'])
        self.assertEqual(found['native_logs'], ['/var/log/native.log'])
        self.assertEqual(found['owner'], 'root')
        self.assertEqual(found['kind'], 'mail')

    def test_missing_documented_hook_is_reported_and_never_replaced(self):
        dump = '# configuration file ' + str(webmail.CONFIG) + ':\nevents {} http { server { location /mail/ {} } }\n'
        with patch.object(webuzo, 'run', return_value=dump), patch.object(webmail.Path, 'is_file', return_value=True):
            self.assertFalse(webmail.discover()['supported'])


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root-owned native log fixtures')
class NativeActivityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / 'native.log'
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.enterContext(patch.object(storage, 'log_uids', return_value={0}))
        self.enterContext(patch.object(webmail, 'worker_uids', return_value={0}))
        self.enterContext(patch.object(activity, 'LOG', self.root / 'matches.log'))
        self.profile = dict(mode='enforce', agents=['Crawler'], scanners=True)
        self.base = 1767225600

    def line(self, second, target, agent='Crawler', status=403):
        stamp = datetime.datetime.fromtimestamp(self.base + second, datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        return f'198.51.100.45 - - [{stamp}] "GET {target} HTTP/1.1" {status} 0 "https://example.test/?private=referrer" "{agent}" "-"\n'

    def test_policy_modes_transitions_escaped_agents_and_scope_preserve_privacy(self):
        webmail.remember(self.state, self.profile, [str(self.log)], now=self.base + 1.5)
        webmail.remember(self.state, {**self.profile, 'mode': 'observe'}, [str(self.log)], now=self.base + 5.5)
        webmail.remember(self.state, dict(mode='off', agents=[], scanners=False), [str(self.log)], now=self.base + 8.5)
        self.log.write_text(self.line(0, '/mail/?token=before') +
                            self.line(2, '/mail/?token=private-request', r'Crawler \x22full\x22') +
                            self.line(3, '/mail/%2eenv?password=private-value', 'Browser') +
                            self.line(4, '/index.php?token=panel') +
                            self.line(5, '/mail/', 'Crawler') +
                            self.line(6, '/mail/?token=observed', status=200) +
                            self.line(9, '/mail/?token=off'))
        result = activity.summary({'webmail'}, self.base + 10, state=self.state, include_webmail=True)
        self.assertEqual(result['total'], 4)
        self.assertEqual({row['outcome'] for row in result['recent']}, {'blocked', 'observed', 'matched'})
        self.assertIn('Crawler "full"', {row['agent'] for row in result['recent']})
        for private in ('198.51.100.45', 'private-request', 'private-value', 'private=referrer', 'token=panel'):
            self.assertNotIn(private, json.dumps(result))
        other = activity.summary({'alice.test'}, self.base + 10, state=self.state)
        self.assertEqual(other['total'], 0)
        self.assertEqual(other['webmail'], {})
        # A hosting domain with the service's display name is still an account
        # scope, not permission to read the shared panel's native request log.
        collision = activity.summary({'webmail'}, self.base + 10, state=self.state)
        self.assertEqual(collision['total'], 0)
        self.assertEqual(collision['webmail'], {})

    def test_retention_keeps_the_old_policy_boundary_and_missing_logs_are_explicit(self):
        webmail.remember(self.state, self.profile, [str(self.log)], now=1)
        webmail.remember(self.state, {**self.profile, 'mode': 'observe'}, [str(self.log)], now=40 * 86400)
        rows = webmail.history(self.state)
        self.assertEqual(rows[0]['since'], 1)
        report = activity.summary({'webmail'}, 40 * 86400 + 1, state=self.state, include_webmail=True)
        self.assertFalse(report['webmail']['available'])

    def test_native_custom_content_and_permissions_survive_mail_install_and_remove(self):
        custom = self.root / 'custom.conf'; original = '# Administrator setting\n'
        custom.write_text(original); custom.chmod(0o640)
        with patch.object(webmail, 'CUSTOM', custom), patch.object(webmail, 'SNIPPET', self.root / 'webmail.conf'), \
                patch.object(webuzo, 'GLOBAL_CUSTOM', self.root / 'http-custom.conf'):
            manifest, changes = integration.prepare([], {}, mail=True)
            integration.write(changes)
            self.assertIn('webmail.conf', custom.read_text())
            self.assertEqual(custom.stat().st_mode & 0o777, 0o640)
            manifest, changes = integration.prepare([], manifest, remove=True)
            integration.write(changes)
        self.assertEqual(custom.read_text(), original)
        self.assertEqual(custom.stat().st_mode & 0o777, 0o640)


@unittest.skipUnless(os.name == 'posix' and os.environ.get('HDN_TEST_NGINX'), 'Native Linux Nginx')
class ServerScopeTests(unittest.TestCase):
    def test_shared_server_blocks_only_mail_and_never_other_panel_routes(self):
        with tempfile.TemporaryDirectory(prefix='webmail-scope-') as folder:
            root = Path(folder); root.chmod(0o755)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            literal = 'Odd";${variable}#(a)+[b]\\c'
            profile = dict(mode='enforce', agents=['Crawler', literal], scanners=True)
            config = root / 'nginx.conf'
            def text(value):
                return ('daemon off; pid ' + str(root / 'pid') + '; error_log ' + str(root / 'error') + '; '
                        'events {} http { server { listen 127.0.0.1:' + str(port) + '; ' +
                        webmail.compile(value) + ' location / { return 200 "native route"; } } }')
            config.write_text(text(profile))
            binary = os.environ['HDN_TEST_NGINX']
            child = subprocess.Popen([binary, '-c', str(config), '-p', folder], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not (root / 'pid').exists():
                    if child.poll() is not None: self.fail(child.stderr.read().decode())
                    if time.monotonic() > deadline: self.fail('Nginx startup timeout')
                    time.sleep(.02)
                for path, agent, expected in [('/mail/', 'Crawler', 403), ('/mail/.env', 'Browser', 403),
                        ('/mail/skins/elastic/styles.css', 'Browser', 200), ('/mail/?_task=login', 'Browser', 200),
                        ('/mail/', literal, 403), ('/mail/', 'odd plain text', 200),
                        ('/index.php?act=login', 'Crawler', 200), ('/.env', 'Browser', 200),
                        ('/filemanager/', 'Crawler', 200), ('/mailing/', 'Crawler', 200)]:
                    with self.subTest(path=path, agent=agent):
                        client = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                        client.request('POST', path, headers={'User-Agent': agent})
                        response = client.getresponse(); response.read(); client.close()
                        self.assertEqual(response.status, expected)
            finally:
                child.terminate(); child.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
