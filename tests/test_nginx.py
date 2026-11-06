"""Optional real Nginx tests in a disposable local directory, never Hestia."""
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from native_nginx import isolated_config

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from policy import DEFAULT, global_config, site_config
import ban_evidence

NGINX = os.environ.get('HDN_TEST_NGINX')


class Origin(BaseHTTPRequestHandler):
    hits = 0
    def do_GET(self):
        type(self).hits += 1
        self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'OK')
    do_POST = do_GET

    def log_message(self, *args):
        pass


@unittest.skipUnless(NGINX, 'Set HDN_TEST_NGINX to a local Nginx binary to run live request checks')
class NativeNginxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='hdn-test-')
        cls.directory = Path(cls.temp.name)
        cls.directory.chmod(0o755)
        (cls.directory / 'logs').mkdir()
        (cls.directory / 'temp').mkdir()
        cls.origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        cls.thread = threading.Thread(target=cls.origin.serve_forever, daemon=True); cls.thread.start()
        cls.origin_port = cls.origin.server_address[1]
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); cls.port = probe.getsockname()[1]
        policy = copy.deepcopy(DEFAULT)
        policy['mode'] = 'enforce'
        cls.literal = 'Odd";${literal}#(a)+[b]\\c'
        policy['agents'] = ['Crawler', cls.literal]
        policy['scanners'] = True
        policy['bans']['enabled'] = True
        policy['bans']['missing_files'].update(enabled=True, paths=policy['bans']['missing_files']['paths'] + ['/existing.php'])
        policy['bans']['suspicious_queries']['enabled'] = True
        policy['probe_exceptions'] = {'files': {'alice/enforce.test': ['/test.php']},
                                     'queries': {'alice/enforce.test': ['/wp-admin/file-manager.php']}}
        policy['login'] = {'enabled': True, 'rate': 1, 'burst': 1}
        policy['xmlrpc'] = {'enabled': True, 'rate': 10, 'burst': 3}
        policy['overrides'] = {'alice/observe.test': 'observe', 'alice/off.test': 'off'}
        policy['filters'] = [
            {'id': 'facets', 'enabled': True, 'path': '/shop/', 'targets': [],
             'parameters': ['min_price', 'orderby'], 'agents': ['Applebot', 'Amazonbot'],
             'action': 'limit', 'rate': 1, 'burst': 0},
            {'id': 'filtered_block', 'enabled': True, 'path': '/',
             'targets': ['alice/enforce.test', 'alice/observe.test', 'alice/off.test'],
             'parameters': ['listing_tag'], 'agents': ['Reflectionbot'],
             'action': 'block', 'rate': 30, 'burst': 3}]
        policy['static'] = [{'id': 'maps', 'enabled': True, 'path': '/wp-content/',
                             'extensions': ['map'], 'targets': []},
                            {'id': 'special_maps', 'enabled': True, 'path': '/wp-content/special/',
                             'extensions': ['map'], 'targets': []}]
        policy['static_exceptions'] = {'alice/enforce.test': [
            '/wp-content/missing-generated.map', '/wp-content/special/dynamic.map',
            '/wp-content/a%20b.map', '/wp-content/%CF%87.map', '/wp-content/a%25name.map',
            '/wp-content/literal$var.map', '/wp-content/quote%22%3Bfile.map', '/wp-content/.env.map']}
        (cls.directory / 'wp-content').mkdir()
        (cls.directory / 'wp-content/existing.map').write_text('existing')
        (cls.directory / 'existing.php').write_text('existing')
        sites = [{'key': 'alice/' + host} for host in ('enforce.test', 'other.test', 'observe.test', 'off.test')]
        text = 'worker_processes 1;\npid logs/nginx.pid;\nerror_log logs/error.log notice;\nevents { worker_connections 64; }\nhttp {\n'
        text += global_config(policy, sites)
        for site in sites:
            host = site['key'].split('/')[1]
            text += 'server { listen 127.0.0.1:' + str(cls.port) + '; server_name ' + host + ' www.' + host + ';\n'
            text += site_config(policy, site, cls.directory.as_posix()).replace('/var/log/webuzo-de-noise/matches.log',
                                                     (cls.directory / 'matches.log').as_posix()).replace('/var/log/webuzo-de-noise/ban-events.log', (cls.directory / 'ban-events.log').as_posix())
            text += 'location / { proxy_pass http://127.0.0.1:' + str(cls.origin_port) + '; }\n}\n'
        text += '}\n'
        (cls.directory / 'nginx.conf').write_text(isolated_config(text, cls.directory))
        cls.command = [NGINX, '-p', cls.directory.as_posix() + '/', '-c', 'nginx.conf']
        result = subprocess.run([*cls.command, '-t'], capture_output=True, text=True)
        if result.returncode:
            cls.origin.shutdown(); cls.origin.server_close()
            cls.temp.cleanup()
            raise AssertionError(result.stderr)
        cls.process = subprocess.Popen(cls.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    cls.tearDownClass()
                    raise AssertionError('Local test Nginx did not start')
                time.sleep(.05)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'process'):
            subprocess.run([*cls.command, '-s', 'quit'], capture_output=True, timeout=5)
            cls.process.wait(timeout=10)
        cls.origin.shutdown(); cls.origin.server_close(); cls.thread.join(timeout=2)
        cls.temp.cleanup()

    def request(self, path='/', agent='Mozilla/5.0', host='enforce.test', method='GET', source=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3,
                                                source_address=(source, 0) if source else None)
        connection.request(method, path, headers={'Host': host, 'User-Agent': agent})
        response = connection.getresponse()
        status = response.status; response.read(); connection.close()
        return status

    def test_agent_blocks_case_insensitive_literal_and_observe_off_allow(self):
        self.assertEqual(self.request(agent='Some CRAWLER v1'), 403)
        self.assertEqual(self.request(agent=self.literal), 403)
        self.assertEqual(self.request(agent='Odd'), 200)
        self.assertEqual(self.request(agent='Crawler', host='observe.test'), 200)
        self.assertEqual(self.request(agent='Crawler', host='off.test'), 200)

    def test_expected_rejections_use_notice_and_remain_in_activity(self):
        results=[self.request('/wp-login.php',method='POST',source='127.3.8.1') for _ in range(3)]
        self.assertEqual(results,[200,200,429])
        time.sleep(.02)
        rows=[line for line in (self.directory/'logs/error.log').read_text().splitlines()
              if 'limiting requests' in line and '127.3.8.1' in line]
        self.assertTrue(rows);self.assertTrue(all('[notice]' in row for row in rows))
        self.assertIn(' login REJECTED 429 enforce',(self.directory/'matches.log').read_text())

    def test_selected_php_probes_preserve_existing_files_and_domain_exceptions(self):
        before = Origin.hits
        self.assertEqual(self.request('/auth.php'), 404)
        self.assertEqual(Origin.hits, before)
        self.assertEqual(self.request('/existing.php'), 200)
        self.assertEqual(self.request('/test.php'), 200)
        self.assertEqual(self.request('/test.php', host='other.test'), 404)
        self.assertEqual(self.request('/unlisted.php'), 200)
        self.assertEqual(self.request('/auth.php', host='observe.test'), 200)
        self.assertEqual(self.request('/auth.php', host='off.test'), 200)

    def test_expanded_php_probes_stop_before_origin_but_existing_files_still_route(self):
        paths = ['/wp-content/module.php', '/wp-content/data.php',
                 '/wp-admin/maint/config.php', '/wp-includes/SimplePie/write.php']
        for path in paths:
            with self.subTest(path=path):
                before = Origin.hits
                self.assertEqual(self.request(path), 404)
                self.assertEqual(Origin.hits, before)
        created = self.directory / 'wp-content/module.php'
        created.write_text('legitimate application')
        try:
            self.assertEqual(self.request('/wp-content/module.php'), 200)
            self.assertEqual(self.request('/wp-content/data.php', host='observe.test'), 200)
            self.assertEqual(self.request('/wp-content/data.php', host='off.test'), 200)
        finally:
            created.unlink()

    def test_secret_queries_encoded_variants_and_file_manager_exception(self):
        for path in ['/?file=/etc/passwd', '/?path=../../etc/shadow',
                     '/?file=%2fetc%2fpasswd', '/?file=%252fetc%252fpasswd',
                     '/?file=%252F%2565%2574%2563%252F%2570%2561%2573%2573%2577%2564',
                     '/?file=php://filter/read=convert.base64-encode/resource=wp-config.php',
                     '/?x=ok&file=../../wp-config.php&other=1']:
            with self.subTest(path=path):
                before = Origin.hits
                self.assertEqual(self.request(path), 404)
                self.assertEqual(Origin.hits, before)
        for path in ['/?file=../uploads/photo.jpg', '/?path=../documents', '/?s=wp-config.php', '/?s=.env',
                     '/?s=How+to+edit+wp-config.php', '/?file=/etc/passwd-example',
                     '/wp-admin/file-manager.php?file=/etc/passwd']:
            with self.subTest(path=path): self.assertEqual(self.request(path), 200)
        self.assertEqual(self.request('/wp-admin/file-manager.php?file=/etc/passwd', host='other.test'), 404)
        self.assertEqual(self.request('/?file=/etc/passwd', host='observe.test'), 200)
        self.assertEqual(self.request('/?file=/etc/passwd', host='off.test'), 200)

    def test_probe_ban_log_requires_404_and_never_contains_query_values(self):
        self.request('/auth.php', host='other.test')
        self.request('/existing.php')
        self.request('/?file=/etc/passwd')
        self.request('/wp-admin/file-manager.php?file=/etc/passwd')
        rows = (self.directory / 'ban-events.log').read_text().splitlines()
        records = [ban_evidence.event(row) for row in rows]
        self.assertTrue(any(row and row[3] == 'missing-file' and row[5] == '/auth.php' for row in records))
        self.assertTrue(any(row and row[3] == 'suspicious-query' and row[5] == '/' for row in records))
        self.assertFalse(any(row and row[3] == 'missing-file' and row[5] == '/existing.php' for row in records))
        self.assertNotIn('file=/etc/passwd', '\n'.join(rows))

    def test_configuration_is_valid_before_any_domains_exist(self):
        text = 'pid logs/empty.pid;\nerror_log logs/empty.log;\nevents {}\nhttp {\n'
        text += global_config(DEFAULT, []) + '\n}\n'
        (self.directory / 'empty.conf').write_text(isolated_config(text, self.directory))
        command = [NGINX, '-p', self.directory.as_posix() + '/', '-c', 'empty.conf', '-t']
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_long_parameter_lists_are_split_within_native_config_token_limit(self):
        policy = copy.deepcopy(DEFAULT)
        policy['bans']['enabled'] = True
        policy['bans']['suspicious_queries']['enabled'] = True
        policy['bans']['suspicious_queries']['parameters'] = ['parameter_' + str(n) + '_' + 'x'*45 for n in range(50)]
        text = 'pid logs/long-query.pid;\nerror_log logs/long-query.log;\nevents {}\nhttp {\n'
        text += global_config(policy, []) + '\n}\n'
        (self.directory / 'long-query.conf').write_text(isolated_config(text, self.directory))
        result = subprocess.run([NGINX, '-p', self.directory.as_posix()+'/', '-c', 'long-query.conf', '-t'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_domain_only_protection_and_ipv4_ipv6_bans_do_not_affect_other_hosts(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        policy = copy.deepcopy(DEFAULT); policy['mode'] = 'enforce'
        policy['domain_bans']['sites'] = {'alice/one.test': {'missing_files': True, 'suspicious_queries': True, 'any_404': False}}
        sites = [{'key': 'alice/one.test'}, {'key': 'bob/two.test'}]
        blocks = {'alice/one.test': {'127.0.0.9': {}, '::1': {}}}
        text = 'pid logs/domain.pid;\nerror_log logs/domain-error.log;\nevents {}\nhttp {\n' + global_config(policy, sites, blocks)
        for site in sites:
            host = site['key'].split('/')[1]
            text += 'server { listen 127.0.0.1:' + str(port) + '; listen [::1]:' + str(port) + '; server_name '+host+' www.'+host+';\n'
            text += site_config(policy, site, str(self.directory)).replace('/var/log/webuzo-de-noise/matches.log', str(self.directory/'domain-matches.log')).replace('/var/log/webuzo-de-noise/ban-events.log', str(self.directory/'domain-events.log'))
            text += 'location / { proxy_pass http://127.0.0.1:'+str(self.origin_port)+'; }\n}\n'
        text += '}\n'; (self.directory/'domain.conf').write_text(isolated_config(text, self.directory))
        command = [NGINX, '-p', str(self.directory)+'/', '-c', 'domain.conf']
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        def get(host, path='/', address='127.0.0.1', source=None):
            connection = http.client.HTTPConnection(address, port, timeout=3, source_address=(source,0) if source else None)
            connection.request('GET', path, headers={'Host':host}); response = connection.getresponse()
            status = response.status; response.read(); connection.close(); return status
        try:
            self.assertEqual(get('one.test','/auth.php'),404)
            self.assertEqual(get('two.test','/auth.php'),200)
            self.assertEqual(get('one.test','/?file=/etc/passwd'),404)
            self.assertEqual(get('two.test','/?file=/etc/passwd'),200)
            self.assertEqual(get('one.test',source='127.0.0.9'),403)
            self.assertEqual(get('www.one.test',source='127.0.0.9'),403)
            self.assertEqual(get('two.test',source='127.0.0.9'),200)
            self.assertEqual(get('one.test',address='::1'),403)
            self.assertEqual(get('two.test',address='::1'),200)
            lines=(self.directory/'domain-events.log').read_text()
            self.assertIn('domain-file',lines);self.assertIn('domain-query',lines)
            self.assertNotIn('passwd',lines)
        finally:
            subprocess.run([*command,'-s','quit'],capture_output=True,timeout=5)

    def test_global_ipv4_and_ipv6_bans_cover_both_accounts_and_aliases(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        policy = copy.deepcopy(DEFAULT); policy['mode'] = 'enforce'; policy['bans']['enabled'] = True
        sites = [{'key': 'alice/global-one.test'}, {'key': 'bob/global-two.test'}]
        text = 'pid logs/global.pid;\nerror_log logs/global-error.log;\nevents {}\nhttp {\n'
        text += global_config(policy, sites, global_blocks={'127.0.0.9', '::1'})
        for site in sites:
            host = site['key'].split('/')[1]
            text += 'server { listen 127.0.0.1:' + str(port) + '; listen [::1]:' + str(port) + '; server_name ' + host + ' www.' + host + ';\n'
            text += site_config(policy, site, str(self.directory)).replace('/var/log/webuzo-de-noise/matches.log', str(self.directory/'global-matches.log')).replace('/var/log/webuzo-de-noise/ban-events.log', str(self.directory/'global-events.log'))
            text += 'location / { proxy_pass http://127.0.0.1:' + str(self.origin_port) + '; }\n}\n'
        (self.directory/'global.conf').write_text(isolated_config(text + '}\n', self.directory))
        command = [NGINX, '-p', str(self.directory)+'/', '-c', 'global.conf']
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        def get(host, address='127.0.0.1', source=None):
            connection = http.client.HTTPConnection(address, port, timeout=3, source_address=(source,0) if source else None)
            connection.request('GET', '/', headers={'Host':host}); response = connection.getresponse()
            status = response.status; response.read(); connection.close(); return status
        try:
            for host in ('global-one.test', 'www.global-one.test', 'global-two.test'):
                self.assertEqual(get(host), 200)
                self.assertEqual(get(host, source='127.0.0.9'), 403)
                self.assertEqual(get(host, address='::1'), 403)
        finally:
            subprocess.run([*command,'-s','quit'],capture_output=True,timeout=5)

    def test_tool_and_crawler_switches_are_independent_in_real_nginx(self):
        for index, (tools, crawlers) in enumerate([(False, True), (True, False), (False, False)]):
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            policy = copy.deepcopy(DEFAULT); policy['mode'] = 'enforce'
            policy.update(tool_agents=['ProbeTool'], agents=['BulkCrawler'], tool_agents_enabled=tools, agents_enabled=crawlers)
            text = 'pid logs/toggles.pid;\nerror_log logs/toggles.log;\nevents {}\nhttp {\n' + global_config(policy, [])
            text += 'server { listen 127.0.0.1:' + str(port) + '; server_name switches.test;\n'
            text += site_config(policy, {'key': 'alice/switches.test'}).replace('/var/log/webuzo-de-noise/matches.log', (self.directory / 'toggles-matches.log').as_posix())
            text += 'location / { proxy_pass http://127.0.0.1:' + str(self.origin_port) + '; }\n}\n}\n'
            name = 'toggles-' + str(index) + '.conf'; (self.directory / name).write_text(isolated_config(text, self.directory))
            command = [NGINX, '-p', self.directory.as_posix() + '/', '-c', name]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            try:
                for agent, blocked in [('ProbeTool', tools), ('BulkCrawler', crawlers)]:
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                    connection.request('GET', '/', headers={'Host': 'switches.test', 'User-Agent': agent})
                    response = connection.getresponse(); status = response.status; response.read(); connection.close()
                    self.assertEqual(status, 403 if blocked else 200, (agent, tools, crawlers))
            finally:
                subprocess.run([*command, '-s', 'quit'], capture_output=True, timeout=5)

    def test_private_paths_block_but_well_known_and_ordinary_config_paths_work(self):
        hits = Origin.hits
        for path in ('/.env', '/.env.backup', '/.git/config', '/wp-config.php.old',
                     '/nested/.aws/credentials', '/.docker/config.json', '/.kube/config',
                     '/var/run/secrets/kubernetes.io/serviceaccount/token',
                     '/api/w/default/jobs/get_log_file/../../../../proc/self/environ', '/%2eenv', '/etc/shadow'):
            self.assertEqual(self.request(path, agent='Googlebot'), 403, path)
        self.assertEqual(Origin.hits, hits)
        for path in ('/.well-known/acme-challenge/test', '/config', '/api', '/.environment'):
            self.assertEqual(self.request(path), 200, path)

    def test_filtered_crawlers_share_budget_across_ips_versions_and_aliases(self):
        self.assertEqual(self.request('/shop/?min_price=10', agent='Applebot/1'), 200)
        self.assertEqual(self.request('/shop/?min_price=20', agent='Applebot/2', host='www.enforce.test', source='127.0.0.2'), 429)
        self.assertEqual(self.request('/shop/?%6din_price=30', agent='Applebot'), 429)
        self.assertEqual(self.request('/shop/?min_price=20', agent='Amazonbot'), 200)
        self.assertEqual(self.request('/shop/?min_price=20', agent='Applebot', host='other.test'), 200)
        for path in ('/shop/', '/shop/?other=1', '/shopping/?min_price=1', '/news/?min_price=1'):
            self.assertEqual(self.request(path, agent='Applebot'), 200, path)
        self.assertEqual(self.request('/shop/?min_price=10', agent='Mozilla/5.0'), 200)
        for host in ('observe.test', 'off.test'):
            for _ in range(3):
                self.assertEqual(self.request('/shop/?min_price=10', agent='Applebot', host=host), 200)

    def test_filter_block_scope_and_static_existing_files_preserve_routing(self):
        self.assertEqual(self.request('/?listing_tag=x', agent='Reflectionbot'), 403)
        for host in ('other.test', 'observe.test', 'off.test'):
            self.assertEqual(self.request('/?listing_tag=x', agent='Reflectionbot', host=host), 200)
        hits = Origin.hits
        self.assertEqual(self.request('/wp-content/missing.map'), 404)
        self.assertEqual(Origin.hits, hits)
        for path in ('/wp-content/existing.map', '/wp-content/missing.js', '/other/missing.map'):
            self.assertEqual(self.request(path), 200, path)
        self.assertEqual(Origin.hits, hits + 3)
        for host in ('observe.test', 'off.test'):
            self.assertEqual(self.request('/wp-content/missing.map', host=host), 200)
        self.assertEqual(self.request('/wp-content/missing.map', method='POST'), 200)

    def test_static_exceptions_are_domain_scoped_exact_and_do_not_bypass_other_rules(self):
        for path in ['/wp-content/missing-generated.map', '/wp-content/special/dynamic.map',
                     '/wp-content/a%20b.map', '/wp-content/%CF%87.map', '/wp-content/a%25name.map',
                     '/wp-content/literal$var.map', '/wp-content/quote%22%3Bfile.map']:
            self.assertEqual(self.request(path), 200, path)
            self.assertEqual(self.request(path + '?ver=2', host='www.enforce.test'), 200, path)
            self.assertEqual(self.request(path, host='other.test'), 404, path)
        self.assertEqual(self.request('/wp-content/%6dissing-generated.map'), 200)
        for path in ['/wp-content/MISSING-generated.map', '/wp-content/missing-generated.map/more.map',
                     '/wp-content/missing-generated.map2.map']:
            self.assertEqual(self.request(path), 404, path)
        self.assertEqual(self.request('/wp-content/missing-generated.map', agent='Crawler'), 403)
        self.assertEqual(self.request('/wp-content/.env.map'), 403)

    def test_rates_apply_to_post_only_and_aliases_share_the_budget(self):
        self.assertEqual(self.request('/wp-login.php?action=lostpassword', method='POST'), 200)
        # Both native limit zones exist; an alias must not obtain a new budget.
        self.request('/wp-login.php', method='POST', host='www.enforce.test')
        self.assertEqual(self.request('/wp-login.php/', method='POST'), 429)
        self.assertEqual(self.request('/wp-login.php', method='POST', host='www.enforce.test'), 429)
        for path in ('/wp-login.php', '/wp-admin/admin-ajax.php', '/wp-json/plugin/test'):
            self.assertEqual(self.request(path), 200)
        self.assertEqual(self.request('/wp-json/plugin/test', method='POST'), 200)
        for _ in range(5):
            self.assertEqual(self.request('/wp-login.php', method='POST', host='observe.test'), 200)
            self.assertEqual(self.request('/wp-login.php', method='POST', host='off.test'), 200)

    def test_search_social_agents_are_not_automatically_blocked(self):
        for agent in ('Googlebot', 'bingbot', 'Applebot', 'facebookexternalhit', 'Twitterbot', 'WhatsApp'):
            self.assertEqual(self.request(agent=agent), 200)

    def test_xmlrpc_has_its_own_budget_and_logs_do_not_store_request_values(self):
        self.assertEqual(self.request('/xmlrpc.php', method='POST'), 200)
        statuses = [self.request('/xmlrpc.php', method='POST') for _ in range(5)]
        self.assertIn(429, statuses)
        self.assertEqual(self.request('/xmlrpc.php'), 200)
        self.assertEqual(self.request('/?password=synthetic-sensitive-value', agent='Crawler'), 403)
        text = (self.directory / 'matches.log').read_text()
        self.assertIn('enforce.test', text)
        self.assertNotIn('synthetic-sensitive-value', text)
        self.assertIn('Crawler', text)
        self.assertNotIn('127.0.0.1', text)

    def test_activity_retains_the_exact_agent_with_native_json_escaping(self):
        import json
        agent = 'Crawler "<script>" \\ marker'
        self.assertEqual(self.request('/?token=do-not-log-this', agent=agent), 403)
        time.sleep(.02)
        rows = (self.directory / 'matches.log').read_text().splitlines()
        recorded = [json.loads(line.partition('\t')[2]) for line in rows if '\t' in line]
        self.assertIn(agent, recorded)
        self.assertNotIn('do-not-log-this', '\n'.join(rows))
        for row in rows:
            self.assertEqual(len(row.partition('\t')[0].split()), 6, row)

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-owned native activity logs')
    def test_activity_reader_counts_actual_nginx_blocks_without_a_limit_status(self):
        import activity
        from unittest.mock import patch
        agent = 'Crawler Activity E2E'
        self.assertEqual(self.request(agent=agent), 403)
        with patch.object(activity, 'LOG', self.directory / 'matches.log'):
            result = activity.summary({'enforce.test'})
        records = [row for row in result['rows'] if row['agent'] == agent]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['count'], 1)
        self.assertEqual(records[0]['outcome'], 'blocked')


if __name__ == '__main__':
    unittest.main()
