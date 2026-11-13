import base64
import copy
import csv
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import access_protection as access
import country_database as country
import engine
from policy import DEFAULT, target, global_config, site_config


def archive():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr('GeoLite2-Country-CSV_TEST/GeoLite2-Country-Locations-en.csv',
                   'geoname_id,country_iso_code\n1,GR\n2,US\n3,\n')
        z.writestr('GeoLite2-Country-CSV_TEST/GeoLite2-Country-Blocks-IPv4.csv',
                   'network,geoname_id,registered_country_geoname_id\n127.2.0.0/16,1,1\n127.3.0.0/16,2,2\n127.4.0.0/16,,1\n')
        z.writestr('GeoLite2-Country-CSV_TEST/GeoLite2-Country-Blocks-IPv6.csv',
                   'network,geoname_id,registered_country_geoname_id\n2001:db8:1::/48,1,1\n2001:db8:2::/48,2,2\n::1/128,1,1\n')
    stream.seek(0)
    return stream


def settings_with(value, target):
    return access.validate({**access.defaults(), **value}, target)


class AccessValidation(unittest.TestCase):
    def test_new_settings_require_the_complete_schema(self):
        for value in ({'sites': {}}, {**access.defaults(), 'extra': True},
                      {**access.defaults(), 'defaults': {'enabled': False}}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                access.validate(value, target)

    def test_webuzo_alias_lists_accept_spaces_and_commas_without_duplicates(self):
        self.assertEqual(access.hosts(dict(domain='one.test', aliases='www.one.test alias.test,other.test www.one.test')),
                         ['one.test', 'www.one.test', 'alias.test', 'other.test'])

    def test_native_account_lookup_rejects_suspended_missing_and_foreign_accounts(self):
        with patch.object(engine, 'load', return_value=DEFAULT), \
                patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine.webuzo, 'users', return_value={'alice': {'suspended': False}, 'bob': {'suspended': True}}), \
                patch.object(engine, 'apply') as apply:
            for actor, owner, selected in [('alice', 'alice', 'bob'), ('root', 'alice', 'bob'),
                                            ('root', 'root', 'bob'), ('root', 'root', 'missing')]:
                with self.subTest(actor=actor, owner=owner, selected=selected), self.assertRaises((PermissionError, ValueError)):
                    engine.dispatch(dict(actor=actor, owner=owner, action='access_account_save', target=selected, inherit=True))
            apply.assert_not_called()

    def test_explicit_off_and_new_domains_inherit(self):
        settings = settings_with({'sites': {'alice/old.test': copy.deepcopy(access.DEFAULT)}}, target)
        settings['defaults'].update(enabled=True, password_hash='$6$salt$' + 'a' * 86)
        self.assertFalse(access.effective(settings, 'alice/old.test')['enabled'])
        self.assertTrue(access.effective(settings, 'alice/new.test')['enabled'])
        self.assertFalse(access.public(settings, {'alice/new.test'})['alice/new.test']['override'])

    def test_profile_precedence_password_rotation_and_country_inheritance(self):
        settings = {'defaults': copy.deepcopy(access.DEFAULT), 'accounts': {}, 'sites': {}}
        settings['defaults'].update(enabled=True, password_hash='$6$salt$' + 'a' * 86)
        settings['defaults']['country'].update(enabled=True, countries=['US'])
        settings['accounts']['alice'] = copy.deepcopy(access.DEFAULT)
        settings['sites']['alice/one.test'] = {**copy.deepcopy(access.DEFAULT), 'enabled': True}
        settings['sites']['alice/custom.test'] = {**copy.deepcopy(access.DEFAULT), 'enabled': True,
                                                 'password_hash': '$6$salt$' + 'c' * 86}
        settings = access.validate(settings, target)
        self.assertFalse(access.effective(settings, 'alice/new.test')['enabled'])
        self.assertFalse(access.effective(settings, 'alice/one.test')['country']['enabled'])
        self.assertTrue(access.effective(settings, 'bob/new.test')['country']['enabled'])
        settings['defaults']['password_hash'] = '$6$salt$' + 'b' * 86
        self.assertEqual(access.effective(settings, 'alice/one.test')['password_hash'], '$6$salt$' + 'b' * 86)
        self.assertEqual(access.effective(settings, 'alice/custom.test')['password_hash'], '$6$salt$' + 'c' * 86)
        visible = access.public_accounts(settings, {'alice'})
        self.assertEqual(set(visible), {'alice'})
        self.assertTrue(visible['alice']['password_inherited'])
        self.assertNotIn('password_hash', json.dumps(visible))

    def test_account_save_and_return_to_inheritance_preserve_other_levels(self):
        settings = settings_with({'sites': {'alice/one.test': copy.deepcopy(access.DEFAULT)}}, target)
        profile = {k: v for k, v in copy.deepcopy(access.DEFAULT).items() if k != 'password_hash'}
        with patch.object(engine, 'authorize', return_value=(False, 'alice')), \
                patch.object(engine, 'load', return_value=DEFAULT), patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine, 'access_settings', side_effect=lambda: copy.deepcopy(settings)), \
                patch.object(engine, 'snapshot', return_value={}), patch.object(engine, 'apply') as apply:
            engine.dispatch({'actor': 'alice', 'action': 'access_account_save', 'target': 'alice', 'settings': profile})
            saved = apply.call_args.kwargs['access']
            self.assertIn('alice', saved['accounts'])
            self.assertEqual(saved['sites'], settings['sites'])
            settings = saved
            engine.dispatch({'actor': 'alice', 'action': 'access_account_save', 'target': 'alice', 'inherit': True})
            self.assertEqual(apply.call_args.kwargs['access']['accounts'], {})
            for request in ({'action': 'access_account_save', 'target': 'bob', 'inherit': True},
                            {'action': 'access_defaults_save', 'settings': profile}):
                with self.subTest(request=request), self.assertRaises(PermissionError):
                    engine.dispatch({'actor': 'alice', **request})

    def test_central_save_and_domain_password_can_return_to_parent(self):
        hashed = '$6$salt$' + 'a' * 86
        settings = settings_with({'sites': {'alice/one.test': {**copy.deepcopy(access.DEFAULT),
                                    'password_hash': hashed}}}, target)
        profile = {k: v for k, v in copy.deepcopy(access.DEFAULT).items() if k != 'password_hash'}
        sites = [{'key': 'alice/one.test', 'owner': 'alice', 'supported': True, 'suspended': False}]
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'load', return_value=DEFAULT), patch.object(engine, 'collect', return_value=sites), \
                patch.object(engine, 'access_settings', side_effect=lambda: copy.deepcopy(settings)), \
                patch.object(engine, 'snapshot', return_value={}), patch.object(engine, 'apply') as apply, \
                patch.object(access, 'password_hash', return_value=hashed):
            engine.dispatch({'actor': 'admin', 'action': 'access_defaults_save', 'settings': profile, 'password': 'new'})
            self.assertEqual(apply.call_args.kwargs['access']['defaults']['password_hash'], hashed)
            engine.dispatch({'actor': 'admin', 'action': 'access_save', 'target': 'alice/one.test',
                             'settings': profile, 'inherit_password': True})
            self.assertEqual(apply.call_args.kwargs['access']['sites']['alice/one.test']['password_hash'], '')
            engine.dispatch({'actor': 'admin', 'action': 'access_save', 'target': 'alice/one.test', 'inherit': True})
            self.assertEqual(apply.call_args.kwargs['access']['sites'], {})

    def test_admin_looking_as_an_owner_cannot_change_central_or_foreign_account(self):
        with patch.object(engine, 'authorize', return_value=(True, 'alice')), \
                patch.object(engine, 'load', return_value=DEFAULT), patch.object(engine, 'collect', return_value=[]):
            for request in ({'action': 'access_defaults_save'}, {'action': 'access_account_save', 'target': 'bob'}):
                with self.subTest(request=request), self.assertRaises(PermissionError):
                    engine.dispatch({'actor': 'admin', **request})

    def test_disabled_and_country_only_do_not_require_a_password(self):
        entry = copy.deepcopy(access.DEFAULT)
        entry['country'].update(enabled=True, countries=['GR'])
        self.assertEqual(settings_with({'sites': {'alice/one.test': entry}}, target)['sites']['alice/one.test'], entry)
        entry['enabled'] = True
        with self.assertRaisesRegex(ValueError, 'Set an HTTP password'):
            settings_with({'sites': {'alice/one.test': entry}}, target)

    def test_config_injection_and_invalid_codes_are_rejected(self):
        for change in ({'username': 'wp; off'}, {'password_hash': '$6$evil\n'}, {'enabled': 'true'},
                       {'country': {**access.DEFAULT['country'], 'countries': ['GR;']}}):
            entry = {**copy.deepcopy(access.DEFAULT), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                settings_with({'sites': {'alice/one.test': entry}}, target)

    def test_public_settings_never_contain_the_hash_or_foreign_domains(self):
        entry = {**copy.deepcopy(access.DEFAULT), 'password_hash': 'a-secret-hash'}
        data = access.public({'sites': {'alice/one.test': entry, 'bob/two.test': entry}}, {'alice/one.test'})
        self.assertEqual(set(data), {'alice/one.test'})
        self.assertTrue(data['alice/one.test']['password_set'])
        self.assertNotIn('hash', json.dumps(data))

    def test_country_csv_imports_both_families_and_retains_unknowns(self):
        content, meta = country.compile_csv(archive())
        self.assertIn(b'127.2.0.0/16 GR;', content)
        self.assertIn(b'2001:db8:2::/48 US;', content)
        self.assertNotIn(b'127.4.0.0', content)
        self.assertEqual(meta['networks'], 5)
        self.assertEqual(meta['countries'], ['GR', 'US'])

    def test_redirect_drops_credentials_and_rejects_http(self):
        import urllib.request
        request = urllib.request.Request(country.URL, headers={'Authorization': 'Basic SECRET'})
        redirected = country.SafeRedirect().redirect_request(request, None, 302, '', {}, 'https://cdn.example/test')
        self.assertIsNone(redirected.get_header('Authorization'))
        same = country.SafeRedirect().redirect_request(request, None, 302, '', {}, 'https://download.maxmind.com/another-path')
        self.assertEqual(same.get_header('Authorization'), 'Basic SECRET')
        with self.assertRaises(ValueError):
            country.SafeRedirect().redirect_request(request, None, 302, '', {}, 'http://cdn.example/test')

    def test_download_http_error_reports_status_without_disclosing_credentials(self):
        import urllib.error
        failure = urllib.error.HTTPError(country.URL, 401, 'Unauthorized', {}, None)
        with patch.object(country.urllib.request, 'build_opener') as factory:
            factory.return_value.open.side_effect = failure
            with self.assertRaisesRegex(ValueError, 'HTTP 401') as raised:
                country.download({'account_id': '123', 'license_key': 'SECRET'})
        self.assertNotIn('SECRET', str(raised.exception))

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Root-owned country state')
    def test_failed_automatic_country_download_preserves_working_database_and_rules(self):
        import storage
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            data = b'# Existing local country database\n127.0.0.0/8 GR;\n'
            import hashlib
            metadata = dict(updated=1, sha256=hashlib.sha256(data).hexdigest())
            database = country.path(state, metadata)
            storage.replace(database, data, 0o600)
            storage.replace(state / country.METADATA, storage.json_bytes(metadata), 0o600)
            storage.replace(state / country.CONFIG, storage.json_bytes(dict(automatic=True, account_id='123', license_key='SECRET')), 0o600)
            settings = access.defaults()
            settings['defaults']['country'].update(enabled=True, countries=['US'])
            sites = [dict(key='alice/one.test', supported=True)]
            with patch.object(engine, 'STATE', state), patch.object(engine, 'access_settings', return_value=settings), \
                    patch.object(country, 'download', side_effect=ValueError('Country download failed')), \
                    patch.object(engine, 'apply') as apply:
                engine.refresh_countries(DEFAULT, sites)
                apply.assert_not_called()
            retained = json.loads((state / country.METADATA).read_bytes())
            self.assertEqual(retained['sha256'], metadata['sha256'])
            self.assertEqual(database.read_bytes(), data)
            self.assertEqual(retained['error'], 'Country download failed')
            self.assertNotIn('SECRET', json.dumps(retained))

    def test_owner_cannot_save_foreign_domain_or_download_database(self):
        sites = [{'key': 'bob/two.test', 'owner': 'bob', 'supported': True, 'suspended': False}]
        with patch.object(engine, 'authorize', return_value=(False, 'alice')), \
                patch.object(engine, 'load', return_value=DEFAULT), patch.object(engine, 'collect', return_value=sites):
            for request in ({'action': 'access_save', 'target': 'bob/two.test'}, {'action': 'geoip_update'}):
                with self.subTest(request=request), self.assertRaises(PermissionError):
                    engine.dispatch({'actor': 'alice', **request})

    def test_disabling_automatic_updates_does_not_require_a_download(self):
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'load', return_value=DEFAULT), patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine.storage, 'read', return_value=None), patch.object(engine.storage, 'replace') as write, \
                patch.object(engine, 'snapshot', return_value={}), patch.object(country, 'download') as download:
            engine.dispatch({'actor': 'admin', 'action': 'geoip_save', 'account_id': '123', 'license_key': 'SECRET', 'automatic': False})
            download.assert_not_called()
            self.assertEqual(write.call_args.args[2], 0o600)
            self.assertFalse(json.loads(write.call_args.args[1])['automatic'])


class Origin(BaseHTTPRequestHandler):
    hits = 0
    body = b''
    def do_GET(self):
        Origin.hits += 1
        Origin.body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.send_response(401 if self.path == '/wp-admin/origin-401.php' else 200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')
    do_POST = do_GET
    def log_message(self, *args):
        pass


@unittest.skipUnless(os.environ.get('HDN_TEST_NGINX'), 'Requires optional live Nginx test binary')
class NativeAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='hdn-access-test-')
        cls.root = Path(cls.temp.name); cls.root.chmod(0o755)
        (cls.root / 'logs').mkdir(); (cls.root / 'temp').mkdir()
        cls.origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        cls.thread = threading.Thread(target=cls.origin.serve_forever, daemon=True); cls.thread.start()
        cls.credentials = cls.root / 'passwords'; cls.credentials.mkdir()
        cls.patcher = patch.object(access, 'DIRECTORY', cls.credentials); cls.patcher.start()
        hashed = access.password_hash('login')
        hosts = ['gate.test', 'strict.test', 'country.test', 'site-country.test', 'allow.test',
                 'unknown.test', 'observe.test', 'off.test', 'untouched.test']
        cls.sites = [{'key': 'alice/' + h, 'domain': h, 'aliases': 'www.' + h, 'supported': True} for h in hosts]
        cls.settings = access.defaults()
        for s in cls.sites[:-1]:
            entry = {**copy.deepcopy(access.DEFAULT), 'enabled': True, 'password_hash': hashed}
            cls.settings['sites'][s['key']] = entry
            (cls.credentials / (access.identifier(s['key']) + '.htpasswd')).write_text('wp:' + hashed + '\n')
        cls.settings['sites']['alice/strict.test']['bypass_internal'] = False
        for host in ('country.test', 'site-country.test', 'allow.test', 'unknown.test', 'observe.test'):
            entry = cls.settings['sites']['alice/' + host]
            entry['country'].update(enabled=True, countries=['US'])
            if host == 'site-country.test': entry['country']['scope'] = 'site'
            if host == 'allow.test': entry['country'].update(mode='allow', countries=['GR'])
            if host == 'unknown.test': entry['country']['allow_unknown'] = False
        # Exercise inheritance through real Nginx, including explicit account Off
        # and a domain overriding that account while inheriting the central hash.
        cls.settings = access.validate(cls.settings, target)
        cls.settings['defaults'].update(enabled=True, password_hash=hashed)
        cls.settings['defaults']['country'].update(enabled=True, countries=['US'])
        cls.settings['sites']['alice/untouched.test'] = copy.deepcopy(access.DEFAULT)
        cls.settings['accounts']['bob'] = copy.deepcopy(access.DEFAULT)
        cls.settings['sites']['bob/domain-override.test'] = {**copy.deepcopy(access.DEFAULT), 'enabled': True}
        for owner, host in [('carol', 'central.test'), ('bob', 'account-off.test'), ('bob', 'domain-override.test')]:
            site = {'key': owner + '/' + host, 'domain': host, 'aliases': '', 'supported': True}
            cls.sites.append(site)
            entry = access.effective(cls.settings, site['key'])
            if entry['enabled']:
                (cls.credentials / (access.identifier(site['key']) + '.htpasswd')).write_text('wp:' + entry['password_hash'] + '\n')
        cls.geo = cls.root / 'countries.geo'; cls.geo.write_bytes(country.compile_csv(archive())[0])
        cls.policy = copy.deepcopy(DEFAULT); cls.policy['mode'] = 'enforce'
        cls.policy['overrides'] = {'alice/observe.test': 'observe', 'alice/off.test': 'off'}
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); cls.port = sock.getsockname()[1]
        text = 'worker_processes 1;\npid logs/nginx.pid;\nerror_log logs/error.log notice;\nevents { worker_connections 64; }\nhttp {\n'
        text += global_config(cls.policy, cls.sites, access_settings=cls.settings, geo_path=cls.geo)
        for site in cls.sites:
            text += 'server { listen 127.0.0.1:' + str(cls.port) + '; server_name ' + site['domain'] + ' www.' + site['domain'] + ';\n'
            if socket.has_ipv6:
                text += 'listen [::1]:' + str(cls.port) + ';\n'
            text += site_config(cls.policy, site, access_settings=cls.settings).replace('/var/log/webuzo-de-noise/matches.log', str(cls.root / 'matches.log'))
            text += 'location / { proxy_pass http://127.0.0.1:' + str(cls.origin.server_address[1]) + '; }\n}\n'
        (cls.root / 'nginx.conf').write_text(text + '}\n')
        cls.command = [os.environ['HDN_TEST_NGINX'], '-p', str(cls.root) + '/', '-c', 'nginx.conf']
        result = subprocess.run([*cls.command, '-t'], capture_output=True, text=True)
        if result.returncode:
            cls.patcher.stop(); cls.origin.shutdown(); cls.origin.server_close(); cls.temp.cleanup()
            raise AssertionError(result.stderr)
        cls.process = subprocess.Popen([*cls.command, '-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.1): break
            except OSError: time.sleep(.02)
        else: raise AssertionError('Isolated access Nginx did not start')

    @classmethod
    def tearDownClass(cls):
        subprocess.run([*cls.command, '-s', 'quit'], capture_output=True)
        cls.process.wait(timeout=10)
        cls.patcher.stop(); cls.origin.shutdown(); cls.origin.server_close(); cls.thread.join()
        cls.temp.cleanup()

    def request(self, path='/wp-login.php', host='gate.test', headers=None, source='127.2.1.1', method='GET', body=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5, source_address=(source, 0))
        connection.request(method, path, body=body, headers={'Host': host, 'User-Agent': 'Access regression test', **(headers or {})})
        response = connection.getresponse(); status = response.status; response.read(); connection.close()
        return status

    def test_direct_get_and_post_stop_before_origin_and_correct_credentials_work(self):
        before = Origin.hits
        self.assertEqual(self.request(), 401)
        self.assertEqual(self.request(method='POST', body='log=user&pwd=pass'), 401)
        self.assertEqual(self.request(headers={'Authorization': 'Basic ' + base64.b64encode(b'wp:wrong').decode()}), 401)
        self.assertEqual(Origin.hits, before)
        self.assertEqual(self.request(headers={'Authorization': 'Basic ' + base64.b64encode(b'wp:login').decode()}), 200)

    def test_central_account_and_domain_inheritance_at_native_request_time(self):
        self.assertEqual(self.request(host='central.test'), 401)
        self.assertEqual(self.request(host='central.test', source='127.3.1.1'), 403)
        self.assertEqual(self.request(host='account-off.test', source='127.3.1.1'), 200)
        self.assertEqual(self.request(host='domain-override.test', source='127.3.1.1'), 401)
        self.assertEqual(self.request(host='domain-override.test', headers={
            'Authorization': 'Basic ' + base64.b64encode(b'wp:login').decode()}), 200)

    def test_same_origin_and_fallback_preserve_post_and_strict_mode_still_prompts(self):
        self.assertEqual(self.request(headers={'Sec-Fetch-Site': 'same-origin'}, method='POST', body='log=user&pwd=pass'), 200)
        self.assertEqual(Origin.body, b'log=user&pwd=pass')
        self.assertEqual(self.request(headers={'Referer': 'http://gate.test/my-account/'}), 200)
        self.assertEqual(self.request(host='www.gate.test', headers={'Referer': 'http://www.gate.test/my-account/'}), 200)
        self.assertEqual(self.request(host='strict.test', headers={'Sec-Fetch-Site': 'same-origin'}), 401)

    def test_external_same_site_none_and_hostname_prefix_do_not_bypass(self):
        for headers in ({'Sec-Fetch-Site': 'none'}, {'Sec-Fetch-Site': 'same-site'},
                        {'Referer': 'http://gate.test.evil.test/'}, {'Referer': 'http://gate.test:8080/'},
                        {'Referer': 'https://gate.test/'}, {'Sec-Fetch-Site': 'cross-site', 'Referer': 'http://gate.test/'}):
            with self.subTest(headers=headers): self.assertEqual(self.request(headers=headers), 401)

    def test_customer_flows_and_frontend_handlers_remain_accessible(self):
        for path in ('/my-account/', '/my-account/lost-password/', '/checkout/', '/?wc-ajax=checkout',
                     '/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php',
                     '/wp-admin/js/password-strength-meter.min.js', '/wp-admin/js/password-strength-meter.js',
                     '/wp-json/wc/v3/orders', '/wp-cron.php', '/shop/wp-admin/admin-ajax.php'):
            with self.subTest(path=path): self.assertEqual(self.request(path, method='POST', body='field=value'), 200)
        for path in ('/wp-admin', '/wp-admin/', '/shop/wp-login.php', '/shop/wp-admin/edit.php', '/wp-login.php/path-info'):
            with self.subTest(path=path): self.assertEqual(self.request(path), 401)

    def test_country_filters_apply_independently_of_origin_and_cover_selected_scope(self):
        headers = {'Sec-Fetch-Site': 'same-origin'}
        self.assertEqual(self.request(host='country.test', source='127.3.1.1', headers=headers), 403)
        self.assertEqual(self.request(host='country.test', source='127.2.1.1', headers=headers), 200)
        self.assertEqual(self.request('/my-account/', host='country.test', source='127.3.1.1'), 200)
        self.assertEqual(self.request('/my-account/', host='site-country.test', source='127.3.1.1'), 403)
        self.assertEqual(self.request('/.well-known/acme-challenge/test', host='site-country.test', source='127.3.1.1'), 200)
        self.assertEqual(self.request(host='allow.test', source='127.2.1.1', headers=headers), 200)
        self.assertEqual(self.request(host='allow.test', source='127.3.1.1', headers=headers), 403)
        self.assertEqual(self.request(host='allow.test', source='127.4.1.1', headers=headers), 200)
        self.assertEqual(self.request(host='unknown.test', source='127.4.1.1', headers=headers), 403)

    def test_observe_off_and_other_domains_do_not_reject(self):
        self.assertEqual(self.request(host='observe.test', source='127.3.1.1'), 200)
        self.assertEqual(self.request(host='off.test'), 200)
        self.assertEqual(self.request(host='untouched.test'), 200)

    def test_activity_records_actual_challenges_and_country_blocks(self):
        self.request()
        self.request(host='country.test', source='127.3.1.1')
        self.request(host='observe.test', source='127.3.1.1')
        time.sleep(.03)
        body = (self.root / 'matches.log').read_text()
        self.assertIn('wordpress-access - 401 enforce', body)
        self.assertIn('country-filter - 403 enforce', body)
        self.assertIn('country-filter - 200 observe', body)
        self.assertNotIn('wp:login', body)

    @unittest.skipUnless(socket.has_ipv6, 'IPv6 not supported by this system')
    def test_native_ipv6_country_lookup(self):
        connection = http.client.HTTPConnection('::1', self.port, timeout=5)
        connection.request('GET', '/wp-login.php', headers={'Host': 'unknown.test', 'Sec-Fetch-Site': 'same-origin'})
        response = connection.getresponse(); status = response.status; response.read(); connection.close()
        self.assertEqual(status, 200)  # ::1 is GR; unknown locations are denied on this host.

    def test_origin_401_is_not_misreported_as_an_http_gate_challenge(self):
        log = self.root / 'matches.log'
        before = log.read_text().count('wordpress-access - 401 enforce') if log.exists() else 0
        headers = {'Authorization': 'Basic ' + base64.b64encode(b'wp:login').decode()}
        self.assertEqual(self.request('/wp-admin/origin-401.php', headers=headers), 401)
        time.sleep(.02)
        after = log.read_text().count('wordpress-access - 401 enforce') if log.exists() else 0
        self.assertEqual(after, before)
