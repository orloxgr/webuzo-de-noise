"""Opt-in isolated WordPress tables/files using an existing lab owner/core.

No production service or WordPress installation is modified. Test tables have a
random prefix in the lab database and are removed together with the fixture.
"""
import copy
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import enumeration
from policy import DEFAULT, global_config, site_config, site_mode

CORE=os.environ.get('HDN_TEST_WORDPRESS_CORE')
OWNER=os.environ.get('HDN_TEST_WORDPRESS_OWNER')
PHP=os.environ.get('HDN_TEST_PHP','/usr/bin/php')
WPCLI=os.environ.get('HDN_TEST_WPCLI','/usr/local/bin/wp')
NGINX=os.environ.get('HDN_TEST_NGINX','/usr/sbin/nginx')


def port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));return probe.getsockname()[1]


@unittest.skipUnless(CORE and OWNER and os.name=='posix','Opt-in Linux WordPress fixture')
class WordPressIntegrationTests(unittest.TestCase):
    @classmethod
    def owner_command(cls,*args):
        result=subprocess.run(['/usr/sbin/runuser','-u',OWNER,'--',*map(str,args)],capture_output=True,text=True,timeout=45)
        if result.returncode:raise AssertionError('Lab owner command failed: '+result.stderr[-3000:])
        return result.stdout.strip()

    @classmethod
    def wp(cls,*args):
        return cls.owner_command(PHP,WPCLI,'--path='+str(cls.root),*args)

    @classmethod
    def setUpClass(cls):
        import pwd
        user=pwd.getpwnam(OWNER)
        assert user.pw_uid != 0
        cls.prefix='hdn_enum_'+secrets.token_hex(6)+'_'
        cls.temp=tempfile.TemporaryDirectory(prefix='.hdn-enum-',dir=user.pw_dir)
        cls.root=Path(cls.temp.name);os.chown(cls.root,user.pw_uid,user.pw_gid);cls.root.chmod(0o755)
        cls.processes=[];cls.installed=False
        try:
            core=Path(CORE)
            for name in ('wp-admin','wp-includes'):
                shutil.copytree(core/name,cls.root/name)
            for source in core.glob('*.php'):
                if source.name!='wp-config.php':shutil.copyfile(source,cls.root/source.name)
            for name in ('wp-content','wp-content/mu-plugins','logs','temp'):
                directory=cls.root/name;directory.mkdir(exist_ok=True);os.chown(directory,user.pw_uid,user.pw_gid)
            credentials={}
            for key in ('DB_NAME','DB_USER','DB_PASSWORD','DB_HOST'):
                credentials[key]=cls.owner_command(PHP,WPCLI,'--path='+str(core),'config','get',key)
            def quoted(value):return "'"+value.replace('\\','\\\\').replace("'","\\'")+"'"
            config='<?php\n'+''.join('define('+quoted(key)+','+quoted(value)+');\n' for key,value in credentials.items())
            for key in ('AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT'):
                config+='define('+quoted(key)+','+quoted(secrets.token_hex(32))+');\n'
            config+="define('WP_ENVIRONMENT_TYPE','local');\ndefine('DISABLE_WP_CRON',true);\n"
            config+="$table_prefix="+quoted(cls.prefix)+";\ndefine('ABSPATH',__DIR__.'/');\nrequire_once ABSPATH.'wp-settings.php';\n"
            (cls.root/'wp-config.php').write_text(config);(cls.root/'wp-config.php').chmod(0o640)
            os.chown(cls.root/'wp-config.php',user.pw_uid,user.pw_gid)
            cls.front,cls.backend=port(),port()
            cls.host='enum.example.test:'+str(cls.front)
            cls.wp('core','install','--url=http://'+cls.host,'--title=Enumeration test','--admin_user=enum_admin',
                   '--admin_password='+secrets.token_urlsafe(30),'--admin_email=enum@example.test','--skip-email')
            cls.installed=True
            cls.wp('option','update','permalink_structure','/%postname%/')
            cls.wp('post','create','--post_title=Public fixture','--post_status=publish','--porcelain')
            # No outbound mail is sent by reset-form checks.
            (cls.root/'wp-content/mu-plugins/no-mail.php').write_text("<?php add_filter('pre_wp_mail', '__return_true');")
            cls.auth=json.loads(cls.wp('eval',"$u=get_user_by('login','enum_admin');$e=time()+3600;"
                "$t=WP_Session_Tokens::get_instance($u->ID)->create($e);"
                "$c=wp_generate_auth_cookie($u->ID,$e,'logged_in',$t);$_COOKIE[LOGGED_IN_COOKIE]=$c;"
                "wp_set_current_user($u->ID);echo json_encode(['cookie'=>LOGGED_IN_COOKIE.'='.$c,'nonce'=>wp_create_nonce('wp_rest')]);"))
            cls.application_password=cls.wp('user','application-password','create','enum_admin','enum-lab','--porcelain')
            policy=copy.deepcopy(DEFAULT);policy['mode']='enforce';policy['enumeration'].update(enabled=True)
            cls.site=dict(owner=OWNER,domain='enum.example.test',key=OWNER+'/enum.example.test',supported=True,
                          roots={'fixture':str(cls.root)},enumeration_ready=True)
            _,cls.manifest,changes=enumeration.prepare(policy,[cls.site],{},site_mode)
            enumeration.apply(changes)
            router=cls.root/'router.php'
            router.write_text("<?php $p=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);if($p!=='/' && is_file(__DIR__.$p)){return false;}require __DIR__.'/index.php';")
            backend=subprocess.Popen(['/usr/sbin/runuser','-u',OWNER,'--',PHP,'-S','127.0.0.1:'+str(cls.backend),'-t',str(cls.root),str(router)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            cls.processes.append(backend)
            text='worker_processes 1;\npid logs/nginx.pid;\nerror_log logs/error.log notice;\nevents{worker_connections 64;}\nhttp{\n'
            text+=global_config(policy,[cls.site])
            text+='server{listen 127.0.0.1:'+str(cls.front)+';server_name enum.example.test;\n'
            text+=site_config(policy,cls.site,str(cls.root)).replace('/var/log/webuzo-de-noise/matches.log',str(cls.root/'matches.log'))
            text+='location /{proxy_set_header Host $http_host;proxy_pass http://127.0.0.1:'+str(cls.backend)+';}\n}\n}'
            (cls.root/'nginx.conf').write_text(text)
            cls.nginx=[NGINX,'-p',str(cls.root)+'/', '-c','nginx.conf']
            result=subprocess.run([*cls.nginx,'-t'],capture_output=True,text=True)
            if result.returncode:raise AssertionError(result.stderr)
            frontend=subprocess.Popen([*cls.nginx,'-g','daemon off;'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            cls.processes.append(frontend)
            for current in (cls.front,cls.backend):
                deadline=time.monotonic()+5
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1',current),timeout=.2):break
                    except OSError:
                        if time.monotonic()>deadline:raise AssertionError('Fixture did not start')
                        time.sleep(.05)
        except Exception:
            cls.tearDownClass();raise

    @classmethod
    def tearDownClass(cls):
        for process in reversed(cls.processes):
            process.terminate()
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        if cls.installed:
            assert re.fullmatch('hdn_enum_[0-9a-f]{12}_',cls.prefix)
            # Only tables with this exact random fixture prefix can be dropped.
            cls.wp('eval',"global $wpdb;foreach($wpdb->get_col('SHOW TABLES') as $t){"
                "if(str_starts_with($t,'"+cls.prefix+"') && preg_match('/^[a-z0-9_]+$/',$t)){$wpdb->query('DROP TABLE `'.$t.'`');}}")
        cls.temp.cleanup()

    def request(self,path,headers=None,method='GET',body=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.front,timeout=15)
        connection.request(method,path,body=body,headers={'Host':self.host,**(headers or {})})
        response=connection.getresponse();data=response.read();status=response.status;values=dict(response.getheaders());connection.close()
        return status,data,values

    def test_anonymous_and_forged_credentials_cannot_list_users(self):
        for path in ['/wp-json/wp/v2/users','/?rest_route=/wp/v2/users','/wp-json/wp/v2/users/1']:
            for headers in [{},{'Cookie':'wordpress_logged_in_fake=bogus'},{'Authorization':'Bearer invented'}]:
                with self.subTest(path=path,headers=list(headers)):
                    status,body,_=self.request(path,headers)
                    self.assertEqual(status,403,body[:500]);self.assertNotIn(b'enum_admin',body)

    def test_real_cookie_nonce_and_application_password_keep_user_api_working(self):
        import base64
        for headers in [dict(Cookie=self.auth['cookie'],**{'X-WP-Nonce':self.auth['nonce']}),
                        {'Authorization':'Basic '+base64.b64encode(('enum_admin:'+self.application_password).encode()).decode()}]:
            status,body,values=self.request('/wp-json/wp/v2/users',headers)
            self.assertEqual(status,200,body[:500]);self.assertIn(b'enum_admin',body)
            self.assertIn('no-store',values.get('Cache-Control',''))

    def test_editor_rest_post_creation_and_public_posts_still_work(self):
        headers={'Cookie':self.auth['cookie'],'X-WP-Nonce':self.auth['nonce'],'Content-Type':'application/json'}
        status,body,_=self.request('/wp-json/wp/v2/posts',headers,'POST',json.dumps({'title':'Editor draft','status':'draft'}))
        self.assertEqual(status,201,body[:500])
        status,body,_=self.request('/wp-json/wp/v2/posts')
        self.assertEqual(status,200,body[:500])

    def test_author_enumeration_forged_cookie_and_reset_form(self):
        for path in ['/?author=1','/index.php?author=1']:
            for headers in [{},{'Cookie':'wordpress_logged_in_fake=bogus'}]:
                status,body,_=self.request(path,headers)
                self.assertEqual(status,403,body[:500]);self.assertNotIn(b'/author/enum_admin',body)
        status,body,_=self.request('/wp-login.php?action=lostpassword')
        self.assertEqual(status,200,body[:500]);self.assertIn(b'user_login',body)
        status,body,values=self.request('/wp-login.php?action=lostpassword',{'Content-Type':'application/x-www-form-urlencoded'},
                                        'POST','user_login=enum_admin&wp-submit=Get+New+Password')
        self.assertIn(status,(302,303),body[:500]);self.assertIn('checkemail=confirm',values.get('Location',''))

    def test_guard_removal_restores_the_previous_public_behavior(self):
        # Restore the companion in a finally block for later tests.
        previous=enumeration.helper(OWNER,str(self.root),'inspect')['body']
        try:
            enumeration.helper(OWNER,str(self.root),'replace',expected=previous,body=None)
            # Pass the native credential gate; without the companion WP exposes
            # the same public author data again, proving which layer rejects it.
            status,body,_=self.request('/wp-json/wp/v2/users',{'Cookie':'wordpress_logged_in_fake=bogus'})
            self.assertEqual(status,200,body[:500]);self.assertIn(b'enum_admin',body)
        finally:
            enumeration.helper(OWNER,str(self.root),'replace',expected=None,body=previous)

    def test_optional_archive_control_and_shared_root_hostname_scope(self):
        before=enumeration.helper(OWNER,str(self.root),'inspect')['body']
        status,body,_=self.request('/author/enum_admin/')
        self.assertEqual(status,200,body[:500])
        settings={**enumeration.SETTINGS,'author_archives':True}
        after=enumeration.payload(settings,['enum.example.test'])
        try:
            enumeration.helper(OWNER,str(self.root),'replace',expected=before,body=after)
            status,body,_=self.request('/author/enum_admin/',{'Cookie':'wordpress_logged_in_fake=bogus'})
            self.assertEqual(status,403,body[:500])
            connection=http.client.HTTPConnection('127.0.0.1',self.backend,timeout=15)
            connection.request('GET','/wp-json/wp/v2/users',headers={'Host':'unselected.example.test'})
            response=connection.getresponse();body=response.read();connection.close()
            self.assertEqual(response.status,200,body[:500]);self.assertIn(b'enum_admin',body)
        finally:
            enumeration.helper(OWNER,str(self.root),'replace',expected=after,body=before)

    def test_website_helper_refuses_unmanaged_files_links_and_custom_content(self):
        import pwd
        user=pwd.getpwnam(OWNER)
        with tempfile.TemporaryDirectory(prefix='helper-',dir=self.root) as temp:
            root=Path(temp);os.chown(root,user.pw_uid,user.pw_gid);root.chmod(0o755)
            for name in ('wp-includes','wp-content','wp-content/mu-plugins'):
                p=root/name;p.mkdir();os.chown(p,user.pw_uid,user.pw_gid)
            (root/'wp-load.php').touch();(root/'wp-includes/version.php').touch();(root/'wp-config.php').write_text('<?php')
            plugin=root/'wp-content/mu-plugins'/enumeration.PLUGIN
            plugin.write_text('unmanaged')
            with self.assertRaisesRegex(ValueError,'unmanaged'):enumeration.helper(OWNER,str(root),'inspect')
            self.assertEqual(plugin.read_text(),'unmanaged');plugin.unlink()
            target=root/'keep.txt';target.write_text('keep');plugin.symlink_to(target)
            with self.assertRaises(ValueError):enumeration.helper(OWNER,str(root),'inspect')
            self.assertEqual(target.read_text(),'keep');plugin.unlink()
            (root/'wp-config.php').write_text("<?php define('WP_CONTENT_DIR','/custom');")
            with self.assertRaisesRegex(ValueError,'Custom WordPress'):enumeration.helper(OWNER,str(root),'inspect')
            (root/'wp-config.php').write_text('<?php')
            body=enumeration.payload(enumeration.SETTINGS,['enum.example.test'])
            enumeration.helper(OWNER,str(root),'replace',expected=None,body=body)
            with self.assertRaisesRegex(ValueError,'changed during'):enumeration.helper(OWNER,str(root),'replace',expected=None,body=None)
            self.assertEqual(plugin.read_text(),body)
        with self.assertRaisesRegex(ValueError,'within the website owner home'):
            enumeration.helper(OWNER,'/tmp','inspect')
