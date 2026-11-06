import configparser
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import wordpress


@unittest.skipUnless(importlib.util.find_spec('fail2ban'), 'Native Fail2ban evaluator')
class Fail2banDurations(unittest.TestCase):
    @unittest.skipUnless(shutil.which('fail2ban-regex'), 'Native Fail2ban regex command')
    def test_authentication_filter_handles_current_host_tags_and_older_plain_tags(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rendered = wordpress.render(wordpress.DEFAULT, root, source='backend = auto\nlogpath = /var/log/auth.log tail\n')
            source = next(body for path, body in rendered.items() if path.name == 'wdn-wordpress-login.conf')
            config = root / 'wordpress.conf'
            config.write_bytes(source.replace(b'before = common.conf', b'before = /etc/fail2ban/filter.d/common.conf'))
            lines = [
                'Nov  6 12:00:00 host wordpress(example.test)[123]: Authentication attempt for unknown user unknown from 198.51.100.1',
                'Nov  6 12:00:01 host wordpress[124]: Authentication failure for user from 198.51.100.2',
                'Nov  6 12:00:02 host wp(example.test/blog)[125]: REST authentication failure for user from 2001:db8::1',
                'Nov  6 12:00:03 host sshd[126]: Authentication failure for user from 198.51.100.3',
                'Nov  6 12:00:04 host wordpress[127]: Authentication failure for user from 198.51.100.4 trailing-text',
            ]
            log = root / 'auth.log'; log.write_text('\n'.join(lines) + '\n')
            result = subprocess.run(['fail2ban-regex', str(log), str(config)], capture_output=True, text=True, check=True)
            self.assertIn('5 lines, 0 ignored, 3 matched, 2 missed', result.stdout)

    def test_non_whitelisted_first_duration_reaches_exact_sqlite_permanent_sentinel(self):
        from fail2ban.server.jail import Jail
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            rendered=wordpress.render({**wordpress.DEFAULT,'durations':[4020,259200,-1]},Path(folder))
            text=next(value.decode() for path,value in rendered.items() if path.name=='webuzo-denoise-wordpress.local')
            parser=configparser.ConfigParser(interpolation=None);parser.read_string(text)
            values=parser[wordpress.JAIL]
            jail=Jail('hdn-proof',backend='polling')
            jail.setBanTimeExtra('factor',values['bantime.factor'])
            jail.setBanTimeExtra('multipliers',values['bantime.multipliers'])
            evaluate=jail.getBanTimeExtra()['evformula']
            db=sqlite3.connect(':memory:');self.addCleanup(db.close)
            db.execute('CREATE TABLE proof (bantime INTEGER)')
            expected=[4020,259200,-1,-1]
            for count,target in enumerate(expected):
                duration=evaluate(SimpleNamespace(Time=4020,Count=count))
                self.assertIs(type(duration),int)
                self.assertEqual(duration,target)
                db.execute('INSERT INTO proof VALUES (?)',(duration,))
            self.assertEqual([row[0] for row in db.execute('SELECT * FROM proof')],expected)
