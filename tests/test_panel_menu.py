"""Native end-user themes need a session-relative index URL, not globals.ind."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'Native PHP CLI')
class MenuTests(unittest.TestCase):
    def test_admin_and_account_links_work_with_empty_native_index_global(self):
        code = '''define('SOFTACULOUS', true);
function register_activation_hook(...$args) {}
function register_deactivation_hook(...$args) {}
function add_filter(...$args) {}
function admin_act(...$args) {}
function enduser_act(...$args) {}
$globals = ['ind' => ''];
require $argv[1];
echo json_encode([wdn_admin_menu([]), wdn_user_menu([])]);'''
        result = subprocess.run(['php', '-r', code, str(ROOT/'webuzo-de-noise.php')],
                                capture_output=True, text=True, check=True)
        admin, account = json.loads(result.stdout)
        for href in (admin['webuzo-de-noise']['href'], account['security']['icons']['webuzo-de-noise']['href']):
            for port in (2003, 2005):
                base = 'https://panel.example.test:' + str(port) + '/sessFixture/'
                self.assertEqual(urljoin(base, href), base + 'index.php?act=webuzo-de-noise')
