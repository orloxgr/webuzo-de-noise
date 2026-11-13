#!/usr/bin/python3
"""Socket-activated local challenge renderer. Never executes application code."""
import json
import os
from pathlib import Path
import re
import socket
import socketserver
from http.server import BaseHTTPRequestHandler
import time
import sys
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import captcha

CONFIG = Path('/etc/webuzo-de-noise/access/captcha-sites.conf')


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def log_message(self, *args):
        pass  # Never record answers, challenge tokens, reset URLs or app cookies.

    def reply(self, code, body=b'', extra=()):
        self.send_response(code)
        fields = [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'private, no-store'),
                  ('Content-Length', str(len(body))), ('X-Robots-Tag', 'noindex, nofollow'),
                  ('Referrer-Policy', 'strict-origin'), ('X-Content-Type-Options', 'nosniff'),
                  ('Content-Security-Policy', "default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")]
        for key, value in [*fields, *extra]: self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)

    def profile(self):
        info = CONFIG.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or CONFIG.is_symlink():
            raise ValueError('Untrusted service configuration')
        entries = json.loads(CONFIG.read_text().partition('\n')[2])['sites']
        scope = self.headers.get('X-HDN-Site', '')
        entry = entries[scope]
        host = self.headers.get('X-HDN-Host', '').lower()
        scheme = self.headers.get('X-HDN-Scheme', '')
        if scheme not in ('http', 'https') or not re.fullmatch(r'[a-z0-9.-]+', host):
            raise ValueError('Invalid origin')
        if not any(host == name or name.startswith('*.') and host.endswith(name[1:]) and host != name[2:] for name in entry['hosts']):
            raise ValueError('Foreign host')
        return scope, entry, host, scheme

    def serve(self):
        try:
            scope, entry, host, scheme = self.profile()
            challenges = self.server.challenges
            rev = entry['revision']
            language = self.headers.get('Accept-Language', 'en')
            if self.headers.get('X-HDN-Action') == 'challenge' and self.command in ('GET', 'HEAD'):
                target = captcha.safe_target(self.headers.get('X-HDN-Target', '/'))
                token, data = challenges.create(scope, host, scheme, rev, target)
                submitted = self.headers.get('X-HDN-Method') not in ('GET', 'HEAD')
                return self.reply(200, captcha.page(challenges, token, data, language=language, submitted=submitted).encode())
            if self.command != 'POST' or urlsplit(self.path).path != captcha.PREFIX + 'verify':
                return self.reply(404, b'Not found')
            origin = self.headers.get('Origin')
            if origin:
                parsed = urlsplit(origin)
                if parsed.scheme != scheme or parsed.hostname != host or parsed.port not in (None, 443 if scheme == 'https' else 80):
                    raise ValueError('Foreign origin')
            if self.headers.get('Sec-Fetch-Site') in ('cross-site', 'same-site'):
                raise ValueError('Foreign form submission')
            fields = parse_qs(self.rfile.read(int(self.headers.get('Content-Length', '0'))).decode(), keep_blank_values=True)
            token = fields.get('challenge', [''])[0]
            answer = fields.get('answer', [''])[0]
            refresh = fields.get('refresh', [''])[0] == '1'
            valid, previous = challenges.consume(token, scope, host, scheme, rev, answer, refresh)
            if valid:
                expires = int(time.time()) + entry['seconds']
                value = captcha.clearance(challenges.secret, scope, rev, host, scheme, expires)
                attributes = '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + str(entry['seconds']) + ('; Secure' if scheme == 'https' else '')
                return self.reply(200, captcha.verified_page(previous['target'], language=language).encode(),
                                  extra=[('Set-Cookie', captcha.cookie(scope) + '=' + value + attributes),
                                         ('X-HDN-Captcha-Result', 'verified')])
            token, data = challenges.create(scope, host, scheme, rev, previous['target'])
            return self.reply(200, captcha.page(challenges, token, data, language=language, error=not refresh).encode())
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            self.reply(400, b'This check is no longer valid. Return to the original page and try again.')

    do_GET = serve
    do_HEAD = serve
    do_POST = serve


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
    secret = (credentials / 'signing-key').read_bytes()
    if len(secret) != 32: raise ValueError('Invalid signing key')
    if int(os.environ.get('LISTEN_PID', '0')) != os.getpid() or os.environ.get('LISTEN_FDS') != '1':
        raise RuntimeError('Start this service through its managed systemd socket')
    server = Server('/unused', Handler, bind_and_activate=False)
    server.socket.close()
    server.socket = socket.socket(fileno=3)
    server.server_address = server.socket.getsockname()
    server.challenges = captcha.Challenges(secret, Path(os.environ['STATE_DIRECTORY']) / 'challenges.sqlite')
    server.serve_forever()


if __name__ == '__main__': main()
