"""Small local math challenge. No WordPress, third-party service or image package."""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import struct
import time
from urllib.parse import unquote
import zlib

PREFIX = '/__hdn-captcha/'
DEFAULT_SECONDS = 21600
CHALLENGE_SECONDS = 600
FONT = {
    '0': ['01110','10001','10011','10101','11001','10001','01110'],
    '1': ['00100','01100','00100','00100','00100','00100','01110'],
    '2': ['01110','10001','00001','00010','00100','01000','11111'],
    '3': ['11110','00001','00001','01110','00001','00001','11110'],
    '4': ['00010','00110','01010','10010','11111','00010','00010'],
    '5': ['11111','10000','10000','11110','00001','00001','11110'],
    '6': ['01110','10000','10000','11110','10001','10001','01110'],
    '7': ['11111','00001','00010','00100','01000','01000','01000'],
    '8': ['01110','10001','10001','01110','10001','10001','01110'],
    '9': ['01110','10001','10001','01111','00001','00001','01110'],
    '+': ['00000','00100','00100','11111','00100','00100','00000'],
    '=': ['00000','00000','11111','00000','11111','00000','00000'],
    '?': ['01110','10001','00001','00010','00100','00000','00100'],
}


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def scope_key(secret, scope, revision):
    return hmac.digest(secret, ('clearance|' + scope + '|' + revision).encode(), 'sha256').hex()


def revision(entry):
    return hashlib.sha256(str(entry.get('captcha_seconds', DEFAULT_SECONDS)).encode()).hexdigest()[:16]


def cookie(scope):
    return 'hdn_captcha_' + scope


def clearance(secret, scope, revision_value, host, scheme, expires):
    # This is the native Nginx secure_link format, using a per-site derived key.
    material = str(expires) + '|' + host + '|' + scheme + '|' + scope_key(secret, scope, revision_value)
    return b64(hashlib.md5(material.encode(), usedforsecurity=False).digest()) + '.' + str(expires)


def safe_target(value):
    if not isinstance(value, str) or not value.startswith('/'):
        raise ValueError('Invalid return address')
    decoded = unquote(value)
    if decoded.startswith('//') or '\\' in decoded or any(ord(c) < 32 or ord(c) == 127 for c in decoded):
        raise ValueError('Invalid return address')
    return value


def picture(left, right):
    text = str(left) + '+' + str(right) + '=?'
    scale, width, height = 6, 300, 76
    pixels = bytearray([245, 248, 253] * width * height)
    offset = (width - (len(text) * 6 - 1) * scale) // 2
    for index, char in enumerate(text):
        for y, row in enumerate(FONT[char]):
            for x, mark in enumerate(row):
                if mark == '1':
                    for dy in range(scale):
                        for dx in range(scale):
                            start = ((17 + y * scale + dy) * width + offset + index * 6 * scale + x * scale + dx) * 3
                            pixels[start:start + 3] = bytes((40, 62, 100))
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
    raw = b''.join(b'\0' + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', width, height, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')


class Challenges:
    def __init__(self, secret, database):
        self.secret, self.database = secret, str(database)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS challenges (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS challenge_expiry ON challenges(expires)')

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.database)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def numbers(self, nonce):
        values = hmac.digest(self.secret, ('question|' + nonce).encode(), 'sha256')
        return values[0] % 9 + 1, values[1] % 9 + 1

    def decode(self, token, scope, host, scheme, rev):
        if not isinstance(token, str) or token.count('.') != 1:
            raise ValueError('Invalid challenge')
        body, signature = token.split('.')
        expected = b64(hmac.digest(self.secret, body.encode(), 'sha256'))
        if not hmac.compare_digest(signature, expected):
            raise ValueError('Invalid challenge')
        data = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
        if any(data[k] != v for k, v in dict(scope=scope, host=host, scheme=scheme, revision=rev).items()):
            raise ValueError('Challenge belongs to another website')
        safe_target(data['target'])
        return data

    def create(self, scope, host, scheme, rev, target):
        data = dict(nonce=secrets.token_urlsafe(24), expires=int(time.time()) + CHALLENGE_SECONDS,
                    scope=scope, host=host, scheme=scheme, revision=rev, target=safe_target(target))
        body = b64(json.dumps(data, separators=(',', ':')).encode())
        with self.connect() as db:
            db.execute('DELETE FROM challenges WHERE expires < ?', (int(time.time()),))
            db.execute('INSERT INTO challenges VALUES (?, ?)', (data['nonce'], data['expires']))
        return body + '.' + b64(hmac.digest(self.secret, body.encode(), 'sha256')), data

    def consume(self, token, scope, host, scheme, rev, answer, refresh=False):
        data = self.decode(token, scope, host, scheme, rev)
        with self.connect() as db:
            row = db.execute('DELETE FROM challenges WHERE nonce = ? RETURNING expires', (data['nonce'],)).fetchone()
        if not row or row[0] < int(time.time()):
            return False, data
        expected = str(sum(self.numbers(data['nonce'])))
        return not refresh and hmac.compare_digest(str(answer).strip(), expected), data


def verified_page(target, *, language='en'):
    target = html.escape(safe_target(target), quote=True)
    el = language.lower().startswith('el')
    title, message, link = ('Ο έλεγχος ολοκληρώθηκε', 'Σε μεταφέρουμε στη σελίδα σου.', 'Συνέχεια') if el else (
        'Check complete', 'Taking you back to your page.', 'Continue')
    # Commit a new document before navigating to the app. A POST redirect keeps
    # the original form-action policy across the app's later canonical/SSO
    # redirects, which Chromium can block even after successful verification.
    return f'''<!doctype html><html lang="{'el' if el else 'en'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0;url={target}"><title>{title}</title>
<style>*{{box-sizing:border-box}}body{{margin:0;min-height:100svh;display:grid;place-items:center;padding:24px;background:#f3f6fb;color:#20314c;font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}main{{width:100%;max-width:420px;padding:36px;border:1px solid #e2e9f3;border-radius:22px;background:#fff;box-shadow:0 18px 60px #263d6110}}h1{{font-size:25px;line-height:1.25;margin:0 0 12px}}p{{color:#64728a}}a{{color:#3c66d8}}</style></head>
<body><main><h1>✓ {title}</h1><p>{message}</p><a href="{target}">{link} →</a></main></body></html>'''


def page(challenges, token, data, *, language='en', error=False, submitted=False):
    el = language.lower().startswith('el')
    words = ('Ένας γρήγορος έλεγχος', 'Λύσε την απλή πράξη για να συνεχίσεις.', 'Η απάντησή σου', 'Συνέχεια',
             'Άλλη εικόνα', 'Η απάντηση δεν ήταν σωστή ή ο έλεγχος έληξε. Δοκίμασε τη νέα πράξη.',
             'Μετά τον έλεγχο θα χρειαστεί να υποβάλεις ξανά τη φόρμα σου.', 'Απλή αριθμητική πράξη') if el else (
             'A quick check', 'Solve the simple sum to continue.', 'Your answer', 'Continue', 'New image',
             'That answer was incorrect or the check expired. Please try the new sum.',
             'After this check, please submit your original form again.', 'Simple addition challenge')
    title, subtitle, label, button, refresh, incorrect, resubmit, alt = map(html.escape, words)
    # PNG data URLs use standard base64, rather than the URL-safe token alphabet.
    image = base64.b64encode(picture(*challenges.numbers(data['nonce']))).decode()
    notice = ('<p class="notice" role="alert">' + incorrect + '</p>') if error else ''
    if submitted: notice += '<p class="hint">' + resubmit + '</p>'
    return f'''<!doctype html><html lang="{'el' if el else 'en'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>*{{box-sizing:border-box}}body{{margin:0;min-height:100svh;display:grid;place-items:center;padding:24px;background:#f3f6fb;color:#20314c;font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}main{{width:100%;max-width:420px;padding:36px;border:1px solid #e2e9f3;border-radius:22px;background:white;box-shadow:0 18px 60px #263d6110}}.icon{{display:grid;place-items:center;width:48px;height:48px;border-radius:15px;background:#edf3ff;color:#3b66d9;font-size:26px;margin-bottom:22px}}h1{{font-size:25px;line-height:1.25;letter-spacing:-.6px;margin:0 0 10px}}p{{margin:0 0 22px;color:#64728a}}.site{{font-size:13px;overflow-wrap:anywhere;margin-bottom:20px}}img{{display:block;width:100%;height:auto;border:1px solid #e5ebf5;border-radius:12px;margin:0 0 22px}}label{{display:block;font-size:14px;font-weight:600;margin-bottom:8px}}input{{width:100%;padding:13px 16px;border:1px solid #cad5e5;border-radius:10px;color:#20314c;font:inherit;font-size:19px;outline:none}}input:focus{{border-color:#4772e7;box-shadow:0 0 0 3px #4772e71a}}button{{cursor:pointer;font:inherit}}.primary{{width:100%;margin-top:16px;padding:13px;border:0;border-radius:10px;background:#3c66d8;color:white;font-weight:600}}.primary:hover{{background:#3158c2}}.refresh{{display:block;margin:16px auto 0;border:0;background:none;color:#64728a;font-size:14px;padding:6px}}.refresh:hover{{color:#3158c2}}.notice{{color:#a34237;background:#fff3ef;padding:12px;border-radius:10px;font-size:14px}}.hint{{font-size:13px;margin-bottom:16px}}@media(max-width:420px){{main{{padding:26px}}}}</style></head>
<body><main><div class="icon" aria-hidden="true">✓</div><h1>{title}</h1><p>{subtitle}</p><p class="site">{html.escape(data['host'])}</p>{notice}<form method="post" action="{PREFIX}verify"><input type="hidden" name="challenge" value="{html.escape(token, quote=True)}"><img src="data:image/png;base64,{image}" alt="{alt}" width="300" height="76"><label for="answer">{label}</label><input id="answer" name="answer" type="text" inputmode="numeric" pattern="[0-9]+" autocomplete="off" autofocus required><button class="primary" type="submit">{button} →</button><button class="refresh" type="submit" name="refresh" value="1" formnovalidate>↻ {refresh}</button></form></main></body></html>'''
