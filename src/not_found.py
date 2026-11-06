"""Incremental final-404 counters from native Webuzo Nginx access logs.

Nginx serves static files and Apache serves origin responses into the same native
combined log. Local Nginx rejections that inherit server logging have a separate
metadata-only event, because they never reach either native logging location.
"""
import datetime
import os
from pathlib import Path
import re
import stat
import storage
import log_files
import ban_evidence
from urllib.parse import unquote

LOG_ROOT = Path('/usr/local/apps/nginx/var/log')
LINE = re.compile(rb'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ((?:[^"\\\s]|\\.)+) [^"\r\n]+" 404 (?:[0-9]+|-) ')

ASSETS = re.compile(r'\.(?:avif|webp|jpe?g|png|gif|svgz?|ico|bmp|tiff?|apng|jxl|heic|heif|css|m?js|map|woff2?|ttf|otf|eot|mp[34]|webm|ogg|wav|pdf)$', re.I)


def normal_path(path):
    return unquote(ban_evidence.path_only(path))


def countable(rule, path):
    # Legacy records without a URL cannot prove that an asset was excluded.
    path = normal_path(path)
    return bool(path) and not (rule['exclude_static'] and ASSETS.search(path))


def events(db, sites, namespace):
    if namespace not in ('native', 'domain'):
        raise ValueError('Invalid native access-log cursor namespace')
    db.execute('CREATE TABLE IF NOT EXISTS access_cursors (namespace TEXT, domain TEXT, device INTEGER, inode INTEGER, offset INTEGER, PRIMARY KEY(namespace,domain,device,inode))')
    names = sorted({site['domain'] for site in sites})
    if not names:
        return
    row = db.execute('SELECT value FROM meta WHERE key=?', ('404-next:'+namespace,)).fetchone()
    first = int(row[0]) % len(names) if row else 0
    names = names[first:] + names[:first]
    for index, domain in enumerate(names):
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', domain):
            raise ValueError('Invalid native access-log domain')
        for path in log_files.rotations(LOG_ROOT / (domain + '.log')):
            try:
                context = log_files.opened(path)
                stream, raw_stream = context.__enter__()
            except FileNotFoundError:
                continue
            try:
                info = os.fstat(raw_stream.fileno())
                cursor = db.execute('SELECT offset FROM access_cursors WHERE namespace=? AND domain=? AND device=? AND inode=?',
                                    (namespace, domain, info.st_dev, info.st_ino)).fetchone()
                offset = cursor[0] if cursor and (log_files.compressed(path) or cursor[0] <= info.st_size) else 0
                stream.seek(offset)
                end = offset
                for raw in stream:
                    if not log_files.compressed(path) and end + len(raw) > info.st_size:
                        break  # Appended data remains for the next cursor pass.
                    if not raw.endswith(b'\n'):
                        break
                    end += len(raw)
                    match = LINE.match(raw)
                    if not match:
                        continue
                    ip, date, method, target = match.groups()
                    try:
                        stamp = datetime.datetime.strptime(date.decode('ascii'), '%d/%b/%Y:%H:%M:%S %z').timestamp()
                        yield (str(stamp), ip.decode('ascii'), domain, 'not-found', '-',
                               ban_evidence.path_only(target.decode('utf-8', errors='replace')),
                               ban_evidence.method_only(method.decode('ascii')))
                    except (ValueError, UnicodeError):
                        continue
                db.execute('INSERT OR REPLACE INTO access_cursors VALUES (?,?,?,?,?)',
                            (namespace,domain,info.st_dev,info.st_ino,end))
            finally:
                context.__exit__(None, None, None)
        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('404-next:'+namespace,str((first+index+1) % len(names))))
