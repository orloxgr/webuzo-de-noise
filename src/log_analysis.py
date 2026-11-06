"""Operator-triggered, complete streamed log review. Findings never change protection."""
from collections import Counter
from contextlib import contextmanager
import datetime
import gzip
import bz2
import lzma
from contextlib import ExitStack
from analysis_store import Groups
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qsl, unquote, urlsplit

import storage
import agent_catalog
from policy import domain as valid_domain

LOG_ROOTS = (Path('/usr/local/apps/nginx/var/log'),)
GOOGLE_URL = 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json'
GOOGLE_CACHE = 'google-common-crawlers.json'
FETCH = '''import sys
from urllib.request import urlopen
with urlopen(sys.argv[1], timeout=None) as response:
    if response.geturl() != sys.argv[1]: raise ValueError('Unexpected redirect')
    data = response.read()
sys.stdout.buffer.write(data)
'''
COMBINED = re.compile(r'^([^ ]+) \S+ \S+ \[([^\]]+)\] "((?:\\.|[^"\\])*)" (\d{3}) \S+ "(?:\\.|[^"\\])*" "((?:\\.|[^"\\])*)"(.*)$')
ASSET = re.compile(r'\.(?:avif|webp|jpe?g|png|gif|svgz?|ico|bmp|tiff?|apng|jxl|heic|heif|css|m?js|map|woff2?|ttf|otf|eot|mp[34]|webm|ogg|wav|pdf)$', re.I)
IMAGE = re.compile(r'\.(?:avif|webp|jpe?g|png|gif|svgz?|ico|bmp|tiff?|apng|jxl|heic|heif)$', re.I)
SECRET_PATH = re.compile(r'(?:^|/)\.(?:env(?:[./]|$)|git(?:/|$)|svn(?:/|$)|hg(?:/|$))|/(?:etc/(?:passwd|shadow)|proc/self/(?:environ|cmdline)|var/run/secrets/kubernetes.io/serviceaccount)(?:/|$)', re.I)
# These exact cache transport names are not content-filter dimensions. Their
# presence does not authenticate the caller or exempt a request from analysis.
TECHNICAL = {'ver', 'v', 'fbclid', 'gclid', 'msclkid', '_', 'cachebuster', 'rest_route', 'format',
             'ultracache_revalidate', 'ultracache_rt', 'ultracache_rv', 'ultracache_bucket'}
SENSITIVE = {'key', 'token', 'nonce', '_wpnonce', 'password', 'pass', 'email', 'login', 'auth', 'signature',
             'session', 'sessionid', 'sid', 'code', 'state', 'csrf', 'csrf_token', 'access_token',
             'refresh_token', 'api_key', 'api_token', 'action'}
CLAIMS = ('Googlebot', 'bingbot', 'Applebot', 'Baiduspider', 'PetalBot', 'ibou-search',
          'meta-externalagent', 'meta-webindexer', 'facebookexternalhit', 'Twitterbot', 'Slackbot', 'Discordbot',
          'WhatsApp', 'TelegramBot', 'GPTBot', 'ClaudeBot', 'CCBot', 'Amazonbot',
          'Reflectionbot', 'LinkupBot', 'AhrefsBot', 'SemrushBot', 'SERankingBacklinksBot', 'sqlmap', 'Nikto', 'Nuclei')


def selection(sites, target, minutes):
    if type(minutes) is not int or minutes <= 0:
        raise ValueError('Choose a positive time window in minutes')
    known = {site['key']: site for site in sites if site.get('kind', 'web') == 'web'}
    if target != 'all' and (not isinstance(target, str) or target not in known):
        raise ValueError('Select an existing web domain or all web domains')
    chosen = list(known.values()) if target == 'all' else [known[target]]
    for site in chosen:
        valid_domain(site['domain'])
    return sorted(chosen, key=lambda site: site['key'])


@contextmanager
def scan_lock(state):
    import fcntl
    storage.private_directory(state)
    with storage.parent(Path(state) / 'log-analysis.lock') as parent:
        fd = os.open('log-analysis.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Untrusted analysis lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def networks(raw):
    rows = raw.get('prefixes') if isinstance(raw, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError('Invalid published Google ranges')
    result = []
    for row in rows:
        if not isinstance(row, dict) or len(row) != 1 or next(iter(row)) not in ('ipv4Prefix', 'ipv6Prefix'):
            raise ValueError('Invalid published Google range')
        value = ipaddress.ip_network(next(iter(row.values())))
        if value.prefixlen < (8 if value.version == 4 else 16):
            raise ValueError('Unexpectedly broad Google range')
        result.append(value)
    return result


def google_ranges(state, now):
    """Download public CIDRs only; never send visitor addresses or log content."""
    path = Path(state) / GOOGLE_CACHE
    try:
        cached = storage.read(path)
        cached = json.loads(cached) if cached else None
        if cached and 0 <= now - cached['fetched'] < 86400:
            return networks(cached['data']), 'Cached published ranges (less than 24 hours old)'
        # Download only public ranges in an isolated child; no visitor data leaves.
        fetched = subprocess.run([sys.executable, '-I', '-c', FETCH, GOOGLE_URL],
                                 capture_output=True, timeout=None)
        if fetched.returncode:
            raise ValueError('Public Google ranges unavailable')
        raw = fetched.stdout
        data = json.loads(raw)
        result = networks(data)
        storage.replace(path, storage.json_bytes({'fetched': now, 'data': data}), 0o600)
        return result, 'Published ranges downloaded for this review'
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        return [], 'Verification unavailable; all claims remain unverified'


def safe_path(target):
    path = target.split('?', 1)[0].split('#', 1)[0]
    if path.startswith(('http://', 'https://')):
        try:
            path = urlsplit(path).path
        except ValueError:
            return ''
    if not path.startswith('/') or any(ord(char) < 32 or ord(char) == 127 for char in path):
        return ''
    path = re.sub(r'[^/]*@[^/]*', lambda match: '[redacted-' + hashlib.sha256(match.group().encode()).hexdigest() + ']', path)
    path = re.sub(r'(?<=/)[A-Za-z0-9_-]{32,}(?=/|$)', lambda match: '[redacted-' + hashlib.sha256(match.group().encode()).hexdigest() + ']', path)
    return path


def params(target):
    query = target.partition('?')[2]
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return [], None, False
    names = sorted({name.lower() for name, _ in pairs if re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]*', name)})
    features = [name for name in names if name not in TECHNICAL and name not in SENSITIVE and not name.startswith(('utm_', '_wp'))]
    # Values are used only for a one-way digest in the private aggregation.
    # Values never leave this process; tracking tokens must not inflate filter diversity.
    canonical = sorted((name.lower(), value) for name, value in pairs if name.lower() in features)
    digest = hashlib.blake2s(json.dumps(canonical).encode(), digest_size=8).digest() if canonical else None
    decoded = unquote(unquote(query)).replace('\\', '/')
    secret_query = bool(re.search(r'(?:^|&)(?:file|path|include|resource|template|filename|download_file)=(?:(?:\.\./)*|/)(?:etc/(?:passwd|shadow)|proc/self/environ|wp-config\.php)(?:&|$)', decoded, re.I))
    return features, digest, secret_query


def claim(agent):
    low = agent.lower()
    return next((value for value in CLAIMS if value.lower() in low), 'Other / browser-like (unverified)')



def new_group(site, path, names):
    return dict(site=site['key'], domain=site['domain'], path=path, parameters=names,
                count=0, statuses=Counter(), methods=Counter(), agents=Counter(), minutes=Counter(),
                clients=set(), combinations=set(), distinct_capped=False, first=None, last=None,
                secret=False, verified_google=0, unconfirmed_google=0,
                timing_count=0, request_seconds=0, upstream_count=0, upstream_seconds=0, cache=Counter())


def recommendations(group, title):
    """Actionable, domain-scoped guidance. Never an executable protection rule."""
    if group['secret']:
        return [dict(title='Review Private-file protection', detail='Check General and IP bans for this domain, including saved exceptions. Retain the existing protection; this report does not change it.')]
    if title == 'Many combinations of URL parameters':
        return [
            dict(title='Fix crawl space at the site', detail='Keep useful filter landing pages indexable. For disposable combinations, correct generated links and the site canonical/noindex policy. Review robots.txt separately if these URLs should not be crawled.'),
            dict(title='Optional Filtered URLs rule', detail='Use the candidate below only if crawling still needs a limit. Select the crawlers and an acceptable rate after reviewing this domain. Observed crawler names are claims, not verified identities. Leave normal browser traffic out of the rule.')]
    if title == 'Repeated locale-looking URL segment':
        return [dict(title='Correct language links', detail='Check the language switcher, translated menus, sitemap and canonical URLs. Remove the duplicate language segment at its source. If a redirect is needed, verify its destination and apply it only on this domain.')]
    if title == 'Repeated missing static asset':
        return [dict(title='Repair the referenced asset', detail='Restore the missing script, stylesheet, font or document, or correct its generated URL and stale HTML references. Do not add the visitors to an IP-ban rule.')]
    if title == 'Repeated server-error responses':
        return [dict(title='Inspect application errors', detail='Check this domain\'s Apache/PHP error logs at the recorded times. Diagnose the failing plugin, application or upstream before changing timeouts or traffic rules.')]
    if title == 'Recorded slow request timings':
        return [dict(title='Measure the origin work', detail='Compare recorded upstream timings, cache state, PHP workers and slow database queries for this route. Optimize the responsible site component before choosing a crawler limit.')]
    if title == 'Repeated PHP-path 404 responses':
        return [dict(title='Review the missing-PHP list', detail='Check whether the route belongs to the application. Only after confirming it is an unwanted probe, consider adding the literal path in IP bans β†’ selected missing PHP files, scoped to this domain. Keep legitimate virtual routes out.')]
    return [dict(title='Inspect the route before filtering', detail='Identify the responsible plugin, visitors and integrations on this domain. Preserve functional REST, AJAX and cart requests. Frequency alone does not justify a block.')]


def findings(groups, persist=False):
    result = []
    for group in groups.values():
        count, path = group['count'], group['path']
        missing = group['statuses'].get('404', 0)
        asset = bool(ASSET.search(path))
        if IMAGE.search(unquote(unquote(path))) and not group['secret']:
            continue
        kind = title = advice = None
        if group['secret']:
            kind, title = 'security', 'Known secret-file probe signature'
            advice = 'Review existing secret/repository protection and exceptions. A signature is evidence of a probe, not proof that data was read. This review never bans an IP.'
        elif asset and missing >= 5:
            kind, title = 'site', 'Repeated missing static asset'
            advice = 'Check the referenced file, generated assets and cached HTML. Missing images/scripts can affect real visitors; do not infer an abusive client from these 404s.'
        elif re.search(r'^/([a-z]{2}(?:-[a-z]{2})?)/\1(?:/|$)', path, re.I) and count >= 5:
            kind, title = 'site', 'Repeated locale-looking URL segment'
            advice = 'Check internal links and the intended locale structure. A repeated segment may be intentional. Correct the source links before considering a domain-specific redirect; do not add a global rewrite.'
        elif sum(number for code, number in group['statuses'].items() if code.startswith('5')) >= 3:
            kind, title = 'site', 'Repeated server-error responses'
            advice = 'Inspect origin/application errors and timeouts. Server errors alone do not establish malicious traffic; avoid treating broken site behavior as an IP-ban trigger.'
        elif group['timing_count'] >= 5 and group['request_seconds'] / group['timing_count'] >= 1:
            kind, title = 'investigate', 'Recorded slow request timings'
            advice = 'Inspect application and upstream work. Request time includes the whole request and is not a direct measurement of PHP CPU cost; compare upstream timing when recorded.'
        elif group['parameters'] and len(group['combinations']) >= 20 and count >= 30 and not asset and not re.search(r'/(?:wp-admin|wp-json|wp-login\.php)(?:/|$)', path):
            kind, title = 'crawl', 'Many combinations of URL parameters'
            advice = 'These may be valid pages. Review filter links, useful indexable landing pages and query cost. Consider robots.txt only for combinations that should not be crawled. Do not create 404s or bans from frequency alone.'
        elif path.lower().endswith('.php') and missing >= 5:
            kind, title = 'investigate', 'Repeated PHP-path 404 responses'
            advice = 'Check application routing and whether these paths should exist. A virtual PHP route may be legitimate without a physical file. Several 404s alone do not prove a malicious client.'
        elif count >= 50 and (path.startswith('/wp-json/') or path == '/wp-admin/admin-ajax.php' or 'wc-ajax' in group['parameters']):
            kind, title = 'investigate', 'Busy application endpoint'
            advice = 'Inspect the responsible plugin or application work. REST/AJAX and cart calls can be essential to the frontend; do not block the whole endpoint.'
        elif count >= 100 and max(group['minutes'].values(), default=0) >= 40:
            kind, title = 'investigate', 'High activity on one route'
            advice = 'Check normal visitors, integrations and crawl activity before choosing any limit. Volume, browser-like names and HTTP 200 do not establish legitimacy or abuse.'
        if not kind:
            continue
        suggestion = ({key: group[key] for key in ('site', 'domain', 'path', 'parameters', 'count', 'first', 'last', 'verified_google', 'unconfirmed_google')} |
                      dict(kind=kind, title=title, advice=advice, statuses=dict(group['statuses']), methods=dict(group['methods']),
                           agents=dict(group['agents']), peak_per_minute=max(group['minutes'].values(), default=0),
                           clients=len(group['clients']), combinations=len(group['combinations']), distinct_capped=group['distinct_capped'],
                           request_time_samples=group['timing_count'],
                           mean_request_ms=round(group['request_seconds'] / group['timing_count'] * 1000, 2) if group['timing_count'] else None,
                           upstream_time_samples=group['upstream_count'],
                           mean_upstream_ms=round(group['upstream_seconds'] / group['upstream_count'] * 1000, 2) if group['upstream_count'] else None,
                           cache=dict(group['cache']), recommendations=recommendations(group, title)))
        if title == 'Many combinations of URL parameters':
            suggestion['filter_candidate'] = dict(target=group['site'], domain=group['domain'],
                path=path, parameters=group['parameters'],
                observed_crawlers=[name for name in group['agents'] if name != 'Other / browser-like (unverified)'])
        if persist:
            groups.suggest(suggestion)
        else:
            result.append(suggestion)
    order = {'security': 0, 'site': 1, 'crawl': 2, 'investigate': 3}
    return sorted(result, key=lambda row: (order[row['kind']], -row['count'], row['site'], row['path']))


def native_log_paths(site, root):
    for name in site.get('log_domains', [site['domain']]):
        valid_domain(name)
        candidates = [root / (name + '.log')] + sorted(root.glob(name + '.log.[0-9]*'))
        for path in candidates:
            if re.fullmatch(re.escape(name) + r'[.]log(?:[.][0-9]+(?:[.](?:gz|bz2|xz))?)?', path.name):
                yield path


def scan(sites, target, minutes, state=None, verify_google=False, now=None, progress=None, cancelled=None, report_path=None, inventory_kind=None):
    if inventory_kind not in (None, 'agents', 'php_files'):
        raise ValueError('Invalid traffic inventory')
    chosen = selection(sites, target, minutes)
    if type(verify_google) is not bool:
        raise ValueError('Invalid Google verification switch')
    now = time.time() if now is None else now
    started = time.monotonic(); cutoff = now - minutes * 60
    ranges, verification = (google_ranges(state, now) if verify_google else ([], 'Not requested; crawler names are unverified claims'))
    if inventory_kind:
        from traffic_inventory import Inventory
        groups = Inventory(inventory_kind, report_path)
    else:
        groups = Groups(report_path)
    seen, coverage, files = set(), [], []
    totals = Counter(image_records_excluded=0); errors = []; bytes_read = 0; group_dropped = False
    salt = os.urandom(16); date_cache = {}
    try:
        for site in chosen:
            for root in LOG_ROOTS:
                for path in native_log_paths(site, root):
                    try:
                        info = path.lstat()
                    except FileNotFoundError:
                        continue
                    except OSError:
                        errors.append(dict(domain=site['domain'], file=path.name, message='Log metadata unavailable'))
                        continue
                    if info.st_size:
                        files.append((site, path, info))
        for index, (site, path, info) in enumerate(files):
            if cancelled and cancelled():
                raise InterruptedError('Review cancelled by administrator')
            try:
                stack = ExitStack()
                stream = stack.enter_context(storage.log_stream(path))
                info = os.fstat(stream.fileno())
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    stack.close()
                    continue
                seen.add(identity)
                # Snapshot each open file's end. Appended traffic belongs to the next
                # review; no pre-existing record is skipped or tailed away.
                snapshot_size = info.st_size
                if path.suffix == '.gz': stream = stack.enter_context(gzip.GzipFile(fileobj=stream))
                elif path.suffix == '.bz2': stream = stack.enter_context(bz2.BZ2File(stream))
                elif path.suffix == '.xz': stream = stack.enter_context(lzma.LZMAFile(stream))
            except (OSError, ValueError):
                stack.close()
                errors.append(dict(domain=site['domain'], file=path.name, message='Log unavailable or refused by trusted-file checks'))
                continue
            oldest = latest = None; records = 0; interrupted = False
            try:
                for raw in stream:
                    if cancelled and cancelled():
                        raise InterruptedError('Review cancelled by administrator')
                    if path.suffix not in ('.gz', '.bz2', '.xz') and stream.tell() > snapshot_size:
                        break
                    bytes_read += len(raw)
                    if progress: progress(dict(records=totals['requests'], bytes=bytes_read, files_done=index, files_total=len(files), domain=site['domain']))
                    if not raw.endswith(b'\n'):
                        totals['incomplete_lines'] += 1
                        break
                    match = COMBINED.fullmatch(raw.decode('utf-8', errors='replace').rstrip('\r\n'))
                    if not match:
                        totals['unparsed'] += 1
                        continue
                    address, stamp, request, status, agent, extra = match.groups()
                    try:
                        if stamp not in date_cache:
                            if len(date_cache) >= 4096:
                                date_cache.clear()
                            date_cache[stamp] = datetime.datetime.strptime(stamp, '%d/%b/%Y:%H:%M:%S %z').timestamp()
                        at = date_cache[stamp]
                    except ValueError:
                        totals['unparsed'] += 1
                        continue
                    oldest = at if oldest is None else min(oldest, at)
                    latest = at if latest is None else max(latest, at)
                    if not cutoff <= at <= now:
                        continue
                    parts = request.split()
                    if len(parts) != 3:
                        totals['unparsed'] += 1
                        continue
                    method, target_url, _ = parts
                    path_only = safe_path(target_url)
                    if not path_only:
                        continue
                    records += 1; totals['requests'] += 1; totals['status_' + status] += 1
                    if progress: progress(dict(records=totals['requests'], bytes=bytes_read, files_done=index, files_total=len(files), domain=site['domain']))
                    if inventory_kind:
                        groups.observe(site, path_only, status, agent, at)
                        continue
                    decoded_path = unquote(unquote(path_only))
                    if IMAGE.search(decoded_path):
                        # Preserve positive secret-probe evidence even when the
                        # requested filename happens to have an image extension.
                        names, combination, secret_query = params(target_url)
                        if not SECRET_PATH.search(decoded_path) and not secret_query:
                            totals['image_records_excluded'] += 1
                            continue
                    elif ASSET.search(path_only) and status != '404':
                        continue  # Keep totals; aggregate diagnostic routes rather than successful assets.
                    names, combination, secret_query = params(target_url)
                    key = (site['key'], path_only, tuple(names))
                    if key not in groups:
                        groups[key] = new_group(site, path_only, names)
                    group = groups[key]
                    group['count'] += 1; group['statuses'][status] += 1; group['methods'][method] += 1
                    group['minutes'][int(at // 60)] += 1
                    group['first'] = at if group['first'] is None else min(group['first'], at)
                    group['last'] = at if group['last'] is None else max(group['last'], at)
                    agent_claim = claim(agent); group['agents'][agent_claim] += 1
                    groups.track(key, hashlib.blake2s(address.encode(), key=salt, digest_size=8).digest(), combination)
                    group['secret'] |= bool(SECRET_PATH.search(unquote(unquote(path_only)))) or secret_query
                    if agent_claim == 'Googlebot':
                        try:
                            ip = ipaddress.ip_address(address)
                            verified = any(ip.version == network.version and ip in network for network in ranges)
                        except ValueError:
                            verified = False
                        group['verified_google' if verified else 'unconfirmed_google'] += 1
                    timing = re.search(r'(?:^|\s)rt=([0-9]+(?:\.[0-9]+)?)(?:\s|$)', extra)
                    if timing:
                        seconds = float(timing[1])
                        if math.isfinite(seconds) and seconds >= 0:
                            group['timing_count'] += 1; group['request_seconds'] += seconds
                    upstream = re.search(r'(?:^|\s)urt=([0-9]+(?:\.[0-9]+)?)(?:\s|$)', extra)
                    if upstream:
                        seconds = float(upstream[1])
                        if math.isfinite(seconds) and seconds >= 0:
                            group['upstream_count'] += 1; group['upstream_seconds'] += seconds
                    cache = re.search(r'(?:^|\s)cache=(HIT|MISS|BYPASS|EXPIRED|STALE|UPDATING|REVALIDATED)(?:\s|$)', extra)
                    if cache:
                        group['cache'][cache[1]] += 1
            except InterruptedError:
                raise
            except (OSError, EOFError, lzma.LZMAError):
                interrupted = True
                errors.append(dict(domain=site['domain'], file=path.name, message='Log decompression/read failed'))
            finally:
                stack.close()
            coverage.append(dict(domain=site['domain'], file=path.name, source=path.parent.parent.name, records=records,
                                 first=oldest, last=latest, partial=interrupted,
                                 note='Read failed' if interrupted else 'Available file read'))
        selected_domains = {site['domain'] for site in chosen}
        seen_domains = {row['domain'] for row in coverage}
        partial = bool(errors or group_dropped or totals['unparsed'] or totals['incomplete_lines'] or any(row['partial'] for row in coverage) or selected_domains - seen_domains)
        if inventory_kind:
            suggestions, inventory_total = groups.finish(report_path is not None)
        else:
            suggestions = findings(groups, persist=report_path is not None)
        return dict(generated_at=now, minutes=minutes, target=target, domains=len(chosen), bytes_read=bytes_read,
                    elapsed_seconds=round(time.monotonic() - started, 3), partial=partial, limits={},
                    totals=dict(totals), findings=suggestions,
                    findings_total=inventory_total if inventory_kind else (groups.suggestion_count() if report_path is not None else len(suggestions)),
                    inventory_kind=inventory_kind,
                    categories={key: value['title'] for key, value in agent_catalog.CATEGORIES.items()} if inventory_kind else {},
                    findings_database=report_path is not None, coverage=coverage, errors=errors,
                    unavailable_domains=sorted(selected_domains - seen_domains), group_limit_reached=group_dropped,
                    verification=verification, verified_google_requested=verify_google,
                    note=('Counts reflect retained native access logs. Cache HITs and early blocks may be absent; layered logs may duplicate records. Agent names are unverified declarations. No protection setting was changed.' if inventory_kind else 'Native log records are not total incoming traffic or PHP executions. Early blocks and cache HITs may be absent. Known UltraCache revalidation/bucket parameters do not count as content-filter diversity; this does not verify the caller or exempt errors, slow requests or secret probes. Query values, client IPs and raw User-Agents are not returned or retained. No protection setting was changed.'))
    finally:
        groups.close()


def review(sites, target, minutes, state, verify_google=False):
    selection(sites, target, minutes)
    if type(verify_google) is not bool:
        raise ValueError('Invalid Google verification switch')
    with scan_lock(state):
        os.nice(10)  # Only this short-lived bridge process, not website workers.
        return scan(sites, target, minutes, state, verify_google)
