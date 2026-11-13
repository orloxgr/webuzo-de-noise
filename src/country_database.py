"""Download GeoLite2 Country CSV once; compile native IPv4/IPv6 Nginx geo data."""
import base64
import csv
import hashlib
import io
import ipaddress
import json
import re
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit
import zipfile
from pathlib import Path

CONFIG = 'geoip-config.json'
METADATA = 'geoip.json'
URL = 'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip'


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if not newurl.startswith('https://'):
            raise ValueError('Country database redirect must use HTTPS')
        result = super().redirect_request(request, fp, code, msg, headers, newurl)
        # Presigned CDN downloads need no account credentials. Never forward them.
        origin = lambda url: (urlsplit(url).scheme, urlsplit(url).hostname, urlsplit(url).port or 443)
        if origin(request.full_url) != origin(newurl):
            result.remove_header('Authorization')
        return result


def compile_csv(archive):
    countries = {}
    codes = set()
    rows = []
    with zipfile.ZipFile(archive) as data:
        names = {}
        for name in data.namelist():
            base = name.rsplit('/', 1)[-1]
            if base in ('GeoLite2-Country-Locations-en.csv', 'GeoLite2-Country-Blocks-IPv4.csv',
                        'GeoLite2-Country-Blocks-IPv6.csv'):
                if base in names:
                    raise ValueError('Duplicate country database CSV member')
                names[base] = name
        if len(names) != 3:
            raise ValueError('Expected GeoLite2 Country locations, IPv4 and IPv6 CSV files')
        with data.open(names['GeoLite2-Country-Locations-en.csv']) as stream:
            for row in csv.DictReader(io.TextIOWrapper(stream, encoding='utf-8-sig')):
                code = row['country_iso_code']
                if not code:
                    continue
                if not re.fullmatch(r'[A-Z]{2}', code) or code == 'ZZ':
                    raise ValueError('Invalid country code in GeoLite2 database')
                countries[row['geoname_id']] = code
                codes.add(code)
        for version in (4, 6):
            with data.open(names[f'GeoLite2-Country-Blocks-IPv{version}.csv']) as stream:
                for row in csv.DictReader(io.TextIOWrapper(stream, encoding='utf-8-sig')):
                    net = ipaddress.ip_network(row['network'])
                    if net.version != version:
                        raise ValueError('Country database IP version does not match its file')
                    # A registered-country address is not necessarily located there.
                    # Missing location remains unknown rather than inventing a location.
                    code = countries.get(row['geoname_id'])
                    if code:
                        rows.append(f'    {net} {code};\n')
    if not rows:
        raise ValueError('The country database contains no geolocated networks')
    content = ('# Managed by webuzo-de-noise\n# GeoLite2 data created by MaxMind, https://www.maxmind.com\n' + ''.join(rows)).encode()
    return content, {'networks': len(rows), 'countries': sorted(codes), 'source': 'MaxMind GeoLite2 Country'}


def download(config):
    account = config.get('account_id')
    key = config.get('license_key')
    if not isinstance(account, str) or not re.fullmatch(r'[0-9]+', account) or not isinstance(key, str) or not key or any(c in key for c in '\r\n\x00'):
        raise ValueError('Configure the MaxMind account ID and license key before downloading countries')
    credentials = base64.b64encode((account + ':' + key).encode()).decode()
    request = urllib.request.Request(URL, headers={'Authorization': 'Basic ' + credentials,
                                                  'User-Agent': 'Webuzo-De-Noise-country-update'})
    # Spooled files grow to disk rather than imposing a maximum archive size.
    import tempfile
    import shutil
    opener = urllib.request.build_opener(SafeRedirect())
    with tempfile.TemporaryFile() as archive:
        try:
            with opener.open(request) as response:
                shutil.copyfileobj(response, archive)
        except urllib.error.HTTPError as error:
            raise ValueError('Country database download returned HTTP ' + str(error.code) + '; check MaxMind download credentials and service availability') from None
        except Exception as error:
            raise ValueError('Country database download failed; check MaxMind credentials and network access (' + type(error).__name__ + ')') from None
        archive.seek(0)
        content, metadata = compile_csv(archive)
    metadata.update(updated=time.time(), sha256=hashlib.sha256(content).hexdigest())
    return content, metadata


def validate_config(config):
    if (not isinstance(config, dict) or set(config) != {'account_id', 'license_key', 'automatic'}
            or not isinstance(config['account_id'], str)
            or config['account_id'] and not re.fullmatch(r'[0-9]+', config['account_id'])
            or not isinstance(config['license_key'], str)
            or any(c in config['license_key'] for c in '\r\n\x00')
            or type(config['automatic']) is not bool):
        raise ValueError('Use a numeric MaxMind account ID, a valid license key and an update switch')
    return config


def path(state, metadata):
    digest = metadata.get('sha256', '')
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        return None
    return Path(state) / ('country-' + digest + '.geo')


def status(state, reader):
    def read(name, fallback):
        value = reader(Path(state) / name)
        return json.loads(value) if value else fallback
    config = read(CONFIG, {})
    metadata = read(METADATA, {})
    return {**metadata, 'configured': bool(config.get('account_id') and config.get('license_key')),
            'account_id': config.get('account_id', ''), 'automatic': config.get('automatic', True),
            'available': bool(path(state, metadata) and path(state, metadata).is_file())}
