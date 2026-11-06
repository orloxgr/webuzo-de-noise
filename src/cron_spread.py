"""Explicit preview/apply/restore of existing native Webuzo WordPress cron jobs."""
import copy
import math
import re
import secrets
from urllib.parse import urlsplit

FIELDS = ('MIN', 'HOUR', 'DAY', 'MONTH', 'WDAY', 'CMD')


def minutes(minimum=5, maximum=15, rng=None, period=60):
    if type(minimum) is not int or type(maximum) is not int or not 1 <= minimum <= maximum:
        raise ValueError('Cron intervals must be positive integers in increasing order')
    lo, hi = max(1, math.ceil(period/maximum)), min(period, math.floor(period/minimum))
    if lo > hi:
        raise ValueError('This interval range cannot be expressed by one repeating native cron field')
    rng = rng or secrets.SystemRandom()
    count, offset = rng.randint(lo, hi), rng.randrange(period)
    values = sorted((offset + index*period//count) % period for index in range(count))
    return ','.join(map(str, values))


def schedule(minimum, maximum):
    try:
        return {'MIN': minutes(minimum, maximum), 'HOUR': '*', 'WDAY': '*'}
    except ValueError:
        # One Webuzo cron job has independent calendar fields. Preserve exact
        # requested gap bounds instead of pretending a nonrepresentable range fits.
        if type(minimum) is not int or type(maximum) is not int or not 1 <= minimum <= maximum:
            raise
    rng = secrets.SystemRandom()
    for unit, period, field in ((60, 24, 'HOUR'), (1440, 7, 'WDAY')):
        low, high = math.ceil(minimum / unit), math.floor(maximum / unit)
        if low < 1 or high < low:
            continue
        try:
            values = minutes(low, high, rng, period)
        except ValueError:
            continue
        result = {'MIN': str(rng.randrange(60)), 'HOUR': str(rng.randrange(24)), 'WDAY': '*'}
        result[field] = values
        return result
    raise ValueError('The requested gap range cannot be represented by a single native calendar cron job')


def preview(metadata, minimum=5, maximum=15):
    schedule(minimum, maximum)  # Validate before calling native commands.
    rows = []
    for owner, user in metadata('accounts').items():
        if user.get('SUSPENDED') == 'yes':
            continue
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', owner):
            raise ValueError('Invalid Webuzo cron owner')
        for ident, job in metadata('cron_jobs', owner).items():
            if job.get('SUSPENDED') != 'no' or any(job.get(key) != '*' for key in ('HOUR', 'DAY', 'MONTH', 'WDAY')):
                continue
            match = re.search(r'(?:https?://[A-Za-z0-9.-]+|/home/[A-Za-z0-9_./-]+)/wp-cron\.php\b', job.get('CMD', ''))
            if not match:
                continue
            if not re.fullmatch(r'[0-9]+', ident) or not all(isinstance(job.get(key), str) for key in FIELDS):
                raise ValueError('Malformed native WordPress cron job')
            before = {key: job[key] for key in FIELDS}
            after = {**before, **schedule(minimum, maximum)}
            rows.append({'key': owner+'/'+ident, 'owner': owner, 'job': ident,
                         'label': match[0], 'before': before, 'after': after, 'state': 'preview'})
    return {'id': secrets.token_hex(16), 'minimum': minimum, 'maximum': maximum, 'rows': rows}


def public(plan):
    if not plan:
        return None
    if (not isinstance(plan, dict) or not isinstance(plan.get('id'), str)
            or not re.fullmatch('[0-9a-f]{32}', plan['id']) or not isinstance(plan.get('rows'), list)):
        return {'error': 'Saved cron preview is invalid. Generate a new preview.'}
    return {'id': plan['id'], 'minimum': plan['minimum'], 'maximum': plan['maximum'],
            'rows': [{**{key: row[key] for key in ('key', 'owner', 'job', 'label', 'state')},
                      'site': site_label(row['label']),
                      'before': row['before']['MIN'], 'after': row['after']['MIN'],
                      'before_label': interval_label(row['before']['MIN']),
                      'after_label': interval_label(row['after']['MIN']) if row['after']['HOUR'] == '*' and row['after']['WDAY'] == '*' else
                          'Minutes ' + row['after']['MIN'] + ' · hours ' + row['after']['HOUR'] + ' · weekdays ' + row['after']['WDAY']}
                     for row in plan['rows']]}


def site_label(label):
    if label.startswith(('http://', 'https://')):
        return urlsplit(label).hostname or label
    parts = label.split('/')
    if len(parts) > 4 and parts[1] == 'home':
        return parts[4] if parts[3] == 'web' and len(parts) > 5 else parts[3]
    return label


def interval_label(value):
    if value == '*':
        return 'Every minute'
    match = re.fullmatch(r'\*/([1-9][0-9]?)', value)
    if match:
        step = int(match[1])
        values = list(range(0, 60, step))
    elif re.fullmatch(r'[0-9]+(?:,[0-9]+)*', value):
        values = sorted(set(map(int, value.split(','))))
    else:
        return 'Custom schedule'
    if not values or any(not 0 <= minute < 60 for minute in values):
        return 'Custom schedule'
    gaps = [right-left for left, right in zip(values, values[1:]+[values[0]+60])]
    low, high = min(gaps), max(gaps)
    return 'Every ' + (str(low) if low == high else str(low)+'–'+str(high)) + ' minutes'


def apply(plan, selection, metadata, change, save, restore=False):
    if (not isinstance(selection, list) or not selection
            or any(not isinstance(key, str) for key in selection)):
        raise ValueError('Select existing WordPress cron jobs')
    known = {row['key']: row for row in plan['rows']}
    if any(key not in known for key in selection):
        raise ValueError('The selected cron job is not in this preview')
    jobs = {}
    # Check the whole selection before any change; a stale preview cannot
    # overwrite a command or schedule edited in the native Webuzo interface.
    for key in dict.fromkeys(selection):
        row = known[key]
        if row['owner'] not in jobs:
            jobs[row['owner']] = metadata('cron_jobs', row['owner'])
        current = jobs[row['owner']].get(row['job'], {})
        source, destination = (row['after'], row['before']) if restore else (row['before'], row['after'])
        if current.get('SUSPENDED') != 'no' or {field: current.get(field) for field in FIELDS} not in (source, destination):
            raise ValueError('Cron job changed after preview: ' + key + '. Create a fresh preview.')
        if restore and row['state'] == 'preview':
            raise ValueError('This cron job has not been changed by this preview: ' + key)
    for key in dict.fromkeys(selection):
        row = known[key]
        destination = row['before'] if restore else row['after']
        source = row['after'] if restore else row['before']
        current = metadata('cron_jobs', row['owner']).get(row['job'], {})
        if current.get('SUSPENDED') != 'no' or {field: current.get(field) for field in FIELDS} not in (source, destination):
            raise ValueError('Cron job changed after preview: ' + key + '. Create a fresh preview.')
        row['state'] = 'restoring' if restore else 'applying'; save(plan)
        if {field: current.get(field) for field in FIELDS} != destination:
            try:
                change(row['owner'], row['job'], *[destination[field] for field in FIELDS])
            except Exception as error:
                # Keep actual native error details, without echoing a private
                # existing cron command into the panel's error banner.
                raise RuntimeError(str(error).replace(destination['CMD'], '[existing cron command]')) from error
        confirmed = metadata('cron_jobs', row['owner']).get(row['job'], {})
        if confirmed.get('SUSPENDED') != 'no' or {field: confirmed.get(field) for field in FIELDS} != destination:
            raise RuntimeError('Webuzo did not confirm the requested schedule: ' + key)
        row['state'] = 'restored' if restore else 'applied'; save(plan)
    return copy.deepcopy(plan)
