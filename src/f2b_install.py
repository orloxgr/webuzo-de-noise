"""Explicit, previewed installation from authenticated Debian/Ubuntu repositories."""
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys
import time

sys.dont_write_bytecode = True
sys.pycache_prefix = str(Path(__file__).resolve().parent / '.bytecode')
sys.path.insert(0, str(Path(__file__).resolve().parent))
import storage
import host_protection

PLAN = 'fail2ban-install-plan.json'
JOB = 'fail2ban-install-job.json'
OS_RELEASE = Path('/etc/os-release')


def read(state, name):
    raw = storage.read(Path(state) / name)
    return json.loads(raw) if raw is not None else None


def candidate(run):
    """Accept the OS package, not arbitrary download URLs or package names."""
    values = {}
    for line in OS_RELEASE.read_text(encoding='utf-8').splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            values[key] = shlex.split(value)[0] if value else ''
    system = values.get('ID')
    if system not in ('ubuntu', 'debian'):
        raise ValueError('Automatic installation currently supports Debian and Ubuntu. Install the OS Fail2ban package manually on this distribution, then refresh status.')
    cache = host_protection.binary('apt-cache')
    apt = host_protection.binary('apt-get')
    if not cache or not apt:
        raise ValueError('The system APT package manager is unavailable')
    output = run(cache, 'policy', 'fail2ban')
    match = re.search(r'^\s*Candidate:\s*(\S+)', output, re.M)
    if not match or not re.fullmatch(r'[A-Za-z0-9.+:~_-]+', match[1]) or match[1] == '(none)':
        raise ValueError('No Fail2ban package is available in the current APT indexes. Refresh the OS package indexes and retry.')
    version = match[1]
    # python-apt supplies the verified repository Origin for this exact version.
    # Never infer authenticity from a download hostname or a version suffix.
    code = ('import apt,json; p=apt.Cache()["fail2ban"]; c=p.candidate; '
            'print(json.dumps({"version":c.version,"origins":[{"origin":o.origin,"trusted":o.trusted,"archive":o.archive,"site":o.site} for o in c.origins]}))')
    try:
        metadata = json.loads(run('/usr/bin/python3', '-I', '-c', code))
    except (RuntimeError, ValueError) as error:
        raise ValueError('Repository verification requires the distribution python3-apt package') from error
    expected = 'Ubuntu' if system == 'ubuntu' else 'Debian'
    origins = [o for o in metadata.get('origins', []) if not (o.get('archive') == 'now' and not o.get('site'))]
    if metadata.get('version') != version or not origins or any(
            origin.get('origin') != expected or origin.get('trusted') is not True for origin in origins):
        raise ValueError('The Fail2ban candidate must come exclusively from authenticated ' + expected + ' repositories')
    # APT performs dependency selection and authentication; its simulation is the reviewable plan.
    commands = [apt, '-s', '--no-install-recommends', 'install', 'fail2ban=' + version]
    simulation = run(*commands)
    if re.search(r'^Remv ', simulation, re.M):
        raise ValueError('APT proposes removing existing packages. Resolve the package conflict manually before installing Fail2ban.')
    packages = []
    for line in simulation.splitlines():
        if line.startswith('Inst '):
            selected = re.match(r'^Inst ([A-Za-z0-9.+:-]+)(?: \[[^\]]+\])? \(([^\s)]+)', line)
            if not selected:
                raise ValueError('APT returned an unsupported package plan')
            packages.append([selected[1], selected[2]])
    if packages:
        code = ('import apt,json,sys; c=apt.Cache(); r=[]; '
                '\nfor name,version in json.loads(sys.argv[1]):\n'
                ' v=next(v for v in c[name].versions if v.version==version); '
                'r.append({"name":name,"origins":[{"origin":o.origin,"trusted":o.trusted} for o in v.origins if not (o.archive=="now" and not o.site)]})\n'
                'print(json.dumps(r))')
        dependencies = json.loads(run('/usr/bin/python3', '-I', '-c', code, json.dumps(packages)))
        if (len(dependencies) != len(packages) or any(not item.get('origins') or any(
                origin.get('origin') != expected or origin.get('trusted') is not True
                for origin in item['origins']) for item in dependencies)):
            raise ValueError('Every package in the installation plan must come from authenticated ' + expected + ' repositories')
    changes = '\n'.join(line for line in simulation.splitlines() if line.startswith(('Inst ', 'Conf ')))
    return dict(os=values.get('PRETTY_NAME', system), version=version, package='fail2ban', changes=changes,
                simulation=simulation, command=['/usr/bin/env', 'DEBIAN_FRONTEND=noninteractive', apt, '-y', '--no-install-recommends',
                '-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::AllowInsecureRepositories=false',
                '-o', 'Dpkg::Options::=--force-confold',
                'install', 'fail2ban=' + version])


def preview(state, run):
    if host_protection.binary('fail2ban-client'):
        raise ValueError('Fail2ban is already installed. Refresh its status instead.')
    plan = candidate(run)
    plan.update(token=secrets.token_hex(32), created=time.time())
    storage.replace(Path(state) / PLAN, storage.json_bytes(plan), 0o600)
    return plan


def status(state):
    result = read(state, JOB) or {'state': 'idle'}
    if result['state'] in ('queued', 'running') and time.time() - result['created'] > 1800:
        # A killed worker must not leave an indefinite spinner or permit concurrent APT.
        result = {**result, 'state': 'failed', 'error': 'Installation did not finish within 30 minutes. Check the OS package manager before retrying.'}
    return result


def start(state, token, run):
    current = status(state)
    if current['state'] in ('queued', 'running'):
        return current
    plan = read(state, PLAN)
    if (not isinstance(token, str) or not re.fullmatch('[0-9a-f]{64}', token) or not plan or
            plan['token'] != token or time.time() - plan['created'] > 3600):
        raise ValueError('Generate a fresh installation preview before installing')
    if host_protection.binary('fail2ban-client'):
        raise ValueError('Fail2ban is already installed')
    fresh = candidate(run)
    if any(fresh[name] != plan[name] for name in ('os', 'version', 'command', 'simulation')):
        raise ValueError('The package plan has changed. Generate and review a new preview.')
    job = dict(id=secrets.token_hex(16), state='queued', created=time.time(), version=plan['version'])
    storage.replace(Path(state) / JOB, storage.json_bytes(job), 0o600)
    argv = ['/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), '--worker', job['id']]
    actions = [(os.POSIX_SPAWN_OPEN, fd, os.devnull, flags, 0o600)
               for fd, flags in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY))]
    try:
        os.posix_spawn(argv[0], argv, {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                       'DEBIAN_FRONTEND': 'noninteractive'}, file_actions=actions, setsid=True)
    except Exception as error:
        storage.replace(Path(state) / JOB, storage.json_bytes({**job, 'state': 'failed', 'error': str(error)}), 0o600)
        raise
    return job


def worker(state, identity, run):
    """The caller holds the protection lock; no commands are accepted from HTTP."""
    job, plan = read(state, JOB), read(state, PLAN)
    if (not re.fullmatch('[0-9a-f]{32}', identity) or not job or job['id'] != identity or
            job['state'] != 'queued' or not plan):
        raise ValueError('Invalid Fail2ban installation job')
    def report(**values):
        job.update(values)
        storage.replace(Path(state) / JOB, storage.json_bytes(job), 0o600)
    report(state='running')
    try:
        fresh = candidate(run)
        if any(fresh[name] != plan[name] for name in ('os', 'version', 'command', 'simulation')):
            raise ValueError('The package plan changed before installation. Review it again.')
        report(message='Installing Fail2ban packages. Service checks will follow when APT finishes.')
        run(*fresh['command'], timeout=900)
        report(message='Packages installed. Checking Fail2ban configuration.')
        client = host_protection.client()
        run(client, '-t')
        systemctl = host_protection.binary('systemctl')
        if not systemctl:
            raise ValueError('Systemd is required to start the Fail2ban service')
        report(message='Starting Fail2ban and checking service readiness.')
        run(systemctl, 'enable', '--now', 'fail2ban')
        for attempt in range(10):
            try:
                host_protection.active_jails(run)
                break
            except RuntimeError:
                if attempt == 9: raise
                time.sleep(1)
        report(state='complete', message='Fail2ban installed and running. Review existing jails before enabling additional service protection.')
        storage.replace(Path(state) / PLAN, None)
    except Exception as error:
        # Package manager changes are not erased: retain its diagnostic for recovery.
        report(state='failed', error=str(error))


if __name__ == '__main__':
    if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] != '--worker':
        raise SystemExit('Use the authenticated administrator panel to install Fail2ban')
    import engine
    import fcntl
    import stat
    # Package operations have their own lock; page status and web maintenance
    # stay responsive while APT runs. Authentication-jail writes are blocked below.
    lock = Path(engine.STATE) / 'fail2ban-package.lock'
    with storage.parent(lock) as directory:
        descriptor = os.open(lock.name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    info = os.fstat(descriptor)
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
        raise SystemExit('Untrusted package installation lock')
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    with engine.locked():
        active = engine.load('active.json', {}).get('active') is True
    if active:
        worker(engine.STATE, sys.argv[2], engine.run)
    os.close(descriptor)
