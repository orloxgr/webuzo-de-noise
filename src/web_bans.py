"""Server-wide HTTP bans through the native Nginx custom configuration."""
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import stat

import storage
import webuzo

APPLIED = 'global-ban-applied.json'
CREATED = 'global-ban-backend.json'


class Native:
    def __init__(self, root, run, state=None):
        self.state = Path(state) if state is not None else webuzo.STATE
        self.run = run

    def available(self):
        if not webuzo.NGINX.is_file():
            raise ValueError('Web bans require the native Webuzo website Nginx')

    @contextmanager
    def locked(self):
        import fcntl
        with storage.parent(self.state / 'web-bans.lock') as parent:
            fd = os.open('web-bans.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError('Untrusted web-ban lock')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def own_ips(self):
        data = json.loads(self.run('/usr/sbin/ip', '-j', 'address', 'show'))
        return {str(ipaddress.ip_address(entry['local']))
                for interface in data for entry in interface.get('addr_info', [])}

    def exclusions(self):
        return []

    def inspect(self):
        raw = storage.read(self.state / APPLIED)
        saved = set(json.loads(raw)) if raw is not None else set()
        saved = {str(ipaddress.ip_address(value)) for value in saved}
        raw = storage.owned(webuzo.GLOBAL)
        active = set()
        if raw is not None:
            nodes = webuzo.directives(raw.decode())
            blocks = [children for name, args, children in nodes
                      if name == 'geo' and args == ['$remote_addr', '$hdn_global_blocked']]
            if len(blocks) != 1:
                raise ValueError('The native global web-ban map is missing or ambiguous')
            for value, args, child in blocks[0]:
                if value != 'default':
                    network = ipaddress.ip_network(value)
                    if args != ['1'] or network.prefixlen != network.max_prefixlen:
                        raise ValueError('Invalid native global web-ban entry')
                    active.add(str(network.network_address))
        return storage.read(self.state / CREATED) is not None, saved, active

    def create(self):
        self.available()
        if storage.read(self.state / CREATED) is None:
            storage.replace(self.state / CREATED, b'{"backend":"native-nginx"}\n', 0o600)

    def change(self, address, adding):
        import engine
        address = str(ipaddress.ip_address(address))
        _, saved, active = self.inspect()
        if saved != active:
            raise ValueError('Native web-ban state does not match the installed configuration')
        desired = saved | {address} if adding else saved - {address}
        policy = engine.validate(engine.load('policy.json', engine.DEFAULT))
        engine.apply(policy, webuzo.collect(), global_blocks=desired)

    def add(self, address):
        self.change(address, True)

    def remove(self, address):
        self.change(address, False)

    def drop_chain(self):
        _, saved, active = self.inspect()
        if saved or active:
            raise ValueError('Refusing to remove a nonempty web-ban backend')
        storage.replace(self.state / CREATED, None)
