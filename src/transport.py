"""One-shot requests passed by the authenticated panel through native wexec."""
import json
import os
from pathlib import Path
import pwd
import re
import stat

DIRECTORY = Path('/run/webuzo-de-noise')
LIMIT = 1024 * 1024


def read(identity):
    if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity):
        raise ValueError('Invalid panel request identity')
    panel = pwd.getpwnam('webuzo')
    fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory = os.fstat(fd)
        if (directory.st_uid != 0 or directory.st_gid != panel.pw_gid or
                stat.S_IMODE(directory.st_mode) != 0o730):
            raise ValueError('Untrusted panel request directory')
        name = identity + '.json'
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(handle, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != panel.pw_uid or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > LIMIT):
                raise ValueError('Untrusted panel request file')
            raw = stream.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError('Panel request exceeds the safe transport size')
        os.unlink(name, dir_fd=fd)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError('A panel request must be an object')
        return value
    finally:
        os.close(fd)
