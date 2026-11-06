"""No-follow file access and durable replacement of addon-owned files."""
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import secrets
import stat
import re
from functools import lru_cache

from policy import MARKER


@lru_cache(maxsize=1)
def log_uids():
    """Nginx USR1 assigns open logs to its configured worker, not root."""
    import pwd
    config = read('/usr/local/apps/nginx/etc/nginx.conf')
    users = re.findall(rb'^\s*user\s+[\'\"]?([A-Za-z0-9_-]+)[\'\"]?(?:\s+[A-Za-z0-9_-]+)?\s*;', config or b'', re.M)
    if len(users) > 1:
        raise ValueError('Ambiguous Nginx worker user')
    return {0, pwd.getpwnam(users[0].decode('ascii')).pw_uid} if users else {0}


def check_log(fd, uids=None):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (log_uids() if uids is None else uids) or info.st_mode & 0o022:
        raise ValueError('Refusing an untrusted Nginx log')
    return info


def log_stream(path, uids=None):
    """Pin the root-controlled directory and refuse links/FIFOs/writable logs."""
    with parent(path) as directory:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    stream = os.fdopen(fd, 'rb')
    try:
        check_log(stream.fileno(), uids)
    except Exception:
        stream.close()
        raise
    return stream


@contextmanager
def parent(path):
    """Pin every ancestor with openat; never follow user-controlled symlinks."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('An absolute managed path is required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for piece in path.parent.parts[1:]:
            new = os.open(piece, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Managed directory must be owned and writable only by root: ' + str(path.parent))
        yield fd
    finally:
        os.close(fd)


def read(path):
    with parent(path) as fd:
        try:
            handle = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return None
        with os.fdopen(handle, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Refusing a non-regular or untrusted managed file: ' + str(path))
            data = stream.read()
            return data


def replace(path, data, mode=0o644, gid=None):
    path = Path(path)
    if gid is not None and (type(gid) is not int or not 0 <= gid < 4294967295):
        raise ValueError('Invalid managed file group')
    with parent(path) as fd:
        temporary = '.' + path.name + '.tmp-' + secrets.token_hex(8)
        if data is None:
            try:
                os.unlink(path.name, dir_fd=fd)
            except FileNotFoundError:
                pass
        else:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                                 mode, dir_fd=fd)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    if gid is not None:
                        os.fchown(stream.fileno(), -1, gid)
                    os.fchmod(stream.fileno(), mode)
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
        os.fsync(fd)


def owned(path):
    data = read(path)
    if data is not None and not data.startswith((MARKER + '\n').encode()):
        raise ValueError('Refusing an existing file not owned by De-Noise: ' + str(path))
    return data


def json_bytes(data):
    return (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, exist_ok=True)
    # Validate ancestors, ownership and exact privacy before using a root lock.
    with parent(path / '.check'):
        if path.stat().st_mode & 0o077:
            raise ValueError('State directory must be root-private: ' + str(path))
