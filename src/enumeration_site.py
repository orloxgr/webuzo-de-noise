"""Unprivileged, narrowly scoped WordPress companion file operations."""
import json
import os
from pathlib import Path
import secrets
import stat
import sys

NAME = 'webuzo-de-noise-user-enumeration.php'
MARKER = '<?php // Managed by webuzo-de-noise\n'


def execute(request):
    if os.geteuid() == 0:
        raise ValueError('Website operations must run as the site owner')
    root = Path(request['root']).resolve(strict=True)
    import pwd
    home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
    if not root.is_relative_to(home) or root == home:
        raise ValueError('Document root must be within the website owner home')
    wordpress = (root / 'wp-load.php').is_file() and (root / 'wp-includes/version.php').is_file()
    directory = root / 'wp-content/mu-plugins'
    if wordpress and not request.get('removing'):
        config = root / 'wp-config.php'
        if not config.is_file():
            config = root.parent / 'wp-config.php'
        text = config.read_text(encoding='utf-8')
        if any(name in text for name in ('WPMU_PLUGIN_DIR', 'WP_CONTENT_DIR')):
            raise ValueError('Custom WordPress content/MU directories require separate integration')
    if directory.is_symlink() or directory.parent.is_symlink():
        raise ValueError('Refusing a symbolic WordPress plugin directory')
    if not directory.exists():
        if request['action'] == 'inspect':
            return dict(wordpress=wordpress, body=None)
        if request.get('body') is None:
            return dict(wordpress=wordpress, body=None)
        if not wordpress:
            raise ValueError('WordPress document root disappeared')
        directory.mkdir(mode=0o755)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            handle = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        except FileNotFoundError:
            current = None
        else:
            with os.fdopen(handle, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('Refusing a non-regular companion file')
                current = stream.read().decode('utf-8')
            if not current.startswith(MARKER):
                raise ValueError('Refusing an unmanaged WordPress companion file')
        if request['action'] == 'inspect':
            return dict(wordpress=wordpress, body=current)
        if request['action'] != 'replace':
            raise ValueError('Unknown website operation')
        body = request.get('body')
        if body is not None and (not isinstance(body, str) or not body.startswith(MARKER)):
            raise ValueError('Invalid companion payload')
        # Recovery is idempotent if this particular write was not reached.
        if current == body:
            return dict(wordpress=wordpress, body=body)
        if current != request.get('expected'):
            raise ValueError('Companion changed during the transaction; kept unchanged')
        if body is None:
            os.unlink(NAME, dir_fd=descriptor)
        else:
            temporary = '.' + NAME + '-' + secrets.token_hex(8)
            try:
                handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=descriptor)
                with os.fdopen(handle, 'wb') as stream:
                    os.fchmod(stream.fileno(), 0o644)
                    stream.write(body.encode()); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, NAME, src_dir_fd=descriptor, dst_dir_fd=descriptor)
            finally:
                try: os.unlink(temporary, dir_fd=descriptor)
                except FileNotFoundError: pass
        os.fsync(descriptor)
        return dict(wordpress=wordpress, body=body)
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        print(json.dumps(execute(json.load(sys.stdin))))
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
