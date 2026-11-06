"""Build the native Webuzo plugin ZIP from the distributable source only."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build():
    version = json.loads((ROOT / 'info.json').read_text())['version']
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    target = output / ('webuzo-de-noise-' + version + '.zip')
    paths = [ROOT / name for name in ('webuzo-de-noise.php', 'info.json', 'LICENSE', 'README.md', 'FEATURES.md', 'UPSTREAM')]
    for folder in ('src', 'panel', 'wordpress', 'config'):
        paths += [path for path in (ROOT / folder).rglob('*') if path.is_file() and
                  '__pycache__' not in path.parts and path.suffix != '.pyc' and path.name != 'menu.js']
    # Use a revision/source epoch rather than one permanent timestamp for every
    # release. Native Python/PHP caches must see a new source modification time.
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', max(path.stat().st_mtime for path in paths)))
    date = datetime.fromtimestamp(epoch, timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(paths):
            if path.is_symlink():
                raise ValueError('Source symlinks are not distributable')
            info = zipfile.ZipInfo('webuzo-de-noise/' + path.relative_to(ROOT).as_posix(), date)
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    print(target.name, hashlib.sha256(target.read_bytes()).hexdigest())
    return target


if __name__ == '__main__':
    build()
