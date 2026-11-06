"""Trusted native log rotations, streamed without a total byte quota."""
from contextlib import contextmanager
import bz2
import gzip
import lzma
from pathlib import Path
import re

import storage


def rotations(path):
    path = Path(path)
    candidates = list(path.parent.glob(path.name + '.[0-9]*'))
    candidates = [p for p in candidates if re.fullmatch(re.escape(path.name) + r'[.][0-9]+(?:[.](?:gz|bz2|xz))?', p.name)]
    candidates.sort(key=lambda p: int(p.name[len(path.name) + 1:].split('.')[0]), reverse=True)
    return [*candidates, path]


def compressed(path):
    return Path(path).suffix in ('.gz', '.bz2', '.xz')


@contextmanager
def opened(path):
    with storage.log_stream(path) as raw:
        if Path(path).suffix == '.gz':
            with gzip.GzipFile(fileobj=raw) as stream: yield stream, raw
        elif Path(path).suffix == '.bz2':
            with bz2.BZ2File(raw) as stream: yield stream, raw
        elif Path(path).suffix == '.xz':
            with lzma.LZMAFile(raw) as stream: yield stream, raw
        else:
            yield raw, raw
