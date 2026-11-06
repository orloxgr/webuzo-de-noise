"""Own only a delimited include in Webuzo's documented custom domain files."""
from pathlib import Path
import glob

import storage
import webuzo
from policy import domain

BEGIN = '# BEGIN Webuzo De-Noise\n'
END = '# END Webuzo De-Noise\n'


def custom_path(value):
    path = Path(value)
    if path.parent != webuzo.CUSTOM or not path.name.endswith('.conf'):
        raise ValueError('Invalid custom configuration destination')
    domain(path.name[:-5])
    return path


def block(name):
    return BEGIN + 'include ' + str(webuzo.SNIPPETS / (domain(name) + '.conf')) + ';\n' + END


def independent_limits(text, ancestors=frozenset()):
    """Inspect administrator includes as data, with the same no-link ownership checks."""
    nodes = webuzo.directives(text)
    if webuzo.has_limits(nodes):
        return True
    def includes(items):
        for key, args, children in items:
            if key == 'include':
                if len(args) != 1 or '$' in args[0]:
                    raise ValueError('Cannot inspect an independent Nginx include')
                path = Path(args[0])
                if not path.is_absolute():
                    path = webuzo.CONFIG.parent / path
                pattern = str(path)
                matches = sorted(glob.glob(pattern)) if glob.has_magic(pattern) else [pattern]
                for name in matches:
                    path = Path(name)
                    if path in ancestors:
                        raise ValueError('Recursive independent Nginx include')
                    raw = storage.read(path)
                    if raw is None:
                        raise ValueError('Independent Nginx include is missing: ' + str(path))
                    if independent_limits(raw.decode('utf-8'), ancestors | {path}):
                        return True
            if children is not None and includes(children):
                return True
        return False
    return includes(nodes)


def prepare(sites, manifest, remove=False):
    desired = {site['domain']: site for site in sites if site['supported']} if not remove else {}
    changes, next_manifest = [], {}
    for name in sorted(set(manifest) | set(desired)):
        domain(name)
        path = custom_path(webuzo.CUSTOM / (name + '.conf'))
        raw = storage.read(path)
        previous = None if raw is None else raw.decode('utf-8')
        text = previous or ''
        owned = block(name)
        if BEGIN in text or END in text:
            if text.count(owned) != 1 or text.count(BEGIN) != 1 or text.count(END) != 1:
                raise ValueError('The De-Noise custom include was changed: ' + str(path))
            if name not in manifest:
                raise ValueError('Unregistered De-Noise custom include: ' + str(path))
        elif name in manifest and not (name not in desired and previous is None):
            raise ValueError('A registered De-Noise custom include is missing: ' + str(path))
        clean = text.replace(owned, '')
        if name in desired:
            # Existing administrator directives continue to be interpreted by
            # Nginx. Never silently override an independent rate-limit policy.
            if independent_limits(clean, frozenset({path})):
                raise ValueError('Custom domain configuration already defines request limits: ' + name)
            if name in manifest:
                after = text
                entry = manifest[name]
            else:
                separator = '' if not text or text.endswith('\n') else '\n'
                after = text + separator + owned
                entry = {'created': previous is None, 'separator': separator}
            next_manifest[name] = entry
        else:
            entry = manifest[name]
            # Remove only our include. Preserve any later administrator edits.
            after = clean
            if entry.get('separator') and after.endswith('\n'):
                after = after[:-1]
            if entry.get('created') and after == '':
                after = None
        if after != previous:
            changes.append({'path': str(path), 'before': previous, 'after': after})
    return next_manifest, changes


def write(changes, restore=False):
    for change in changes:
        path = custom_path(change['path'])
        expected = change['after'] if restore else change['before']
        value = change['before'] if restore else change['after']
        current = storage.read(path)
        current = None if current is None else current.decode('utf-8')
        if current == value:
            continue
        if current != expected:
            raise ValueError('Custom configuration changed during the transaction: ' + str(path))
        storage.replace(path, None if value is None else value.encode())
