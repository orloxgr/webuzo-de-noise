"""Own only a delimited include in Webuzo's documented custom domain files."""
from pathlib import Path
import glob
import stat

import storage
import webuzo
import webmail
from policy import domain

BEGIN = '# BEGIN Webuzo De-Noise\n'
END = '# END Webuzo De-Noise\n'
HTTP = '@http'
MAIL = '@webmail'


def custom_path(value):
    path = Path(value)
    if path in (webuzo.GLOBAL_CUSTOM, webmail.CUSTOM):
        return path
    if path.parent != webuzo.CUSTOM or not path.name.endswith('.conf'):
        raise ValueError('Invalid custom configuration destination')
    domain(path.name[:-5])
    return path


def block(name, target=None):
    if name == HTTP:
        return BEGIN + 'include ' + str(webuzo.GLOBAL) + ';\n' + END
    if name == MAIL:
        return BEGIN + 'include ' + str(webmail.SNIPPET) + ';\n' + END
    return BEGIN + 'include ' + str(webuzo.SNIPPETS / (domain(target or name) + '.conf')) + ';\n' + END


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


def prepare(sites, manifest, remove=False, mail=False):
    desired = {name: site for site in sites if site['supported'] and not site.get('shared_webmail')
               for name in site.get('custom_domains', [site['domain']])} if not remove else {}
    if not remove:
        desired[HTTP] = None
        if mail:
            desired[MAIL] = None
    changes, next_manifest = [], {}
    for name in sorted(set(manifest) | set(desired)):
        if name not in (HTTP, MAIL):
            domain(name)
        path = custom_path(webuzo.GLOBAL_CUSTOM if name == HTTP else webmail.CUSTOM if name == MAIL
                           else webuzo.CUSTOM / (name + '.conf'))
        raw = storage.read(path)
        info = path.lstat() if raw is not None else None
        previous = None if raw is None else raw.decode('utf-8')
        text = previous or ''
        owned = block(name, manifest.get(name, {}).get('site', name))
        if BEGIN in text or END in text:
            if text.count(owned) != 1 or text.count(BEGIN) != 1 or text.count(END) != 1:
                raise ValueError('The De-Noise custom include was changed: ' + str(path))
            if name not in manifest:
                raise ValueError('Unregistered De-Noise custom include: ' + str(path))
        elif name in manifest and not (name not in desired and previous is None):
            raise ValueError('A registered De-Noise custom include is missing: ' + str(path))
        clean = text.replace(owned, '')
        if name in desired:
            target = name if name in (HTTP, MAIL) else domain(desired[name]['domain'])
            next_block = block(name, target)
            # Existing administrator directives continue to be interpreted by
            # Nginx. Never silently override an independent rate-limit policy.
            if name not in (HTTP, MAIL) and independent_limits(clean, frozenset({path})):
                raise ValueError('Custom domain configuration already defines request limits: ' + name)
            if name in manifest:
                after = text.replace(owned, next_block)
                entry = {**manifest[name], 'site': target}
            else:
                separator = '' if not text or text.endswith('\n') else '\n'
                after = text + separator + next_block
                entry = {'created': previous is None, 'separator': separator, 'site': target}
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
            changes.append({'path': str(path), 'before': previous, 'after': after,
                            'mode': stat.S_IMODE(info.st_mode) if info is not None else 0o644,
                            'gid': info.st_gid if info is not None else 0})
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
        mode, gid = change.get('mode', 0o644), change.get('gid', 0)
        if type(mode) is not int or mode & ~0o777 or mode & 0o022:
            raise ValueError('Invalid custom configuration recovery permissions')
        storage.replace(path, None if value is None else value.encode(), mode, gid=gid)
