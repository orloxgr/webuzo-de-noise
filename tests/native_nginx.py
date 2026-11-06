"""Keep compiled-in Nginx temporary paths outside the hosting installation."""
from pathlib import Path
import re


def isolated_config(text, directory):
    root = Path(directory).resolve() / 'nginx-temporary'
    root.mkdir(mode=0o755, exist_ok=True)
    def path(kind):
        return str(root / kind).replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')
    directives = '\n'.join(name + '_temp_path "' + path(name) + '";'
                           for name in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'))
    directives += '\naccess_log off;'
    result, count = re.subn(r'\bhttp\s*\{', lambda match: match.group(0) + '\n' + directives + '\n', text, count=1)
    if count != 1:
        raise ValueError('An isolated Nginx fixture requires an HTTP block')
    if not re.search(r'\berror_log\s', result):
        result = 'error_log "' + path('error.log') + '";\n' + result
    return result
