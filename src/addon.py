#!/usr/bin/python3
"""Root bridge; installed wrapper starts Python in isolated mode."""
import json
from pathlib import Path
import sys

# A panel ZIP update can preserve source timestamps. Compile our modules from
# source instead of reusing an older installation's timestamp-based bytecode.
sys.dont_write_bytecode = True
sys.pycache_prefix = str(Path(__file__).resolve().parent / '.bytecode')
sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine import main

if __name__ == '__main__':
    try:
        print(json.dumps(main()))
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__, 'error': str(error)}))
        raise SystemExit(1)
