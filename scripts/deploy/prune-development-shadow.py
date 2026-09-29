#!/usr/bin/env python3
"""Remove only reproducible normalized copies; keep evidence and run summaries."""
import argparse
import json
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True)
parser.add_argument('--apply', action='store_true')
args = parser.parse_args()
root = Path(args.root).resolve()
cutoff = time.time() - 86400
files = sorted(p for p in root.glob('*/normalized.jsonl')
               if not p.parent.is_symlink() and not p.is_symlink()
               and p.is_file() and p.stat().st_mtime < cutoff)
report = {'mode': 'apply' if args.apply else 'preview', 'files': len(files),
          'bytes': sum(p.stat().st_size for p in files),
          'removed': 0, 'timestamp': time.time()}
for p in files:
    if args.apply:
        p.unlink()
        report['removed'] += 1
print(json.dumps(report))
