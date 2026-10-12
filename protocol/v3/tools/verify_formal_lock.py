#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser();ap.add_argument('--strict',action='store_true');args=ap.parse_args()
lock=json.loads((ROOT/'formal/model-lock.json').read_text())
for p,want in lock['files'].items():
    got=hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
    if got!=want: raise SystemExit(f'FORMAL DRIFT: {p}; review implementation + formal models before regenerating the lock')
print(f'formal/executable drift lock verified for {len(lock["files"])} artifacts')
subprocess.run([sys.executable,str(ROOT/'tools/run_formal_checks.py')]+(['--strict'] if args.strict else []),check=True)
