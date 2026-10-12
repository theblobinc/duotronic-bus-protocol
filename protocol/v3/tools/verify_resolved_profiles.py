#!/usr/bin/env python3
from __future__ import annotations
import json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3 import ProfileRegistry
r=ProfileRegistry.from_directory(ROOT/'profiles')
for name in sorted(r.docs):
    path=ROOT/'fixtures/resolved-profiles'/f'{name}.json'
    want=r.resolve(name).manifest();got=json.loads(path.read_text())
    if got!=want: raise SystemExit(f'resolved profile drift: {name}; regenerate with tools/generate_resolved_profiles.py')
print(f'verified {len(r.docs)} canonical resolved profile manifests')
