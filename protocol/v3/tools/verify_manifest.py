#!/usr/bin/env python3
from __future__ import annotations
import hashlib,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
manifest=ROOT/'MANIFEST.sha256'
if not manifest.exists(): raise SystemExit('MANIFEST.sha256 missing')
for line in manifest.read_text().splitlines():
    if not line.strip(): continue
    want,rel=line.split('  ',1);p=ROOT/rel
    if not p.is_file(): raise SystemExit(f'manifest file missing: {rel}')
    got=hashlib.sha256(p.read_bytes()).hexdigest()
    if got!=want: raise SystemExit(f'manifest mismatch: {rel}')
print('repository checksum manifest verified')
