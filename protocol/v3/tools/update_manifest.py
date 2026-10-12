#!/usr/bin/env python3
from __future__ import annotations
import hashlib,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
exclude={'MANIFEST.sha256'}
rows=[]
for p in sorted(x for x in ROOT.rglob('*') if x.is_file()):
    rel=p.relative_to(ROOT).as_posix()
    if rel in exclude or '/__pycache__/' in f'/{rel}/' or rel.startswith('.pytest_cache/') or rel.endswith('.pyc') or '/target/' in f'/{rel}/': continue
    rows.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}')
(ROOT/'MANIFEST.sha256').write_text('\n'.join(rows)+'\n')
print(f'manifest updated for {len(rows)} files')
