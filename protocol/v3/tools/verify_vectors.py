#!/usr/bin/env python3
import json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from dbp3 import decode_frame, DevelopmentHMACProvider
meta=json.loads((ROOT/'vectors/manifest.json').read_text())
p=DevelopmentHMACProvider(bytes.fromhex(meta['development_key_hex']))
for row in meta['valid']:
    raw=(ROOT/'vectors'/row['file']).read_bytes(); f=decode_frame(raw,p); assert f.frame_size==row['frame_size']; assert [r.type_id for r in f.records]==row['record_types']
for row in meta['invalid']:
    raw=(ROOT/'vectors'/row['file']).read_bytes()
    try: decode_frame(raw,p)
    except Exception: pass
    else: raise AssertionError(f"invalid vector accepted: {row['file']}")
print(f"verified {len(meta['valid'])} valid and {len(meta['invalid'])} invalid golden vectors")
