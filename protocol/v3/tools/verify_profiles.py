#!/usr/bin/env python3
from __future__ import annotations
import json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3.profile_registry import ProfileRegistry
from dbp3.generated_registry import RECORD_TYPES
profiles=ROOT/'profiles';required={'id','name','protected','suite','fec','max_records','replay_window','frame_sizes'};all_record_names=set(RECORD_TYPES.values())
for p in profiles.glob('*.json'):
    if p.name in {'registry.json','privacy.json','resilience.json'}:continue
    d=json.loads(p.read_text());missing=required-set(d)
    if missing:raise AssertionError(f'{p.name}: missing required profile fields {sorted(missing)}')
    if not isinstance(d['id'],int) or not 1<=d['id']<=65535:raise AssertionError(f'{p.name}: id outside u16')
    if not isinstance(d['protected'],bool):raise AssertionError(f'{p.name}: protected must be boolean')
    if not 1<=int(d['max_records'])<=128:raise AssertionError(f'{p.name}: max_records')
    if not 32<=int(d['replay_window'])<=65536:raise AssertionError(f'{p.name}: replay_window')
    if not d['frame_sizes'] or len(d['frame_sizes'])!=len(set(d['frame_sizes'])):raise AssertionError(f'{p.name}: frame sizes')
    unknown=set(d.get('record_names',[]))-all_record_names
    if unknown:raise AssertionError(f'{p.name}: unregistered record names {sorted(unknown)}')
r=ProfileRegistry.from_directory(profiles)
resolved={name:r.resolve(name) for name in r.docs}
for p in resolved.values():
    assert p.frame_sizes and p.security_suite and p.fec_policy and p.manifest_digest and p.record_names
assert resolved['dbp3-ai-free-1'].closure==('baseline-secure','dbp3-comms-1','dbp3-ai-comms-1','dbp3-ai-free-1')
assert resolved['xavi-utm'].closure==('baseline-secure','dbp3-comms-1','dbp3-ai-comms-1','dbp3-ai-free-1','xavi-utm')
assert resolved['wg-rnn'].closure==('baseline-secure','dbp3-comms-1','dbp3-ai-comms-1','dbp3-ai-free-1','wg-rnn')
assert {'utm-aircraft-state','utm-human-decision','agent-consent','voice','object-chunk'}<=resolved['xavi-utm'].record_names
assert {'wgrnn-observation','wgrnn-gate-receipt','agent-proposal','text','object-chunk'}<=resolved['wg-rnn'].record_names
comp=json.loads((ROOT/'schemas/profile-composition.json').read_text())
for row in comp['profiles']:
    assert tuple(r.docs[row['name']].get('extends',[]))==tuple(row['extends'])
idx=json.loads((profiles/'registry.json').read_text());seen_ids=set();seen_names=set()
for row in idx['profiles']:
    if row['id'] in seen_ids or row['name'] in seen_names:raise AssertionError('duplicate profile index id/name')
    seen_ids.add(row['id']);seen_names.add(row['name']);d=json.loads((profiles/row['file']).read_text())
    if d['id']!=row['id'] or d['name']!=row['name']:raise AssertionError(f"profile index mismatch: {row['name']}")
if seen_names!=set(r.docs):raise AssertionError('profile index and operational profile files differ')
print(f'profile semantics verified for {len(r.docs)} operational profiles')
