#!/usr/bin/env python3
from __future__ import annotations
import json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
subprocess.run([sys.executable,str(ROOT/'tools/generate_registry_code.py'),'--check'],check=True)
from dbp3.generated_registry import RECORD_TYPES,SECURITY_SUITE_IDS,SECURITY_SUITE_STATUS,FEC_ALGORITHM_IDS,FEC_ALGORITHM_STATUS

def bounded(v,bits,label,*,minimum=0):
    if not isinstance(v,int) or not (minimum<=v<=(1<<bits)-1): raise AssertionError(f'{label} outside u{bits}: {v!r}')

def unique(rows,label):
    ids=[x['id'] for x in rows];names=[x['name'] for x in rows]
    if len(ids)!=len(set(ids)) or len(names)!=len(set(names)): raise AssertionError(f'duplicate {label} id/name')

records={int(k):v for k,v in json.loads((ROOT/'schemas/record-registry.json').read_text())['records'].items()}
for i,n in records.items(): bounded(i,16,f'record {n}',minimum=1)
assert RECORD_TYPES==records,'Python generated record registry drift'
alg=json.loads((ROOT/'schemas/algorithm-registry.json').read_text());sec_doc=json.loads((ROOT/'registries/security-suites.json').read_text())
unique(alg['security_suites'],'algorithm security suite');unique(sec_doc['suites'],'security suite');unique(alg['fec'],'FEC algorithm')
for x in alg['security_suites']:bounded(x['id'],16,f"security suite {x['name']}",minimum=1)
for x in alg['fec']:bounded(x['id'],8,f"FEC {x['name']}")
alg_suites={x['name']:int(x['id']) for x in alg['security_suites']};sec={x['name']:int(x['id']) for x in sec_doc['suites']}
assert alg_suites==sec==SECURITY_SUITE_IDS,'security-suite registry ID drift'
alg_status={x['name']:x['status'] for x in alg['security_suites']};sec_status={x['name']:x['status'] for x in sec_doc['suites']}
assert alg_status==sec_status==SECURITY_SUITE_STATUS,'security-suite status drift'
fec={x['name']:int(x['id']) for x in alg['fec']};fec_st={x['name']:x['status'] for x in alg['fec']}
assert fec==FEC_ALGORITHM_IDS and fec_st==FEC_ALGORITHM_STATUS
pol=json.loads((ROOT/'registries/fec-policies.json').read_text())['policies'];names={p['name'] for p in pol}
for p in pol:
    if p['algorithm'] not in fec:raise AssertionError(f"unregistered FEC algorithm in policy {p['name']}")
    bounded(int(p['min_k']),8,f"{p['name']} min_k")
    bounded(int(p['max_n']),8,f"{p['name']} max_n")
    if p['algorithm']=='none':
        if p['min_k']!=0 or p['max_n']!=0:raise AssertionError('none FEC policy bounds')
    elif not (1<=p['min_k']<=p['max_n']<=255):raise AssertionError(f"invalid FEC policy bounds {p['name']}")
    parent=p.get('extends')
    if parent and parent not in names:raise AssertionError(f"unknown FEC parent {parent}")
# Validate wire ABI widths/offsets and reject overlaps or width/type disagreement.
abi=json.loads((ROOT/'schemas/wire-abi.json').read_text());sizes={'u8':1,'u16':2,'u32':4,'u64':8}
for section,total in (('header_fields',abi['header_size']),('trailer_fields',abi['trailer_size'])):
    used=set()
    for name,off,width,typ in abi[section]:
        if not all(isinstance(x,int) for x in (off,width)) or off<0 or width<1 or off+width>total:raise AssertionError(f'ABI range {name}')
        if typ in sizes and sizes[typ]!=width:raise AssertionError(f'ABI width/type mismatch {name}')
        cells=set(range(off,off+width))
        if used&cells:raise AssertionError(f'ABI overlap {name}')
        used|=cells
# Profile/index IDs are wire u16.
idx=json.loads((ROOT/'profiles/registry.json').read_text())['profiles'];unique(idx,'profile')
for row in idx:bounded(int(row['id']),16,f"profile {row['name']}",minimum=1)
print(f'registry coherence verified: {len(records)} records, {len(sec)} suites, {len(fec)} FEC algorithms, ABI widths/ranges clean')
