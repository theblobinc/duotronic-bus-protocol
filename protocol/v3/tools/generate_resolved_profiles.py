#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,pathlib,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3 import ProfileRegistry

def generate(out:pathlib.Path):
    r=ProfileRegistry.from_directory(ROOT/'profiles');out.mkdir(parents=True,exist_ok=True)
    for old in out.glob('*.json'):old.unlink()
    for name in sorted(r.docs):
        m=r.resolve(name).manifest();(out/f'{name}.json').write_text(json.dumps(m,indent=2,sort_keys=True)+'\n')
    return len(r.docs)

def compare(expected:pathlib.Path,actual:pathlib.Path):
    a={p.name:p.read_bytes() for p in expected.glob('*.json')};b={p.name:p.read_bytes() for p in actual.glob('*.json')}
    if a.keys()!=b.keys():raise SystemExit('resolved-profile fixture set is stale')
    stale=[k for k in a if a[k]!=b[k]]
    if stale:raise SystemExit('stale resolved profiles: '+', '.join(sorted(stale)))

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--check',action='store_true');a=ap.parse_args();target=ROOT/'fixtures/resolved-profiles'
    if a.check:
        with tempfile.TemporaryDirectory() as td:
            tmp=pathlib.Path(td);n=generate(tmp);compare(tmp,target)
        print(f'resolved-profile freshness verified: {n}')
    else:
        n=generate(target);print(f'generated {n} resolved profile manifests')
