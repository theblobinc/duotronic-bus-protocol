#!/usr/bin/env python3
from __future__ import annotations
import copy,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3.profile_registry import ProfileRegistry,ProfileError
base=ProfileRegistry.from_directory(ROOT/'profiles');cases=json.loads((ROOT/'fixtures/invalid-profiles/cases.json').read_text())['cases']
for case in cases:
    docs=copy.deepcopy(base.docs);docs[case['target']].update(case.get('patch',{}))
    for n,p in case.get('parent_patch',{}).items():docs[n].update(p)
    r=ProfileRegistry(docs,security_suites=base.security_suites,fec_policies=base.fec_policies,fec_algorithms=base.fec_algorithms,known_record_names=base.known_record_names)
    try:r.resolve(case['target'])
    except ProfileError as e:
        if case['error'] not in str(e):raise AssertionError(f"{case['name']}: unexpected error {e}")
    else:raise AssertionError(f"{case['name']}: malformed profile unexpectedly resolved")
print(f'verified {len(cases)} semantic-negative profile cases')
