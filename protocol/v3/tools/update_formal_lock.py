#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser();ap.add_argument('--skip-formal-checks',action='store_true',help='bootstrap hashes only; strict CI still runs all formal tools');a=ap.parse_args()
if not a.skip_formal_checks:
    subprocess.run([sys.executable,str(ROOT/'tools/run_formal_checks.py'),'--strict'],check=True)
cov=json.loads((ROOT/'formal/MODEL-COVERAGE.json').read_text());paths=set()
for m in cov['mappings']:paths.update(m['implementation']);paths.update(m['formal'])
for ext in ('*.tla','*.cfg','lean/*.lean'):paths.update(str(x.relative_to(ROOT)) for x in (ROOT/'formal').glob(ext))
paths.update(['formal/MODEL-COVERAGE.json','schemas/wire-abi.json','schemas/profile-composition.json','schemas/record-registry.json','schemas/algorithm-registry.json','registries/security-suites.json','registries/fec-policies.json','tools/run_formal_checks.py','tools/verify_formal_lock.py','tools/update_formal_lock.py','tools/generate_registry_code.py','tools/verify_registry_coherence.py'])
def h(rel):return hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()
out={'schema':'dbp3-formal-lock/v3','note':'Drift lock only. update_formal_lock runs strict formal tools by default; --skip-formal-checks is bootstrap-only and release CI still executes strict TLA+/Lean gates.','files':{rel:h(rel) for rel in sorted(paths)}}
(ROOT/'formal/model-lock.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(f'formal lock updated for {len(paths)} artifacts')
