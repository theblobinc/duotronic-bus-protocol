#!/usr/bin/env python3
from __future__ import annotations
import pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]

def run(*args):subprocess.run([sys.executable,*map(str,args)],cwd=ROOT,check=True)
# Ordering is intentional: semantic inputs must validate before freshness is checked.
run(ROOT/'tools/verify_profiles.py')
run(ROOT/'tools/verify_negative_profiles.py')
run(ROOT/'tools/generate_registry_code.py','--check')
run(ROOT/'tools/generate_vectors.py','--check')
run(ROOT/'tools/generate_resolved_profiles.py','--check')
run(ROOT/'tools/verify_registry_coherence.py')
run(ROOT/'tools/verify_resolved_profiles.py')
print('ordered deterministic-artifact gate passed')
