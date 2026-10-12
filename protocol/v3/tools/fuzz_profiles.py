#!/usr/bin/env python3
"""Deterministic semantic profile mutation fuzzer with process watchdog."""
from __future__ import annotations
import copy,multiprocessing as mp,pathlib,random,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3.profile_registry import ProfileRegistry,ProfileError

def worker(seed,count,q):
 base=ProfileRegistry.from_directory(ROOT/'profiles');rng=random.Random(seed);ok=reject=0
 suites=list(base.security_suites)+['unknown-suite'];fecs=list(base.fec_policies)+['unknown-fec'];frames=[256,512,1024,2048,4096]
 for _ in range(count):
  docs=copy.deepcopy(base.docs);d=docs['dbp3-ai-free-1'];choice=rng.randrange(7)
  if choice==0:d['suite']=rng.choice(suites)
  elif choice==1:d['fec']=rng.choice(fecs)
  elif choice==2:d['max_records']=rng.choice([-1,0,1,64,128,129,1<<40])
  elif choice==3:d['replay_window']=rng.choice([0,31,32,2048,65536,65537,1<<40])
  elif choice==4:d['frame_sizes']=rng.choice([[256],[4096],[123],[256,256],[]])
  elif choice==5:d['protected']=rng.choice([True,False])
  else:d['record_names']=rng.choice([['agent-consent'],['unknown-record'],[]])
  r=ProfileRegistry(docs,security_suites=base.security_suites,fec_policies=base.fec_policies,fec_algorithms=base.fec_algorithms,known_record_names=base.known_record_names)
  try:
   p=r.resolve('dbp3-ai-free-1');m=p.manifest();assert 1<=m['profile_id']<=65535 and m['frame_sizes'] and m['digest']==r.resolve('dbp3-ai-free-1').manifest_digest;ok+=1
  except (ProfileError,ValueError,AssertionError):reject+=1
 q.put((ok,reject))

def main():
 q=mp.Queue(1);p=mp.Process(target=worker,args=(0xDB0310,3000,q),daemon=True);p.start();p.join(4.0)
 if p.is_alive():p.terminate();p.join(1);raise SystemExit('profile fuzz watchdog timeout')
 if p.exitcode!=0 or q.empty():raise SystemExit('profile fuzz child failed')
 ok,reject=q.get();print(f'profile semantic fuzz: canonical={ok} rejected={reject} timeouts=0')
if __name__=='__main__':main()
