#!/usr/bin/env python3
"""Deterministic wire mutation + process watchdog smoke fuzzer.

Parent-owned deadlines convert parser stalls into failures. A second sustained
stream test proves that repeated malformed traffic is quarantined before it can
force unbounded expensive work. This complements, not replaces, AFL/libFuzzer.
"""
from __future__ import annotations
import json,multiprocessing as mp,pathlib,random,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3 import decode_frame,DevelopmentHMACProvider,PeerGuard,PeerState
meta=json.loads((ROOT/'vectors/manifest.json').read_text());key=bytes.fromhex(meta['development_key_hex']);seeds=[(ROOT/'vectors'/r['file']).read_bytes() for r in meta['valid']]

def mutate(buf:bytes,rng:random.Random)->bytes:
 b=bytearray(buf);total_bits=len(b)*8;count=min(rng.randint(1,8),total_bits)
 for bitpos in rng.sample(range(total_bits),count):i,bit=divmod(bitpos,8);b[i]^=1<<bit
 out=bytes(b);assert out!=buf;return out

def _batch(seed,seed_number,count,q):
 p=DevelopmentHMACProvider(key);rng=random.Random(seed_number);accepted=rejected=0
 for _ in range(count):
  try:decode_frame(mutate(seed,rng),p)
  except Exception:rejected+=1
  else:accepted+=1
 q.put((accepted,rejected))

def run_batch(seed,seed_number,count=100,timeout_s=3.0):
 q=mp.Queue(1);proc=mp.Process(target=_batch,args=(seed,seed_number,count,q),daemon=True);proc.start();proc.join(timeout_s)
 if proc.is_alive():proc.terminate();proc.join(1);raise RuntimeError('wire fuzz watchdog timeout: parser failed bounded progress')
 if proc.exitcode!=0 or q.empty():raise RuntimeError('wire fuzz child failed')
 return q.get()

def _sustained(seed,q):
 p=DevelopmentHMACProvider(key);rng=random.Random(0xBADBABB1);guard=PeerGuard(peer_id='fuzz-peer',max_invalid_per_window=8,window_ms=1000,quarantine_ms=10000)
 processed=dropped=0
 for i in range(5000):
  if not guard.allowed(i):dropped+=1;continue
  processed+=1
  try:decode_frame(mutate(seed,rng),p)
  except Exception:guard.observe_invalid(i)
 if guard.state is not PeerState.QUARANTINED:q.put(('bad-state',processed,dropped));return
 q.put(('ok',processed,dropped))

def sustained_quarantine(seed,timeout_s=3.0):
 q=mp.Queue(1);proc=mp.Process(target=_sustained,args=(seed,q),daemon=True);proc.start();proc.join(timeout_s)
 if proc.is_alive():proc.terminate();proc.join(1);raise RuntimeError('sustained malformed-stream watchdog timeout')
 if proc.exitcode!=0 or q.empty():raise RuntimeError('sustained malformed-stream child failed')
 state,processed,dropped=q.get()
 if state!='ok' or processed>8 or dropped<4900:raise RuntimeError(f'quarantine did not bound malformed stream: {state=} {processed=} {dropped=}')
 return processed,dropped

def main():
 accepted=rejected=0
 for n,seed in enumerate(seeds):
  for batch in range(5):
   a,r=run_batch(seed,0xDB030000+n*31+batch,100,3.0);accepted+=a;rejected+=r
 if accepted:raise SystemExit(f'mutation fuzz unexpectedly accepted {accepted} corrupted frames')
 processed,dropped=sustained_quarantine(seeds[0])
 print(f'mutation fuzz watchdog: rejected={rejected} accepted={accepted} timeouts=0; sustained processed={processed} quarantined_drops={dropped}')
if __name__=='__main__':main()
