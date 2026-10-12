#!/usr/bin/env python3
from __future__ import annotations
import json,pathlib,subprocess,sys,shutil
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3 import decode_frame,DevelopmentHMACProvider,AdmissionRequest,RuntimeKind,estimate_runtime_cost
from dbp3.generated_registry import RECORD_TYPES,SECURITY_SUITE_IDS,SECURITY_SUITE_STATUS,FEC_ALGORITHM_IDS,FEC_ALGORITHM_STATUS
meta=json.loads((ROOT/'vectors/manifest.json').read_text());key=meta['development_key_hex'];p=DevelopmentHMACProvider(bytes.fromhex(key))
if not shutil.which('cargo'):
    print('cargo unavailable: differential vectors skipped locally');raise SystemExit(0)
crate=ROOT/'rust/dbp3-ref'
# Generated registry parity is part of the differential contract, not a separate assumption.
cp=subprocess.run(['cargo','run','--quiet','--manifest-path',str(crate/'Cargo.toml'),'--bin','dbp3-conformance','--','--registry'],text=True,capture_output=True)
if cp.returncode:raise AssertionError('Rust registry snapshot failed: '+cp.stderr)
rr=json.loads(cp.stdout)
want_records=[[i,n] for i,n in sorted(RECORD_TYPES.items())]
want_suites=[[n,i,SECURITY_SUITE_STATUS[n]] for n,i in sorted(SECURITY_SUITE_IDS.items())]
want_fec=[[n,i,FEC_ALGORITHM_STATUS[n]] for n,i in sorted(FEC_ALGORITHM_IDS.items())]
assert rr['records']==want_records,'generated record registry parity mismatch'
assert rr['security_suites']==want_suites,'generated security-suite parity mismatch'
assert rr['fec_algorithms']==want_fec,'generated FEC registry parity mismatch'

# Cross-language resource accounting parity is checked for the Rust model only.
# Python intentionally uses a different runtime multiplier.
for req in [
 AdmissionRequest(frame_size=256,max_records=16,concurrent_sessions=1,inflight_messages=4,fec_k=2,fec_n=3,fec_groups=2,group_fanout=2,merge_page_bytes=4096,merge_items=8,mailbox_items=8),
 AdmissionRequest(frame_size=1024,max_records=48,concurrent_sessions=4,inflight_messages=32,fec_k=8,fec_n=12,fec_groups=8,group_fanout=16,merge_page_bytes=262144,merge_items=128,mailbox_items=64),
 AdmissionRequest(frame_size=4096,max_records=64,concurrent_sessions=8,inflight_messages=64,fec_k=8,fec_n=12,fec_groups=16,group_fanout=32,merge_page_bytes=1048576,merge_items=256,mailbox_items=128),
]:
 vals=[req.frame_size,req.max_records,req.concurrent_sessions,req.inflight_messages,req.fec_k,req.fec_n,req.fec_groups,req.group_fanout,req.merge_page_bytes,req.merge_items,req.mailbox_items]
 cp=subprocess.run(['cargo','run','--quiet','--manifest-path',str(crate/'Cargo.toml'),'--bin','dbp3-conformance','--','--estimate',*map(str,vals)],text=True,capture_output=True)
 if cp.returncode:raise AssertionError('Rust resource estimate failed: '+cp.stderr)
 rr_est=json.loads(cp.stdout);py_est=estimate_runtime_cost(req,RuntimeKind.RUST)
 assert rr_est=={'estimated_heap_bytes':py_est.estimated_heap_bytes,'estimated_cpu_tokens':py_est.estimated_cpu_tokens,'minimum_working_set_bytes':py_est.minimum_working_set_bytes,'cost_model_version':py_est.cost_model_version},'Rust resource cost-model parity mismatch'

def py_shape(f):
 h=f.header
 return {'frame_size':f.frame_size,'header':{'flags':h.flags,'frame_kind':h.frame_kind,'profile_id':h.profile_id,'sequence':h.sequence,'session_epoch':h.session_epoch,'stream_id':h.stream_id,'message_id':h.message_id,'source_time_us':h.source_time_us,'observed_time_us':h.observed_time_us,'time_uncertainty_us':h.time_uncertainty_us,'body_used':sum(len(x.encode()) for x in f.records),'record_count':len(f.records),'path_id':h.path_id,'qos':h.qos,'priority':h.priority},'suite_id':p.suite_id,'security_mode':1,'key_epoch':h.key_epoch,'fec':[h.fec_scheme,h.fec_k,h.fec_n,h.fec_index],'records':[{'type_id':x.type_id,'flags':x.flags,'codec':x.codec,'qos':x.qos,'priority':x.priority,'channel':x.channel,'message_id':x.message_id,'fragment_index':x.fragment_index,'fragment_count':x.fragment_count,'payload_len':len(x.payload),'deadline_ms':x.deadline_ms} for x in f.records]}
for row in meta['valid']:
 path=ROOT/'vectors'/row['file'];py=decode_frame(path.read_bytes(),p)
 cp=subprocess.run(['cargo','run','--quiet','--manifest-path',str(crate/'Cargo.toml'),'--bin','dbp3-conformance','--',str(path),key],text=True,capture_output=True)
 if cp.returncode:raise AssertionError(f'Rust rejected valid {path.name}: {cp.stderr}')
 assert json.loads(cp.stdout)==py_shape(py),f'structural decode mismatch for {path.name}'
for row in meta['invalid']:
 path=ROOT/'vectors'/row['file'];py_ok=True
 try:decode_frame(path.read_bytes(),p)
 except Exception:py_ok=False
 cp=subprocess.run(['cargo','run','--quiet','--manifest-path',str(crate/'Cargo.toml'),'--bin','dbp3-conformance','--',str(path),key],text=True,capture_output=True)
 rust_ok=cp.returncode==0
 if py_ok or rust_ok:raise AssertionError(f'invalid parity failure {path.name}: python={py_ok} rust={rust_ok}')
print('Python/Rust generated-registry + structural differential parity verified')
