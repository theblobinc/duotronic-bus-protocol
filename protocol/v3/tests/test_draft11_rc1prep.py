import subprocess,sys
from pathlib import Path
import pytest
from dbp3 import (
    BootstrapBackoffPolicy,BootstrapController,BootstrapState,ProcessingBudgetError,
    AdmissionRequest,ResourceLimits,RuntimeKind,PlatformLimits,
    require_runtime_admission,require_platform_admission,AdmissionError,ProfileRegistry
)
ROOT=Path(__file__).resolve().parents[1]

def test_bootstrap_backoff_is_bounded_nonce_derived_and_clock_independent():
    p=BootstrapBackoffPolicy(initial_window_ms=25,max_window_ms=100,multiplier=2,max_attempts=3)
    b=BootstrapController('agent:a',7,3,b'n'*32,p)
    d0=b.begin();assert b.state is BootstrapState.DISCOVERY_BACKOFF and 0<=d0<=25
    assert d0==BootstrapController('agent:a',7,3,b'n'*32,p).begin()
    b.announce();d1=b.collision();assert b.state is BootstrapState.BACKOFF_RETRY and 0<=d1<=50
    b.announce();d2=b.collision();assert 0<=d2<=100
    b.announce()
    with pytest.raises(ProcessingBudgetError):b.collision()

def test_bootstrap_success_path_is_explicit():
    b=BootstrapController('agent:b',1,1,b'z'*32)
    b.begin();b.announce();b.negotiate();b.activate()
    assert b.state is BootstrapState.ACTIVE

def test_platform_admission_separates_runtime_heap_from_addressability_and_contiguous_limit():
    req=AdmissionRequest(frame_size=4096,max_records=16,concurrent_sessions=1,inflight_messages=2,fec_k=4,fec_n=6,fec_groups=1,group_fanout=2,merge_page_bytes=64*1024,merge_items=4,mailbox_items=4)
    lim=ResourceLimits(memory_bytes=64*1024*1024,cpu_tokens=1_000_000)
    est=require_runtime_admission(req,lim,RuntimeKind.RUST)
    p32=PlatformLimits(pointer_bits=32,allocator_ceiling_bytes=32*1024*1024,contiguous_allocation_ceiling_bytes=512*1024)
    adm=require_platform_admission(req,est,p32);assert adm.required_contiguous_bytes<=512*1024
    with pytest.raises(AdmissionError):require_platform_admission(req,est,PlatformLimits(pointer_bits=32,allocator_ceiling_bytes=256*1024,contiguous_allocation_ceiling_bytes=64*1024))

def test_profile_activation_can_enforce_platform_limits():
    r=ProfileRegistry.from_directory(ROOT/'profiles')
    req=AdmissionRequest(frame_size=512,max_records=8,concurrent_sessions=1,inflight_messages=1,fec_k=4,fec_n=6,fec_groups=1,group_fanout=1,merge_page_bytes=32*1024,merge_items=1,mailbox_items=1)
    lim=ResourceLimits(memory_bytes=64*1024*1024,cpu_tokens=1_000_000)
    with pytest.raises(AdmissionError):
        r.activate('baseline-secure',runtime=RuntimeKind.RUST,limits=lim,request=req,platform=PlatformLimits(pointer_bits=32,allocator_ceiling_bytes=128*1024,contiguous_allocation_ceiling_bytes=64*1024))

def test_vector_and_resolved_profile_generators_have_freshness_modes():
    subprocess.run([sys.executable,str(ROOT/'tools/generate_vectors.py'),'--check'],check=True)
    subprocess.run([sys.executable,str(ROOT/'tools/generate_resolved_profiles.py'),'--check'],check=True)

def test_ordered_generated_artifact_gate_runs_semantics_before_freshness():
    subprocess.run([sys.executable,str(ROOT/'tools/verify_generated_artifacts.py')],check=True)

def test_ci_contains_32bit_cross_compile_and_active_formal_gate():
    text=(ROOT/'.github/workflows/ci.yml').read_text()
    assert 'i686-unknown-linux-gnu' in text
    assert 'verify_formal_lock.py --strict' in text
    assert 'generate_vectors.py --check' in text
