import json
from pathlib import Path
import pytest

from dbp3 import (
    ProfileRegistry, ProfileError, ResourceLimits, AdmissionRequest, AdmissionError, RuntimeKind,
    require_runtime_admission, MergeItem, MergeCursor, reconcile_page, PeerGuard, PeerState,
    SupervisorContract, SupervisorAction, WitnessQuorum, QuorumStatus, GroupEpoch, GroupPolicy,
    GroupMemberCapabilities, GroupError,
)
from dbp3.fec import encode,recover,estimate_workspace_bytes,FECWorkspaceError

ROOT=Path(__file__).resolve().parents[1]
SUITE='xavi-pq1-shake256-512-mldsa87-mlkem1024-kmac256-aes256gcmsiv'

def registry(): return ProfileRegistry.from_directory(ROOT/'profiles')

def test_resolved_profile_is_canonical_and_complete():
    p=registry().resolve('dbp3-ai-free-1')
    m=p.manifest()
    assert m['protected'] is True and m['fec_policy']=='adaptive-gf256'
    assert m['max_records']==64 and m['replay_window']==2048
    assert len(m['digest'])==64 and m['digest']==registry().resolve('dbp3-ai-free-1').manifest_digest

def test_profile_activation_requires_runtime_admission():
    r=registry()
    with pytest.raises((AdmissionError,ValueError)):
        r.activate('dbp3-ai-free-1',runtime=RuntimeKind.PYTHON,limits=ResourceLimits(memory_bytes=64*1024,cpu_tokens=100_000))

def test_runtime_costs_are_not_assumed_equal():
    req=AdmissionRequest(frame_size=4096,max_records=64,concurrent_sessions=8,inflight_messages=64,fec_k=8,fec_n=12,group_fanout=32,merge_page_bytes=1024*1024,mailbox_items=128)
    lim=ResourceLimits(memory_bytes=256*1024*1024,cpu_tokens=1_000_000)
    py=require_runtime_admission(req,lim,RuntimeKind.PYTHON)
    rs=require_runtime_admission(req,lim,RuntimeKind.RUST)
    assert py.estimated_heap_bytes > rs.estimated_heap_bytes and py.estimated_cpu_tokens > rs.estimated_cpu_tokens

def test_fec_zero_or_subminimum_workspace_fails_closed():
    shards=[b'abcd',b'efgh']
    need=estimate_workspace_bytes(2,3,4)
    with pytest.raises(FECWorkspaceError): encode(shards,3,workspace_bytes=0)
    coded=encode(shards,3,workspace_bytes=need)
    with pytest.raises(FECWorkspaceError): recover({0:coded[0],2:coded[2]},2,3,workspace_bytes=need-1)
    assert recover({0:coded[0],2:coded[2]},2,3,workspace_bytes=need)==shards

def test_oversized_merge_item_eventually_converges_by_chunks():
    row=MergeItem('big','bulk',1,25,b'abcdefghijklmnopqrstuvwxyz'[:25])
    cur=None;out=b'';digest=None
    for _ in range(10):
        page=reconcile_page([row],cursor=cur,max_items=2,max_bytes=8)
        digest=digest or page.snapshot_digest
        assert page.snapshot_digest==digest and page.bytes_used<=8
        out+=b''.join(x.payload for x in page.segments)
        cur=page.next_cursor
        if cur is None: break
    assert cur is None and out==row.payload

def test_merge_cursor_is_snapshot_bound():
    a=[MergeItem('x','state',1,4,b'abcd')]
    p=reconcile_page(a,max_items=1,max_bytes=2)
    with pytest.raises(ValueError): reconcile_page([MergeItem('x','state',1,4,b'abce')],cursor=p.next_cursor,max_items=1,max_bytes=2)

def test_noisy_peer_cooldown_does_not_bypass_authenticated_readmission():
    g=PeerGuard(max_invalid_per_window=3,window_ms=100,quarantine_ms=200)
    assert g.observe_invalid(0)==PeerState.DEGRADED
    g.observe_invalid(10); assert g.observe_invalid(20)==PeerState.QUARANTINED
    assert not g.allowed(100)
    assert g.readmission_eligible(221)
    assert not g.allowed(221)  # cooldown only permits a challenge; it never re-admits by itself

def test_supervisor_contract_is_fail_silent_before_restart():
    s=SupervisorContract(heartbeat_timeout_ms=100,isolate_before_restart=True)
    assert s.evaluate(now_ms=50,last_heartbeat_ms=0)==SupervisorAction.HEALTHY
    assert s.evaluate(now_ms=101,last_heartbeat_ms=0)==SupervisorAction.ISOLATE
    assert s.evaluate(now_ms=101,last_heartbeat_ms=0,already_isolated=True)==SupervisorAction.RESTART

def test_witness_loss_never_lowers_quorum_threshold():
    q=WitnessQuorum(frozenset({'a','b','c'}),2)
    assert q.approve('a')==QuorumStatus.PENDING
    assert q.mark_unavailable('b')==QuorumStatus.PENDING
    assert q.mark_unavailable('c')==QuorumStatus.IMPOSSIBLE
    assert q.threshold==2

def test_group_rejects_suite_mismatch_before_membership():
    gp=GroupPolicy(SUITE,max_members=4)
    g=GroupEpoch('g',policy=gp)
    with pytest.raises(GroupError): g.admit_member(GroupMemberCapabilities('x','development-hmac'))
    assert not g.members

def test_group_multicast_uses_common_frame_and_bounded_recovery():
    gp=GroupPolicy(SUITE,max_members=4,max_fanout=4,max_fragments=64,max_parallel_recovery_groups=4)
    g=GroupEpoch('g',policy=gp)
    g.admit_member(GroupMemberCapabilities('a',SUITE,(256,512),max_recovery_groups=2,supported_records=frozenset({'text'})))
    g.admit_member(GroupMemberCapabilities('b',SUITE,(512,1024),max_recovery_groups=3,supported_records=frozenset({'text'})))
    p=g.plan_multicast(1000,record_name='text')
    assert p.frame_size==512 and p.recovery_concurrency==2 and p.recipients==2 and p.fragments<=64

def test_group_fanout_budget_fails_closed():
    gp=GroupPolicy(SUITE,max_members=3,max_fanout=1)
    g=GroupEpoch('g',policy=gp)
    g.admit_member(GroupMemberCapabilities('a',SUITE,supported_records=frozenset({'text'})));g.admit_member(GroupMemberCapabilities('b',SUITE,supported_records=frozenset({'text'})))
    with pytest.raises(GroupError): g.plan_multicast(10,record_name='text')

def test_security_registry_ids_are_coherent():
    a=json.loads((ROOT/'schemas/algorithm-registry.json').read_text())
    b=json.loads((ROOT/'registries/security-suites.json').read_text())
    assert {x['name']:(x['id'],x['status']) for x in a['security_suites']} == {x['name']:(x['id'],x['status']) for x in b['suites']}

def test_fec_policy_resolves_to_registered_algorithm():
    a={x['name'] for x in json.loads((ROOT/'schemas/algorithm-registry.json').read_text())['fec']}
    for p in json.loads((ROOT/'registries/fec-policies.json').read_text())['policies']:
        assert p['algorithm'] in a

def test_ai_free_profile_is_extension_not_exclusion():
    p=registry().resolve('dbp3-ai-free-1')
    assert p.closure==('baseline-secure','dbp3-comms-1','dbp3-ai-comms-1','dbp3-ai-free-1')
    assert {'call-invite','agent-proposal','agent-consent'} <= p.record_names

def test_unknown_registered_profile_record_names_are_forbidden_by_verifier_contract():
    r=registry()
    with pytest.raises(ProfileError): r.accepts_record('dbp3-ai-free-1','not-a-registered-critical-record',critical=True)
