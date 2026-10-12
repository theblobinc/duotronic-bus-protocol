import hashlib,json,subprocess,sys
from pathlib import Path
import pytest
from dbp3 import *
from dbp3.fec import encode,recover,estimate_workspace_bytes,estimate_encode_work_units,FECWorkLimitError
from dbp3.records import Record
from dbp3.frame import Header,Frame,encode_frame
from dbp3.security import DevelopmentHMACProvider
from dbp3.quarantine import ReadmissionProof
ROOT=Path(__file__).resolve().parents[1]
SUITE='xavi-pq1-shake256-512-mldsa87-mlkem1024-kmac256-aes256gcmsiv'

class V:
    def verify_readmission(self,peer_id,payload,authenticator):
        return authenticator==hashlib.sha256(b'v'+payload).digest()

def proof_for(g,challenge,generation,session=b's'*32,witness='witness:1'):
    base=ReadmissionProof(g.peer_id,g.quarantine_epoch,generation,challenge.nonce,session,witness,b'x')
    auth=hashlib.sha256(b'v'+base.canonical_payload()).digest()
    return ReadmissionProof(g.peer_id,g.quarantine_epoch,generation,challenge.nonce,session,witness,auth)

def test_authenticated_readmission_requires_generation_challenge_and_probation():
    g=PeerGuard(peer_id='node-a',max_invalid_per_window=2,window_ms=100,quarantine_ms=50,probation_valid_required=2)
    g.observe_invalid(0);g.observe_invalid(1);assert g.state is PeerState.QUARANTINED
    with pytest.raises(Exception):g.issue_readmission_challenge(now_ms=10,generation=1,nonce=b'n'*32)
    c=g.issue_readmission_challenge(now_ms=52,generation=1,nonce=b'n'*32,ttl_ms=100)
    bad=ReadmissionProof('node-a',g.quarantine_epoch,1,c.nonce,b's'*32,'witness:1',b'bad')
    with pytest.raises(Exception):g.admit_readmission(bad,now_ms=60,verifier=V())
    # failed auth keeps quarantine; obtain a fresh challenge and prove it.
    c=g.issue_readmission_challenge(now_ms=61,generation=1,nonce=b'm'*32,ttl_ms=100)
    assert g.admit_readmission(proof_for(g,c,1),now_ms=62,verifier=V()) is PeerState.DEGRADED
    assert g.observe_valid(200) is PeerState.DEGRADED
    assert g.observe_valid(201) is PeerState.ACTIVE
    g.force_quarantine(300)
    with pytest.raises(Exception):g.issue_readmission_challenge(now_ms=351,generation=1,nonce=b'z'*32)

def test_quarantine_snapshot_preserves_anti_reboot_epoch_generation():
    g=PeerGuard(peer_id='node-a',max_invalid_per_window=1,window_ms=10,quarantine_ms=10)
    g.observe_invalid(0);g.last_generation=7
    h=PeerGuard.from_snapshot(g.snapshot(),max_invalid_per_window=1,window_ms=10,quarantine_ms=10,probation_valid_required=3,now_ms=100)
    assert h.quarantine_epoch==g.quarantine_epoch and h.last_generation==7 and h.state is PeerState.QUARANTINED and h.quarantine_until_ms==110

def test_correlated_noise_degrades_path_instead_of_mass_peer_quarantine():
    q=WitnessQuorum(frozenset({'a','b','c'}),2);c=QuarantineCoordinator(q,correlation_window_ms=100,correlated_peer_threshold=2)
    a1,_=c.contain(peer_id='a',path_id='radio-1',now_ms=0,fault=FaultClass.MALFORMED_PEER)
    a2,status=c.contain(peer_id='b',path_id='radio-1',now_ms=10,fault=FaultClass.MALFORMED_PEER)
    assert a1 is ContainmentAction.DEGRADE_PEER
    assert a2 is ContainmentAction.DEGRADE_PATH and 'radio-1' in c.degraded_paths
    # hard security quarantine is never suppressed to preserve quorum
    action,status=c.contain(peer_id='c',path_id='radio-2',now_ms=20,fault=FaultClass.SECURITY)
    assert action is ContainmentAction.QUARANTINE_PEER and status is QuorumStatus.PENDING and q.threshold==2
    action,status=c.contain(peer_id='a',path_id='radio-3',now_ms=30,fault=FaultClass.SECURITY)
    assert action is ContainmentAction.QUARANTINE_PEER and status is QuorumStatus.IMPOSSIBLE and q.threshold==2

def test_resource_budget_detects_accounting_underflow():
    b=ResourceBudget();b.reserve('fec_groups',1);b.release('fec_groups',1)
    with pytest.raises(BudgetAccountingError):b.release('fec_groups',1)

def test_admission_scalars_are_bounded_before_bigint_costing():
    with pytest.raises(ValueError):AdmissionRequest(mailbox_items=1<<40)

def test_fec_work_budget_fails_before_expensive_loop():
    shards=[b'a'*64,b'b'*64];need=estimate_workspace_bytes(2,4,64);work=estimate_encode_work_units(2,4,64)
    with pytest.raises(FECWorkLimitError):encode(shards,4,workspace_bytes=need,max_work_units=work-1)
    assert len(encode(shards,4,workspace_bytes=need,max_work_units=work))==4

def test_group_checks_record_capability_and_recovery_work():
    gp=GroupPolicy(SUITE,max_members=4,max_recovery_work_units=5000,max_recovery_bytes=1_000_000)
    g=GroupEpoch('g',policy=gp)
    g.admit_member(GroupMemberCapabilities('a',SUITE,supported_records=frozenset({'text'}),max_recovery_work_units=5000))
    g.admit_member(GroupMemberCapabilities('b',SUITE,supported_records=frozenset({'text'}),max_recovery_work_units=5000))
    with pytest.raises(GroupError):g.plan_multicast(10,record_name='agent-state-sync')
    with pytest.raises(GroupError):g.plan_multicast(1000,record_name='text',fec_k=8,fec_n=12)

def test_resolved_profile_binds_registry_ids_and_full_inheritance():
    r=ProfileRegistry.from_directory(ROOT/'profiles');p=r.resolve('xavi-utm');m=p.manifest()
    assert p.closure==('baseline-secure','dbp3-comms-1','dbp3-ai-comms-1','dbp3-ai-free-1','xavi-utm')
    assert m['security_suite_id']==1 and m['fec_algorithm']=='gf256-systematic' and m['fec_algorithm_id']==1
    assert m['fec_max_n']==32 and {'utm-human-decision','agent-consent','voice'}<=p.record_names

def test_profile_activation_enforces_resolved_fec_bounds():
    r=ProfileRegistry.from_directory(ROOT/'profiles');lim=ResourceLimits(memory_bytes=512*1024*1024,cpu_tokens=10_000_000)
    req=AdmissionRequest(frame_size=4096,max_records=48,concurrent_sessions=1,inflight_messages=1,fec_k=8,fec_n=33,fec_groups=1,group_fanout=1,merge_page_bytes=1024,merge_items=1,mailbox_items=1)
    with pytest.raises(ProfileError):r.activate('xavi-utm',runtime=RuntimeKind.PYTHON,limits=lim,request=req)

def test_explicit_wire_integer_boundaries_fail_cleanly():
    p=DevelopmentHMACProvider(b'1'*32)
    with pytest.raises(Exception):encode_frame(Frame(Header(flags=1,profile_id=1,sequence=1<<64),[Record(6,b'x')],frame_size=512),p)
    with pytest.raises(Exception):Record(6,b'x',deadline_ms=1<<32).encode()
    with pytest.raises(Exception):encode_frame(Frame(Header(flags=1,profile_id=0),[Record(6,b'x')],frame_size=512),p)

def test_codegen_freshness_and_negative_profile_suite():
    subprocess.run([sys.executable,str(ROOT/'tools/generate_registry_code.py'),'--check'],check=True)
    subprocess.run([sys.executable,str(ROOT/'tools/verify_negative_profiles.py')],check=True)

def test_golden_vectors_include_deep_authenticated_negatives():
    m=json.loads((ROOT/'vectors/manifest.json').read_text());names={x['file'] for x in m['invalid']}
    assert {'invalid-record-message-zero-f512.dbp3','invalid-record-padding-f512.dbp3','invalid-unregistered-fec-f512.dbp3','invalid-security-mode-f512.dbp3'}<=names

def test_witness_reavailability_does_not_restore_old_approval():
    q=WitnessQuorum(frozenset({'a','b','c'}),2);q.approve('a');q.mark_unavailable('a')
    assert 'a' not in q.approvals
    assert q.mark_available('a') is QuorumStatus.PENDING and 'a' not in q.approvals


def test_bounded_merge_rejects_unbounded_in_memory_snapshot_and_supports_storage_snapshot():
    from dbp3.bounded_merge import MergeItem, MergeResourceError, InMemoryMergeSnapshot, reconcile_snapshot_page, MergeCursor
    rows=[MergeItem(str(i),'state',i+1,1,b'x') for i in range(3)]
    with pytest.raises(MergeResourceError):
        InMemoryMergeSnapshot.from_items(rows,max_snapshot_items=2)
    snap=InMemoryMergeSnapshot.from_items(rows,max_snapshot_items=3)
    page1=reconcile_snapshot_page(snap,max_items=1,max_bytes=1)
    assert len(page1.segments)==1 and page1.next_cursor is not None
    page2=reconcile_snapshot_page(snap,cursor=page1.next_cursor,max_items=2,max_bytes=2)
    assert len(page2.segments)==2 and page2.next_cursor is None
    with pytest.raises(ValueError):
        reconcile_snapshot_page(snap,cursor=MergeCursor(0,0,'deadbeef'),max_items=1,max_bytes=1)


def test_idempotency_ledger_never_silently_evicts():
    from dbp3.transaction import CommandTransaction, IdempotencyLedger, LedgerCapacityError
    ledger=IdempotencyLedger(max_entries=1)
    a=CommandTransaction('a','key-a','noop',0)
    b=CommandTransaction('b','key-b','noop',0)
    assert ledger.execute_once(a,lambda:'first')=='first'
    assert ledger.execute_once(a,lambda:'second')=='first'
    with pytest.raises(LedgerCapacityError):
        ledger.execute_once(b,lambda:'new')


def test_store_forward_rejects_loops_and_hop_exhaustion():
    from dbp3.comms import StoreForwardEnvelope
    e=StoreForwardEnvelope('e','dest',1000,max_hops=2)
    e.accept_custody('a',1).accept_custody('b',2)
    with pytest.raises(ValueError): e.accept_custody('c',3)
    with pytest.raises(ValueError): StoreForwardEnvelope('x','dest',1000,custody_hops=['a','a'])


def test_replay_window_and_call_epochs_are_bounded():
    from dbp3.replay import ReplayWindow
    from dbp3.comms import CallSession, StreamKeyEpochs
    from dbp3.errors import ReplayError
    with pytest.raises(ReplayError): ReplayWindow(width=0)
    r=ReplayWindow(width=8)
    with pytest.raises(ReplayError): r.accept(0)
    with pytest.raises(ReplayError): r.accept(1<<64)
    c=CallSession('c','a','b',generation=0xffffffffffffffff,participants={'old'})
    with pytest.raises(OverflowError): c.handoff('old','new')
    k=StreamKeyEpochs(text=0xffffffffffffffff)
    with pytest.raises(OverflowError): k.rekey('text')


def test_session_history_is_bounded_but_committed_and_epochs_fail_closed():
    from dbp3.session import Session,SessionState,U32_MAX
    from dbp3.errors import StateError
    s=Session(b's',history_limit=2)
    s.transition(SessionState.NEGOTIATE);s.transition(SessionState.ESTABLISH);s.transition(SessionState.ACTIVE)
    assert len(s.history)==2 and s.history_digest and len(s.history_digest)==32
    x=Session(b'x',state=SessionState.ACTIVE,key_epoch=U32_MAX)
    with pytest.raises(StateError): x.transition(SessionState.REKEY)


def test_group_and_coalition_epoch_and_membership_bounds():
    from dbp3.group import GroupEpoch,GroupError,GroupPolicy
    from dbp3.autonomy import AutonomousCoalition
    g=GroupEpoch('g',epoch=0xffffffffffffffff,members={'a'},key_epoch=1)
    with pytest.raises(GroupError): g.change_membership({'a','b'})
    c=AutonomousCoalition('c',1,max_members=1)
    c.join('a')
    with pytest.raises(ValueError): c.join('b')


def test_revocation_set_capacity_fails_closed():
    from dbp3.revocation import Revocation,RevocationSet
    r=RevocationSet(max_targets=1)
    r.apply(Revocation('a','auth',1,1))
    with pytest.raises(RuntimeError): r.apply(Revocation('b','auth',2,2))
