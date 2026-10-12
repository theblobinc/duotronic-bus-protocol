import json
from pathlib import Path
import pytest
from dbp3 import (
    ProfileRegistry, ProfileError, ResourceBudget, ResourceLimits, BudgetExceeded,
    MergeItem, bounded_reconcile, ReplayWindow, Frame, Header, Record, encode_frame, decode_frame
)
from dbp3.constants import REC_CRITICAL

ROOT=Path(__file__).resolve().parents[1]

def test_ai_free_is_transitive_extension_not_competing_profile():
    r=ProfileRegistry.from_directory(ROOT/'profiles')
    p=r.resolve('dbp3-ai-free-1')
    assert p.closure == ('baseline-secure','dbp3-comms-1','dbp3-ai-comms-1','dbp3-ai-free-1')
    assert 'text' in p.record_names and 'wgrnn-observation' in p.record_names and 'agent-consent' in p.record_names

def test_unknown_critical_profile_record_is_rejected():
    r=ProfileRegistry.from_directory(ROOT/'profiles')
    with pytest.raises(ProfileError): r.accepts_record('dbp3-comms-1','future-critical-x',critical=True)
    assert r.accepts_record('dbp3-comms-1','future-optional-x',critical=False) is False

def test_global_resource_budget_cross_subsystems():
    b=ResourceBudget(ResourceLimits(memory_bytes=100,merge_items=2,mailbox_items=2,fanout_targets=2,cpu_tokens=10))
    b.reserve('memory_bytes',60).reserve('merge_items',2)
    with pytest.raises(BudgetExceeded): b.reserve('memory_bytes',41)
    with pytest.raises(BudgetExceeded): b.reserve('merge_items',1)
    b.release('memory_bytes',20).reserve('memory_bytes',40)
    assert b.memory_bytes==80

def test_bounded_merge_revocations_first_and_resumable():
    rows=[
        MergeItem('bulk','bulk',1,4,b'abcd',priority=200),
        MergeItem('state','state',2,4,b'efgh',priority=100),
        MergeItem('rev','revocation',3,4,b'ijkl',priority=0,revoked=True),
    ]
    p1=bounded_reconcile(rows,max_items=1,max_bytes=8)
    assert p1.items[0].item_id=='rev' and p1.next_cursor==1 and p1.yielded
    p2=bounded_reconcile(rows,cursor=p1.next_cursor,max_items=2,max_bytes=8)
    assert [x.item_id for x in p2.items]==['state','bulk'] and p2.next_cursor is None

def test_bounded_merge_rejects_unbounded_single_item():
    with pytest.raises(ValueError): bounded_reconcile([MergeItem('x','bulk',1,9,b'123456789')],max_bytes=8)

def test_replay_is_logical_sequence_not_wall_clock():
    w=ReplayWindow(width=8)
    w.accept(100); w.accept(99)
    with pytest.raises(Exception): w.accept(100)
    # No time input exists: partition/reconnect safety is driven by sequence chronology.
    assert w.highest==100

def test_wire_unknown_critical_record_rejected():
    raw=encode_frame(Frame(Header(),[Record(65000,b'x',flags=REC_CRITICAL)],frame_size=512))
    with pytest.raises(Exception): decode_frame(raw)

def test_wire_unknown_noncritical_record_is_forward_compatible():
    raw=encode_frame(Frame(Header(),[Record(65000,b'x')],frame_size=512))
    f=decode_frame(raw); assert f.records[0].type_id==65000

def test_profile_composition_schema_matches_runtime():
    spec=json.loads((ROOT/'schemas/profile-composition.json').read_text())
    expected={x['name']:tuple(x['extends']) for x in spec['profiles']}
    r=ProfileRegistry.from_directory(ROOT/'profiles')
    for name,parents in expected.items(): assert tuple(r.docs[name].get('extends',[]))==parents

def test_formal_coverage_has_bounded_merge_mapping():
    d=json.loads((ROOT/'formal/MODEL-COVERAGE.json').read_text())
    assert any('src/dbp3/bounded_merge.py' in x['implementation'] and 'formal/DBP3BoundedMerge.tla' in x['formal'] for x in d['mappings'])
