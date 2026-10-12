import pytest, random
from dbp3 import *
from dbp3.constants import REC_CRITICAL, FLAG_PROTECTED
from dbp3.records import decode_records
from dbp3.errors import RecordError, StateError
from dbp3.extensions import extension_range

def test_unknown_critical_rejected():
    raw=Record(40000,b'x',flags=REC_CRITICAL).encode()
    with pytest.raises(RecordError): decode_records(raw,1)
def test_unknown_noncritical_skippable(): assert decode_records(Record(40000,b'x').encode(),1)[0].type_id==40000
def test_negotiation_no_downgrade():
    a={'frame_size':[256,4096],'security_suite':['pq1']}; b={'frame_size':[4096],'security_suite':['pq1']}; assert validate_selection(a,b,{'frame_size':4096,'security_suite':'pq1'})
    with pytest.raises(StateError): validate_selection(a,b,{'frame_size':256})
def test_compromised_session_cannot_resume():
    s=Session(b'x'*16); s.transition(SessionState.NEGOTIATE); s.transition(SessionState.ESTABLISH); s.transition(SessionState.ACTIVE); s.compromise(); assert s.state==SessionState.QUARANTINED and not s.can_resume()
def test_group_membership_rekeys():
    g=GroupEpoch('g',members={'a','b'}); e=g.epoch; k=g.key_epoch; g.change_membership({'a'}); assert g.epoch==e+1 and g.key_epoch==k+1 and not g.accepts('b',g.epoch)
def test_revocation_high_water():
    rs=RevocationSet(); rs.apply(Revocation('device:a','auth',100,1)); assert rs.revoked('device:a',100)
    with pytest.raises(ValueError): rs.apply(Revocation('device:b','auth',100,1))
def test_emergency_fixed_shape():
    e=EmergencyRecord(EmergencyCode.COLLISION_RISK,255,7,123,9); raw=e.encode(); assert len(raw)==24 and EmergencyRecord.decode(raw)==e
def test_multipath_failure_domain_diversity():
    ps=[PathMetric(1,10,0,1,1000,True,'radio-a'),PathMetric(2,11,0,1,1000,True,'radio-a'),PathMetric(3,20,0,1,500,True,'lte')]
    out=choose_paths(ps,critical=True,independent_domains=True); assert [p.path_id for p in out]==[1,3]
def test_wgrnn_nonmutation():
    GateReceipt('w',False,state_mutated=False).validate()
    with pytest.raises(ValueError): GateReceipt('w',False,state_mutated=True).validate()
def test_utm_units_and_datum(): SpatialState('a',53,-122,700,'MSL',(1,2,3),1,2).validate()
def test_extension_ranges(): assert extension_range(1)=='core' and extension_range(65535)=='vendor-private'
def test_idempotency_at_most_once():
    led=IdempotencyLedger(); tx=CommandTransaction('t','k','land',1000); calls=[]
    assert led.execute_once(tx,lambda: calls.append(1) or 'ok')=='ok'; assert led.execute_once(tx,lambda: calls.append(2) or 'bad')=='ok'; assert calls==[1]
def test_property_roundtrip_randomized():
    p=DevelopmentHMACProvider(b'0123456789abcdef0123456789abcdef'); rng=random.Random(3)
    for size in (256,512,1024,2048,4096):
        for _ in range(20):
            n=rng.randrange(0,max(1,min(32,size-224)))
            payload=bytes(rng.randrange(256) for _ in range(n)); raw=encode_frame(Frame(Header(flags=FLAG_PROTECTED,sequence=rng.randrange(1,2**16)),[Record(6,payload)],frame_size=size),p)
            assert decode_frame(raw,p).records[0].payload==payload
