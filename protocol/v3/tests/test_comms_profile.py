import pytest
from dbp3.comms import CallSession,CallState,PTTFloor,ParticipantBinding,StreamKeyEpochs,MessageEvent,StoreForwardEnvelope,MediaLayer,degraded_media_mode,RecordingCommitment
from dbp3.federation import ConversationFederation

def test_call_lifecycle_and_illegal_transition():
    c=CallSession('c1','alice','bob').transition(CallState.INVITED).transition(CallState.RINGING).transition(CallState.ACTIVE).transition(CallState.HELD).transition(CallState.ACTIVE).transition(CallState.ENDED)
    assert c.state is CallState.ENDED
    with pytest.raises(ValueError): c.transition(CallState.ACTIVE)

def test_device_handoff_increments_generation():
    c=CallSession('c','a','b',state=CallState.ACTIVE,participants={'dev1'})
    c.handoff('dev1','dev2'); assert c.generation==2 and c.participants=={'dev2'}

def test_ptt_floor_priority_and_emergency_preemption():
    f=PTTFloor('ops')
    assert f.request('a',1); assert not f.request('b',0); assert f.request('b',2); assert f.holder=='b'; assert f.request('emergency',-99,True); assert f.holder=='emergency'
    assert not f.release('b'); assert f.release('emergency')

def test_participant_binding_validation():
    assert ParticipantBinding('human:1','device:1',1,2,'w:1').validate()
    with pytest.raises(ValueError): ParticipantBinding('','d',1).validate()

def test_per_stream_epochs_are_independent():
    e=StreamKeyEpochs(); assert e.rekey('voice')==2; assert e.voice==2 and e.text==1 and e.control==1

def test_message_event_chain_digest_is_deterministic():
    a=MessageEvent('room','m1','alice','text','abc',created_us=10); d=a.digest()
    b=MessageEvent('room','m2','bob','text','def',previous_event_digest=d,created_us=11)
    assert a.digest()==d and b.digest()!=d

def test_store_forward_custody_is_not_delivery():
    e=StoreForwardEnvelope('e','bob',1000).accept_custody('relay1',100).accept_custody('relay2',200)
    assert e.custody_hops==['relay1','relay2'] and not e.delivered
    e.mark_delivered(); assert e.delivered
    with pytest.raises(ValueError): StoreForwardEnvelope('x','b',10).accept_custody('r',11)

def test_media_adaptation_and_layer_validation():
    assert degraded_media_mode(.01,50)=='video'
    assert degraded_media_mode(.15,100)=='thumbnail'
    assert degraded_media_mode(.3,100)=='audio-only'
    assert degraded_media_mode(.5,100)=='text-ptt-survival'
    assert MediaLayer('low',12000,300,'audio-only').validate()

def test_recording_commitment_is_only_a_commitment_object():
    assert RecordingCommitment('r','c','sha256:x',1,2,'w').validate()
    with pytest.raises(ValueError): RecordingCommitment('r','c','x',2,1).validate()

def test_federation_merge_is_epoch_bounded():
    f=ConversationFederation('room',epoch=2,homes={'a'},sequence=5)
    f.merge(1,99,{'evil'}); assert f.sequence==5 and 'evil' not in f.homes
    f.merge(2,7,{'b'}); assert f.sequence==7 and f.homes=={'a','b'}
    f.merge(3,1,{'c'}); assert (f.epoch,f.sequence,f.homes)==(3,1,{'c'})
