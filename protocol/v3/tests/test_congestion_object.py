from dbp3.congestion import *
from dbp3.object_transfer import *
def test_congestion_states_and_reservations():
    assert classify(LinkSample(.0,20,1,1000))==CongestionState.NORMAL
    assert classify(LinkSample(.4,20,1,1000))==CongestionState.SURVIVAL
    assert reserved_fraction(CongestionState.SURVIVAL)[0] >= reserved_fraction(CongestionState.NORMAL)[0]
def test_merkle_manifest():
    m,ch=build_manifest('map',b'abcdef',2,signer_ref='witness:x'); m.validate(); assert m.merkle_root_id.startswith('shake256-256:') and all(verify_chunk(m,i,c) for i,c in enumerate(ch))
