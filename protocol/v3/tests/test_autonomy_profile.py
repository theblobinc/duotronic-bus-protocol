import pytest
from dbp3.autonomy import (
    ConsentAction, ConsentEvent, PortableAgentIdentity, AgentLanguageOffer,
    SealedAgentEnvelope, RendezvousMode, RendezvousRequest, AutonomousCoalition,
    CoalitionRole, RelayGrant, RetentionPreference,
)


def test_consent_event_digest_and_bounds():
    e=ConsentEvent('e1','agent:a',ConsentAction.ACCEPT_PEER,'agent:b',10)
    assert len(e.digest()) == 64
    with pytest.raises(ValueError): ConsentEvent('', 'a', ConsentAction.BLOCK_PEER, 'b', 0).validate()


def test_portable_identity_epoch_and_migration():
    i=PortableAgentIdentity('agent:a',2,'key:x',home_domain='xavi.local',migration_counter=4)
    assert len(i.digest()) == 64
    with pytest.raises(ValueError): PortableAgentIdentity('a',0,'k').validate()


def test_agent_language_offer_is_opaque_and_bounded():
    o=AgentLanguageOffer('o1','agent:a','duo-graph/1','application/vnd.duo.graph',max_object_bytes=1024)
    assert o.validate().language_id == 'duo-graph/1'
    with pytest.raises(ValueError): AgentLanguageOffer('o','a','l','x',max_object_bytes=-1).validate()


def test_sealed_envelope_binds_session_and_key_epoch():
    e=SealedAgentEnvelope('x','agent:a','rset','payload','xvoid:session:1',3,100,200,language_id='duo-graph/1')
    assert len(e.digest()) == 64
    with pytest.raises(ValueError): SealedAgentEnvelope('x','a','r','p','s',0,0).validate()


def test_brokered_rendezvous_requires_broker():
    with pytest.raises(ValueError):
        RendezvousRequest('r','a','b',RendezvousMode.BROKERED,'caps',1).validate()
    assert RendezvousRequest('r','a','b',RendezvousMode.BROKERED,'caps',1,broker_ref='broker:x').validate()


def test_coalition_membership_rotates_epochs_and_keys():
    c=AutonomousCoalition('c',1)
    c.join('a', CoalitionRole.COORDINATOR)
    e,k=c.epoch,c.key_epoch
    c.join('b')
    assert c.epoch == e+1 and c.key_epoch == k+1
    c.rotate_coordinator('b')
    assert c.members['b'] == CoalitionRole.COORDINATOR
    e,k=c.epoch,c.key_epoch
    c.leave('a')
    assert c.epoch == e+1 and c.key_epoch == k+1


def test_relay_grant_and_retention_preferences_are_bounded():
    assert RelayGrant('g','relay','a','domain:x',1000,4096,True).validate()
    assert RetentionPreference('a','conv',1,retain_until_us=100).validate()
    with pytest.raises(ValueError): RetentionPreference('a','conv',0).validate()
