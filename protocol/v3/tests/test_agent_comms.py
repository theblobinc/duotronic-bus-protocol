import pytest
from dbp3.agent_comms import (
    AgentPrincipal, AgentEnvelope, AgentExchangeKind, DeliveryPattern,
    StructuredDataEnvelope, FeatureReference, DelegatedAction,
    QuorumExchange, AgentPolicyGate,
)


def test_agent_principal_identity_layers():
    p=AgentPrincipal('ai:observer:1','wgrnn-runtime','model-x','inst-7','w:auth','d:1',2)
    assert p.validate().session_generation==2
    with pytest.raises(ValueError): AgentPrincipal('','runtime').validate()


def test_agent_envelope_digest_and_recipient_rule():
    e=AgentEnvelope('x1','conv','ai:a',AgentExchangeKind.PROPOSAL,DeliveryPattern.UNICAST,'sha256:abc',recipient='ai:b',created_us=1,expires_us=2,response_required=True)
    assert len(e.digest())==64
    with pytest.raises(ValueError): AgentEnvelope('x','c','a',AgentExchangeKind.QUERY,DeliveryPattern.UNICAST,'d').validate()


def test_publish_can_be_asymmetric_without_recipient():
    e=AgentEnvelope('x','telemetry','observer',AgentExchangeKind.OBSERVATION,DeliveryPattern.PUBLISH,'d')
    assert e.validate().recipient==''


def test_structured_data_supports_files_and_machine_data():
    e=StructuredDataEnvelope('obj','application/vnd.apache.arrow.stream','schema:features:v1','sha256:x',1234,'arrow-ipc','zstd','merkle:r')
    assert e.validate().byte_length==1234
    with pytest.raises(ValueError): StructuredDataEnvelope('o','x','','d',1,'pickle').validate()


def test_feature_reference_is_opaque_and_shaped():
    f=FeatureReference('f','embedding','float16',(1,768),'sha256:v','ai:encoder',semantic_ref='text-embedding')
    assert f.validate().shape==(1,768)
    with pytest.raises(ValueError): FeatureReference('f','embedding','f16',(0,768),'d','a').validate()


def test_delegated_action_requires_delegation():
    assert DelegatedAction('a','ai:1','tool-call','utm.read','deleg:1').validate()
    with pytest.raises(ValueError): DelegatedAction('a','ai:1','tool-call','utm.read','').validate()


def test_quorum_is_transport_not_truth():
    q=QuorumExchange('q',{'a','b','c'},2)
    assert not q.vote('a','candidate:1')
    assert q.vote('b','candidate:1')
    assert q.reached('candidate:1')
    with pytest.raises(ValueError): q.vote('outsider','candidate:1')


def test_authentication_alone_never_grants_action_or_mutation():
    g=AgentPolicyGate(True,False,True,True,True)
    assert g.may_deliver() and not g.may_act() and not g.may_mutate_state()


def test_mutation_requires_auth_delegation_policy_witness():
    g=AgentPolicyGate(True,True,True,True,True)
    assert g.may_act() and g.may_mutate_state()
    assert not AgentPolicyGate(True,True,False,True,True).may_mutate_state()
