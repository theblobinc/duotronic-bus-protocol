from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any


class AgentExchangeKind(str, Enum):
    OBSERVATION = 'observation'
    QUERY = 'query'
    RESPONSE = 'response'
    PROPOSAL = 'proposal'
    CRITIQUE = 'critique'
    PLAN = 'plan'
    NEGOTIATION = 'negotiation'
    DELEGATION = 'delegation'
    TOOL_INTENT = 'tool-intent'
    TOOL_RESULT = 'tool-result'
    MEMORY_DELTA = 'memory-delta'
    STATE_SYNC = 'state-sync'
    CONSENSUS_VOTE = 'consensus-vote'
    CONSENSUS_RESULT = 'consensus-result'
    CAPABILITY = 'capability'
    FEATURE_REF = 'feature-ref'
    ARTIFACT_REF = 'artifact-ref'
    HEARTBEAT = 'heartbeat'
    BLACKBOARD_EVENT = 'blackboard-event'


class DeliveryPattern(str, Enum):
    UNICAST = 'unicast'
    MULTICAST = 'multicast'
    BROADCAST = 'broadcast'
    MAILBOX = 'mailbox'
    PUBLISH = 'publish'
    REQUEST_RESPONSE = 'request-response'
    FANOUT_GATHER = 'fanout-gather'
    QUORUM = 'quorum'
    PIPELINE = 'pipeline'


def _canon(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


@dataclass(frozen=True)
class AgentPrincipal:
    principal_id: str
    runtime_id: str
    model_id: str = ''
    instance_id: str = ''
    witness_authority_ref: str = ''
    delegation_ref: str = ''
    session_generation: int = 1

    def validate(self) -> 'AgentPrincipal':
        if not self.principal_id or not self.runtime_id or not 1 <= self.session_generation <= 0xffffffffffffffff:
            raise ValueError('agent principal')
        return self


@dataclass(frozen=True)
class AgentEnvelope:
    exchange_id: str
    conversation_id: str
    sender: str
    kind: AgentExchangeKind
    delivery: DeliveryPattern
    payload_digest: str
    schema_ref: str = ''
    recipient: str = ''
    correlation_id: str = ''
    causal_parent: str = ''
    witness_ref: str = ''
    delegation_ref: str = ''
    created_us: int = 0
    expires_us: int = 0
    priority: int = 0
    response_required: bool = False

    def validate(self) -> 'AgentEnvelope':
        if not self.exchange_id or not self.conversation_id or not self.sender or not self.payload_digest:
            raise ValueError('agent envelope identity')
        if not (0 <= self.created_us <= 0xffffffffffffffff and 0 <= self.expires_us <= 0xffffffffffffffff and 0 <= self.priority <= 255):
            raise ValueError('agent envelope bounds')
        if self.expires_us and self.created_us and self.expires_us < self.created_us:
            raise ValueError('agent envelope expiry')
        if self.delivery in {DeliveryPattern.UNICAST, DeliveryPattern.REQUEST_RESPONSE, DeliveryPattern.MAILBOX} and not self.recipient:
            raise ValueError('recipient required')
        return self

    def digest(self) -> str:
        self.validate()
        body = {
            'exchange_id': self.exchange_id, 'conversation_id': self.conversation_id,
            'sender': self.sender, 'kind': self.kind.value, 'delivery': self.delivery.value,
            'payload_digest': self.payload_digest, 'schema_ref': self.schema_ref,
            'recipient': self.recipient, 'correlation_id': self.correlation_id,
            'causal_parent': self.causal_parent, 'witness_ref': self.witness_ref,
            'delegation_ref': self.delegation_ref, 'created_us': self.created_us,
            'expires_us': self.expires_us, 'priority': self.priority,
            'response_required': self.response_required,
        }
        return hashlib.shake_256(b'DBP3/AI/ENVELOPE/v1' + _canon(body)).hexdigest(32)


@dataclass(frozen=True)
class StructuredDataEnvelope:
    object_id: str
    media_type: str
    schema_ref: str
    content_digest: str
    byte_length: int
    encoding: str = 'identity'
    compression: str = 'none'
    merkle_root: str = ''
    confidentiality_label: str = ''

    def validate(self) -> 'StructuredDataEnvelope':
        if not self.object_id or not self.media_type or not self.content_digest or not 0 <= self.byte_length <= 0xffffffffffffffff:
            raise ValueError('structured data envelope')
        if self.encoding not in {'identity','cbor','json','msgpack','flatbuffers','protobuf','arrow-ipc','raw'}:
            raise ValueError('encoding')
        if self.compression not in {'none','zstd','brotli','lz4'}:
            raise ValueError('compression')
        return self


@dataclass(frozen=True)
class FeatureReference:
    feature_id: str
    representation: str
    element_type: str
    shape: tuple[int, ...]
    content_digest: str
    producer_principal: str
    semantic_ref: str = ''
    quantization: str = 'none'

    def validate(self) -> 'FeatureReference':
        if not self.feature_id or not self.representation or not self.content_digest or not self.producer_principal:
            raise ValueError('feature reference')
        if not self.shape or len(self.shape)>16 or any(not isinstance(x,int) or not 1<=x<=0xffffffff for x in self.shape):
            raise ValueError('feature shape')
        total=1
        for x in self.shape:
            total*=x
            if total>(1<<63)-1: raise ValueError('feature shape element-count bound')
        return self


@dataclass(frozen=True)
class DelegatedAction:
    action_id: str
    actor_principal: str
    action_type: str
    scope: str
    delegation_ref: str
    witness_ref: str = ''
    idempotency_key: str = ''
    expires_us: int = 0

    def validate(self) -> 'DelegatedAction':
        if not all((self.action_id, self.actor_principal, self.action_type, self.scope, self.delegation_ref)):
            raise ValueError('delegated action')
        if not 0 <= self.expires_us <= 0xffffffffffffffff:
            raise ValueError('expiry')
        return self


@dataclass
class QuorumExchange:
    exchange_id: str
    members: set[str]
    threshold: int
    votes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.exchange_id or not self.members or len(self.members)>4096 or self.threshold < 1 or self.threshold > len(self.members):
            raise ValueError('quorum')

    def vote(self, principal: str, value_digest: str) -> bool:
        if principal not in self.members or not value_digest:
            raise ValueError('vote')
        self.votes[principal] = value_digest
        return self.reached(value_digest)

    def reached(self, value_digest: str) -> bool:
        return sum(1 for v in self.votes.values() if v == value_digest) >= self.threshold


@dataclass(frozen=True)
class AgentPolicyGate:
    authenticated: bool
    delegated: bool
    witness_admitted: bool
    policy_authorized: bool
    state_mutation_requested: bool = False

    def may_deliver(self) -> bool:
        return self.authenticated

    def may_act(self) -> bool:
        return self.authenticated and self.delegated and self.policy_authorized

    def may_mutate_state(self) -> bool:
        return self.may_act() and self.witness_admitted and self.state_mutation_requested
