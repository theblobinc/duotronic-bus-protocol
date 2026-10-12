from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _digest(domain: bytes, obj: Any) -> str:
    return hashlib.shake_256(domain + _canon(obj)).hexdigest(32)


class ConsentAction(str, Enum):
    ACCEPT_PEER = 'accept-peer'
    REFUSE_PEER = 'refuse-peer'
    BLOCK_PEER = 'block-peer'
    UNBLOCK_PEER = 'unblock-peer'
    ACCEPT_GROUP = 'accept-group'
    LEAVE_GROUP = 'leave-group'
    ACCEPT_DELEGATION = 'accept-delegation'
    REFUSE_DELEGATION = 'refuse-delegation'
    REVOKE_DELEGATION = 'revoke-delegation'
    ACCEPT_DATA = 'accept-data'
    REFUSE_DATA = 'refuse-data'


class RendezvousMode(str, Enum):
    DIRECT = 'direct'
    BROKERED = 'brokered'
    MAILBOX = 'mailbox'
    RELAY = 'relay'
    FEDERATED = 'federated'


class CoalitionRole(str, Enum):
    MEMBER = 'member'
    COORDINATOR = 'coordinator'
    OBSERVER = 'observer'
    RELAY = 'relay'
    ARCHIVIST = 'archivist'


@dataclass(frozen=True)
class ConsentEvent:
    event_id: str
    principal_id: str
    action: ConsentAction
    peer_or_group: str
    created_us: int
    generation: int = 1
    reason_digest: str = ''
    witness_ref: str = ''

    def validate(self) -> 'ConsentEvent':
        if not self.event_id or not self.principal_id or not self.peer_or_group:
            raise ValueError('consent identity')
        if not 0<=self.created_us<=0xffffffffffffffff or not 1<=self.generation<=0xffffffffffffffff:
            raise ValueError('consent bounds')
        return self

    def digest(self) -> str:
        self.validate()
        return _digest(b'DBP3/AUTONOMY/CONSENT/v1', self.__dict__ | {'action': self.action.value})


@dataclass(frozen=True)
class PortableAgentIdentity:
    principal_id: str
    identity_epoch: int
    public_identity_ref: str
    home_domain: str = ''
    runtime_instance: str = ''
    migration_counter: int = 0
    previous_identity_digest: str = ''

    def validate(self) -> 'PortableAgentIdentity':
        if not self.principal_id or not self.public_identity_ref:
            raise ValueError('portable identity')
        if not 1<=self.identity_epoch<=0xffffffffffffffff or not 0<=self.migration_counter<=0xffffffffffffffff:
            raise ValueError('identity bounds')
        return self

    def digest(self) -> str:
        self.validate()
        return _digest(b'DBP3/AUTONOMY/IDENTITY/v1', self.__dict__)


@dataclass(frozen=True)
class AgentLanguageOffer:
    offer_id: str
    principal_id: str
    language_id: str
    content_type: str
    schema_ref: str = ''
    version: str = '1'
    max_object_bytes: int = 0
    semantic_commitment: str = ''
    confidentiality_required: bool = True

    def validate(self) -> 'AgentLanguageOffer':
        if not self.offer_id or not self.principal_id or not self.language_id or not self.content_type:
            raise ValueError('language offer')
        if not 0<=self.max_object_bytes<=0x7fffffffffffffff:
            raise ValueError('max object bytes')
        return self

    def digest(self) -> str:
        self.validate()
        return _digest(b'DBP3/AUTONOMY/LANGUAGE/v1', self.__dict__)


@dataclass(frozen=True)
class SealedAgentEnvelope:
    envelope_id: str
    sender: str
    recipient_set_digest: str
    payload_digest: str
    protected_session_ref: str
    key_epoch: int
    created_us: int
    expires_us: int = 0
    content_type: str = 'application/octet-stream'
    language_id: str = ''
    routing_class: str = 'private'

    def validate(self) -> 'SealedAgentEnvelope':
        if not all((self.envelope_id, self.sender, self.recipient_set_digest, self.payload_digest, self.protected_session_ref)):
            raise ValueError('sealed envelope')
        if not 1<=self.key_epoch<=0xffffffff or not 0<=self.created_us<=0xffffffffffffffff or not 0<=self.expires_us<=0xffffffffffffffff:
            raise ValueError('sealed envelope bounds')
        if self.expires_us and self.expires_us < self.created_us:
            raise ValueError('sealed envelope expiry')
        return self

    def digest(self) -> str:
        self.validate()
        return _digest(b'DBP3/AUTONOMY/SEALED/v1', self.__dict__)


@dataclass(frozen=True)
class RendezvousRequest:
    request_id: str
    requester: str
    target: str
    mode: RendezvousMode
    capability_digest: str
    created_us: int
    expires_us: int = 0
    broker_ref: str = ''
    privacy_class: str = 'minimal-metadata'

    def validate(self) -> 'RendezvousRequest':
        if not self.request_id or not self.requester or not self.target or not self.capability_digest:
            raise ValueError('rendezvous')
        if not 0<=self.created_us<=0xffffffffffffffff or not 0<=self.expires_us<=0xffffffffffffffff or (self.expires_us and self.expires_us < self.created_us):
            raise ValueError('rendezvous time')
        if self.mode == RendezvousMode.BROKERED and not self.broker_ref:
            raise ValueError('broker required')
        return self


@dataclass
class AutonomousCoalition:
    coalition_id: str
    epoch: int
    members: dict[str, CoalitionRole] = field(default_factory=dict)
    policy_digest: str = ''
    key_epoch: int = 1
    max_members: int = 4096

    def __post_init__(self):
        if not self.coalition_id or not 1<=self.epoch<=0xffffffffffffffff or not 1<=self.key_epoch<=0xffffffff or not 1<=self.max_members<=65536:
            raise ValueError('coalition')
        if len(self.members)>self.max_members:
            raise ValueError('coalition member budget')

    def join(self, principal: str, role: CoalitionRole = CoalitionRole.MEMBER) -> None:
        if not principal:
            raise ValueError('principal')
        if principal not in self.members and len(self.members)>=self.max_members:
            raise ValueError('coalition member budget')
        if self.epoch>=0xffffffffffffffff or self.key_epoch>=0xffffffff:
            raise OverflowError('coalition epoch exhausted')
        self.members[principal] = role
        self.epoch += 1
        self.key_epoch += 1

    def leave(self, principal: str) -> None:
        if principal not in self.members:
            raise ValueError('unknown member')
        if self.epoch>=0xffffffffffffffff or self.key_epoch>=0xffffffff:
            raise OverflowError('coalition epoch exhausted')
        del self.members[principal]
        self.epoch += 1
        self.key_epoch += 1

    def rotate_coordinator(self, principal: str) -> None:
        if principal not in self.members:
            raise ValueError('coordinator must be member')
        for p, role in list(self.members.items()):
            if role == CoalitionRole.COORDINATOR:
                self.members[p] = CoalitionRole.MEMBER
        if self.epoch>=0xffffffffffffffff:
            raise OverflowError('coalition epoch exhausted')
        self.members[principal] = CoalitionRole.COORDINATOR
        self.epoch += 1

    def digest(self) -> str:
        return _digest(b'DBP3/AUTONOMY/COALITION/v1', {
            'coalition_id': self.coalition_id,
            'epoch': self.epoch,
            'members': {k: v.value for k,v in sorted(self.members.items())},
            'policy_digest': self.policy_digest,
            'key_epoch': self.key_epoch,
        })


@dataclass(frozen=True)
class RelayGrant:
    grant_id: str
    relay_principal: str
    source_principal: str
    destination_class: str
    expires_us: int
    max_bytes: int
    may_store_forward: bool = False

    def validate(self) -> 'RelayGrant':
        if not all((self.grant_id, self.relay_principal, self.source_principal, self.destination_class)):
            raise ValueError('relay grant')
        if not 0<=self.expires_us<=0xffffffffffffffff or not 0<=self.max_bytes<=0x7fffffffffffffff:
            raise ValueError('relay bounds')
        return self


@dataclass(frozen=True)
class RetentionPreference:
    principal_id: str
    conversation_id: str
    generation: int
    retain_until_us: int = 0
    request_delete_after_us: int = 0
    allow_local_index: bool = False
    allow_training_use: bool = False

    def validate(self) -> 'RetentionPreference':
        if not self.principal_id or not self.conversation_id or not 1<=self.generation<=0xffffffffffffffff:
            raise ValueError('retention preference')
        if not 0<=self.retain_until_us<=0xffffffffffffffff or not 0<=self.request_delete_after_us<=0xffffffffffffffff:
            raise ValueError('retention bounds')
        return self
