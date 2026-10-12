from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol
import hashlib

class PeerState(str, Enum):
    ACTIVE='active'
    DEGRADED='degraded'
    QUARANTINED='quarantined'

class ReadmissionError(RuntimeError):
    pass

class ReadmissionVerifier(Protocol):
    """Xavi-Void/Witness-facing verifier boundary.

    DBP never interprets a production signature primitive here.  Deployments
    provide a verifier that authenticates the canonical proof payload against
    the peer's currently valid portable identity / authority material.
    """
    def verify_readmission(self, peer_id:str, payload:bytes, authenticator:bytes)->bool: ...

@dataclass(frozen=True)
class ReadmissionChallenge:
    peer_id:str
    quarantine_epoch:int
    min_generation:int
    nonce:bytes
    issued_ms:int
    expires_ms:int

    def canonical(self)->bytes:
        if not self.peer_id or self.quarantine_epoch < 1 or self.min_generation < 1:
            raise ReadmissionError('invalid readmission challenge')
        if not (16 <= len(self.nonce) <= 64):
            raise ReadmissionError('readmission nonce length')
        if self.issued_ms < 0 or self.expires_ms <= self.issued_ms:
            raise ReadmissionError('readmission challenge chronology')
        parts=(
            b'DBP3/READMISSION-CHALLENGE/v1', self.peer_id.encode(),
            self.quarantine_epoch.to_bytes(8,'little'), self.min_generation.to_bytes(8,'little'),
            self.nonce, self.issued_ms.to_bytes(8,'little'), self.expires_ms.to_bytes(8,'little')
        )
        return b'\0'.join(parts)

@dataclass(frozen=True)
class ReadmissionProof:
    peer_id:str
    quarantine_epoch:int
    generation:int
    nonce:bytes
    session_commitment:bytes
    witness_ref:str
    authenticator:bytes

    def canonical_payload(self)->bytes:
        if not self.peer_id or self.quarantine_epoch < 1 or self.generation < 1:
            raise ReadmissionError('invalid readmission proof')
        if not (16 <= len(self.nonce) <= 64) or len(self.session_commitment) != 32:
            raise ReadmissionError('readmission proof lengths')
        if not self.witness_ref:
            raise ReadmissionError('readmission requires witness reference')
        return b'\0'.join((
            b'DBP3/READMISSION-PROOF/v1', self.peer_id.encode(),
            self.quarantine_epoch.to_bytes(8,'little'), self.generation.to_bytes(8,'little'),
            self.nonce, self.session_commitment, self.witness_ref.encode()
        ))

@dataclass
class PeerGuard:
    """Monotonic peer-noise guard with authenticated, generation-bound re-admission.

    Cooldown NEVER re-admits a peer by itself.  A quarantined peer must present
    a fresh challenge response authenticated by the deployment's Xavi-Void /
    portable-identity verifier and then pass a probation window.

    `snapshot()` is intentionally JSON-safe so the host supervisor can persist
    quarantine epoch/generation outside the peer process.  Production systems
    MUST persist it across peer/container reboot to prevent ghost-node reset.
    """
    peer_id:str='peer'
    max_invalid_per_window:int=16
    window_ms:int=1000
    quarantine_ms:int=5000
    probation_valid_required:int=3
    invalid_times:list[int]=field(default_factory=list)
    state:PeerState=PeerState.ACTIVE
    quarantine_until_ms:int=0
    quarantine_epoch:int=0
    last_generation:int=0
    probation_valid:int=0
    pending_challenge:ReadmissionChallenge|None=None

    def __post_init__(self):
        if not self.peer_id:
            raise ValueError('peer id')
        if min(self.max_invalid_per_window,self.window_ms,self.quarantine_ms,self.probation_valid_required) < 1:
            raise ValueError('invalid peer guard limits')

    def _trim(self, now_ms:int):
        floor=now_ms-self.window_ms
        self.invalid_times=[x for x in self.invalid_times if x>=floor]

    def _enter_quarantine(self, now_ms:int):
        if self.state is not PeerState.QUARANTINED:
            self.quarantine_epoch += 1
        self.state=PeerState.QUARANTINED
        self.quarantine_until_ms=max(self.quarantine_until_ms,now_ms+self.quarantine_ms)
        self.probation_valid=0
        self.pending_challenge=None

    def force_quarantine(self, now_ms:int)->PeerState:
        if now_ms < 0: raise ValueError('monotonic time')
        self._enter_quarantine(now_ms)
        return self.state

    def observe_invalid(self, now_ms:int)->PeerState:
        if now_ms < 0: raise ValueError('monotonic time')
        self._trim(now_ms); self.invalid_times.append(now_ms)
        if self.state is PeerState.QUARANTINED:
            self.quarantine_until_ms=max(self.quarantine_until_ms,now_ms+self.quarantine_ms)
            return self.state
        if len(self.invalid_times) >= self.max_invalid_per_window:
            self._enter_quarantine(now_ms)
        elif self.state is PeerState.ACTIVE:
            self.state=PeerState.DEGRADED
        return self.state

    def observe_valid(self, now_ms:int)->PeerState:
        if now_ms < 0: raise ValueError('monotonic time')
        self._trim(now_ms)
        if self.state is PeerState.QUARANTINED:
            return self.state
        if self.state is PeerState.DEGRADED:
            self.probation_valid += 1
            if self.probation_valid >= self.probation_valid_required and not self.invalid_times:
                self.state=PeerState.ACTIVE
                self.probation_valid=0
        elif not self.invalid_times:
            self.state=PeerState.ACTIVE
        return self.state

    def allowed(self, now_ms:int)->bool:
        if now_ms < 0: raise ValueError('monotonic time')
        return self.state is not PeerState.QUARANTINED

    def readmission_eligible(self, now_ms:int)->bool:
        if now_ms < 0: raise ValueError('monotonic time')
        return self.state is PeerState.QUARANTINED and now_ms >= self.quarantine_until_ms

    def issue_readmission_challenge(self, *, now_ms:int, generation:int, nonce:bytes, ttl_ms:int=5000)->ReadmissionChallenge:
        if not self.readmission_eligible(now_ms):
            raise ReadmissionError('peer is not eligible for readmission challenge')
        if generation <= self.last_generation:
            raise ReadmissionError('readmission generation must advance monotonically')
        if ttl_ms < 1:
            raise ReadmissionError('challenge ttl')
        c=ReadmissionChallenge(self.peer_id,self.quarantine_epoch,generation,bytes(nonce),now_ms,now_ms+ttl_ms)
        c.canonical()
        self.pending_challenge=c
        return c

    def admit_readmission(self, proof:ReadmissionProof, *, now_ms:int, verifier:ReadmissionVerifier)->PeerState:
        c=self.pending_challenge
        if self.state is not PeerState.QUARANTINED or c is None:
            raise ReadmissionError('no pending readmission challenge')
        if now_ms < c.issued_ms or now_ms > c.expires_ms:
            self.pending_challenge=None
            raise ReadmissionError('readmission challenge expired')
        # Challenge is single-use for every proof attempt, successful or not.
        self.pending_challenge=None
        if proof.peer_id!=self.peer_id or proof.quarantine_epoch!=self.quarantine_epoch:
            raise ReadmissionError('readmission peer/epoch mismatch')
        if proof.generation < c.min_generation or proof.generation <= self.last_generation:
            raise ReadmissionError('stale readmission generation')
        if proof.nonce != c.nonce:
            raise ReadmissionError('readmission challenge mismatch')
        payload=proof.canonical_payload()
        if not proof.authenticator or not verifier.verify_readmission(self.peer_id,payload,proof.authenticator):
            raise ReadmissionError('readmission authentication failed')
        self.last_generation=proof.generation
        self.invalid_times.clear()
        self.state=PeerState.DEGRADED
        self.probation_valid=0
        return self.state

    def snapshot(self)->dict:
        return {
            'schema':'dbp3-peer-guard/v2','peer_id':self.peer_id,
            'state':self.state.value,'quarantine_until_ms':self.quarantine_until_ms,
            'quarantine_epoch':self.quarantine_epoch,'last_generation':self.last_generation,
            'probation_valid':self.probation_valid,
        }

    @classmethod
    def from_snapshot(cls, doc:dict, **limits):
        if doc.get('schema')!='dbp3-peer-guard/v2': raise ReadmissionError('peer guard snapshot schema')
        qms=int(limits.get('quarantine_ms',5000))
        state=PeerState(doc['state'])
        # Never trust an absolute persisted monotonic timestamp across host reboot.
        # A restored quarantined peer starts a fresh local cooldown.
        now_ms=int(limits.pop('now_ms',0))
        until=now_ms+qms if state is PeerState.QUARANTINED else 0
        return cls(peer_id=str(doc['peer_id']),state=state,quarantine_until_ms=until,
                   quarantine_epoch=int(doc['quarantine_epoch']),last_generation=int(doc['last_generation']),
                   probation_valid=int(doc.get('probation_valid',0)),**limits)
