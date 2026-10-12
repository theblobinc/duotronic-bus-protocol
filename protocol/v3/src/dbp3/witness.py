from dataclasses import dataclass, field
from enum import Enum
from .errors import AuthorityError

@dataclass(frozen=True)
class WitnessBinding:
    object_type:str
    object_id:str
    authority_domain:str=''
    authority_snapshot_id:str=''
    ledger_high_water_sequence:int=0
    authorization_witness_id:str=''
    def validate(self, *, authority_bearing=False):
        if not self.object_type or not self.object_id: raise AuthorityError('missing witness object identity')
        if authority_bearing:
            if not self.authority_domain or not self.authority_snapshot_id or not self.authorization_witness_id:
                raise AuthorityError('authority-bearing operation lacks authority binding')
            if self.ledger_high_water_sequence < 1: raise AuthorityError('authority chronology must be one-origin')
        return self

def require_authority(*, transport_authenticated:bool, semantic_valid:bool, binding:WitnessBinding|None, policy_allowed:bool)->bool:
    if not transport_authenticated or not semantic_valid or binding is None or not policy_allowed: return False
    binding.validate(authority_bearing=True)
    return True

class QuorumStatus(str, Enum):
    PENDING='pending'; SATISFIED='satisfied'; IMPOSSIBLE='impossible'

@dataclass
class WitnessQuorum:
    """Fixed-threshold quorum. Peer loss never lowers authorization threshold."""
    eligible:frozenset[str]
    threshold:int
    approvals:set[str]=field(default_factory=set)
    unavailable:set[str]=field(default_factory=set)
    def __post_init__(self):
        if not self.eligible or not (1<=self.threshold<=len(self.eligible)): raise ValueError('invalid witness quorum')
    def approve(self,principal:str):
        if principal not in self.eligible or principal in self.unavailable: raise AuthorityError('ineligible/unavailable witness')
        self.approvals.add(principal); return self.status()
    def mark_unavailable(self,principal:str):
        if principal in self.eligible: self.unavailable.add(principal); self.approvals.discard(principal)
        return self.status()
    def mark_available(self,principal:str):
        if principal not in self.eligible: raise AuthorityError('ineligible witness')
        self.unavailable.discard(principal); self.approvals.discard(principal); return self.status()
    def status(self)->QuorumStatus:
        if len(self.approvals)>=self.threshold:return QuorumStatus.SATISFIED
        possible=len(self.eligible-self.unavailable)
        if possible<self.threshold:return QuorumStatus.IMPOSSIBLE
        return QuorumStatus.PENDING
