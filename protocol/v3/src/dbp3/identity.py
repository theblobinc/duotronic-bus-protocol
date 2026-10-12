from dataclasses import dataclass
from enum import IntEnum
class PrincipalKind(IntEnum):
    HUMAN=1; DEVICE=2; NODE=3; AUTONOMOUS_AGENT=4; FEDERATION=5; APPLICATION=6; WITNESS_AUTHORITY=7
@dataclass(frozen=True)
class PrincipalRef:
    kind:PrincipalKind; namespace:str; identifier:str
    def validate(self):
        if not self.namespace or not self.identifier: raise ValueError('principal namespace/identifier')
        if len(self.namespace)>64 or len(self.identifier)>256: raise ValueError('principal too long')
        return self
    def canonical(self)->str: return f'{int(self.kind)}:{self.namespace}:{self.identifier}'
