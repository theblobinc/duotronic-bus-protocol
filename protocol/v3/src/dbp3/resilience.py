from dataclasses import dataclass
from .congestion import CongestionState
@dataclass(frozen=True)
class ResiliencePlan:
    fec_k:int; fec_n:int; duplicate_paths:int; interleave_depth:int; media_scale:float

def plan(state:CongestionState, *, authenticated_feedback:bool=True)->ResiliencePlan:
    # Unauthenticated feedback may only move conservatively; it cannot request expensive expansion.
    if not authenticated_feedback:
        return ResiliencePlan(4,5,1,1,0.5)
    s=CongestionState(state)
    if s==CongestionState.NORMAL: return ResiliencePlan(8,9,1,1,1.0)
    if s==CongestionState.CONSTRAINED: return ResiliencePlan(6,8,1,2,0.75)
    if s==CongestionState.DEGRADED: return ResiliencePlan(4,7,2,3,0.35)
    return ResiliencePlan(2,5,2,4,0.0)
