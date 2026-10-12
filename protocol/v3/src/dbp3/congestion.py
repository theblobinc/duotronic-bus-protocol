from dataclasses import dataclass
from enum import IntEnum
class CongestionState(IntEnum): NORMAL=0; CONSTRAINED=1; DEGRADED=2; SURVIVAL=3
@dataclass(frozen=True)
class LinkSample:
    loss:float; rtt_ms:float; jitter_ms:float; available_kbps:float; authenticated:bool=True

def classify(sample:LinkSample)->CongestionState:
    if not sample.authenticated: return CongestionState.SURVIVAL
    if sample.loss>=0.35 or sample.available_kbps<8: return CongestionState.SURVIVAL
    if sample.loss>=0.15 or sample.available_kbps<32 or sample.rtt_ms>1500: return CongestionState.DEGRADED
    if sample.loss>=0.05 or sample.available_kbps<128 or sample.rtt_ms>500: return CongestionState.CONSTRAINED
    return CongestionState.NORMAL
RESERVED_FRACTIONS={CongestionState.NORMAL:(0.05,0.10),CongestionState.CONSTRAINED:(0.10,0.20),CongestionState.DEGRADED:(0.20,0.35),CongestionState.SURVIVAL:(0.35,0.50)}
def reserved_fraction(state):
    """Returns (emergency, control) minimum scheduler shares."""
    return RESERVED_FRACTIONS[CongestionState(state)]
