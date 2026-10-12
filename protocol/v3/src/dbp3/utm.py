from dataclasses import dataclass, asdict
import json, math

def _canon(obj)->bytes: return json.dumps(asdict(obj),sort_keys=True,separators=(',',':'),allow_nan=False).encode()
@dataclass(frozen=True)
class SpatialState:
    aircraft_id:str; lat_deg:float; lon_deg:float; altitude_m:float; altitude_datum:str; velocity_mps:tuple[float,float,float]; source_time_us:int; uncertainty_m:float; crs:str='EPSG:4979'
    def validate(self):
        vals=(self.lat_deg,self.lon_deg,self.altitude_m,self.uncertainty_m,*self.velocity_mps)
        if not all(math.isfinite(x) for x in vals): raise ValueError('nonfinite spatial state')
        if not -90<=self.lat_deg<=90 or not -180<=self.lon_deg<=180 or self.uncertainty_m<0: raise ValueError('spatial range')
        if self.altitude_datum not in {'WGS84_ELLIPSOID','MSL','AGL'}: raise ValueError('altitude datum')
        if not self.aircraft_id or self.source_time_us<0: raise ValueError('identity/time')
        return self
    def encode(self): self.validate(); return _canon(self)
@dataclass(frozen=True)
class ConflictProposal:
    proposal_id:str; subject_ids:tuple[str,...]; valid_until_us:int; evidence_ref:str; severity:int; proposed_action:str
    def validate(self):
        if not self.proposal_id or len(self.subject_ids)<1 or self.valid_until_us<0 or not self.evidence_ref or not (0<=self.severity<=255) or not self.proposed_action: raise ValueError('conflict proposal')
        return self
@dataclass(frozen=True)
class DeconflictionDecision:
    proposal_id:str; decision_id:str; authority_ref:str; action:str; effective_us:int; witness_ref:str
    def validate(self):
        if not all((self.proposal_id,self.decision_id,self.authority_ref,self.action,self.witness_ref)) or self.effective_us<0: raise ValueError('deconfliction decision')
        return self
@dataclass(frozen=True)
class HumanDecision:
    proposal_id:str; operator_ref:str; state:str; decided_at_us:int; witness_ref:str=''; amendment_ref:str=''
    ALLOWED=('presented','accepted','rejected','amended','executed','outcome_observed')
    def validate(self):
        if self.state not in self.ALLOWED or not self.proposal_id or not self.operator_ref or self.decided_at_us<0: raise ValueError('human decision')
        return self
    def encode(self): self.validate(); return _canon(self)
