from dataclasses import dataclass, field
U64_MAX=(1<<64)-1
@dataclass(frozen=True)
class Revocation:
    target_ref:str; authority_ref:str; effective_us:int; sequence:int; reason:str=''; witness_ref:str=''
    def validate(self):
        if not self.target_ref or not self.authority_ref or not 1<=self.sequence<=U64_MAX or not 0<=self.effective_us<=U64_MAX: raise ValueError('revocation')
        if len(self.target_ref)>4096 or len(self.authority_ref)>4096 or len(self.reason)>4096 or len(self.witness_ref)>4096: raise ValueError('revocation field length')
        return self
@dataclass
class RevocationSet:
    high_water:int=0; targets:dict[str,Revocation]=field(default_factory=dict); max_targets:int=65536
    def __post_init__(self):
        if not 1<=self.max_targets<=1_000_000 or not 0<=self.high_water<=U64_MAX or len(self.targets)>self.max_targets: raise ValueError('revocation set bounds')
    def apply(self,r:Revocation):
        r.validate()
        if r.sequence <= self.high_water: raise ValueError('stale revocation chronology')
        if r.target_ref not in self.targets and len(self.targets)>=self.max_targets: raise RuntimeError('revocation target capacity exhausted; externalize/persist chronology')
        self.targets[r.target_ref]=r; self.high_water=r.sequence
    def revoked(self,target_ref:str,at_us:int)->bool:
        if not 0<=at_us<=U64_MAX: raise ValueError('revocation query time')
        r=self.targets.get(target_ref); return bool(r and at_us>=r.effective_us)
