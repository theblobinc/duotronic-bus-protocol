from dataclasses import dataclass, asdict
import json, hashlib

def canonical(obj): return json.dumps(asdict(obj),sort_keys=True,separators=(',',':')).encode()
@dataclass(frozen=True)
class Observation:
    witness_id:str; source_ref:str; sequence_number:int; source_time_us:int|None; observed_time_us:int; uncertainty_us:int=0
    def validate(self):
        if not self.witness_id or not self.source_ref or self.sequence_number<1 or self.observed_time_us<0 or self.uncertainty_us<0: raise ValueError('observation')
        if self.source_time_us is not None and self.source_time_us<0: raise ValueError('source time')
        return self
    def digest(self): self.validate(); return hashlib.shake_256(b'DBP3/WGRNN/OBS/v1'+canonical(self)).hexdigest(32)
@dataclass(frozen=True)
class GateReceipt:
    witness_id:str; admitted:bool; previous_receipt_id:str=''; state_mutated:bool=False; reason:str=''
    def validate(self):
        if not self.witness_id: raise ValueError('witness id')
        if not self.admitted and self.state_mutated: raise ValueError('blocked witness cannot mutate recurrent state')
        return self
