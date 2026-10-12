from dataclasses import dataclass, field
from enum import Enum
import hashlib, json
from .errors import StateError

U32_MAX=(1<<32)-1
U64_MAX=(1<<64)-1

class SessionState(str,Enum):
    DISCOVER='discover'; NEGOTIATE='negotiate'; ESTABLISH='establish'; ACTIVE='active'; DEGRADED='degraded'; REKEY='rekey'; QUARANTINED='quarantined'; SUSPENDED='suspended'; RESUME='resume'; CLOSED='closed'
_ALLOWED={
 SessionState.DISCOVER:{SessionState.NEGOTIATE,SessionState.CLOSED}, SessionState.NEGOTIATE:{SessionState.ESTABLISH,SessionState.CLOSED},
 SessionState.ESTABLISH:{SessionState.ACTIVE,SessionState.CLOSED}, SessionState.ACTIVE:{SessionState.DEGRADED,SessionState.REKEY,SessionState.QUARANTINED,SessionState.SUSPENDED,SessionState.CLOSED},
 SessionState.DEGRADED:{SessionState.ACTIVE,SessionState.REKEY,SessionState.QUARANTINED,SessionState.SUSPENDED,SessionState.CLOSED},
 SessionState.REKEY:{SessionState.ACTIVE,SessionState.DEGRADED,SessionState.QUARANTINED,SessionState.CLOSED},
 SessionState.QUARANTINED:{SessionState.CLOSED}, SessionState.SUSPENDED:{SessionState.RESUME,SessionState.QUARANTINED,SessionState.CLOSED},
 SessionState.RESUME:{SessionState.ACTIVE,SessionState.DEGRADED,SessionState.QUARANTINED,SessionState.CLOSED}, SessionState.CLOSED:set()}

def canonical_capabilities(caps:dict)->bytes:
    raw=json.dumps(caps,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    if len(raw)>1_048_576: raise StateError('capability transcript too large')
    return raw

def negotiation_commitment(local:dict,remote:dict,chosen:dict, *, session_id:bytes=b'')->bytes:
    if len(session_id)>65535: raise StateError('session id too large for negotiation commitment')
    parts=[b'DBP3/NEGOTIATION/v2',len(session_id).to_bytes(2,'little'),session_id,canonical_capabilities(local),canonical_capabilities(remote),canonical_capabilities(chosen)]
    return hashlib.shake_256(b'\0'.join(parts)).digest(32)

def validate_selection(local:dict,remote:dict,chosen:dict):
    for key,value in chosen.items():
        if key in {'frame_size','security_suite','fec','compression','codec','witness_profile'}:
            lv=local.get(key,[]); rv=remote.get(key,[])
            lv=lv if isinstance(lv,list) else [lv]; rv=rv if isinstance(rv,list) else [rv]
            if value not in lv or value not in rv: raise StateError(f'downgrade/unsupported selection: {key}')
    return True

@dataclass
class Session:
    session_id:bytes
    state:SessionState=SessionState.DISCOVER
    generation:int=1
    key_epoch:int=1
    negotiation_digest:bytes=b''
    compromised_epochs:set[int]=field(default_factory=set)
    history:list[tuple[str,str]]=field(default_factory=list)
    history_limit:int=256
    compromised_epoch_limit:int=4096
    history_digest:bytes=b''

    def __post_init__(self):
        if not isinstance(self.session_id,(bytes,bytearray)) or not 1<=len(self.session_id)<=65535: raise StateError('session id')
        if not 1<=self.generation<=U64_MAX or not 1<=self.key_epoch<=U32_MAX: raise StateError('session generation/key epoch')
        if not 1<=self.history_limit<=65536 or not 1<=self.compromised_epoch_limit<=65536: raise StateError('session local history bounds')
        if len(self.history)>self.history_limit or len(self.compromised_epochs)>self.compromised_epoch_limit: raise StateError('session local history exceeds bounds')
        if any(not 1<=x<=U32_MAX for x in self.compromised_epochs): raise StateError('compromised key epoch range')

    def _record_transition(self,old:SessionState,new:SessionState)->None:
        row=(old.value,new.value)
        prior=self.history_digest or b'\0'*32
        self.history_digest=hashlib.shake_256(b'DBP3/SESSION-HISTORY/v1'+prior+('|'.join(row)).encode()).digest(32)
        self.history.append(row)
        if len(self.history)>self.history_limit:
            del self.history[0]

    def transition(self,new_state:SessionState, reason:str='')->None:
        if new_state not in _ALLOWED[self.state]: raise StateError(f'invalid transition {self.state}->{new_state}')
        old=self.state
        if new_state==SessionState.REKEY and self.key_epoch>=U32_MAX: raise StateError('key epoch exhausted')
        if new_state==SessionState.RESUME and self.generation>=U64_MAX: raise StateError('session generation exhausted')
        self._record_transition(old,new_state); self.state=new_state
        if new_state==SessionState.REKEY: self.key_epoch += 1
        if new_state==SessionState.RESUME: self.generation += 1

    def compromise(self):
        if self.key_epoch not in self.compromised_epochs and len(self.compromised_epochs)>=self.compromised_epoch_limit:
            raise StateError('compromised epoch ledger capacity exhausted')
        self.compromised_epochs.add(self.key_epoch)
        if self.state not in {SessionState.CLOSED,SessionState.QUARANTINED}: self.transition(SessionState.QUARANTINED,'suspected key compromise')

    def can_resume(self): return self.state==SessionState.SUSPENDED and self.key_epoch not in self.compromised_epochs
