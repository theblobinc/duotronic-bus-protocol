from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import hashlib

class CallState(str, Enum):
    IDLE='idle'; INVITED='invited'; RINGING='ringing'; ACTIVE='active'; HELD='held'; ENDED='ended'

_ALLOWED={
    CallState.IDLE:{CallState.INVITED},
    CallState.INVITED:{CallState.RINGING,CallState.ACTIVE,CallState.ENDED},
    CallState.RINGING:{CallState.ACTIVE,CallState.ENDED},
    CallState.ACTIVE:{CallState.HELD,CallState.ENDED},
    CallState.HELD:{CallState.ACTIVE,CallState.ENDED},
    CallState.ENDED:set(),
}

@dataclass
class CallSession:
    call_id:str; initiator:str; peer_or_group:str; state:CallState=CallState.IDLE; generation:int=1
    participants:set[str]=field(default_factory=set);max_participants:int=256
    def __post_init__(self):
        if not self.call_id or not self.initiator or not self.peer_or_group or not 1<=self.generation<=0xffffffffffffffff or not 1<=self.max_participants<=4096: raise ValueError('call session')
        if len(self.participants)>self.max_participants: raise ValueError('call participant budget')
    def transition(self,new_state:CallState):
        if new_state not in _ALLOWED[self.state]: raise ValueError(f'illegal call transition {self.state}->{new_state}')
        self.state=new_state
        return self
    def add_participant(self,p:str):
        if not p: raise ValueError('participant')
        if p not in self.participants and len(self.participants)>=self.max_participants: raise ValueError('call participant budget')
        self.participants.add(p); return self
    def handoff(self,old_device:str,new_device:str):
        if old_device not in self.participants or not new_device: raise ValueError('handoff')
        if self.generation>=0xffffffffffffffff: raise OverflowError('call generation exhausted')
        self.participants.remove(old_device); self.participants.add(new_device); self.generation += 1; return self

class FloorState(str, Enum): IDLE='idle'; GRANTED='granted'
@dataclass
class PTTFloor:
    channel_id:str; holder:str=''; priority:int=-1; state:FloorState=FloorState.IDLE; epoch:int=1
    def request(self,principal:str,priority:int=0,emergency:bool=False)->bool:
        if not principal or not isinstance(priority,int): raise ValueError('principal/priority')
        # Emergency preemption is a separate protocol semantic: caller-supplied
        # priority is ignored and cannot weaken or strengthen it.
        if emergency:
            eff=256
        else:
            if not 0<=priority<=255: raise ValueError('principal/priority')
            eff=priority
        if self.state==FloorState.IDLE or principal==self.holder or eff>self.priority:
            self.holder=principal; self.priority=eff; self.state=FloorState.GRANTED; self.epoch += 1; return True
        return False
    def release(self,principal:str)->bool:
        if self.state==FloorState.GRANTED and principal==self.holder:
            self.holder=''; self.priority=-1; self.state=FloorState.IDLE; self.epoch += 1; return True
        return False

@dataclass(frozen=True)
class ParticipantBinding:
    principal_id:str; device_id:str; session_generation:int; group_epoch:int=0; witness_authority_ref:str=''
    def validate(self):
        if not self.principal_id or not self.device_id or self.session_generation<1 or self.group_epoch<0: raise ValueError('participant binding')
        return self

@dataclass
class StreamKeyEpochs:
    text:int=1; voice:int=1; video:int=1; telemetry:int=1; control:int=1
    def rekey(self,stream:str):
        if stream not in self.__dict__: raise ValueError('stream')
        cur=getattr(self,stream)
        if not 1<=cur<0xffffffffffffffff: raise OverflowError('stream key epoch exhausted')
        setattr(self,stream,cur+1); return getattr(self,stream)

@dataclass(frozen=True)
class MessageEvent:
    conversation_id:str; message_id:str; sender:str; kind:str; payload_digest:str; previous_event_digest:str=''; created_us:int=0
    def validate(self):
        if not all((self.conversation_id,self.message_id,self.sender,self.kind,self.payload_digest)) or not 0<=self.created_us<=0xffffffffffffffff: raise ValueError('message event')
        return self
    def digest(self)->str:
        self.validate();body='|'.join((self.conversation_id,self.message_id,self.sender,self.kind,self.payload_digest,self.previous_event_digest,str(self.created_us)))
        return hashlib.sha256(body.encode()).hexdigest()

@dataclass
class StoreForwardEnvelope:
    envelope_id:str; destination:str; expires_us:int; priority:int=0; custody_hops:list[str]=field(default_factory=list); delivered:bool=False;max_hops:int=64
    def __post_init__(self):
        if not self.envelope_id or not self.destination or not 0<=self.expires_us<=0xffffffffffffffff or not 0<=self.priority<=255 or not 1<=self.max_hops<=1024: raise ValueError('store-forward envelope')
        if len(self.custody_hops)>self.max_hops or len(self.custody_hops)!=len(set(self.custody_hops)): raise ValueError('custody path')
    def accept_custody(self,node:str,now_us:int):
        if now_us<0 or now_us>self.expires_us: raise ValueError('expired/clock')
        if not node: raise ValueError('custody node')
        if node in self.custody_hops: raise ValueError('custody routing loop')
        if len(self.custody_hops)>=self.max_hops: raise ValueError('custody hop budget')
        self.custody_hops.append(node);return self
    def mark_delivered(self): self.delivered=True; return self

@dataclass(frozen=True)
class MediaLayer:
    layer_id:str; bitrate_bps:int; max_latency_ms:int; mode:str
    def validate(self):
        if not self.layer_id or self.bitrate_bps<0 or self.max_latency_ms<1: raise ValueError('media layer')
        if self.mode not in {'video','audio','thumbnail','keyframe-only','audio-only','text-ptt-survival'}: raise ValueError('mode')
        return self

SURVIVAL_ORDER=('video','voice','text','control-emergency')
def degraded_media_mode(loss_fraction:float,latency_ms:int)->str:
    if loss_fraction>=0.45 or latency_ms>=2500: return 'text-ptt-survival'
    if loss_fraction>=0.25 or latency_ms>=1200: return 'audio-only'
    if loss_fraction>=0.12 or latency_ms>=600: return 'thumbnail'
    return 'video'

@dataclass(frozen=True)
class RecordingCommitment:
    recording_id:str; conversation_id:str; media_digest:str; started_us:int; ended_us:int; witness_ref:str=''
    def validate(self):
        if not self.recording_id or not self.conversation_id or not self.media_digest or self.started_us<0 or self.ended_us<self.started_us or self.ended_us>0xffffffffffffffff: raise ValueError('recording commitment')
        return self
