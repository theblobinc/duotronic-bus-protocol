from dataclasses import dataclass
import struct
from .constants import REC_CRITICAL, RECORD_TYPES
from .errors import RecordError
_RECORD = struct.Struct('<HHHBBIQHHII')
assert _RECORD.size == 32
@dataclass(frozen=True)
class Record:
    type_id:int; payload:bytes; flags:int=0; codec:int=0; qos:int=7; priority:int=128; channel:int=0
    message_id:int=1; fragment_index:int=0; fragment_count:int=1; deadline_ms:int=0
    def encode(self)->bytes:
        if not (1 <= self.type_id <= 0xffff): raise RecordError('record type')
        if not (0 <= self.flags <= 0xffff and 0 <= self.codec <= 0xffff): raise RecordError('record flags/codec')
        if not (0 <= self.qos <= 255 and 0 <= self.priority <= 255 and 0 <= self.channel <= 0xffffffff): raise RecordError('qos/priority/channel')
        if not (1 <= self.message_id <= 0xffffffffffffffff): raise RecordError('message_id is one-origin')
        if not (1 <= self.fragment_count <= 0xffff and 0 <= self.fragment_index < self.fragment_count): raise RecordError('fragmentation')
        if len(self.payload) > 0xffffffff: raise RecordError('record too large')
        if not (0 <= self.deadline_ms <= 0xffffffff): raise RecordError('deadline range')
        h=_RECORD.pack(self.type_id,self.flags,self.codec,self.qos,self.priority,self.channel,self.message_id,self.fragment_index,self.fragment_count,len(self.payload),self.deadline_ms)
        return h+self.payload+b'\0'*((-len(self.payload)) & 3)
def encode_records(records): return b''.join(r.encode() for r in records)
def decode_records(data:bytes,count:int, *, max_records=128, reject_unknown_critical=True):
    if count > max_records: raise RecordError('record limit')
    out=[]; off=0
    for _ in range(count):
        if off+_RECORD.size > len(data): raise RecordError('truncated record header')
        t,f,c,q,p,ch,mid,fi,fc,n,dl=_RECORD.unpack_from(data,off); off += _RECORD.size
        if t < 1: raise RecordError('record type is one-origin')
        if fc < 1 or fi >= fc or mid < 1: raise RecordError('bad fragmentation/message identity')
        if off+n > len(data): raise RecordError('truncated record payload')
        payload=data[off:off+n]; off += n; pad=(-n)&3
        if off+pad>len(data) or any(data[off:off+pad]): raise RecordError('non-zero/bad record padding')
        off += pad
        if reject_unknown_critical and t not in RECORD_TYPES and (f & REC_CRITICAL): raise RecordError('unknown critical record')
        out.append(Record(t,payload,f,c,q,p,ch,mid,fi,fc,dl))
    if any(data[off:]): raise RecordError('non-zero trailing bytes')
    return out
