from dataclasses import dataclass
import struct
# fixed 24-byte emergency payload: no schema lookup, no compression
_STRUCT=struct.Struct('<BBHIQII')
class EmergencyCode:
    DISTRESS=1; COLLISION_RISK=2; ABORT=3; LOSS_OF_CONTROL=4; EMERGENCY_LAND=5; SHUTDOWN=6
@dataclass(frozen=True)
class EmergencyRecord:
    code:int; severity:int; subject_id:int; source_time_us:int; reason_code:int=0; flags:int=0
    def encode(self):
        if not (1<=self.code<=255 and 0<=self.severity<=255 and 1<=self.subject_id<=0xffffffff): raise ValueError('emergency field')
        return _STRUCT.pack(self.code,self.severity,0,self.subject_id,self.source_time_us,self.reason_code,self.flags)
    @classmethod
    def decode(cls,b:bytes):
        if len(b)!=_STRUCT.size: raise ValueError('emergency payload size')
        code,severity,reserved,subject,source,reason,flags=_STRUCT.unpack(b)
        if reserved: raise ValueError('reserved emergency bits')
        return cls(code,severity,subject,source,reason,flags)
