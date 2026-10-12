from dataclasses import dataclass, field
import struct, hashlib, zlib
from .constants import *
from .records import Record, encode_records, decode_records
from .errors import FrameError

@dataclass
class Header:
    flags:int=0; frame_kind:int=1; profile_id:int=1; sequence:int=1; session_epoch:int=1
    stream_id:int=1; message_id:int=1; source_time_us:int=0; observed_time_us:int=0
    time_uncertainty_us:int=0; path_id:int=0; qos:int=QOS_BACKGROUND; priority:int=128
    key_epoch:int=1; fec_scheme:int=FEC_NONE; fec_k:int=0; fec_n:int=0; fec_index:int=0

@dataclass
class Frame:
    header:Header=field(default_factory=Header)
    records:list[Record]=field(default_factory=list)
    witness_commitment:bytes=b'\0'*32
    carrier_binding:bytes=b'\0'*16
    frame_size:int=DEFAULT_FRAME_SIZE

def _pack_header(h:Header, used:int, count:int, frame_size:int)->bytes:
    if frame_size not in FRAME_SIZES: raise FrameError('unsupported frame size')
    if min(h.sequence,h.session_epoch,h.stream_id,h.message_id,h.key_epoch) < 1: raise FrameError('one-origin identifiers required')
    if h.sequence > 0xffffffffffffffff or h.key_epoch > 0xffffffff: raise FrameError('sequence/key epoch range')
    if not (0 <= h.flags <= 0xffffffff and 1 <= h.frame_kind <= 0xffff and 1 <= h.profile_id <= 0xffff): raise FrameError('header range')
    if not (0 <= h.session_epoch <= 0xffffffff and 0 <= h.stream_id <= 0xffffffff and 0 <= h.message_id <= 0xffffffff): raise FrameError('identifier range')
    if not (0 <= h.source_time_us <= 0xffffffffffffffff and 0 <= h.observed_time_us <= 0xffffffffffffffff): raise FrameError('time range')
    if not (0 <= h.time_uncertainty_us <= 0xffffffff and 0 <= h.path_id <= 0xffff): raise FrameError('metadata range')
    if not (0 <= used <= body_size(frame_size) and 0 <= used <= 0xffff and 0 <= count <= 0xffff): raise FrameError('body/count')
    if not (0 <= h.qos <= 255 and 0 <= h.priority <= 255): raise FrameError('qos/priority')
    b=bytearray(HEADER_SIZE)
    struct.pack_into('<4sBBH',b,H_MAGIC,MAGIC,MAJOR,MINOR,HEADER_SIZE)
    struct.pack_into('<IHHQIIIQQIHHHBB',b,H_FLAGS,h.flags,h.frame_kind,h.profile_id,h.sequence,h.session_epoch,
                     h.stream_id,h.message_id,h.source_time_us,h.observed_time_us,h.time_uncertainty_us,
                     used,count,h.path_id,h.qos,h.priority)
    return bytes(b)

def _unpack_header(b:bytes, frame_size:int):
    if len(b)!=HEADER_SIZE: raise FrameError('header size')
    magic,maj,minr,hlen=struct.unpack_from('<4sBBH',b,H_MAGIC)
    if magic!=MAGIC or maj!=MAJOR or minr!=MINOR or hlen!=HEADER_SIZE: raise FrameError('magic/version/header')
    vals=struct.unpack_from('<IHHQIIIQQIHHHBB',b,H_FLAGS)
    flags,fk,pid,seq,epoch,sid,mid,st,ot,unc,used,count,path,qos,pri=vals
    if min(fk,pid,seq,epoch,sid,mid) < 1 or used > body_size(frame_size): raise FrameError('invalid structural field')
    return Header(flags,fk,pid,seq,epoch,sid,mid,st,ot,unc,path,qos,pri),used,count

def payload_commitment(body_plain:bytes)->bytes:
    return hashlib.shake_256(b'DBP3/PAYLOAD/v2'+body_plain).digest(32)

def frame_commitment(frame_bytes:bytes)->bytes:
    if len(frame_bytes) not in FRAME_SIZES: raise FrameError('frame size')
    return hashlib.shake_256(b'DBP3/FRAME/v2'+frame_bytes).digest(32)

def encode_frame(frame:Frame, provider=None)->bytes:
    frame_size=frame.frame_size
    bsize=body_size(frame_size)
    logical=encode_records(frame.records)
    if len(logical)>bsize: raise FrameError('records exceed selected frame body')
    body=logical+b'\0'*(bsize-len(logical))
    hdr=_pack_header(frame.header,len(logical),len(frame.records),frame_size)
    tr=bytearray(TRAILER_SIZE)
    tr[T_PAYLOAD_COMMITMENT:T_PAYLOAD_COMMITMENT+32]=payload_commitment(logical)
    if len(frame.witness_commitment)!=32: raise FrameError('witness commitment')
    if len(frame.carrier_binding)!=16: raise FrameError('carrier binding')
    tr[T_WITNESS_COMMITMENT:T_WITNESS_COMMITMENT+32]=frame.witness_commitment
    tr[T_CARRIER_BINDING:T_CARRIER_BINDING+16]=frame.carrier_binding
    suite=0 if provider is None else provider.suite_id
    struct.pack_into('<HHI',tr,T_SUITE,suite,1 if provider else 0,frame.header.key_epoch)
    for name,v in [('fec_scheme',frame.header.fec_scheme),('fec_k',frame.header.fec_k),('fec_n',frame.header.fec_n),('fec_index',frame.header.fec_index)]:
        if not 0 <= v <= 255: raise FrameError(name)
    tr[T_FEC_SCHEME]=frame.header.fec_scheme; tr[T_FEC_K]=frame.header.fec_k; tr[T_FEC_N]=frame.header.fec_n; tr[T_FEC_INDEX]=frame.header.fec_index
    associated=hdr+bytes(tr[:T_AUTH_TAG])
    tag=b'' if provider is None else provider.authenticate(associated,body,frame.header.key_epoch)
    if len(tag) < (0 if provider is None else 16): raise FrameError('authentication tag too short')
    tr[T_AUTH_TAG:T_AUTH_TAG+AUTH_TAG_SIZE]=tag[:AUTH_TAG_SIZE].ljust(AUTH_TAG_SIZE,b'\0')
    raw=bytearray(hdr+body+tr)
    crc=zlib.crc32(raw[:frame_size-8]) & 0xffffffff
    struct.pack_into('<I',raw,frame_size-8,crc); raw[frame_size-4:]=VERSION_FENCE
    return bytes(raw)

def decode_frame(raw:bytes, provider=None, *, max_records=128)->Frame:
    frame_size=len(raw)
    if frame_size not in FRAME_SIZES: raise FrameError('unsupported fixed frame size')
    h,used,count=_unpack_header(raw[:HEADER_SIZE],frame_size)
    trailer_offset=frame_size-TRAILER_SIZE
    if raw[-4:] != VERSION_FENCE: raise FrameError('version fence')
    expect=struct.unpack_from('<I',raw,frame_size-8)[0]; got=zlib.crc32(raw[:frame_size-8]) & 0xffffffff
    if got!=expect: raise FrameError('wire CRC')
    body=raw[HEADER_SIZE:trailer_offset]; tr=raw[trailer_offset:]
    logical=body[:used]
    if payload_commitment(logical)!=tr[T_PAYLOAD_COMMITMENT:T_PAYLOAD_COMMITMENT+32]: raise FrameError('payload commitment')
    suite,mode,key_epoch=struct.unpack_from('<HHI',tr,T_SUITE)
    if any(tr[92:96]): raise FrameError('reserved trailer bytes')
    h.key_epoch=key_epoch; h.fec_scheme=tr[T_FEC_SCHEME]; h.fec_k=tr[T_FEC_K]; h.fec_n=tr[T_FEC_N]; h.fec_index=tr[T_FEC_INDEX]
    if h.fec_scheme not in set(FEC_ALGORITHM_IDS.values()): raise FrameError('unregistered FEC scheme')
    if h.fec_scheme==0 and any((h.fec_k,h.fec_n,h.fec_index)): raise FrameError('FEC tuple without scheme')
    if h.fec_scheme and (h.fec_k<1 or h.fec_n<h.fec_k or h.fec_index>=h.fec_n): raise FrameError('invalid FEC tuple')
    if key_epoch < 1: raise FrameError('key epoch')
    if mode not in (0,1): raise FrameError('unsupported security mode')
    if mode:
        if not (h.flags & FLAG_PROTECTED): raise FrameError('security mode without protected flag')
        if provider is None or suite != provider.suite_id: raise FrameError('security provider/suite unavailable')
        associated=raw[:HEADER_SIZE]+tr[:T_AUTH_TAG]
        if not provider.verify(associated,body,key_epoch,tr[T_AUTH_TAG:T_AUTH_TAG+AUTH_TAG_SIZE]): raise FrameError('authentication')
    else:
        if suite != 0: raise FrameError('suite without security mode')
        if any(tr[T_AUTH_TAG:T_AUTH_TAG+AUTH_TAG_SIZE]): raise FrameError('authentication tag without security mode')
        if h.flags & FLAG_PROTECTED: raise FrameError('protected flag without security mode')
    recs=decode_records(logical,count,max_records=max_records)
    return Frame(h,recs,tr[T_WITNESS_COMMITMENT:T_WITNESS_COMMITMENT+32],tr[T_CARRIER_BINDING:T_CARRIER_BINDING+16],frame_size)
