#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,pathlib,struct,sys,tempfile,zlib
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3 import Frame,Header,Record,encode_frame,DevelopmentHMACProvider
from dbp3.constants import FLAG_PROTECTED,REC_CRITICAL,QOS_CONTROL,QOS_TEXT,FEC_GF256,HEADER_SIZE,TRAILER_SIZE,T_PAYLOAD_COMMITMENT,T_SUITE,T_AUTH_TAG,AUTH_TAG_SIZE
KEY=bytes.fromhex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');P=DevelopmentHMACProvider(KEY)

def resign(raw:bytearray):
    fs=len(raw);toff=fs-TRAILER_SIZE;used=struct.unpack_from('<H',raw,56)[0];body=bytes(raw[HEADER_SIZE:toff]);logical=body[:used]
    raw[toff+T_PAYLOAD_COMMITMENT:toff+T_PAYLOAD_COMMITMENT+32]=hashlib.shake_256(b'DBP3/PAYLOAD/v2'+logical).digest(32)
    suite,mode,key_epoch=struct.unpack_from('<HHI',raw,toff+T_SUITE)
    if mode==1:
        associated=bytes(raw[:HEADER_SIZE])+bytes(raw[toff:toff+T_AUTH_TAG])
        raw[toff+T_AUTH_TAG:toff+T_AUTH_TAG+AUTH_TAG_SIZE]=P.authenticate(associated,body,key_epoch)[:AUTH_TAG_SIZE]
    raw[fs-8:fs-4]=struct.pack('<I',zlib.crc32(raw[:fs-8])&0xffffffff)
    return bytes(raw)

def write_invalid(out:pathlib.Path,name,raw,reason,rows):
    (out/name).write_bytes(bytes(raw));rows.append({'file':name,'reason':reason})

def generate(out:pathlib.Path):
    out.mkdir(parents=True,exist_ok=True)
    for p in out.glob('*.dbp3'):p.unlink()
    valid=[]
    for i,fs in enumerate((256,512,1024,2048,4096),1):
        h=Header(flags=FLAG_PROTECTED,profile_id=4,sequence=100+i,session_epoch=2,stream_id=3,message_id=10+i,source_time_us=100000+i,observed_time_us=100100+i,time_uncertainty_us=25,path_id=2,qos=QOS_TEXT,priority=80,key_epoch=3)
        raw=encode_frame(Frame(h,[Record(6,f'hello-f{fs}'.encode(),flags=REC_CRITICAL,qos=QOS_TEXT,priority=80,channel=7,message_id=1000+i)],frame_size=fs),P)
        fn=f'valid-f{fs}.dbp3';(out/fn).write_bytes(raw);valid.append({'file':fn,'frame_size':fs,'record_types':[6]})
    extra=[('valid-call-control-f512.dbp3',512,4,35,b'invite',QOS_CONTROL,40),('valid-ai-proposal-f1024.dbp3',1024,5,106,b'proposal-ref',QOS_CONTROL,55),('valid-ai-consent-f1024.dbp3',1024,6,123,b'accept-peer',QOS_CONTROL,30),('valid-readmission-challenge-f512.dbp3',512,1,142,b'challenge-ref',QOS_CONTROL,10)]
    for j,(fn,fs,pid,typ,payload,qos,pri) in enumerate(extra,1):
        h=Header(flags=FLAG_PROTECTED,profile_id=pid,sequence=200+j,session_epoch=4,stream_id=20+j,message_id=30+j,source_time_us=200000+j,observed_time_us=200200+j,time_uncertainty_us=50,path_id=3,qos=qos,priority=pri,key_epoch=5,fec_scheme=FEC_GF256,fec_k=4,fec_n=6,fec_index=0)
        raw=encode_frame(Frame(h,[Record(typ,payload,flags=REC_CRITICAL,qos=qos,priority=pri,channel=9,message_id=2000+j,deadline_ms=500)],frame_size=fs),P)
        (out/fn).write_bytes(raw);valid.append({'file':fn,'frame_size':fs,'record_types':[typ]})
    invalid=[];base=(out/'valid-f512.dbp3').read_bytes();toff=512-TRAILER_SIZE
    b=bytearray(base);b[100]^=1;write_invalid(out,'invalid-crc-f512.dbp3',b,'CRC/authenticated bytes modified',invalid)
    b=bytearray(base);b[-1]^=1;write_invalid(out,'invalid-fence-f512.dbp3',b,'version fence',invalid)
    h=Header(flags=FLAG_PROTECTED,profile_id=4,sequence=400,session_epoch=2,stream_id=3,message_id=4,key_epoch=2)
    write_invalid(out,'invalid-unknown-critical-f512.dbp3',encode_frame(Frame(h,[Record(65000,b'x',flags=REC_CRITICAL)],frame_size=512),P),'authenticated unknown critical record',invalid)
    h=Header(flags=FLAG_PROTECTED,profile_id=4,sequence=401,session_epoch=2,stream_id=3,message_id=4,key_epoch=2,fec_scheme=FEC_GF256,fec_k=0,fec_n=1,fec_index=0)
    write_invalid(out,'invalid-fec-tuple-f512.dbp3',encode_frame(Frame(h,[Record(6,b'x')],frame_size=512),P),'authenticated invalid FEC tuple',invalid)
    for name,off,fmt,val,reason in [
     ('invalid-record-message-zero-f512.dbp3',HEADER_SIZE+12,'<Q',0,'zero record message id'),
     ('invalid-fragment-count-zero-f512.dbp3',HEADER_SIZE+22,'<H',0,'zero fragment count'),
     ('invalid-record-type-zero-f512.dbp3',HEADER_SIZE,'<H',0,'zero record type'),
     ('invalid-profile-id-zero-f512.dbp3',14,'<H',0,'zero profile id'),
     ('invalid-record-count-overflow-f512.dbp3',58,'<H',129,'record count exceeds decoder limit')]:
        b=bytearray(base);struct.pack_into(fmt,b,off,val);write_invalid(out,name,resign(b),reason,invalid)
    b=bytearray(base);used=struct.unpack_from('<H',b,56)[0];b[HEADER_SIZE+used-1]=1;write_invalid(out,'invalid-record-padding-f512.dbp3',resign(b),'non-zero record padding',invalid)
    b=bytearray(base);struct.pack_into('<HH',b,toff+80,0,0);b[toff+96:toff+120]=b'\0'*24;write_invalid(out,'invalid-protected-no-security-f512.dbp3',resign(b),'protected flag without security mode',invalid)
    b=bytearray(base);struct.pack_into('<H',b,toff+80,1);write_invalid(out,'invalid-suite-mismatch-f512.dbp3',resign(b),'authenticated suite mismatch',invalid)
    b=bytearray(base);struct.pack_into('<H',b,toff+82,2);write_invalid(out,'invalid-security-mode-f512.dbp3',resign(b),'unsupported security mode',invalid)
    b=bytearray(base);b[toff+88]=250;b[toff+89]=1;b[toff+90]=2;b[toff+91]=0;write_invalid(out,'invalid-unregistered-fec-f512.dbp3',resign(b),'unregistered FEC scheme',invalid)
    meta={'schema':'dbp3-golden-vectors/v0.11','development_key_hex':KEY.hex(),'valid':valid,'invalid':invalid}
    (out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
    return len(valid),len(invalid)

def compare_dirs(expected:pathlib.Path,actual:pathlib.Path):
    a={p.relative_to(expected):p.read_bytes() for p in expected.iterdir() if p.is_file()}
    b={p.relative_to(actual):p.read_bytes() for p in actual.iterdir() if p.is_file()}
    if a.keys()!=b.keys():
        missing=sorted(map(str,b.keys()-a.keys()));extra=sorted(map(str,a.keys()-b.keys()))
        raise SystemExit(f'vector freshness mismatch: missing={missing} extra={extra}')
    stale=[str(k) for k in a if a[k]!=b[k]]
    if stale:raise SystemExit('stale generated vectors: '+', '.join(stale))

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--check',action='store_true');a=ap.parse_args();V=ROOT/'vectors'
    if a.check:
        with tempfile.TemporaryDirectory() as td:
            tmp=pathlib.Path(td);nvalid,ninvalid=generate(tmp);compare_dirs(tmp,V)
        print(f'vector freshness verified: {nvalid} valid / {ninvalid} invalid')
    else:
        nvalid,ninvalid=generate(V);print(f'generated {nvalid} valid and {ninvalid} invalid vectors')
