from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from dbp3 import *
from dbp3.constants import FLAG_PROTECTED

p=DevelopmentHMACProvider(b'0123456789abcdef0123456789abcdef')
f=Frame(Header(flags=FLAG_PROTECTED,sequence=1,stream_id=1,message_id=1),[Record(6,b'hello dbp3')],frame_size=512)
raw=encode_frame(f,p)
out=decode_frame(raw,p)
assert out.records[0].payload==b'hello dbp3'
print(f'DBP v3 Draft 0.11 round-trip OK: {len(raw)} bytes')
