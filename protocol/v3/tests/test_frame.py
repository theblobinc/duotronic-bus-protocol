import pytest
from dbp3 import *
from dbp3.constants import FLAG_PROTECTED, FRAME_SIZES, body_size
from dbp3.errors import FrameError
def provider(): return DevelopmentHMACProvider(b'0123456789abcdef0123456789abcdef')
@pytest.mark.parametrize('size',FRAME_SIZES)
def test_roundtrip_family(size):
    p=provider(); f=Frame(Header(flags=FLAG_PROTECTED),[Record(6,b'hi')],frame_size=size)
    raw=encode_frame(f,p); assert len(raw)==size; out=decode_frame(raw,p); assert out.frame_size==size and out.records[0].payload==b'hi'
def test_small_frame_enforces_capacity():
    with pytest.raises(FrameError): encode_frame(Frame(Header(),[Record(6,b'x'*64)],frame_size=256))
def test_corruption_rejected():
    p=provider(); raw=bytearray(encode_frame(Frame(Header(flags=FLAG_PROTECTED),[Record(3,b'x')],frame_size=512),p)); raw[80]^=1
    with pytest.raises(FrameError): decode_frame(bytes(raw),p)
def test_unknown_shape():
    with pytest.raises(FrameError): decode_frame(b'x'*768)
