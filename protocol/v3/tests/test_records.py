import pytest
from dbp3.records import *
from dbp3.errors import RecordError
def test_fragment_record_roundtrip():
    r=Record(9,b'abc',flags=2,codec=7,qos=4,priority=5,channel=2,message_id=99,fragment_index=1,fragment_count=3,deadline_ms=80)
    assert decode_records(r.encode(),1)[0]==r
def test_bad_fragment_rejected():
    with pytest.raises(RecordError): Record(9,b'x',message_id=1,fragment_index=2,fragment_count=2).encode()
