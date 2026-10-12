from dbp3.fec import encode,recover
import pytest
def test_multi_erasure_recovery():
    data=[bytes([i])*64 for i in range(1,5)]; shards=encode(data,7); avail={0:shards[0],2:shards[2],4:shards[4],6:shards[6]}; assert recover(avail,4,7)==data
def test_insufficient_fec():
    with pytest.raises(ValueError): recover({0:b'a'},2,3)
