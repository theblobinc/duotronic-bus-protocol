from dbp3.object_transfer import *
from dbp3.multipath import *
from dbp3.time_state import TimeState
def test_object_manifest_chunks():
    m,ch=build_manifest('map',b'abcdefghij',4); m.validate(); assert all(verify_chunk(m,i,c) for i,c in enumerate(ch)); assert not verify_chunk(m,0,b'bad')
def test_multipath_critical_duplicates():
    p=[PathMetric(1,10,.01,2,1000,True,'a'),PathMetric(2,20,.0,1,500,True,'b'),PathMetric(3,1,1.0,0,1000,True,'c')]; assert len(choose_paths(p,critical=True))==2
def test_time_uncertainty(): TimeState(100,120,20,'gnss',1).validate()
