import pytest
from dbp3 import ProcessingWindow,ProcessingBudgetError,AuthenticatedLiveness,LivenessState

def test_processing_window_bounds_work_and_monotonic_time():
    w=ProcessingWindow(100,50);assert w.check(estimated_work_units=90,consumed_work_units=90,start_ms=10,now_ms=50)
    with pytest.raises(ProcessingBudgetError):w.check(estimated_work_units=101,start_ms=10,now_ms=10)
    with pytest.raises(ProcessingBudgetError):w.check(estimated_work_units=90,start_ms=10,now_ms=61)

def test_only_authenticated_activity_refreshes_liveness():
    l=AuthenticatedLiveness(100);assert l.state(0) is LivenessState.EXPIRED
    l.observe_authenticated(10);assert l.state(20) is LivenessState.ACTIVE
    assert l.state(90) is LivenessState.SUSPECT
    assert l.state(111) is LivenessState.EXPIRED
