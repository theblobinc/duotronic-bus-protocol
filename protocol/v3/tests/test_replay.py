import pytest
from dbp3.replay import ReplayWindow
from dbp3.errors import ReplayError
def test_replay_window():
    r=ReplayWindow(8); r.accept(1); r.accept(3); r.accept(2)
    with pytest.raises(ReplayError): r.accept(2)
