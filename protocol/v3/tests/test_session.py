import pytest
from dbp3.session import *
from dbp3.errors import StateError
def test_session_lifecycle_and_rekey():
    s=Session(b'1'*16); s.transition(SessionState.NEGOTIATE); s.transition(SessionState.ESTABLISH); s.transition(SessionState.ACTIVE); e=s.key_epoch; s.transition(SessionState.REKEY); assert s.key_epoch==e+1; s.transition(SessionState.ACTIVE)
def test_invalid_transition():
    with pytest.raises(StateError): Session(b'1'*16).transition(SessionState.ACTIVE)
def test_negotiation_commitment_deterministic():
    a={'b':2,'a':1}; assert negotiation_commitment(a,{},a)==negotiation_commitment({'a':1,'b':2},{},{'a':1,'b':2})
