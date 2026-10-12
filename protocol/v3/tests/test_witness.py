import pytest
from dbp3.witness import *
from dbp3.errors import AuthorityError
def test_transport_auth_not_authority():
    assert not require_authority(transport_authenticated=True,semantic_valid=True,binding=None,policy_allowed=True)
def test_authority_binding():
    b=WitnessBinding('authority_snapshot/v2','obj','domain','snap',7,'authz')
    assert require_authority(transport_authenticated=True,semantic_valid=True,binding=b,policy_allowed=True)
def test_missing_authority_fails():
    with pytest.raises(AuthorityError): WitnessBinding('x','y').validate(authority_bearing=True)
