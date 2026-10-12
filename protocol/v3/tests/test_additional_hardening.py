import pytest
from dbp3.compression import validate_expansion
from dbp3.resilience import plan
from dbp3.congestion import CongestionState
from dbp3.merge import *
from dbp3.media import MediaCorrelation
from dbp3.privacy import PrivacyProfile,pad_to_bucket
from dbp3.update import UpdateManifest,UpdateReceipt
from dbp3.diagnostics import public_detail,DiagnosticCode
from dbp3.utm import ConflictProposal,DeconflictionDecision

def test_compression_limits():
    validate_expansion(compressed_bytes=10,declared_plain_bytes=100,max_plain_bytes=1000,max_ratio=10)
    with pytest.raises(ValueError): validate_expansion(compressed_bytes=10,declared_plain_bytes=101,max_plain_bytes=1000,max_ratio=10)
def test_resilience_authenticated_feedback():
    assert plan(CongestionState.SURVIVAL).duplicate_paths==2
    assert plan(CongestionState.SURVIVAL,authenticated_feedback=False).fec_n <= plan(CongestionState.SURVIVAL).fec_n
def test_offline_revocation_merge_monotone():
    a=AuthoritySnapshot('d',5,frozenset({'x'}),'wa'); b=AuthoritySnapshot('d',7,frozenset({'y'}),'wb'); m=merge_authority(a,b); assert m.revoked==frozenset({'x','y'}) and m.sequence==7
def test_media_correlation(): MediaCorrelation('cam',10,1,90000,'wit',3).validate()
def test_privacy_profile_and_padding(): PrivacyProfile(64000,20,100,True).validate(); assert pad_to_bucket(33,32)==64
def test_update_authority_fields(): UpdateManifest('utm','1.2','obj','sig','wit',3).validate(); UpdateReceipt('obj','node','installed',3).validate()
def test_safe_diagnostics(): assert 'key' not in public_detail(DiagnosticCode.AUTH_FAILURE).lower()
def test_utm_conflict_decision(): ConflictProposal('p',('a','b'),100,'e',5,'hold').validate(); DeconflictionDecision('p','d','auth','hold',90,'w').validate()
