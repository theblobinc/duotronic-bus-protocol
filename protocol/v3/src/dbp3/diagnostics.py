from enum import IntEnum
class DiagnosticCode(IntEnum):
    FRAME_SHAPE=1; CRC_FAILURE=2; AUTH_FAILURE=3; REPLAY_REJECTED=4; MALFORMED_RECORD=5; RESOURCE_LIMIT=6; FEC_INSUFFICIENT=7; STALE_WITNESS=8; AUTHORITY_DENIED=9; REVOKED=10; EXPIRED_TRANSACTION=11; UNSUPPORTED_CRITICAL_EXTENSION=12
SAFE_DETAIL={c:'protocol processing failure' for c in DiagnosticCode}
SAFE_DETAIL.update({DiagnosticCode.RESOURCE_LIMIT:'configured resource bound exceeded',DiagnosticCode.REPLAY_REJECTED:'replay window rejection',DiagnosticCode.AUTHORITY_DENIED:'authority/policy denied'})
def public_detail(code:int)->str:
    try: return SAFE_DETAIL[DiagnosticCode(code)]
    except Exception: return 'protocol processing failure'
