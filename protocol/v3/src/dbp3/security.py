from typing import Protocol
import hashlib, hmac
from .constants import AUTH_TAG_SIZE
from .generated_registry import SECURITY_SUITE_IDS
class SecurityProvider(Protocol):
    suite_id:int
    def authenticate(self, associated_data:bytes, protected_body:bytes, key_epoch:int)->bytes: ...
    def verify(self, associated_data:bytes, protected_body:bytes, key_epoch:int, tag:bytes)->bool: ...
class DevelopmentHMACProvider:
    """Conformance-only authenticator. NOT production encryption."""
    suite_id=SECURITY_SUITE_IDS['development-hmac']
    def __init__(self,key:bytes):
        if len(key)<16: raise ValueError('development key too short')
        self.key=key
    def authenticate(self, associated_data, protected_body, key_epoch):
        msg=b'DBP3/DEV-HMAC/v2'+key_epoch.to_bytes(4,'little')+associated_data+protected_body
        return hmac.new(self.key,msg,hashlib.sha256).digest()[:AUTH_TAG_SIZE]
    def verify(self, associated_data, protected_body, key_epoch, tag):
        return hmac.compare_digest(self.authenticate(associated_data,protected_body,key_epoch),tag[:AUTH_TAG_SIZE])
