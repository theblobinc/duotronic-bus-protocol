from dataclasses import dataclass
from enum import Enum
import hashlib,json
class TransactionStatus(str,Enum):PROPOSED='proposed';PRESENTED='presented';AUTHORIZED='authorized';EXECUTING='executing';SUCCEEDED='succeeded';FAILED='failed';CANCELLED='cancelled';SUPERSEDED='superseded'
class LedgerCapacityError(RuntimeError):pass
@dataclass(frozen=True)
class CommandTransaction:
    transaction_id:str;idempotency_key:str;action:str;expires_at_us:int;precondition_ref:str='';witness_ref:str='';supersedes:str='';generation:int=1
    def validate(self,now_us:int):
        if not isinstance(now_us,int) or now_us<0:raise ValueError('transaction clock')
        if not self.transaction_id or not self.idempotency_key or not self.action or not 1<=self.generation<=0xffffffffffffffff:raise ValueError('transaction identity/action')
        if not 0<=self.expires_at_us<=0xffffffffffffffff:raise ValueError('transaction expiry range')
        if self.expires_at_us and now_us>self.expires_at_us:raise ValueError('transaction expired')
        return self
    def digest(self):
        b=json.dumps(self.__dict__,sort_keys=True,separators=(',',':')).encode();return hashlib.shake_256(b'DBP3/TX/v2'+b).hexdigest(32)
class IdempotencyLedger:
    """Bounded at-most-once cache. Capacity exhaustion fails closed.

    Entries must not be silently evicted because doing so could make a duplicate
    command executable again. Persistent deployments should externalize this
    ledger or rotate to a new witnessed generation before capacity is exhausted.
    """
    def __init__(self,max_entries:int=4096):
        if not 1<=max_entries<=1_000_000:raise ValueError('idempotency ledger capacity')
        self.max_entries=max_entries;self._results={}
    def execute_once(self,tx:CommandTransaction,fn):
        if not tx.transaction_id or not tx.idempotency_key or tx.generation<1:raise ValueError('transaction identity')
        key=(tx.generation,tx.idempotency_key)
        if key in self._results:return self._results[key]
        if len(self._results)>=self.max_entries:raise LedgerCapacityError('idempotency ledger capacity exhausted; do not evict silently')
        result=fn();self._results[key]=result;return result
