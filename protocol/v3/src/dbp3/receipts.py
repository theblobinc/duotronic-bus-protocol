from dataclasses import dataclass, field
from enum import IntEnum
import hashlib, json
U64_MAX=(1<<64)-1
class ReceiptStage(IntEnum): TRANSPORT_RECEIVED=1; AUTHENTICATED=2; PARSED=3; WITNESS_VALIDATED=4; AUTHORIZED=5; EXECUTED=6; PERSISTED=7; OBSERVED_OUTCOME=8
@dataclass(frozen=True)
class Receipt:
    object_id:str; stage:ReceiptStage; principal_ref:str; previous_receipt_id:str=''; evidence_ref:str=''; status:str='ok'; session_generation:int=1
    def validate(self):
        if not self.object_id or not self.principal_ref or not isinstance(self.stage,ReceiptStage): raise ValueError('receipt identity/stage')
        if not 1<=self.session_generation<=U64_MAX: raise ValueError('receipt generation')
        if len(self.object_id)>4096 or len(self.principal_ref)>4096 or len(self.previous_receipt_id)>256 or len(self.evidence_ref)>4096 or len(self.status)>256: raise ValueError('receipt field length')
        return self
    def receipt_id(self):
        self.validate()
        obj={'object_id':self.object_id,'stage':int(self.stage),'principal_ref':self.principal_ref,'previous_receipt_id':self.previous_receipt_id,'evidence_ref':self.evidence_ref,'status':self.status,'session_generation':self.session_generation}
        return hashlib.shake_256(b'DBP3/RECEIPT/v2'+json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest(32)
@dataclass
class ReceiptChain:
    receipts:list[Receipt]=field(default_factory=list)
    def append(self,r:Receipt):
        r.validate()
        # The normative stage enum contains only eight strictly increasing stages,
        # so a chain can never grow beyond eight receipts for one object/generation.
        if len(self.receipts)>=len(ReceiptStage): raise ValueError('receipt chain stage capacity exhausted')
        if self.receipts:
            prev=self.receipts[-1]
            if r.object_id!=prev.object_id or r.session_generation!=prev.session_generation: raise ValueError('receipt object/generation mismatch')
            if r.stage <= prev.stage: raise ValueError('receipt stages must advance')
            if r.previous_receipt_id != prev.receipt_id(): raise ValueError('receipt chain break')
        elif r.previous_receipt_id: raise ValueError('genesis receipt has predecessor')
        self.receipts.append(r)
