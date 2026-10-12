from dataclasses import dataclass
@dataclass(frozen=True)
class UpdateManifest:
    component:str; version:str; object_id:str; signer_ref:str; authority_witness_ref:str; rollout_epoch:int; predecessor_id:str=''; rollback_allowed:bool=True
    def validate(self):
        if not all((self.component,self.version,self.object_id,self.signer_ref,self.authority_witness_ref)) or self.rollout_epoch<1: raise ValueError('update manifest')
        return self
@dataclass(frozen=True)
class UpdateReceipt:
    object_id:str; node_ref:str; stage:str; rollout_epoch:int; result:str='ok'
    ALLOWED=('staged','validated','approved','installed','rolled_back','failed')
    def validate(self):
        if self.stage not in self.ALLOWED or self.rollout_epoch<1 or not self.object_id or not self.node_ref: raise ValueError('update receipt')
        return self
