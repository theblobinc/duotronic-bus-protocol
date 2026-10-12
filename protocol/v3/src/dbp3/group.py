from __future__ import annotations
from dataclasses import dataclass,field
import math
from .fec import estimate_recover_work_units
class GroupError(ValueError):pass

@dataclass(frozen=True)
class GroupMemberCapabilities:
    principal_id:str;security_suite:str
    frame_sizes:tuple[int,...]=(256,512,1024,2048,4096)
    max_fec_n:int=16;max_message_bytes:int=8*1024*1024;max_recovery_groups:int=8
    max_recovery_bytes:int=8*1024*1024;max_recovery_work_units:int=20_000_000
    supported_records:frozenset[str]=frozenset()
    def __post_init__(self):
        if not self.principal_id or not self.security_suite:raise GroupError('member identity/security suite')
        if not self.frame_sizes or len(set(self.frame_sizes))!=len(self.frame_sizes) or any(x not in (256,512,1024,2048,4096) for x in self.frame_sizes):raise GroupError('member frame sizes')
        if min(self.max_fec_n,self.max_message_bytes,self.max_recovery_groups,self.max_recovery_bytes,self.max_recovery_work_units)<1:raise GroupError('member resource limits')

@dataclass(frozen=True)
class GroupPolicy:
    required_suite:str;max_members:int=256;max_fanout:int=256;max_fragments:int=4096;max_message_bytes:int=8*1024*1024
    max_parallel_recovery_groups:int=8;max_recovery_bytes:int=8*1024*1024;max_recovery_work_units:int=20_000_000
    require_record_capability:bool=True
    def __post_init__(self):
        vals=(self.max_members,self.max_fanout,self.max_fragments,self.max_message_bytes,self.max_parallel_recovery_groups,self.max_recovery_bytes,self.max_recovery_work_units)
        if not self.required_suite or min(vals)<1:raise GroupError('invalid group policy')

@dataclass(frozen=True)
class MulticastPlan:
    frame_size:int;fragment_payload_bytes:int;fragments:int;recipients:int;recovery_concurrency:int;recovery_bytes:int;recovery_work_units:int

@dataclass
class GroupEpoch:
    group_id:str;epoch:int=1;members:set[str]=field(default_factory=set);key_epoch:int=1
    capabilities:dict[str,GroupMemberCapabilities]=field(default_factory=dict);policy:GroupPolicy|None=None
    def validate(self):
        if not self.group_id or not 1<=self.epoch<=0xffffffffffffffff or not 1<=self.key_epoch<=0xffffffff:raise GroupError('group epoch')
        if self.policy and len(self.members)>self.policy.max_members:raise GroupError('group membership budget')
        return self
    def admit_member(self,caps:GroupMemberCapabilities):
        if self.policy:
            if caps.security_suite!=self.policy.required_suite:raise GroupError('group security-suite mismatch')
            if len(self.members|{caps.principal_id})>self.policy.max_members:raise GroupError('group membership budget')
        self.capabilities[caps.principal_id]=caps;self.change_membership(self.members|{caps.principal_id});return self
    def change_membership(self,new_members:set[str]):
        new_members=set(new_members)
        if self.policy and len(new_members)>self.policy.max_members:raise GroupError('group membership budget')
        additions=new_members-self.members
        if self.policy and any(x not in self.capabilities for x in additions):raise GroupError('new group members require admitted capabilities')
        if new_members!=self.members:
            if self.epoch>=0xffffffffffffffff or self.key_epoch>=0xffffffff:raise GroupError('group/key epoch exhausted')
            self.members=new_members;self.epoch+=1;self.key_epoch+=1;self.capabilities={k:v for k,v in self.capabilities.items() if k in new_members}
        return self
    def accepts(self,member:str,epoch:int)->bool:return epoch==self.epoch and member in self.members
    def plan_multicast(self,payload_bytes:int,*,record_name:str|None=None,record_overhead:int=32,body_reserve:int=0,fec_k:int=0,fec_n:int=0)->MulticastPlan:
        if payload_bytes<0:raise GroupError('payload bytes')
        if not self.policy:raise GroupError('multicast planning requires group policy')
        if payload_bytes>self.policy.max_message_bytes:raise GroupError('group message exceeds policy limit')
        if (fec_k==0)!=(fec_n==0) or (fec_k and not(1<=fec_k<=fec_n<=255)):raise GroupError('FEC tuple')
        if len(self.members)>self.policy.max_fanout:raise GroupError('group fanout exceeds policy limit')
        if not self.members:raise GroupError('no recipients')
        missing=self.members-set(self.capabilities)
        if missing:raise GroupError('missing recipient capabilities')
        caps=[self.capabilities[x] for x in self.members]
        if any(payload_bytes>x.max_message_bytes for x in caps):raise GroupError('recipient message budget exceeded')
        if fec_n and any(fec_n>x.max_fec_n for x in caps):raise GroupError('recipient FEC capability exceeded')
        if self.policy.require_record_capability and not record_name:raise GroupError('multicast record name is required for recipient capability admission')
        if record_name and any(record_name not in x.supported_records for x in caps):raise GroupError('recipient profile does not support multicast record')
        if {x.security_suite for x in caps}!={self.policy.required_suite}:raise GroupError('heterogeneous security suite')
        common=set(caps[0].frame_sizes)
        for c in caps:common&=set(c.frame_sizes)
        if not common:raise GroupError('no common frame size')
        frame_size=max(common);body=frame_size-64-128-record_overhead-body_reserve
        if body<1:raise GroupError('record/body overhead leaves no multicast payload capacity')
        fragments=max(1,math.ceil(payload_bytes/body))
        if fragments>self.policy.max_fragments:raise GroupError('fragment budget exceeded')
        recovery=min(self.policy.max_parallel_recovery_groups,*(c.max_recovery_groups for c in caps))
        recovery_bytes=fragments*frame_size*max(1,recovery)
        cap_bytes=min(self.policy.max_recovery_bytes,*(c.max_recovery_bytes for c in caps))
        if recovery_bytes>cap_bytes:raise GroupError('multicast recovery byte budget exceeded')
        work=0
        if fec_k:
            work=fragments*estimate_recover_work_units(fec_k,fec_n,max(1,body))*max(1,recovery)
            cap_work=min(self.policy.max_recovery_work_units,*(c.max_recovery_work_units for c in caps))
            if work>cap_work:raise GroupError('multicast recovery work budget exceeded')
        return MulticastPlan(frame_size,body,fragments,len(self.members),recovery,recovery_bytes,work)
