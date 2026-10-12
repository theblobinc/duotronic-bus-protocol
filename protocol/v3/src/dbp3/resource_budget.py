from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class BudgetExceeded(RuntimeError): pass
class AdmissionError(BudgetExceeded): pass
class BudgetAccountingError(BudgetExceeded): pass

MAX_ADMISSION_SCALAR=(1<<31)-1

class RuntimeKind(str, Enum):
    PYTHON='python'; RUST='rust'; EMBEDDED='embedded'

@dataclass(frozen=True)
class RuntimeCostModel:
    runtime:RuntimeKind
    heap_multiplier_milli:int
    cpu_multiplier_milli:int
    base_heap_bytes:int
    minimum_working_set_bytes:int
    fec_workspace_floor_bytes:int
    group_workspace_floor_bytes:int
    merge_workspace_floor_bytes:int
    model_version:str='dbp3-runtime-cost/v2'
    def __post_init__(self):
        if not self.model_version: raise ValueError('runtime cost model version')
        for name,value in self.__dict__.items():
            if name in {'runtime','model_version'}: continue
            if not isinstance(value,int) or value<=0: raise ValueError(f'invalid runtime cost field: {name}')

RUNTIME_COST_MODELS={
 RuntimeKind.PYTHON:RuntimeCostModel(RuntimeKind.PYTHON,2800,2000,512*1024,2*1024*1024,64*1024,128*1024,128*1024),
 RuntimeKind.RUST:RuntimeCostModel(RuntimeKind.RUST,1400,1000,128*1024,512*1024,32*1024,64*1024,64*1024),
 RuntimeKind.EMBEDDED:RuntimeCostModel(RuntimeKind.EMBEDDED,1200,1250,32*1024,128*1024,16*1024,24*1024,24*1024),
}

@dataclass(frozen=True)
class ResourceLimits:
    memory_bytes:int=128*1024*1024
    inflight_messages:int=512
    fec_groups:int=128
    merge_items:int=4096
    mailbox_items:int=4096
    fanout_targets:int=256
    cpu_tokens:int=100_000
    def __post_init__(self):
        for name,value in self.__dict__.items():
            if not isinstance(value,int) or not (1<=value<=MAX_ADMISSION_SCALAR): raise ValueError(f'{name} must be bounded positive integer')

@dataclass(frozen=True)
class AdmissionRequest:
    frame_size:int=4096; max_records:int=64; concurrent_sessions:int=8; inflight_messages:int=64
    fec_k:int=8; fec_n:int=12; fec_groups:int=16; group_fanout:int=32
    merge_page_bytes:int=1024*1024; merge_items:int=256; mailbox_items:int=256
    def __post_init__(self):
        for name,v in self.__dict__.items():
            if not isinstance(v,int) or v<0 or v>MAX_ADMISSION_SCALAR: raise ValueError(f'{name} out of admission range')
        if self.frame_size not in (256,512,1024,2048,4096) or self.max_records<1 or self.concurrent_sessions<1: raise ValueError('invalid admission request')
        if (self.fec_k==0)!=(self.fec_n==0): raise ValueError('FEC k/n must both be zero or both non-zero')
        if self.fec_k and not (1<=self.fec_k<=self.fec_n<=255): raise ValueError('invalid FEC request')

@dataclass(frozen=True)
class AdmissionEstimate:
    runtime:RuntimeKind; estimated_heap_bytes:int; estimated_cpu_tokens:int; minimum_working_set_bytes:int; cost_model_version:str

def _mul(a:int,b:int)->int:
    if a<0 or b<0 or a>MAX_ADMISSION_SCALAR or b>MAX_ADMISSION_SCALAR: raise AdmissionError('admission scalar overflow')
    v=a*b
    if v>1<<62: raise AdmissionError('admission arithmetic overflow')
    return v

def estimate_runtime_cost(request:AdmissionRequest,runtime:RuntimeKind|str)->AdmissionEstimate:
    runtime=RuntimeKind(runtime);m=RUNTIME_COST_MODELS[runtime]
    logical_heap=(m.base_heap_bytes + _mul(request.concurrent_sessions,request.frame_size*4)
      + _mul(request.inflight_messages,request.frame_size+256)
      + _mul(_mul(request.max_records,request.concurrent_sessions),192)
      + _mul((request.fec_n or 1),request.frame_size*3)
      + min(request.merge_page_bytes,8*1024*1024) + _mul(request.group_fanout,512)
      + _mul(request.mailbox_items,256) + _mul(request.fec_groups,1024) + _mul(request.merge_items,64))
    heap=max((logical_heap*m.heap_multiplier_milli+999)//1000,m.minimum_working_set_bytes)
    cpu_base=(_mul(request.concurrent_sessions,600)+_mul(request.inflight_messages,30)
      +_mul(_mul(request.max_records,request.concurrent_sessions),25)
      +_mul(_mul((request.fec_n or 1),max(request.fec_k,1)),45)
      +_mul(request.group_fanout,20)+_mul(request.fec_groups,35)+_mul(request.merge_items,2))
    cpu=(cpu_base*m.cpu_multiplier_milli+999)//1000
    return AdmissionEstimate(runtime,heap,cpu,m.minimum_working_set_bytes,m.model_version)

def require_runtime_admission(request:AdmissionRequest,limits:ResourceLimits,runtime:RuntimeKind|str)->AdmissionEstimate:
    estimate=estimate_runtime_cost(request,runtime);model=RUNTIME_COST_MODELS[estimate.runtime]
    if limits.memory_bytes<model.minimum_working_set_bytes: raise AdmissionError(f'{estimate.runtime.value} memory limit below runtime minimum working set')
    if estimate.estimated_heap_bytes>limits.memory_bytes: raise AdmissionError(f'{estimate.runtime.value} estimated heap exceeds configured memory budget')
    if estimate.estimated_cpu_tokens>limits.cpu_tokens: raise AdmissionError(f'{estimate.runtime.value} estimated CPU cost exceeds configured CPU budget')
    checks=(('inflight_messages',request.inflight_messages,limits.inflight_messages),('fec_groups',request.fec_groups,limits.fec_groups),('merge_items',request.merge_items,limits.merge_items),('group fanout',request.group_fanout,limits.fanout_targets),('mailbox',request.mailbox_items,limits.mailbox_items))
    for label,want,cap in checks:
        if want>cap: raise AdmissionError(f'{label} request exceeds budget')
    return estimate

@dataclass
class ResourceBudget:
    limits:ResourceLimits=field(default_factory=ResourceLimits)
    memory_bytes:int=0; inflight_messages:int=0; fec_groups:int=0; merge_items:int=0; mailbox_items:int=0; fanout_targets:int=0; cpu_tokens:int=0
    def reserve(self,kind:str,amount:int=1):
        if not isinstance(amount,int) or amount<0: raise ValueError('amount')
        if not hasattr(self,kind) or not hasattr(self.limits,kind): raise ValueError('unknown budget kind')
        new=getattr(self,kind)+amount
        if new>getattr(self.limits,kind): raise BudgetExceeded(f'{kind} budget exceeded')
        setattr(self,kind,new);return self
    def release(self,kind:str,amount:int=1):
        if not isinstance(amount,int) or amount<0: raise ValueError('amount')
        if not hasattr(self,kind) or not hasattr(self.limits,kind): raise ValueError('unknown budget kind')
        old=getattr(self,kind)
        if amount>old: raise BudgetAccountingError(f'{kind} release underflow')
        setattr(self,kind,old-amount);return self


@dataclass(frozen=True)
class PlatformLimits:
    """Architecture/allocator admission independent of protocol numeric ranges."""
    pointer_bits:int=64
    allocator_ceiling_bytes:int=(1<<31)-1
    contiguous_allocation_ceiling_bytes:int=256*1024*1024
    def __post_init__(self):
        if self.pointer_bits not in (16,32,64):raise ValueError('pointer_bits')
        addressable=(1<<self.pointer_bits)-1
        for name,v in (('allocator_ceiling_bytes',self.allocator_ceiling_bytes),('contiguous_allocation_ceiling_bytes',self.contiguous_allocation_ceiling_bytes)):
            if not isinstance(v,int) or v<1 or v>addressable:raise ValueError(f'{name} outside platform address width')
        if self.contiguous_allocation_ceiling_bytes>self.allocator_ceiling_bytes:raise ValueError('contiguous allocation ceiling exceeds allocator ceiling')

@dataclass(frozen=True)
class PlatformAdmission:
    estimate:AdmissionEstimate
    platform:PlatformLimits
    required_contiguous_bytes:int

def require_platform_admission(request:AdmissionRequest,estimate:AdmissionEstimate,platform:PlatformLimits)->PlatformAdmission:
    # Conservative largest single working buffer.  This is deliberately not the
    # same as total heap: addressability, total allocator capacity and one-shot
    # contiguous allocation are separate contracts.
    required_contiguous=max(request.frame_size*3,min(request.merge_page_bytes,8*1024*1024),request.frame_size*max(request.fec_n,1))
    if estimate.estimated_heap_bytes>platform.allocator_ceiling_bytes:raise AdmissionError('estimated heap exceeds platform allocator ceiling')
    if estimate.minimum_working_set_bytes>platform.allocator_ceiling_bytes:raise AdmissionError('runtime minimum working set exceeds platform allocator ceiling')
    if required_contiguous>platform.contiguous_allocation_ceiling_bytes:raise AdmissionError('required contiguous allocation exceeds platform ceiling')
    # Explicit conversion guard for native usize-like consumers.
    if required_contiguous>(1<<platform.pointer_bits)-1:raise AdmissionError('required allocation exceeds platform pointer width')
    return PlatformAdmission(estimate,platform,required_contiguous)

def require_platform_runtime_admission(request:AdmissionRequest,limits:ResourceLimits,runtime:RuntimeKind|str,platform:PlatformLimits)->PlatformAdmission:
    return require_platform_admission(request,require_runtime_admission(request,limits,runtime),platform)
