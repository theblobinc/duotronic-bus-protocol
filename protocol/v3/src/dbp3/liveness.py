from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import hashlib

class ProcessingBudgetError(RuntimeError):pass
class LivenessState(str,Enum):ACTIVE='active';SUSPECT='suspect';EXPIRED='expired'

@dataclass(frozen=True)
class ProcessingWindow:
    """Runtime-neutral processing contract.

    `max_work_units` bounds algorithmic work independent of implementation
    speed. `deadline_ms` is a local monotonic elapsed-time ceiling. A runtime
    that cannot satisfy both MUST fail resource admission rather than silently
    using a longer timeout and diverging from peers.
    """
    max_work_units:int
    deadline_ms:int
    def __post_init__(self):
        if self.max_work_units<1 or self.deadline_ms<1:raise ValueError('processing window')
    def check(self,*,estimated_work_units:int,consumed_work_units:int=0,start_ms:int,now_ms:int):
        if min(estimated_work_units,consumed_work_units,start_ms,now_ms)<0 or now_ms<start_ms:raise ValueError('processing chronology/work')
        if estimated_work_units>self.max_work_units or consumed_work_units>self.max_work_units:raise ProcessingBudgetError('operation work-unit budget exceeded')
        if now_ms-start_ms>self.deadline_ms:raise ProcessingBudgetError('operation monotonic deadline exceeded')
        return True

@dataclass
class AuthenticatedLiveness:
    """Peer liveness driven only by authenticated accepted activity.

    Garbage, malformed frames, and unauthenticated link noise never refresh
    liveness.  This prevents a babbling peer from keeping itself logically live.
    """
    timeout_ms:int
    suspect_after_milli:int=750
    last_authenticated_ms:int|None=None
    def __post_init__(self):
        if self.timeout_ms<1 or not 1<=self.suspect_after_milli<1000:raise ValueError('liveness policy')
    def observe_authenticated(self,now_ms:int):
        if now_ms<0 or (self.last_authenticated_ms is not None and now_ms<self.last_authenticated_ms):raise ValueError('liveness chronology')
        self.last_authenticated_ms=now_ms
    def state(self,now_ms:int)->LivenessState:
        if now_ms<0:raise ValueError('monotonic time')
        if self.last_authenticated_ms is None:return LivenessState.EXPIRED
        age=now_ms-self.last_authenticated_ms
        if age<0:raise ValueError('liveness chronology')
        if age>self.timeout_ms:return LivenessState.EXPIRED
        if age*1000>=self.timeout_ms*self.suspect_after_milli:return LivenessState.SUSPECT
        return LivenessState.ACTIVE


class BootstrapState(str,Enum):
    COLD='cold'
    DISCOVERY_BACKOFF='discovery-backoff'
    ANNOUNCING='announcing'
    NEGOTIATING='negotiating'
    ACTIVE='active'
    BACKOFF_RETRY='backoff-retry'

@dataclass(frozen=True)
class BootstrapBackoffPolicy:
    """Cold-start contention policy for shared/half-duplex paths.

    Backoff is pseudo-random but reproducible from a fresh boot nonce and
    principal/path identity.  It does not depend on synchronized wall clock.
    Collision/congestion expands the bounded window; it is a path-contention
    signal and MUST NOT itself be treated as peer-malicious evidence.
    """
    initial_window_ms:int=25
    max_window_ms:int=1600
    multiplier:int=2
    max_attempts:int=8
    def __post_init__(self):
        if self.initial_window_ms<1 or self.max_window_ms<self.initial_window_ms:raise ValueError('bootstrap window')
        if self.multiplier<2 or self.max_attempts<1:raise ValueError('bootstrap policy')
    def window_ms(self,attempt:int)->int:
        if not isinstance(attempt,int) or not 0<=attempt<self.max_attempts:raise ValueError('bootstrap attempt')
        return min(self.max_window_ms,self.initial_window_ms*(self.multiplier**attempt))
    def delay_ms(self,*,principal_id:str,boot_epoch:int,path_id:int,boot_nonce:bytes,attempt:int)->int:
        if not principal_id or not isinstance(boot_nonce,(bytes,bytearray)) or len(boot_nonce)<16:raise ValueError('bootstrap identity/nonce')
        if not 0<=boot_epoch<1<<64 or not 0<=path_id<1<<32:raise ValueError('bootstrap epoch/path')
        w=self.window_ms(attempt)
        material=(b'DBP3/BOOTSTRAP/v1\0'+principal_id.encode('utf-8')+b'\0'+boot_epoch.to_bytes(8,'little')+path_id.to_bytes(4,'little')+bytes(boot_nonce)+attempt.to_bytes(2,'little'))
        value=int.from_bytes(hashlib.shake_256(material).digest(8),'little')
        return value%(w+1)

@dataclass
class BootstrapController:
    principal_id:str
    boot_epoch:int
    path_id:int
    boot_nonce:bytes
    policy:BootstrapBackoffPolicy=BootstrapBackoffPolicy()
    state:BootstrapState=BootstrapState.COLD
    attempt:int=0
    def __post_init__(self):
        # Validate all immutable inputs without consuming an attempt.
        self.policy.delay_ms(principal_id=self.principal_id,boot_epoch=self.boot_epoch,path_id=self.path_id,boot_nonce=self.boot_nonce,attempt=0)
    def begin(self)->int:
        if self.state is not BootstrapState.COLD:raise ValueError('bootstrap already started')
        self.state=BootstrapState.DISCOVERY_BACKOFF
        return self.current_delay_ms()
    def current_delay_ms(self)->int:
        if self.state not in {BootstrapState.DISCOVERY_BACKOFF,BootstrapState.BACKOFF_RETRY}:raise ValueError('not in bootstrap backoff')
        return self.policy.delay_ms(principal_id=self.principal_id,boot_epoch=self.boot_epoch,path_id=self.path_id,boot_nonce=self.boot_nonce,attempt=self.attempt)
    def announce(self):
        if self.state not in {BootstrapState.DISCOVERY_BACKOFF,BootstrapState.BACKOFF_RETRY}:raise ValueError('illegal bootstrap announce')
        self.state=BootstrapState.ANNOUNCING;return self
    def collision(self)->int:
        if self.state is not BootstrapState.ANNOUNCING:raise ValueError('collision outside announcement')
        self.attempt+=1
        if self.attempt>=self.policy.max_attempts:raise ProcessingBudgetError('bootstrap contention attempts exhausted')
        self.state=BootstrapState.BACKOFF_RETRY
        return self.current_delay_ms()
    def negotiate(self):
        if self.state is not BootstrapState.ANNOUNCING:raise ValueError('bootstrap negotiation state')
        self.state=BootstrapState.NEGOTIATING;return self
    def activate(self):
        if self.state is not BootstrapState.NEGOTIATING:raise ValueError('bootstrap activation state')
        self.state=BootstrapState.ACTIVE;return self
