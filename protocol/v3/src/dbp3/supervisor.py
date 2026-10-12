from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from .witness import WitnessQuorum, QuorumStatus

class SupervisorAction(str, Enum):
    HEALTHY='healthy'
    ISOLATE='isolate'
    RESTART='restart'

class FaultClass(str, Enum):
    SECURITY='security'
    MALFORMED_PEER='malformed-peer'
    CORRELATED_LINK_NOISE='correlated-link-noise'
    LOCAL_RESOURCE='local-resource'

class ContainmentAction(str, Enum):
    QUARANTINE_PEER='quarantine-peer'
    DEGRADE_PEER='degrade-peer'
    DEGRADE_PATH='degrade-path'
    ISOLATE_LOCAL='isolate-local'
    HOLD_AUTHORITY='hold-authority'

@dataclass(frozen=True)
class SupervisorContract:
    """Contract for an out-of-process fail-silent supervisor.

    DBP itself does not touch hardware transceiver registers. Deployments that
    require physical fail-silent behavior MUST implement this contract outside
    the managed protocol runtime (Python/agent process) using OS, firmware, MCU,
    or hardware watchdog facilities.
    """
    heartbeat_timeout_ms:int=250
    isolate_before_restart:bool=True
    restart_backoff_ms:int=1000
    max_restart_attempts:int=5

    def __post_init__(self):
        if self.heartbeat_timeout_ms < 10: raise ValueError('heartbeat timeout unrealistically low')
        if self.restart_backoff_ms < 1 or self.max_restart_attempts < 1: raise ValueError('restart policy')

    def evaluate(self, *, now_ms:int, last_heartbeat_ms:int, already_isolated:bool=False)->SupervisorAction:
        if min(now_ms,last_heartbeat_ms) < 0 or now_ms < last_heartbeat_ms:
            raise ValueError('monotonic heartbeat chronology')
        if now_ms-last_heartbeat_ms <= self.heartbeat_timeout_ms:
            return SupervisorAction.HEALTHY
        if self.isolate_before_restart and not already_isolated:
            return SupervisorAction.ISOLATE
        return SupervisorAction.RESTART

@dataclass
class QuarantineCoordinator:
    """Containment coordinator with correlation-aware damping.

    Hard security faults are never kept active merely to preserve quorum.
    Authorization threshold is fixed by WitnessQuorum; if containment makes the
    quorum impossible, authority-bearing operations stop rather than weakening
    the threshold.  Correlated faults from multiple peers on the same path are
    classified as path degradation so one noisy carrier does not cause a mass
    peer-quarantine cascade.
    """
    quorum:WitnessQuorum|None=None
    correlation_window_ms:int=500
    correlated_peer_threshold:int=3
    path_events:dict[str,list[tuple[int,str]]]=field(default_factory=dict)
    quarantined:set[str]=field(default_factory=set)
    degraded_paths:set[str]=field(default_factory=set)
    soft_faults:dict[str,int]=field(default_factory=dict)
    soft_quarantine_threshold:int=2

    def __post_init__(self):
        if self.correlation_window_ms < 1 or self.correlated_peer_threshold < 2 or self.soft_quarantine_threshold < 2:
            raise ValueError('quarantine damping limits')

    def _record_path_fault(self,path_id:str,peer_id:str,now_ms:int)->int:
        floor=now_ms-self.correlation_window_ms
        rows=[(t,p) for t,p in self.path_events.get(path_id,[]) if t>=floor]
        rows.append((now_ms,peer_id));self.path_events[path_id]=rows
        return len({p for _,p in rows})

    def contain(self, *, peer_id:str, path_id:str, now_ms:int, fault:FaultClass)->tuple[ContainmentAction,QuorumStatus|None]:
        if not peer_id or not path_id or now_ms < 0: raise ValueError('containment identity/time')
        if fault is FaultClass.LOCAL_RESOURCE:
            return ContainmentAction.ISOLATE_LOCAL, self.quorum.status() if self.quorum else None
        correlated=self._record_path_fault(path_id,peer_id,now_ms)
        if fault is FaultClass.CORRELATED_LINK_NOISE or (fault is FaultClass.MALFORMED_PEER and correlated>=self.correlated_peer_threshold):
            self.degraded_paths.add(path_id)
            return ContainmentAction.DEGRADE_PATH, self.quorum.status() if self.quorum else None
        if fault is FaultClass.MALFORMED_PEER:
            count=self.soft_faults.get(peer_id,0)+1;self.soft_faults[peer_id]=count
            if count < self.soft_quarantine_threshold:
                return ContainmentAction.DEGRADE_PEER, self.quorum.status() if self.quorum else None
        # SECURITY faults and repeated isolated malformed-peer faults quarantine.
        # Never lower witness threshold to keep a suspect witness available.
        self.quarantined.add(peer_id)
        qs=None
        if self.quorum and peer_id in self.quorum.eligible:qs=self.quorum.mark_unavailable(peer_id)
        elif self.quorum:qs=self.quorum.status()
        return ContainmentAction.QUARANTINE_PEER,qs
