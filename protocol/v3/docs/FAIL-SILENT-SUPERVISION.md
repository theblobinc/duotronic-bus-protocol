# Fail-Silent Supervision and Noisy Peers — Draft 0.11

`src/dbp3/emergency.py` encodes emergency records; it is **not** a hardware-isolation driver. DBP does not pretend a managed Python process can reliably disconnect a failed physical transceiver after its own runtime has frozen.

Deployments requiring physical fail-silent behavior MUST provide an out-of-process supervisor (OS service, native sidecar, firmware watchdog, MCU, or hardware watchdog). The supervisor owns the ability to isolate the local transport before restarting an unresponsive protocol process. The reference `SupervisorContract` describes heartbeat timeout -> isolate -> restart semantics without performing hardware I/O.

## Remote peer containment

`PeerGuard` separates peer behavior from shared-path behavior. Repeated isolated malformed/security failures can move a peer from ACTIVE to DEGRADED to QUARANTINED. Correlated malformed observations from several peers on one path may instead degrade/quarantine the path, reducing the chance that common RF/link noise falsely mass-quarantines independent peers.

Hard security quarantine always wins. A witness is never kept active merely to preserve quorum. If the required witness quorum becomes impossible, authority-bearing work is held/pending; the threshold is not lowered.

## Re-admission

Cooldown does **not** restore a quarantined peer. After cooldown, the peer is only eligible for a new readmission attempt. Re-admission requires the challenge/proof/probation sequence in `QUARANTINE-READMISSION.md`, including a newer generation and externally verified protected-session authenticator.

Quarantined traffic is rejected before expensive FEC, Witness or application processing except for the tightly bounded readmission control path.
