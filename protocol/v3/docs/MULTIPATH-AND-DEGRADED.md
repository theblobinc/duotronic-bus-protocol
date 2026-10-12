# Multipath, Path Migration and Degraded Operation

A DBP session may bind multiple authenticated carriers/paths. Each path has an opaque path ID and measured loss, latency, jitter and available capacity. Path metrics are evidence for scheduling, not authority.

Critical frames may be duplicated across two or more independent paths. Noncritical traffic normally uses one selected path. Path migration keeps the logical session and replay identity unless the protected-carrier profile explicitly requires a new session generation.

When capacity falls, implementations reduce service by QoS rather than allowing media/bulk queues to block safety/control. Replaceable telemetry/video can discard expired older updates; reliable control/text cannot silently disappear and uses bounded retransmission/custody rules.
