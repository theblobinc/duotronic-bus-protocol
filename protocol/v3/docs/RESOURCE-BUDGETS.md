# Runtime Resource Admission — Draft 0.11

DBP protocol quotas are logical bounds, not promises about physical heap size or CPU cycles. Python, Rust and embedded runtimes have different object/allocator/execution overhead and therefore use separate conservative cost models.

A resolved profile binds protocol-visible ceilings such as frame family, maximum records, replay window, FEC policy and resource class. Before activation, the local runtime translates the requested workload into its implementation-specific admission estimate and rejects the session if memory, deterministic work units, fanout, mailbox, FEC, merge or in-flight limits cannot be satisfied.

## Rules

- all admission scalars are bounded integers before arithmetic;
- zero/sub-minimum FEC workspace fails closed before matrix work begins;
- FEC encode/recover paths have explicit deterministic work-unit ceilings;
- resource exhaustion never means "retry without cryptographic/FEC protection";
- `ResourceBudget.release()` rejects accounting underflow;
- at-most-once/idempotency caches fail closed at capacity and do not evict keys silently;
- the in-memory merge adapter has a hard snapshot item ceiling; large histories use storage-backed snapshots;
- object transfer, mailbox/custody, agent fanout, feature shapes and federation sets have explicit size/count limits;
- runtime-neutral liveness uses deterministic work admission plus a local monotonic deadline. A slower runtime must reject a workload it cannot complete inside the profile rather than silently extending protocol timeouts.

Cross-language conformance compares protocol ceilings and the independently implemented Rust cost formula; it does not require Python and Rust to report the same physical heap usage.
