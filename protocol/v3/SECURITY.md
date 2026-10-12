# Security Policy

DBP v3 is a draft protocol. Report suspected protocol or implementation vulnerabilities privately before public disclosure when practical.

The reference `DevelopmentHMACProvider` is **not** a production confidentiality provider. Production deployments must use an audited/approved Xavi-Void provider or another profile explicitly registered by a future DBP revision.

Never infer authority solely from frame validity, FEC recovery, encryption, transport authentication, sender hints, a successful receipt, or a DBP record type.

## Draft 0.11 hardening notes

- Quarantine cooldown does not restore trust. Re-admission requires a fresh challenge, monotonic generation, session commitment, Witness reference, externally verified Xavi-Void/readmission authenticator, and probation.
- Correlated shared-path noise is classified separately from isolated peer faults to reduce cascading false quarantine. Hard security quarantine always wins; witness thresholds are never reduced to preserve apparent liveness.
- Operational profile activation requires semantic registry validation **and** runtime-specific resource admission.
- Python/Rust allocator costs are intentionally modeled separately; equal protocol quotas do not imply equal heap usage.
- FEC resource/work failure is fail-closed and never means "retry without protection".
- Multicast fanout/fragment/recovery work is bounded per recipient and requires explicit record capability.
- Long-history merge work is page/segment bounded; production-scale histories use storage-backed immutable snapshots rather than whole-history materialization.
- At-most-once command state is bounded and never silently evicts idempotency keys.
- Generated registries are deterministically checked for freshness in CI, and duplicated ID/name/status mappings are coherence-tested.
- Physical fail-silent isolation is a deployment supervisor responsibility outside the managed protocol runtime.
- Rust reference parsing remains `#![forbid(unsafe_code)]`; this draft has no Python/Rust FFI surface.
- Formal lock hashes are drift indicators only; release CI separately executes TLA+ and Lean gates.

See `docs/QUARANTINE-READMISSION.md`, `docs/FAIL-SILENT-SUPERVISION.md`, `docs/RESOURCE-BUDGETS.md`, and `docs/STABILIZATION-0.10.md`.
