# Draft 0.11 — RC1 preparation

Draft 0.11 intentionally avoids another wire redesign. It closes the remaining pre-RC operational gaps around simultaneous startup, architecture width, artifact freshness and formal readmission coverage.

- `DBP3-BOOTSTRAP-CONTENTION-1` provides bounded, nonce-derived cold-start backoff without synchronized clocks.
- startup collisions are path-contention evidence and do not automatically quarantine peers.
- platform admission separates protocol ranges, pointer width, allocator capacity and contiguous-allocation capacity.
- Rust release CI cross-compiles the reference crate for a 32-bit target.
- vector and resolved-profile generators now expose deterministic `--check` modes.
- pre-commit executes semantic profile checks before generated-artifact freshness checks in one ordered gate.
- Lean now covers the structural requirement that active post-quarantine readmission requires verified proof and a newer generation.
- a TLA+ bootstrap-contention model is included and automatically discovered by the strict formal gate.
