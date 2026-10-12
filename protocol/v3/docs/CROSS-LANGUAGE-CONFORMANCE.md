# Cross-Language Conformance — Draft 0.11

The Python implementation and Rust crate share normative JSON registries. `tools/generate_registry_code.py` deterministically emits Python/Rust record, security-suite and FEC constants. `--check` rejects stale generated source; release CI also regenerates derived artifacts and requires a clean working tree.

Golden-vector differential testing compares the full structural decode: header identity/epochs/timing/QoS, FEC tuple, and every record header field—not merely accept/reject. The corpus includes human communications, AI communications, autonomous-agent traffic, readmission control, and authenticated semantic-negative vectors.

The Rust oracle can emit its generated registry snapshot. Differential CI compares that snapshot to Python's generated registry data so both languages cannot silently compile different ID/name/status tables.

## Resource-model parity

Python and Rust are **not** expected to consume identical heap or CPU resources. Each runtime applies a conservative local cost model and refuses profile activation if its local budgets cannot satisfy the negotiated protocol workload.

For formula/width parity, Rust independently implements the Rust admission-cost calculation. Differential CI feeds a bounded matrix to both implementations and requires Python's calculation *for RuntimeKind.RUST* to equal Rust's native calculation exactly. This detects integer/formula drift without making the false assumption that Python and Rust allocator overheads are equal.

## Native boundary

Rust currently acts as an independent wire oracle and contains `#![forbid(unsafe_code)]`; there is no Python/Rust FFI boundary in this draft. A future FFI is a new security boundary subject to `FFI-SAFETY.md`.
