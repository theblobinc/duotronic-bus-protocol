# Native / FFI Safety Boundary — Draft 0.11

The current DBP3 reference architecture has **no Python-to-Rust FFI boundary**. The Rust crate is an independent conformance oracle and uses `#![forbid(unsafe_code)]`.

A future FFI or native acceleration layer is therefore a new security boundary and MUST NOT be inferred from the current reference crate. Before such a layer is standardized it requires:

- explicit buffer ownership and lifetime rules;
- length and integer-width validation on both sides of the boundary;
- no unchecked pointer arithmetic in the normative implementation;
- allocator ownership rules for returned buffers;
- panic/exception containment and error translation;
- differential boundary vectors including zero-length, maximum-length and truncated buffers;
- independent fuzzing of the FFI entry points;
- an audit of every `unsafe` block if unsafe code is introduced at all.

Protocol resource budgets are logical admission limits. An FFI implementation must still apply runtime/allocator-specific working-set admission before accepting a protected session or FEC/group workload.
