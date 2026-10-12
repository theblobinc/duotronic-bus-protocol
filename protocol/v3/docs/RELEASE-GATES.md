# Release Gates — Draft 0.11

A release candidate must pass all applicable gates:

- Python unit/conformance tests and source compilation;
- exact ABI verification plus valid/deep-invalid golden vectors;
- ordered local semantic/generated-artifact freshness gate (`verify_generated_artifacts.py`);
- generated registry, vector and resolved-profile freshness (`--check` modes);
- full regeneration of registries, vectors and resolved profiles followed by a clean-tree check in CI;
- registry ID/name/status/range/coherence verification;
- semantic profile, negative-profile and canonical resolved-profile verification;
- deterministic watchdog wire fuzzing including sustained malformed streams;
- randomized semantic profile-composition fuzzing;
- Rust build/tests, 32-bit cross-compilation, generated-registry snapshot comparison and Python/Rust full structural differential vectors;
- Python-vs-Rust agreement on the **Rust** runtime admission cost model over the differential matrix;
- formal drift lock verification;
- strict TLA+ model/syntax checks (including bootstrap contention) and Lean proof compilation/readmission invariants in the release CI environment;
- round-trip example and checksum-manifest verification;
- ZIP/package extraction and re-verification for published artifacts.

`formal/model-lock.json` is only a drift detector. A changed lock without a passing active TLA+/Lean tool gate is not a release pass.

A release must not claim local execution of Rust/TLA+/Lean gates on a machine where those toolchains are absent. In that case they remain required remote/CI gates, not silently skipped proof evidence.
