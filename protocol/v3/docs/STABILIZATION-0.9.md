# Draft 0.9 Stabilization Review

This release was driven by an adversarial architecture review. Several reported risks were real; several were based on assumptions that were not true of the repository. Draft 0.9 fixes the real mechanics rather than implementing fictional countermeasures.

| Review concern | Actual Draft 0.8 state | Draft 0.9 action |
|---|---|---|
| Formal lock could be refreshed without proofs | True: lock was only a hash drift detector | Release CI now also runs TLA+ syntax/model checks and Lean compilation in strict mode |
| Bounded merge permanently truncates long history | Legacy API rejected an oversized single item | New snapshot-bound reconciliation chunks oversized items and bounds work per page, not total history |
| Python/Rust resource costs assumed equal | True: quotas were implementation-neutral only | Separate runtime cost/admission models; protocol quotas remain common |
| `ai-free` conflicts with `ai-comms` | False: AI-FREE intentionally extends AI-COMMS | Inheritance is explicit, canonical, semantically verified, and transcript-bindable |
| FEC can be invoked with unusable resource budgets | Resource admission was not connected to FEC workspace | Explicit workspace estimator + fail-closed `FECWorkspaceError` |
| `emergency.py` controls hardware isolation | False: it is only an emergency-record codec | Added explicit out-of-process supervisor contract; DBP makes no false hardware-isolation claim |
| Rust uses unsafe Python FFI | False: no FFI exists and Rust has `#![forbid(unsafe_code)]` | Documented boundary; future FFI requires a separate safety profile |
| Mutation fuzzing misses hangs | True: old tool only decoded mutations inline | Parent/child watchdog batches treat a parser stall as a CI failure |
| Witness tests simulate dynamic quorum | False: only authority-binding assertions existed | Added fixed-threshold quorum semantics; missing peers never lower authority thresholds |
| Multicast may amplify recovery work | Group helper lacked operational limits | Suite/frame admission + fanout/fragment/message/recovery ceilings |
| Registry parity can drift | True: suite and record mappings had already drifted | Generated Python/Rust registry constants + coherence verifier |
| Profile registry duplicates normative data | True | Registry converted to an index-only file; operational profile files are normative |

Draft 0.9 therefore remains ABI-compatible with the mature v3 line while materially strengthening activation, containment, convergence and verification.
