# Formal Verification Gates — Draft 0.11

DBP uses three distinct controls and does not conflate them:

1. **Model/executable drift lock** — hashes mapped implementation + formal artifacts so changes are explicit.
2. **Active formal tool gate** — release CI runs TLA+ syntax/model checks and compiles Lean proofs.
3. **Human review / semantic mapping** — `MODEL-COVERAGE.json` states which executable invariants each model is intended to represent.

Updating `model-lock.json` alone is never considered verification. `tools/verify_formal_lock.py --strict` requires the active tool gate after the hash check. Local development may run without TLA+/Lean installed, but release CI is strict.

Formal models are abstractions. In particular, runtime allocator behavior and hardware line faults are validated by executable resource/fuzz/supervisor tests rather than being misrepresented as fully proven by TLA+.
