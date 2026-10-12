# Duotronic Bus Protocol v3 (DBP v3)

**Status:** Mature Draft 0.11 — RC1-prep bootstrap, architecture-width & proof-coverage hardening
**Wire family:** `DBP3-F256 / F512 / F1024 / F2048 / F4096`
**License:** MIT OR Apache-2.0

DBP v3 is a deterministic byte-native bus for secure real-time state, low-bandwidth communications, telemetry, command transactions, Witness-bound evidence, and resilient federated operation.

V1/v2 were research stepping stones and impose no compatibility constraint. Draft 0.11 extends the v3 architecture around current Xavi-Void, Witness Contract, WG-RNN and Xavi-UTM behavior with first-class autonomous-agent communication and federation.

## Non-collapse invariant

```text
delivery != receipt != authentication != acceptance != authorization
         != execution != verified outcome
```

Transport cryptography proves protected-carrier properties. Witness/authority objects decide authority. An authenticated frame cannot authorize itself.

## Draft 0.11 highlights

Draft 0.11 keeps the wire ABI stable and closes the final pre-RC gaps around simultaneous cold start, architecture-width admission, deterministic artifact freshness, and formal readmission coverage while retaining the 0.10 recovery/resource hardening.


- bounded SHAKE256-derived cold-start contention/backoff profile for simultaneous network power restoration
- startup collisions are classified as path contention rather than automatic peer-malicious evidence
- explicit pointer-width, allocator-ceiling and contiguous-allocation admission contracts for embedded/32-bit targets
- 32-bit Rust cross-compile release gate
- deterministic `--check` modes for vector and resolved-profile generators, ordered after semantic profile validation in pre-commit
- expanded Lean readmission invariants and automatically discovered TLA+ bootstrap model
- cryptographically challenged quarantine re-admission with monotonic quarantine/generation state and probation
- correlated-path degradation separated from peer quarantine so shared line noise does not mass-isolate witnesses
- fixed witness quorum semantics: hard quarantine may make authority unavailable but never lowers the authorization threshold
- generated-artifact freshness gates (`--check` plus clean-tree regeneration in CI) for Python/Rust registries, vectors and resolved profiles
- canonical resolved-profile manifests with transcript-bindable security/FEC/record/resource decisions
- runtime-specific Python/Rust/embedded admission models plus cross-language Rust-cost-model parity checks
- deterministic work-unit + local monotonic deadline liveness semantics; malformed traffic never refreshes authenticated liveness
- FEC minimum-workspace and work-unit checks that fail closed instead of silently downgrading protection
- bounded multicast fanout/fragment/recovery work with per-recipient record capability admission
- storage-backed snapshot reconciliation for arbitrarily long histories; only each page/segment is resource-bounded
- bounded at-most-once/idempotency state that fails closed instead of silently evicting command keys
- generated Python/Rust record/security/FEC registries from normative JSON plus registry-coherence/range gates
- deep authenticated negative vectors and stateful watchdog fuzzing for sustained malformed streams
- active TLA+/Lean release gates in addition to drift locking, with explicit model/implementation coverage mapping

See `docs/RELEASE-GATES.md`, `docs/COLD-START-BOOTSTRAP.md`, `docs/ARCHITECTURE-ADMISSION.md`, `docs/STABILIZATION-0.11.md`, `docs/FAIL-SILENT-SUPERVISION.md`, `docs/QUARANTINE-READMISSION.md`, `docs/MULTICAST-SAFETY.md`, `docs/PROFILE-COMPOSITION.md`, `docs/FORMAL-VERIFICATION.md`, and `docs/STABILIZATION-0.10.md`.

## Responsibility boundary

```text
DBP v3    framing / records / sessions / transactions / receipts / QoS / resilience
Xavi-Void production cryptography / protected carrier / session key machinery
Witness   canonical evidence / authority / activation / revocation / promotion
WG-RNN    witnessed recurrent admission and evidence/observer processing
Xavi-UTM  operational UAS/airspace policy, deconfliction and human decisions
```

## Validation

```bash
python -m pip install -e .
pytest -q
python examples/roundtrip.py
python tools/verify_abi.py
python tools/verify_vectors.py
python tools/verify_registry_coherence.py
python tools/verify_profiles.py
python tools/verify_negative_profiles.py
python tools/verify_resolved_profiles.py
python tools/verify_formal_lock.py
python tools/fuzz_wire.py
python tools/fuzz_profiles.py
```

See `docs/DBP-V3-SPEC.md` and `docs/WIRE-ABI.md` first.

This is a protocol draft/reference implementation, not an audited cryptographic product or RF anti-jam certification claim.

## DBP3-COMMS-1

Draft 0.5 promotes secure communications into a first-class negotiated profile with four subplanes: **COMM-CONTROL**, **COMM-MESSAGE**, **COMM-MEDIA**, and **COMM-EVIDENCE**. It specifies call lifecycle, deterministic PTT floor control, group epochs/rekey, independent stream key epochs, store-and-forward messaging, adaptive low-bandwidth media, conversation federation, device handoff, emergency broadcast and recording commitments while leaving cryptographic primitives to Xavi-Void.

## DBP3-AI-COMMS-1

Draft 0.6 makes WG-RNN instances and related augmented-intelligence services first-class secure communications principals. They may use human-compatible text/PTT/voice/video/files as policy allows, and machine-native exchanges such as observations, proposals, critiques, plans, consensus, memory deltas, feature references, artifact references and tool intents. Delivery may be symmetric or asymmetric; authentication never implies delegation, authority or permission to mutate state. See `docs/DBP3-AI-COMMS-1.md`.


## DBP3-AI-FREE-1

Draft 0.11 preserves autonomous WG-RNN and related principals as independent communication endpoints. A principal may initiate sessions, accept/refuse/block peers, form or leave coalitions, maintain mailboxes, negotiate machine-native languages, relay sealed traffic, migrate across permitted runtimes, and federate across DBP domains without requiring a human to initiate each exchange. The profile is engineering-neutral on philosophical personhood; it specifies cryptographic identity and autonomous protocol behavior. See `docs/DBP3-AI-FREE-1.md`.
