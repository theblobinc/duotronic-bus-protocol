# Changelog

## Mature Draft 0.11 — RC1-prep bootstrap, architecture-width and proof coverage

Draft 0.11 retains major 3 / ABI minor 4 and deliberately avoids another wire-format redesign.

### Cold-start contention
- adds `DBP3-BOOTSTRAP-CONTENTION-1` with nonce-derived bounded backoff, retry expansion and no synchronized-clock dependency;
- startup collision/congestion is path evidence, not automatic peer quarantine;
- adds TLA+ bootstrap contention model and tests for retry bounds/state legality.

### Architecture admission
- separates protocol numeric range, pointer width, total allocator ceiling and contiguous-allocation ceiling;
- adds Python/Rust platform-admission guards with checked conversion semantics;
- adds a 32-bit Rust cross-compilation CI gate.

### Deterministic artifacts and formal coverage
- vector and resolved-profile generators now have deterministic `--check` modes;
- pre-commit uses one ordered semantic -> generated-artifact freshness gate;
- Lean adds post-quarantine proof/generation structural invariants;
- strict formal runner automatically discovers every checked-in TLA+ `.cfg`.

## Mature Draft 0.10 — Pre-RC recovery, generated-state and bounded-resource hardening

Draft 0.10 retains major 3 / ABI minor 4 and focuses on pre-RC failure recovery, deterministic generated state, long-horizon convergence, and runtime-bounded secure communications.

### Quarantine, liveness and supervision
- quarantine cooldown no longer re-admits a peer automatically; cooldown only permits a new readmission attempt;
- readmission requires a fresh challenge, monotonic peer generation, session commitment, Witness reference and externally verified Xavi-Void authenticator, followed by probation;
- quarantine epoch/generation survive persisted supervisor state so reboot cannot become an identity reset;
- correlated faults on one path degrade the path before mass-quarantining unrelated peers, while hard security faults still quarantine immediately;
- witness thresholds never shrink to preserve apparent liveness; authority-bearing work becomes pending/unavailable if quorum is genuinely lost;
- authenticated liveness uses deterministic work budgets plus local monotonic deadlines; malformed/babbling traffic cannot refresh peer liveness;
- physical fail-silent isolation remains an out-of-process OS/native/firmware/hardware supervisor responsibility.

### Generated state, profiles and cross-language parity
- registry code generation has a `--check` freshness mode and release CI regenerates registries, vectors and resolved profiles then requires a clean tree;
- Python/Rust record, security-suite and FEC constants come from normative registries rather than hand-maintained duplicates;
- resolved profile manifests now bind protection, registered suite, FEC policy/algorithm, frame family, record closure, replay window, limits and resource class;
- Xavi-UTM and WG-RNN profiles inherit the secure COMMS -> AI-COMMS -> AI-FREE capability chain before adding domain records;
- the Rust differential gate compares registry snapshots, full structural vector decodes and the Rust runtime-cost model computed independently on both sides;
- integer/range/coherence checks cover ABI widths, registry IDs, profile IDs and canonical one-origin fields.

### Resource and convergence hardening
- FEC encoding/recovery has explicit workspace and deterministic work-unit limits; resource failure cannot silently disable protection;
- multicast planning bounds fanout, fragments, per-recipient recovery bytes/work and record-capability admission;
- long histories can reconcile through immutable storage-backed snapshots and byte-segment cursors without materializing the whole history; the in-memory adapter has an explicit item ceiling;
- at-most-once/idempotency state is capacity-bounded and fails closed rather than evicting keys that could make an old command executable again;
- store-and-forward custody rejects routing loops and hop exhaustion; object transfer, replay, federation, agent data and temporal fields have explicit numeric/size ceilings.

### Verification
- deep authenticated negative vectors exercise semantic failures beyond CRC corruption;
- stateful watchdog fuzzing covers individual mutations and sustained malformed streams under child-process timeouts;
- randomized profile semantic fuzzing tests admission against contradictory/unregistered/range-invalid combinations;
- formal coverage adds quarantine/readmission and multicast containment models; strict release CI executes TLA+ and Lean in addition to drift locking;
- release documentation distinguishes verified implementation behavior from deployment-specific watchdog/hardware behavior.

## Mature Draft 0.9 — Semantic admission, failure containment, active verification

Draft 0.9 keeps major 3 / ABI minor 4 and concentrates on failure containment and verification depth.

### Semantic profile + registry hardening
- operational profiles are self-contained and validated semantically before activation;
- canonical resolved-profile manifests bind suite, FEC policy, frame family, record set, replay window, limits and requirements;
- security-suite ID/status drift was corrected (`development-hmac` is consistently `0xFF01` / 65281 and experimental);
- FEC policy names now resolve through a dedicated policy registry to registered algorithms;
- record/suite IDs are generated into Python/Rust code from normative registries;
- the COMMS -> AI-COMMS -> AI-FREE inheritance hierarchy is explicit and verified rather than treated as a mutual-exclusion rule.

### Runtime resource/failure safety
- separate Python, Rust and embedded cost models translate protocol quotas into conservative local admission;
- profile activation fails before traffic if local memory/CPU/fanout/mailbox/FEC requirements cannot be admitted;
- FEC encoders/decoders have explicit workspace estimation and fail-closed resource errors;
- multicast admission checks suite/frame compatibility and bounds members, fanout, fragments and parallel recovery;
- sustained malformed peers enter local monotonic-time quarantine;
- deployments requiring physical fail-silent behavior now have an explicit out-of-process supervisor contract rather than fictional Python hardware isolation.

### Convergence + Witness
- bounded reconciliation v2 uses snapshot-bound cursors and deterministic chunking, so a long-offline node can eventually converge without an unbounded page;
- fixed witness quorum does not reduce authorization thresholds merely because peers disappear.

### Verification
- watchdog mutation fuzzing treats parser hangs as failures;
- golden vectors cover core text, call control, AI proposal and autonomous consent records plus authenticated negative vectors;
- Python/Rust differential checks compare the full structural decode;
- formal drift locking remains, but release CI additionally runs TLA+ syntax/model checking and Lean compilation;
- new formal models cover profile/resource admission and noisy-peer quarantine abstractions.


## Mature Draft 0.8 — Stabilization, parity, bounded convergence

Draft 0.8 is a mass hardening pass over 0.7. The wire ABI remains at major 3 / ABI minor 4.

### Cross-language parity
- Rust upgraded from a header-only parser to an independent DBP wire conformance oracle.
- Rust validates fixed frame size/version, CRC, SHAKE256 payload commitment, trailer/FEC structure, development authentication vectors, records/padding, one-origin IDs and unknown-critical rejection.
- CI now builds/tests Rust and runs Python/Rust differential golden-vector checks.
- deterministic mutation fuzz smoke runs on every CI change; the repo documents continuous external differential fuzzing as the stronger target.

### Profile safety
- `extends` gives profiles explicit transitive composition semantics.
- `dbp3-ai-free-1` extends `dbp3-ai-comms-1`; `dbp3-ai-comms-1` extends `dbp3-comms-1`.
- unknown non-critical profile records are forward-compatible; unknown critical records fail closed.
- profile closure detects dependency cycles, suite conflicts and empty frame-size intersections.

### Formal drift control
- `formal/MODEL-COVERAGE.json` maps executable components to TLA+/Lean artifacts and named invariants.
- `formal/model-lock.json` is CI-verified. Implementation or formal changes cannot silently drift without an explicit lock refresh/review.
- new bounded-merge TLA+ model.
- Hash locking is explicitly not represented as proof of implementation/spec equivalence.

### Offline convergence and resource safety
- resumable byte/item-bounded reconciliation pages.
- revocation/authority-first merge ordering.
- unified resource accounting across memory, in-flight messages, FEC, merge, mailboxes, fanout and CPU-token budgets.
- oversized merge items must use object transfer/chunking rather than monopolize reconciliation.

### Autonomous communications
- record registry now explicitly allocates autonomous-agent records 123..140 used by `DBP3-AI-FREE-1`.
- secure suite lifecycle registry added.
- autonomy remains first-class while authentication, consent, delegation, Witness admission and state-mutation authority remain distinct.
