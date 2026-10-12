# Duotronic Bus Protocol v3 — Normative Mature Draft 0.11

## 1. State non-collapse

DBP implementations MUST preserve:

```text
shape valid != corruption recoverable != authenticated != parsed != semantically valid
!= Witness resolved != authorized != executed != persisted != observed outcome
```

No frame bit, receipt or encryption result collapses those states.

## 2. Wire family

The normative ABI is in `WIRE-ABI.md`. The protocol supports F256/F512/F1024/F2048/F4096 with identical header/trailer semantics and deterministic parsing. Frame size is negotiated and transcript-bound. F256 exists specifically for bounded emergency/control survival traffic.

## 3. Records/extensions

Core types occupy 1..255. Standards extensions use 256..4095; application 4096..32767; experimental 32768..49151; vendor/private 49152..65535. Unknown critical records fail closed. Unknown noncritical records are skippable.

## 4. Capability negotiation

Peers exchange supported frame sizes, security suites, FEC, compression, media codecs and Witness profiles. Selection MUST be an intersection of advertised sets. The ordered canonical negotiation transcript includes the session identity and is committed into the protected session. Silent downgrade is non-conformant.

## 5. Sessions/rekey/compromise

Sessions follow `SESSION-STATE-MACHINE.md`. Suspected key compromise enters `QUARANTINED`; compromised epochs MUST NOT resume. Recovery establishes fresh session identity/key material and fresh replay domains through Xavi-Void.

## 6. Replay/causality/time

Sequences are one-origin. Replay state is scoped by authenticated direction/session generation/key epoch/stream. DBP distinguishes source time, observation time and uncertainty; observation time is never silently substituted for source time. Cross-stream causality uses explicit Witness/causal references.

## 7. Transactions/receipts

Commands carry transaction and idempotency identity. Duplicate delivery MUST NOT cause duplicate execution. Receipts advance monotonically through transport/authentication/parse/Witness/authorization/execution/persistence/observed-outcome stages.

## 8. Authority/Witness

Authority-bearing operations resolve external Witness authority state, chronology, revocation and policy. Sender hints and transport identity are not authority proof. A blocked WG-RNN witness MUST NOT mutate recurrent state.

## 9. Groups

Group traffic carries membership epoch and key epoch in its group-control semantics. Any membership change increments the group epoch and requires rekey. Removed members cannot be accepted in the new epoch.

## 10. Emergency/control

The emergency record is fixed-shape, uncompressed and schema-independent. Profiles SHOULD duplicate emergency traffic across independent failure domains and reserve scheduler capacity for emergency/control even under bulk congestion.

## 11. Resilience

Baseline FEC is systematic GF(256) over protected shards. Extension registry reserves sliding-window and rateless schemes. FEC reconstruction never bypasses cryptographic, replay, Witness or policy validation. Interleaving parameters are profile-bound.

## 12. Congestion/degraded modes

Authenticated link feedback drives NORMAL/CONSTRAINED/DEGRADED/SURVIVAL state. Profiles reserve minimum scheduler shares for emergency/control. Video/bulk shed before safety/control. Unauthenticated feedback may not increase resource allocation.

## 13. Multipath

Path duplication for critical traffic SHOULD prefer distinct failure domains. Path migration does not change logical identity or authority.

## 14. Object/update transfer

Large objects use content-addressed chunks and Merkle roots. Update profiles additionally bind signer/authority, version lineage, predecessor identity, staging decision and rollback receipts.

## 15. UTM/WG-RNN profiles

Xavi-UTM uses typed aircraft-state, flight-plan, conflict, deconfliction, human-decision, geofence, weather and emergency records. Spatial records explicitly declare CRS, altitude datum, SI units, timestamp and uncertainty.

WG-RNN uses typed observation, observer-result, consensus, gate-receipt, model-provenance and synthesis-evidence records. Temporal observations preserve source-time versus observation-time semantics and one-origin sequencing.

## 16. Resource bounds

All parsers require finite limits for records, reassembly, decompression expansion, FEC groups, replay windows, groups and object sizes. Budget overflow is a typed rejection.

## 17. Validation order

```text
fixed frame class -> structural ABI -> CRC precheck -> resource/profile preflight
-> FEC reconstruction if needed -> Xavi-Void protected-carrier verification
-> replay/transcript -> payload commitment -> record bounds -> semantic validation
-> Witness/revocation/policy -> idempotent execution -> staged receipt/outcome
```

State mutation before applicable authentication/Witness/policy gates is non-conformant.

## 15. Human and augmented-intelligence communications

Implementations advertising `dbp3-comms-1` support secure human-compatible text, PTT, voice, video, file and data exchange. Implementations advertising `dbp3-ai-comms-1` additionally support first-class WG-RNN/agent principals and machine-native asymmetric exchange patterns. An AI principal may participate in human-compatible channels only under local policy and remains explicitly identifiable as an AI/service principal.

## 16. Machine-native asymmetric exchange

DBP3-AI-COMMS-1 defines unicast, multicast, broadcast, mailbox, publish, request/response, fanout/gather, quorum and pipeline patterns. These patterns are transport semantics, not authority semantics. Proposals, critiques, plans, memory deltas, tool intents and consensus votes cannot authorize themselves.

## 17. Files and structured data

Human and machine principals may exchange bounded inline payloads and larger Merkle-rooted objects through the object-transfer plane. Structured-data references carry media type, schema, encoding, compression, digest and length. Executable/model/update artifacts require separate policy and authority checks before activation.

## Draft 0.11 semantic activation and failure containment

An operational profile is not active merely because its JSON parses. The implementation resolves the inheritance closure, validates registered security/FEC choices, emits a canonical resolved manifest, binds that manifest to negotiation, and separately performs local runtime resource admission. Failure at any stage rejects activation before application traffic.

FEC and multicast resource exhaustion are typed fail-closed conditions. Resource pressure never authorizes raw/unprotected fallback. Multicast recovery is bounded per recipient/path to prevent one loss event from amplifying recovery work across every member.

Repeated malformed traffic may place a peer in local quarantine before expensive FEC, Witness, model, or application dispatch. Physical fail-silent behavior, when required by a deployment, is owned by an out-of-process supervisor rather than the managed DBP runtime itself.

Offline reconciliation is bounded per page, not by total history age. Snapshot-bound cursors and deterministic chunking allow eventual convergence after extended partitions while bounding each reconciliation step.
