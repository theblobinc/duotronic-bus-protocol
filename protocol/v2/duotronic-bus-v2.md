# Duotronic Bus Protocol v2 (DBP v2)

**Status:** Draft protocol line  
**Version:** dbp-v2-draft-2026-04-25  
**Wire class:** `DBP2-F4096` fixed 4096-byte frame  
**Relationship to Duotronics:** complementary transport boundary used by Duotronics, not a replacement for DPFC, the Witness Contract, or Duotronic semantic math  
**Recommended production profile:** `dbp-duotronics-witness-authority-s2-v1`

---

## 0. Normative language

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** define requirement levels.

DBP v2 keeps the low-level DBP invariant: a receiver first proves that a frame is structurally and cryptographically acceptable, and only then allows Duotronic semantic interpretation.

Canonical v2 ingress order:

```text
shape validation
-> structural field validation
-> CRC / integrity validation
-> replay validation
-> decrypt if S2
-> lane manifest validation
-> payload decode
-> Witness8 / WSB2 / adapter validation
-> family registry lookup
-> normalizer execution
-> canonicalization
-> policy gate
-> optional lookup, recurrence, promotion, or outbound transport use
```

Any semantic use before this order completes is non-conformant for authority-bearing deployments.

---

## 1. Position in the Duotronics stack

DBP v2 is a transport and frame protocol. It is complementary to Duotronics and is used by the Duotronics source-spec stack as a transport boundary.

DBP v2 does **not** define DPFC arithmetic, family conversion, canonical witness identity, or policy authority. Those belong to Duotronics specifications such as DPFC, the Witness Contract, family registries, normalizer profiles, transport profiles, and policy shield profiles.

DBP v2 does define:

1. byte shape;
2. structural field encoding;
3. security and replay boundary;
4. lane layout and multiplexing;
5. how semantic payloads are carried;
6. when semantic decoders are allowed to run;
7. how versioned semantic context is bound into replay identity;
8. how a DBP receiver reports trust, presence, and failure states to Duotronic runtimes.

The central separation is:

```text
DBP frame validity != semantic validity != canonical identity != policy authority
```

---

## 2. Design goals

DBP v2 upgrades v1.x without discarding its strengths.

Goals:

1. preserve fixed-offset, fixed-size, deterministic decoding for real-time systems;
2. make Duotronic transport boundaries explicit;
3. carry dense or sparse witness state without collapsing absence and numeric zero;
4. support full-duplex operation through independent directional frame streams;
5. bind schema, normalizer, family registry, transport profile, and export policy into replay identity;
6. support authority-gated semantic updates for DW-SSM and other witness runtimes;
7. allow GCD-jump and related recurrence patterns as candidate sparse event gates, never as direct authority;
8. retain v1.x compatibility concepts: integer-as-float structural fields, bands, S1/S2 security modes, ABB/MUX, WSB2, and deterministic validation.

Non-goals:

1. replacing DPFC or Witness Contract semantics;
2. treating raw witness geometry as trusted identity;
3. treating token-free absence as numeric zero;
4. making GCD-jump recurrences a general prime-generation claim;
5. allowing raw untrusted data to select state-transition matrices, memory writes, or promotion decisions;
6. using CRC-only frames for cross-boundary semantic authority.

---

## 3. Wire classes and versioning

### 3.1 Wire class registry

| Wire class | Frame bytes | Cells | Status | Meaning |
|---|---:|---:|---|---|
| `DBP1-F4096` | 4096 | 1024 Float32 | legacy active | v1.x fixed frame |
| `DBP2-F4096` | 4096 | 1024 Float32 | draft | v2 fixed frame with semantic descriptor discipline |
| `DBP2-E` | variable | n/a | future | explicit envelope mode; out of scope for this draft |

This document defines only `DBP2-F4096`.

### 3.2 Magic and parser selection

A v2 frame uses the v2 magic:

| Version | `magic` hex | `magic` decimal | `version` cell |
|---|---:|---:|---:|
| v1.1 | `0xDB11` | `56081` | `11` |
| v2.0 draft | `0xDB20` | `56096` | `20` |

The parser MUST select layout from `magic`, not from advisory text fields or transport labels.

### 3.3 Profile IDs

The legacy `profile_id` carried inside `flags_profile` remains 8 bits for compatibility. DBP v2 adds a larger semantic profile binding through the v2 semantic descriptor.

Receivers MUST NOT treat the 8-bit `profile_id` as sufficient to identify a v2 semantic profile. Authority-bearing v2 frames require the tuple:

```text
wire_class
+ security profile
+ semantic_profile_id
+ semantic_profile_version
+ schema hash
+ normalizer hash
+ family registry hash
+ transport profile hash
+ export policy
```

---

## 4. Frame shape: `DBP2-F4096`

A `DBP2-F4096` frame is exactly 4096 bytes: 1024 consecutive little-endian IEEE-754 Float32 cells.

The cell map intentionally stays close to v1.x so that existing tooling can migrate without a new parser model.

| Region | Cells | Bytes | v2 class | Notes |
|---|---:|---:|---|---|
| Band 0 | `0..8` | `0..35` | structural header | magic, version, sequence, time, flags/profile, tick rate |
| Band 1 | `9..19` | `36..79` | semantic control | low-latency analog/control hints; ciphertext in S2 |
| Band 2 | `20..83` | `80..335` | digital or lane payload | may carry v1 digital chunks or v2 lane data |
| Band 3 | `84..147` | `336..591` | digital or lane payload | may carry v1 digital chunks or v2 lane data |
| Band 4 | `148..275` | `592..1103` | witness semantic | dense Witness8 rows, quantum legacy, or leased lane |
| Band 5 | `276..659` | `1104..2639` | witness semantic | dense Witness8 rows, waveform legacy, WSB2, or leased lane |
| Band 6 | `660..999` | `2640..3999` | MUX/control and leased lane | v2 MCB lives at `660..683` when enabled |
| Band 6T | `1000..1019` | `4000..4079` | security trailer | cleartext structural in secure modes |
| Band 7 | `1020..1023` | `4080..4095` | footer | CRC, byte size, magic echo |

S2 rule: cells `9..999` are opaque ciphertext until AEAD verification and decryption succeed. No v2 semantic decoder may inspect those cells before S2 verification succeeds.

---

## 5. Structural encoding rules

DBP v2 inherits the v1.x integer-as-float rule for structural `u16` and `u24` carriers.

A structural integer field MUST:

1. decode from Float32;
2. be finite;
3. not be subnormal;
4. be integral;
5. be in range (`u16: 0..65535`, `u24: 0..16777215`);
6. round-trip exactly through Float32;
7. reject `-0.0` in hardened v2 profiles.

Structural fields MUST NOT be witness-encoded.

The following regions are structural fences:

1. Band 0 (`cells[0..8]`);
2. Band 6T (`cells[1000..1019]`);
3. Band 7 (`cells[1020..1023]`);
4. any profile-declared MCB, lane descriptor, or semantic descriptor field;
5. any profile-declared integer-decoded semantic lane header.

---

## 6. Header and footer

### 6.1 Header cells

| Cell | Name | Type | v2 meaning |
|---:|---|---|---|
| 0 | `magic` | u16-as-float | `0xDB20` for DBP v2 |
| 1 | `version` | u16-as-float | `20` for this draft line |
| 2 | `seq_lo` | u24-as-float | sequence low word |
| 3 | `seq_hi` | u24-as-float | sequence high word |
| 4 | `unix_day` | u24-as-float | `floor(unix_sec / 86400)` |
| 5 | `sec_of_day` | u24-as-float | `unix_sec % 86400` |
| 6 | `ms` | u24-as-float | millisecond, `0..999` |
| 7 | `flags_profile` | u24-as-float | `(legacy_profile_id << 16) | flags16` |
| 8 | `tick_rate` | u16-as-float | intended frames per second; `0` = paused or unspecified |

### 6.2 Footer cells

| Cell | Name | Type | Meaning |
|---:|---|---|---|
| 1020 | `crc32_lo` | u16-as-float | CRC32 low 16 bits |
| 1021 | `crc32_hi` | u16-as-float | CRC32 high 16 bits |
| 1022 | `byte_size` | u16-as-float | MUST be `4096` |
| 1023 | `magic_echo` | u16-as-float | MUST equal cell 0 |

CRC32 remains CRC-32/ISO-HDLC over `bytes[0..4079]` unless a specific profile explicitly defines an authenticated-only local transport class. Authority-bearing cross-boundary profiles MUST keep CRC and authenticated integrity.

---

## 7. Security profiles

### 7.1 Security modes

| `sec_profile` | Name | v2 use |
|---:|---|---|
| 0 | Open | local experiments only; no authority-bearing semantic trust |
| 1 | S1 | authenticated cleartext; may support constrained authority if policy permits |
| 2 | S2 | authenticated encryption; required for recommended v2 production profiles |

### 7.2 S2 authority rule

For `dbp-duotronics-witness-authority-s2-v1`, S2 is REQUIRED. A frame that is not S2 may still be structurally decoded for diagnostics, but semantic authority MUST be zero.

### 7.3 Direction-bound keys and nonces

Full-duplex profiles MUST bind direction into key derivation, nonce construction, AAD, or all three.

The following MUST be impossible in a conforming profile:

```text
valid uplink frame replayed as valid downlink frame
valid downlink frame replayed as valid uplink frame
old semantic descriptor replayed with a new payload
new payload accepted under an old normalizer hash without downgrade policy
```

---

## 8. v2 MUX Control Block (MCB2)

When enabled, MCB2 occupies cells `660..683` and is profile-structural. These cells are inside the S2 ciphertext region on the wire but become structural after successful decryption.

| Cell | Name | Type | Meaning |
|---:|---|---|---|
| 660 | `mcb_magic` | u16-as-float | `0xD2B2` (`53938`) |
| 661 | `mcb_version` | u16-as-float | `2` |
| 662 | `direction` | u16-as-float | `0=downlink`, `1=uplink`, `2=peer`, `3=local` |
| 663 | `lane_count` | u16-as-float | count of active lane descriptors |
| 664 | `descriptor_cell_start` | u16-as-float | first cell of semantic descriptor lane or `0` |
| 665 | `descriptor_cell_count` | u16-as-float | descriptor cell count or `0` |
| 666 | `ack_seq_lo` | u24-as-float | last opposite-direction seq low word seen |
| 667 | `ack_seq_hi` | u24-as-float | last opposite-direction seq high word seen |
| 668 | `cmd_seq` | u24-as-float | direction-local command sequence |
| 669 | `cmd_type` | u16-as-float | profile command type |
| 670 | `mcb_flags` | u24-as-float | bit flags |
| 671 | `policy_mode` | u16-as-float | L5 policy mode mirror, profile registry defined |
| 672 | `authority_hint` | Float32 | advisory only; policy clamps dominate |
| 673 | `normalizer_confidence` | Float32 | `0..1`; low confidence cannot increase authority |
| 674 | `schema_hash_a` | u24-as-float | low 24 bits of profile schema hash fragment |
| 675 | `schema_hash_b` | u24-as-float | next hash fragment |
| 676 | `normalizer_hash_a` | u24-as-float | normalizer hash fragment |
| 677 | `normalizer_hash_b` | u24-as-float | normalizer hash fragment |
| 678 | `registry_hash_a` | u24-as-float | family registry hash fragment |
| 679 | `registry_hash_b` | u24-as-float | family registry hash fragment |
| 680 | `transport_hash_a` | u24-as-float | transport profile hash fragment |
| 681 | `transport_hash_b` | u24-as-float | transport profile hash fragment |
| 682 | `export_policy` | u16-as-float | declared semantic export policy |
| 683 | `mcb_crc16` | u16-as-float | optional descriptor/MCB check; profile-defined |

Hash fragments in MCB2 are fast routing hints. The full replay identity MUST use full canonical hashes carried in an authenticated descriptor lane or derived from local negotiated profile state.

---

## 9. Lane descriptors

A v2 lane is a semantic or profile-structural slice inside cells `20..999`, excluding reserved MCB2 cells when MCB2 is active.

Each lane descriptor is a logical record. It MAY be stored in the descriptor lane, in a compact MCB extension, or in negotiated profile state. The canonical record is:

```yaml
lane_descriptor:
  lane_id: uint16
  lane_type: enum
  direction: downlink | uplink | peer | local
  start_cell: uint16
  cell_count: uint16
  byte_count: uint16
  payload_profile: string
  schema_id: string
  normalizer_id: string
  family_registry_ref: string | null
  export_policy: string
  absence_zero_policy: string
  integrity_policy: inherited_s2 | lane_crc | signed_payload
  authority_class: none | candidate | canonical | control
```

### 9.1 Lane type registry

| Type | Name | Meaning |
|---:|---|---|
| 1 | `digital_u24` | v1-compatible 3-byte-per-cell digital payload |
| 2 | `analog_f32` | Float32 semantic vector |
| 3 | `quantum_pair` | legacy amplitude pair region |
| 4 | `opaque_bytes` | S2-only byte payload carried in authenticated ciphertext |
| 5 | `witness8_dense` | contiguous dense Witness8 rows, 8 Float32 cells per row |
| 6 | `wsb2_sparse` | WSB2 sparse witness payload, usually via `opaque_bytes` |
| 7 | `dpfc_object_ref` | canonical object reference or hash, not raw arithmetic mutation |
| 8 | `gcd_jump_gate` | candidate sparse recurrence event gate |
| 9 | `dw_ssm_event` | post-canonicalization event embedding for DW-SSM runtime |
| 10 | `semantic_descriptor` | authenticated v2 semantic descriptor |

Unknown lane types MUST be ignored or rejected according to profile policy. Unknown lane types MUST NOT be interpreted as a known payload.

---

## 10. Semantic descriptor

A v2 authority-bearing frame MUST be bound to a semantic descriptor. The descriptor may be carried in a `semantic_descriptor` lane or negotiated out-of-band and referenced by hash.

Canonical descriptor fields:

```yaml
semantic_descriptor:
  descriptor_version: dbp-semantic-descriptor@v2
  wire_class: DBP2-F4096
  dbp_profile_id: string
  dbp_profile_version: string
  security_required: S2
  payload_profiles:
    - Witness8
    - WSB2
    - DPFC-object-ref
    - gcd-jump-gate
    - dw-ssm-event
  schema_hash: string
  normalizer_hash: string
  family_registry_hash: string
  transport_profile_hash: string
  export_policy: positive_index | nonnegative_corrected | raw_transport_integer | normalized_float
  absence_zero_policy: strict_distinction
  replay_identity_policy: dbp-v2-replay-id@v1
  failure_behavior: reject | audit_only | transport_bypass | family_bypass | lookup_bypass | full_bypass
```

The descriptor is identity-affecting. Changing it changes replay identity.

---

## 11. Presence, zero, invalidity, and trust states

DBP v2 receivers MUST report semantic payload status using distinctions compatible with the Witness Contract.

### 11.1 Presence status

```text
structurally_absent
present_unknown
token_free_absent
present_zero_value
present_nonzero_value
present_invalid
rejected_untrusted
```

Token-free absence MUST NOT imply numeric zero. Numeric zero MUST be represented as a present value under a profile that declares numeric zero support.

### 11.2 Trust status

```text
raw
transport_validated
semantic_validated
canonicalized
trusted_for_lookup
trusted_for_recurrence
trusted_for_promotion
rejected
```

A deployment may use fewer internal states only if these boundaries are preserved in logs, policy gates, and replay traces.

---

## 12. Witness8 binding

A Witness8 row has exactly eight ordered Float32 fields:

1. `value_norm`
2. `n_sides_norm`
3. `center_on`
4. `activation_density`
5. `kind_flag`
6. `band_position`
7. `parity`
8. `degeneracy`

Mapping/object inputs MUST be converted using this explicit order. Map iteration order is never authoritative.

A Witness8 decoder MUST output one of:

```text
decoded_exact
decoded_lossy
token_free_absent
present_invalid
unsupported_family
ambiguous
profile_mismatch
```

A Witness8 row is an implementation or transport object. It is not automatically a canonical DPFC object. It must pass active profile decode, range checks, family registry lookup, normalizer execution, and canonicalization before it becomes identity-bearing state.

---

## 13. WSB2 sparse witness binding

WSB2 is the preferred v2 sparse witness transport for mostly-absent overlays.

A WSB2 payload represents sparse semantic rows or lanes. An inactive lane or unset bitmap bit is absence at the sparse-row/profile layer. It is not numeric zero.

Minimum WSB2 v2 header:

```text
magic: 'WSB2'
version: 2
overlay_id: u16
rows: u16
cols: u16, MUST be 8 for Witness8 rows
present_count: u16
flags: u16
semantic_profile_hash: u64 or profile-defined hash bytes
bitmap: ceil(rows / 8) bytes
packed_rows: present_count * cols * Float32LE
optional_crc32_or_authenticated_inherited_integrity
```

For S2 DBP, WSB2 SHOULD be carried in an `opaque_bytes` or `wsb2_sparse` lane. If a WSB2 payload is carried in a Float32 semantic region, the profile MUST define exact packing and numeric validation rules.

---

## 14. DPFC binding

DBP v2 may transport DPFC-derived facts, canonical object references, core magnitude hashes, family IDs, witness-history hashes, and export-policy tags.

DBP v2 MUST NOT redefine:

1. DPFC successor;
2. DPFC addition;
3. DPFC multiplication;
4. inter-family conversion;
5. canonical serialization;
6. export correction.

A DBP v2 lane that crosses from Duotronic objects to conventional numbers MUST declare one of these export policies:

```text
positive_index
nonnegative_corrected
raw_transport_integer
normalized_float
```

Silent switching between export policies is a conformance failure.

---

## 15. GCD-jump sparse witness gates

DBP v2 may carry a GCD-jump recurrence as a candidate sparse event gate.

Reference recurrence:

```text
R_1 = 7
J_n = gcd(n, R_{n-1})
R_n = R_{n-1} + J_n
jump_n = 1 if J_n > 1 else 0
```

The useful import is the event pattern:

```text
cheap local step -> long low-information runs -> sparse high-information jumps
```

Normative authority boundary:

```text
GCD jump detected -> candidate event -> validation -> canonicalization -> policy gate -> optional state update
```

Never:

```text
GCD jump detected -> trusted state update
```

A suggested v2 authority clamp is:

```text
if transport_valid == false: authority = 0
else if canonicalization_success == false: authority = 0
else if J_n <= 1: authority = 0
else authority = min(policy_limit, normalizer_confidence * bounded_jump_score(J_n))
```

GCD-jump lanes MUST be labeled as `candidate` authority class until canonicalization and policy gating succeed.

---

## 16. DW-SSM event binding

DBP v2 may feed Duotronic Witness Selective State-Space Model runtimes after validation and canonicalization.

The DBP output to such a runtime is not raw payload bytes. It is a replay-pinned event context:

```yaml
dw_ssm_event_context:
  transport_valid: true
  canonical_key_hash: string
  normalizer_confidence: float
  policy_mode: string
  presence_status: string
  trust_status: canonicalized | trusted_for_recurrence
  event_embedding_lane: lane_id
  replay_identity: string
```

The runtime may compute a selective update such as:

```text
s_t = rho_t * s_{t-1} + beta_t * B_t u_t + lambda_t * m_t + eta_t * e_jump_t
```

But raw untrusted witness evidence MUST NOT directly select transition matrices, memory-write authority, lookup injection, or promotion decisions when a normal-form path exists.

Low confidence MUST NOT increase authority. L5 policy clamps dominate learned or computed gate values.

---

## 17. Full-duplex operation

Full duplex is defined as two independent directional DBP frame streams over one full-duplex transport.

```text
server -> client: downlink DBP2 frames, direction = 0
client -> server: uplink DBP2 frames, direction = 1
```

Each direction has independent:

1. sequence state;
2. replay window;
3. nonce namespace;
4. key material or direction-bound key derivation;
5. MCB2 direction value;
6. ACK of the opposite stream;
7. lane layout;
8. command sequence;
9. policy state telemetry.

A full-duplex deployment MUST NOT rely on a single half-duplex request/response frame to encode both authorities. Each writer owns the frames it emits.

---

## 18. Replay identity

Authority-bearing DBP v2 replay identity MUST include both transport bytes and semantic interpretation context.

Recommended canonical replay identity input:

```text
DBP2-REPLAY-ID-v1
wire_class
magic
version
security_profile
direction
seq_hi:seq_lo
key_epoch
nonce_or_replay_counter
semantic_profile_id
semantic_profile_version
schema_hash
normalizer_hash
family_registry_hash
transport_profile_hash
export_policy
lane_layout_hash
payload_hash
policy_mode
```

Replay identity MUST be stable for deterministic replays and MUST change when identity-affecting schema, normalizer, registry, export policy, or lane layout changes.

---

## 19. Failure behavior

DBP v2 failure outputs are explicit.

| Failure | Default action |
|---|---|
| invalid shape | reject frame |
| invalid structural integer | reject frame |
| CRC failure | reject frame |
| S1/S2 integrity failure | reject frame |
| replay failure | reject frame |
| descriptor missing for authority profile | transport_bypass |
| unknown semantic profile | transport_bypass or reject |
| unknown family | family_bypass |
| normalizer failure | family_bypass or reject |
| absence/zero collision | full_bypass for authority-bearing path |
| low confidence | clamp authority; do not increase authority |
| GCD jump raw-only | candidate only; no trusted write |

Bypass is valid behavior. A receiver should continue in the safest declared degraded mode rather than silently promoting untrusted data.

---

## 20. Conformance classes

| Class | Name | Required features |
|---|---|---|
| C0 | parser | shape, header/footer, CRC, integer-as-float |
| C1 | secure parser | C0 + S1/S2 verification and replay handling |
| C2 | v2 transport | C1 + MCB2 + lane descriptors + semantic descriptor binding |
| C3 | witness transport | C2 + Witness8/WSB2 status outputs and absence/zero distinction |
| C4 | canonical authority | C3 + family registry, normalizer, replay identity, policy clamps |
| C5 | full-duplex authority | C4 + independent directional streams and direction-bound security |

A production Duotronics integration SHOULD target C4 or C5.

---

## 21. Migration from v1.x

1. Keep v1.x parser and fixtures unchanged.
2. Add v2 magic and `DBP2-F4096` parser selection.
3. Require MCB2 for authority-bearing v2 profiles.
4. Move WSB2 from optional payload convention to registered v2 sparse witness lane.
5. Add semantic descriptor and replay identity binding.
6. Add explicit presence/trust status output states.
7. Make S2 mandatory for production semantic authority.
8. Introduce full-duplex by independent directional streams rather than overloading a single frame.
9. Treat GCD-jump and DW-SSM inputs as post-validation runtime profiles, not core wire arithmetic.

---

## 22. Minimal receiver checklist

A DBP v2 receiver MUST:

1. parse exactly 4096 bytes;
2. decode only clear structural fields before security mode resolution;
3. validate integer-as-float structural fields;
4. verify CRC and secure integrity;
5. in S2, treat cells `9..999` as opaque until AEAD verification succeeds;
6. decrypt before MCB2/lane descriptor interpretation;
7. validate MCB2 and lane descriptors;
8. bind semantic descriptor to replay identity;
9. decode Witness8/WSB2 only after transport validation;
10. preserve absence/zero/invalid distinctions;
11. run declared normalizer before trust;
12. apply policy clamps before lookup, recurrence, or promotion;
13. emit explicit failure and bypass states.

---

## 23. Minimal sender checklist

A DBP v2 sender MUST:

1. zero-fill unused structural and semantic cells according to profile;
2. set `magic=0xDB20` and `version=20` for v2 frames;
3. keep structural fields as integer-as-float carriers;
4. never witness-encode structural cells;
5. include or bind a semantic descriptor for authority-bearing payloads;
6. include direction in full-duplex profiles;
7. use direction-bound replay/nonce policy;
8. include schema/normalizer/registry/transport/export context in replay identity;
9. mark raw recurrence events as candidate until validated;
10. avoid sending authority-bearing semantics in Open mode.

---

## 24. Final boundary statement

DBP v2 is the deterministic, secure, full-duplex-capable transport substrate. Duotronics supplies the semantic mathematics, witness contract, canonicalization, registries, normalizers, recurrence rules, and policy authority. The two are complementary: DBP carries and protects the data; Duotronics decides what the data means after validation.
