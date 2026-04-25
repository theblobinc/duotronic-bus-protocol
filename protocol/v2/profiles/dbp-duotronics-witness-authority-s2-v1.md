# DBP Duotronics Witness Authority S2 Profile v1

**Profile ID:** `dbp-duotronics-witness-authority-s2-v1`  
**Wire class:** `DBP2-F4096`  
**Security:** S2 required  
**Status:** Draft recommended production profile

---

## 1. Purpose

This profile defines how DBP v2 carries authority-bearing Duotronic witness semantics.

It binds DBP transport to:

1. Witness8 row decoding;
2. WSB2 sparse witness transport;
3. DPFC object references and export policy;
4. normalizer and family registry identity;
5. replay-pinned semantic descriptor context;
6. policy-clamped authority outputs;
7. optional GCD-jump candidate gates;
8. optional DW-SSM event contexts.

DBP remains the transport boundary. Duotronics remains the semantic and trust authority.

---

## 2. Mandatory requirements

A conforming implementation MUST:

1. use `magic=0xDB20` and `version=20`;
2. use S2 authenticated encryption;
3. verify shape, structural fields, CRC, AEAD tag, replay counter, and policy gate before semantic authority;
4. carry or bind a semantic descriptor;
5. validate MCB2 when present;
6. decode Witness8 and WSB2 only after transport validation;
7. distinguish token-free absence from numeric zero;
8. run declared normalizer before trust;
9. include schema, normalizer, family registry, transport profile, export policy, and lane layout in replay identity;
10. force semantic authority to zero on failed transport or failed canonicalization.

---

## 3. Security profile

S2 is required.

Open mode may be used only for local parser tests. S1 may be used for compatibility diagnostics, but any S1 semantic payload MUST be marked non-authority unless an explicit local policy exception exists.

S2 AAD MUST bind:

```text
DBP2-F4096
magic
version
direction
seq
security trailer identity
semantic descriptor hash
lane layout hash
```

---

## 4. Semantic descriptor

The profile requires a descriptor equivalent to:

```yaml
semantic_descriptor:
  descriptor_version: dbp-semantic-descriptor@v2
  wire_class: DBP2-F4096
  dbp_profile_id: dbp-duotronics-witness-authority-s2-v1
  dbp_profile_version: 1
  security_required: S2
  payload_profiles:
    - Witness8
    - WSB2
    - DPFC-object-ref
    - gcd-jump-gate
    - dw-ssm-event
  absence_zero_policy: strict_distinction
  transport_before_semantics: true
  normal_form_before_trust: true
  failed_validation_authority: 0
  low_confidence_may_increase_authority: false
```

---

## 5. Authority computation

The receiver exports an authority envelope, not raw trust.

```yaml
authority_envelope:
  transport_valid: bool
  semantic_valid: bool
  canonicalization_result: string
  normalizer_confidence: float
  policy_mode: string
  presence_status: string
  trust_status: string
  authority: float
```

Default clamp:

```text
if not transport_valid: authority = 0
else if canonicalization_result not in {canonical_success, canonical_success_low_confidence}: authority = 0
else if policy_mode in {transport_bypass, full_bypass}: authority = 0
else authority = min(profile_requested_authority, normalizer_confidence, policy_limit)
```

Low confidence MUST NOT increase authority.

---

## 6. Witness8 policy

A Witness8 row is valid input only after:

1. transport validation;
2. explicit ordered-field decode;
3. numeric/range validation;
4. active profile match;
5. absence/zero distinction;
6. family registry lookup;
7. normalizer execution;
8. canonicalization;
9. policy gate.

All-zero Witness8 row means token-free absence, not numeric zero.

---

## 7. WSB2 policy

WSB2 is the preferred sparse witness transport.

Unset bitmap bits mean inactive rows. Inactive rows are absence, not numeric zero. Active rows must decode as Witness8 rows and pass the same validation and canonicalization path.

For production, WSB2 SHOULD be carried in an S2 `opaque_bytes` or `wsb2_sparse` lane.

---

## 8. GCD-jump candidate gate

A GCD-jump event may raise candidate update priority, but never trust by itself.

Required gate path:

```text
jump detected -> candidate event -> validation -> canonicalization -> policy -> optional authority increase
```

If canonicalization fails, authority MUST be zero even when `J_n > 1`.

---

## 9. DW-SSM output contract

This profile may produce a DW-SSM event context after canonicalization:

```yaml
dw_ssm_event_context:
  canonical_key_hash: string
  confidence: float
  policy_mode: string
  event_embedding_lane: integer
  replay_identity: string
```

Raw evidence MUST NOT select state-space matrices or memory-write strength.

---

## 10. Failure behavior

Default failure behavior:

| Condition | Action |
|---|---|
| transport fail | reject or transport_bypass |
| unknown family | family_bypass |
| normalizer error | family_bypass or reject |
| absence/zero collision | full_bypass for authority path |
| low confidence | clamp authority |
| raw GCD jump only | candidate event, no trusted write |
