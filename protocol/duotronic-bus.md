# Duotronic Bus Protocol (DBP)
**Last updated:** 2026-03-04  
**Protocol line:** v1.x (fixed-offset Float32 frame, optional polygon witness semantics)  
**Recommended version:** v1.1  
**Wire format:** IEEE 754 binary32 (single-precision float), little-endian byte order

DBP is a bi-directional multiplexed signal bus for transporting three classes of state in one frame:
- Analog (continuous floats)
- Digital (byte-packed payloads carried inside float cells)
- Quantum-inspired (probabilistic register using amplitude pairs)

It is transport-agnostic and application-agnostic. The core protocol defines shape and rules; application profiles define field semantics.

Terminology shortcut used throughout: "lattice" refers to Band 1 control floats, and "waveform" refers to Band 5 samples/digests.
These are semantic aliases only; structural vs semantic validation boundaries are defined by band ranges and security mode, not by alias terms.

---

## Contents (major sections)

- [Section 0](#0-normative-language) Normative language + quick start
- [Section 2](#2-frame-shape-v11) Frame shape and wire map
- [Section 4](#4-sync-header-band-0-cells-08) Header fields and flag semantics
- [Section 6](#6-band-specifications) Band specifications (including 6T trailer and ABB/MUX)
- [Section 8](#8-security-profiles) Security profiles (S1/S2, suites, nonce, replay)
- [Section 13](#13-receiver-validation-pipeline-normative) Receiver validation pipeline
- [Section 14](#14-sender-behavior-and-timing) Sender behavior and zero-fill policy
- [Section 16](#16-profile-registry-and-capability-negotiation) Profile contracts and hardened templates
- [Section 17](#17-conformance-test-matrix-minimum) Conformance test matrix and deterministic vectors
- [Section 28](#28-float32-precision-detailed-caveats) Integer-as-float canonical decode rules
- [Section 40](#40-reference-verifier) Reference verifier
- [Section 41](#41-wire-map-appendix-single-page-quick-reference) Wire Map Appendix / [Section 42](#42-glossary) Glossary

---

## 0) Normative language
The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are requirement levels.

### 0.1 Quick Start (implementation order)

1. Parse exactly 4096 bytes into the DBP frame model.
2. Preflight MUST canonical-decode the minimum structural mode selectors: `magic` (cell 0) and `flags_profile` (cell 7) as integer-as-float fields ([Section 28.4](#284-integer-as-float-canonical-decode-rule)).
3. Derive effective security mode from `SEC_TRAILER_PRESENT`: if clear, effective `sec_profile = 0` (Open) and Band 6T cells `1000..1019` are required sender zero-fill; if set, validate + decode the on-wire trailer `sec_profile` field (cell 1000) as u16-as-float and require `sec_profile in {1,2}` before mode-dependent numeric checks ([Section 13](#13-receiver-validation-pipeline-normative)).
4. Run a cheap footer sanity precheck early: validate `byte_size` (cell 1022) and `magic_echo` (cell 1023) before expensive checks.
5. Run pre-crypto validity checks (finite/subnormal per mode + structural integer-as-float checks + header time/range checks), then verify frame CRC over `bytes[0..4079]`.
6. Enforce security policy gate; if secure mode, verify anti-replay + S1 HMAC or S2 AEAD tag over raw received wire bytes (do not normalize values first).
7. In S2 mode, decrypt cells `9..999`, then run post-decrypt numeric checks (including authenticated `opaque_bytes` exclusions if active).
8. Decode only validated bands and apply profile logic.

Canonical integer-as-float decode (normative inline rule for all structural u16/u24 fields used above):
- Reject `NaN` and `Infinity`.
- Reject subnormal values.
- Treat `+0.0` as zero; treat `-0.0` as zero in compatibility mode. Hardened classes (`dbp-hardened-v1`, `dbp-hardened-s2-mux`) MUST reject `-0.0` in structural integer fields (Bands `0`, `6T`, and `7`).
- Require integer value (`x == trunc(x)`).
- Require range: `0..65535` for u16-as-float, `0..16777215` for u24-as-float.
- Exactness guard: decoders MUST verify decoded integers round-trip exactly through Float32 conversion (`Float32(trunc(x)) == x`).

Core constants: `DBP_CELLS=1024`, `DBP_BYTES=4096`, `S1 MAC input = mac_domain_tag || bytes[0..4015]` (`bytes[0..4015]` is 4016 bytes; total MAC input length is `tag_len + 4016`), `CRC input = 4080 bytes: bytes[0..4079]`.

Minimal decoder MUST/SHOULD summary:
- MUST: enforce shape, early footer sanity precheck, structural integer checks, CRC, and S1/S2 verification before band decode.
- MUST: in S2, treat `bytes[36..3999]` as opaque until AEAD verification + decryption completes.
- MUST: emit stable reject codes per [Section 13.2](#132-security-reject-code-registry-normative); SHOULD emit telemetry counters for validation failures.

### 0.1.1 Minimum Viable Decoder Checklist

1. Parse exactly 4096 bytes; decode Float32 only for cleartext structural cells (`0..8`, `1000..1023`) until S2 decrypt succeeds.
2. Enforce exact frame length: 4096 bytes.
3. Preflight-decode `magic` (cell 0) and `flags_profile` (cell 7) as integer-as-float.
4. Derive effective security mode from `SEC_TRAILER_PRESENT`; validate trailer field `sec_profile` (cell 1000) only when trailer is present.
5. Run footer sanity precheck (`byte_size`, `magic_echo`).
6. Run mode-dependent numeric checks (NaN/Inf/subnormal policy and structural integer-as-float fields).
7. Verify CRC over `bytes[0..4079]`.
8. If secure mode, enforce policy gate and verify S1/S2 authenticity before accepting payload semantics.
9. In S2, decrypt `cells[9..999]` only after AEAD verification, then run post-decrypt checks.
10. Canonicalize optional downstream values only after integrity verification succeeds.

### 0.2 Core validation rules (normative summary)

The following shared rules apply across receiver pipeline, security validation, and sender hygiene sections:

1. Derive effective mode from `SEC_TRAILER_PRESENT` first:
    - Preflight MUST canonical-decode `magic` (cell 0) and `flags_profile` (cell 7) before selecting mode-dependent numeric scope.
    - `SEC_TRAILER_PRESENT = 0` => effective `sec_profile = 0` (Open), full-frame numeric checks apply.
    - `SEC_TRAILER_PRESENT = 1` => validate/decode trailer field cell 1000 (`sec_profile`) as u16-as-float and require `sec_profile in {1,2}` before selecting S1/S2 numeric scope.
2. In S2, cells `9..999` are treated as opaque wire bytes until AEAD verification + decryption succeeds; numeric checks for that region apply to decrypted plaintext.
3. Band 6T integer-as-float checks include all trailer cells `1000..1019` (including all 16 `sec_words` cells) whenever `SEC_TRAILER_PRESENT = 1`.
4. MAC/CRC always operate over canonical wire bytes, not host-native float reinterpretations.

### 0.3 Interoperability Summary (one-page cheat sheet)

| Item | Required value/behavior |
|------|-------------------------|
| Frame size | `4096` bytes (`1024` Float32 cells) |
| Endianness | little-endian IEEE 754 binary32 |
| Parser split | `magic=0xDB01` (v1.0) or `0xDB11` (v1.1) |
| Footer constants | `byte_size=4096`, `magic_echo==magic` |
| Frame CRC scope | bytes `0..4079` (cells `0..1019`) |
| S1 MAC scope | `mac_domain_tag || bytes[0..4015]` |
| S2 AAD scope | cells `0..8`, then `1000..1003`, then `1018..1019` |
| S2 ciphertext scope | cells `9..999` (bytes `36..3999`) |
| S2 nonce | `nonce96` from `sec_words[0..5]` (12 bytes, direct AEAD nonce) |
| Validation order | shape -> preflight/mode select -> structural checks -> numeric pre-crypto checks -> CRC -> policy gate -> MAC/AEAD -> decrypt (S2) -> numeric post-decrypt checks -> band decode |

Interoperability rationale (normative intent): deterministic numeric-class handling, fixed integrity scopes, and stable reject/event naming reduce parser divergence, downgrade ambiguity, and CPU-amplification abuse paths.

### 0.4 Wire Map (single-page quick reference)

This front-loaded wire map is an implementation convenience mirror of [Section 41](#41-wire-map-appendix-single-page-quick-reference).

| Region | Cells | Bytes | Structural or semantic | S2 wire visibility |
|------|------:|------:|------------------------|--------------------|
| Band 0 (header) | `0..8` | `0..35` | Structural | Cleartext |
| Band 1 (lattice) | `9..19` | `36..79` | Semantic | Ciphertext |
| Band 2 (Digital A) | `20..83` | `80..335` | Semantic | Ciphertext |
| Band 3 (Digital B) | `84..147` | `336..591` | Semantic | Ciphertext |
| Band 4 (quantum) | `148..275` | `592..1103` | Semantic | Ciphertext |
| Band 5 (waveform/digest) | `276..659` | `1104..2639` | Semantic | Ciphertext |
| Band 6 (client slot / MUX) | `660..999` | `2640..3999` | Semantic/profile-structural | Ciphertext |
| Band 6T (security trailer) | `1000..1019` | `4000..4079` | Structural | Cleartext |
| Band 7 (footer) | `1020..1023` | `4080..4095` | Structural | Cleartext |

Integrity scopes (exact): see canonical definitions in [Section 0.5.1](#051-canonical-byte-scopes).

### 0.5 Canonical Normative Sources (single source of truth)

The following subsections are the canonical source of truth for interoperability-sensitive rules. Later sections MUST reference these definitions and MUST NOT redefine semantics with different meaning.

#### 0.5.1 Canonical byte scopes

- Frame CRC input: `bytes[0..4079]` (cells `0..1019`).
- S1 MAC input: `mac_domain_tag || bytes[0..4015]` (cells `0..1003`).
- S1 MAC domain tag default: `mac_domain_tag = "DBP-S1\0"` encoded as bytes `44 42 50 2D 53 31 00` (length 7). Profiles MAY override with a fixed non-empty byte string.
- `mac_domain_tag` MUST be handled as a counted byte string (pointer + explicit length). The embedded `0x00` byte is part of the tag; NUL-terminated string handling MUST NOT be used.
- S2 AAD input (exact order): `bytes(cells[0..8]) || bytes(cells[1000..1003]) || bytes(cells[1018..1019])`.
- S2 ciphertext input: `bytes(cells[9..999])`.

#### 0.5.2 Numeric class policy (canonical matrix)

Float classes: `normal finite`, `+/-0.0`, `subnormal`, `NaN/Inf`.

| Region | Open/S1 pre-accept | S2 pre-decrypt | S2 post-decrypt |
|--------|---------------------|----------------|-----------------|
| Band 0 header (`0..8`) | normal finite/+/-0.0 allowed; `subnormal` and `NaN/Inf` reject | same as Open/S1 | n/a |
| Band 1 analog (`9..19`) | normal finite/+/-0.0 allowed; `subnormal` and `NaN/Inf` reject | opaque ciphertext bytes (do not float-validate) | apply Open/S1 rule on decrypted plaintext |
| Band 2/3 digital (`20..147`) | integer-as-float fields must pass [Section 28.4](#284-integer-as-float-canonical-decode-rule); `subnormal` and `NaN/Inf` reject | opaque ciphertext bytes | apply Open/S1 rule on decrypted plaintext |
| Band 4 quantum (`148..275`) | normal finite/+/-0.0 allowed + normalization policy; `subnormal` and `NaN/Inf` reject | opaque ciphertext bytes | apply Open/S1 rule on decrypted plaintext |
| Band 5 waveform (`276..659`) | normal finite/+/-0.0 allowed; `subnormal` and `NaN/Inf` reject | opaque ciphertext bytes | apply Open/S1 rule on decrypted plaintext |
| Band 6 client/MUX (`660..999`) | normal finite/+/-0.0 allowed; integer subfields must pass [Section 28.4](#284-integer-as-float-canonical-decode-rule) when consumed | opaque ciphertext bytes | apply Open/S1 rule on decrypted plaintext (except authenticated `opaque_bytes` slices) |
| Band 6T trailer (`1000..1019`) | integer-as-float structural fields, `subnormal` and `NaN/Inf` reject when trailer-present | same as Open/S1 (cleartext structural) | n/a |
| Band 7 footer (`1020..1023`) | integer-as-float structural fields, `subnormal` and `NaN/Inf` reject | same as Open/S1 (cleartext structural) | n/a |

Definitive `-0.0` boundary: `-0.0` MAY appear as a semantic float value, but in hardened classes it is forbidden for all structural integer-as-float fields (see [Section 28.4.1](#2841-strict-00-profile-behavior-for-structural-integer-fields)).

#### 0.5.3 Integer-as-float canonical decode

All structural integer-as-float fields MUST use the canonical decode algorithm in [Section 28.4](#284-integer-as-float-canonical-decode-rule), including strict/permissive `-0.0` behavior from [Section 28.4.1](#2841-strict-00-profile-behavior-for-structural-integer-fields).

---

## 1) Design goals and constraints

### Goals
- Constant-time decoding from fixed offsets
- Multiplexing by position (bands)
- Stable frame size for predictable performance
- Zero-allocation fast path for hot loops
- Profile-driven semantics so one core can serve many applications

### Non-goals
- Actual quantum transport or quantum networking
- Security without explicit cryptographic keys
- Infinite extensibility inside Float32 without tradeoffs

### Hard constraints
- Endianness is little-endian on wire
- Wire serialization is exactly 4096 bytes: 1024 consecutive IEEE 754 binary32 values in little-endian order, with no padding or alignment bytes.
- Numeric validity is mode-dependent:
    - Open/S1 (`sec_profile != 2`): valid frames MUST NOT contain `NaN`, `Infinity`, or subnormal Float32 values.
    - S2 (`sec_profile = 2`): cells `9..999` are treated as opaque ciphertext bytes on wire until AEAD verification + decryption; numeric validity for that region MUST be enforced on the decrypted plaintext.
- All integers `0..16,777,215` (`2^24 - 1`) are exactly representable per u24 cell. `2^24` itself is representable, but not every integer above it is exact in Float32.

Byte interval notation used in this specification:
- `bytes[a..b]` means an inclusive byte interval (includes both `a` and `b`).
- `cells[a..b]` means an inclusive cell interval (includes both `a` and `b`).
- `[a, b)` denotes a half-open interval (includes `a`, excludes `b`) when explicitly used.
- Canonical notation is bracketed (`bytes[a..b]`, `cells[a..b]`). Unbracketed forms like `bytes a..b` or `cells a..b` are legacy shorthand and SHOULD NOT appear in new normative text.
- Legacy dotted shorthand like `a.b` MUST be interpreted as `a..b`; it SHOULD NOT appear in new text.
- `cell i` corresponds to `bytes[4*i .. 4*i+3]` (little-endian Float32 wire encoding).

---

## 2) Frame shape (v1.1)

A DBP frame is **4096 wire bytes**.

- In Open/S1, the full frame may be interpreted as `Float32Array(1024)`.
- Structural integer fields remain Float32 numeric carriers and MUST be canonical-decoded per [Section 28.4](#284-integer-as-float-canonical-decode-rule); they are not bit-cast integer lanes.
- In S2, cells `9..999` are opaque ciphertext on wire; Float32 interpretation for that region occurs only after successful AEAD verification + decryption.

**S2 decoding safety rule (normative):** In S2, implementations MUST treat `bytes[36..3999]` (cells `9..999`) as an opaque byte slice and MUST NOT interpret that byte range as Float32 until after AEAD verification + decryption succeeds.

```
Band 0:   cells[0..8]         SYNC HEADER                 9 cells     36 bytes
Band 1:   cells[9..19]        ANALOG CONTROL LATTICE     11 cells     44 bytes
Band 2:   cells[20..83]       DIGITAL CHANNEL A          64 cells    256 bytes
Band 3:   cells[84..147]      DIGITAL CHANNEL B          64 cells    256 bytes
Band 4:   cells[148..275]     QUANTUM REGISTER          128 cells    512 bytes
Band 5:   cells[276..659]     ANALOG WAVEFORM/DIGEST    384 cells   1536 bytes
Band 6:   cells[660..999]     CLIENT SLOT               340 cells   1360 bytes
Band 6T:  cells[1000..1019]   SECURITY TRAILER           20 cells     80 bytes
Band 7:   cells[1020..1023]   FRAME CHECK                 4 cells     16 bytes
--------------------------------------------------------------------------
Total:    1024 cells = 4096 bytes
```

### 2.1 Offsets at a glance (implementation quick reference)

| Region | Cells | Required checks before use |
|--------|-------|----------------------------|
| Header (Band 0) | `0..8` | finite + integer-as-float ([Section 28.4](#284-integer-as-float-canonical-decode-rule)), magic/version/time ranges |
| Digital A (Band 2) | `20..83` | Open/S1: if `HAS_DIGITAL_A`, header u16/u24 checks + payload u24 checks; S2: check after decrypt |
| Digital B (Band 3) | `84..147` | Open/S1: if `HAS_DIGITAL_B`, header u16/u24 checks + payload u24 checks; S2: check after decrypt |
| Quantum (Band 4) | `148..275` | Open/S1: finite + normalization policy ([Section 6.3](#63-band-4-quantum-register-cells148275)/[Section 22.9](#229-normalization-enforcement)); S2: check after decrypt |
| Client Slot (Band 6) | `660..999` | Open/S1: apply [Section 28.4](#284-integer-as-float-canonical-decode-rule) to integer fields if consumed; S2: apply after decrypt |
| Security trailer (Band 6T) | `1000..1019` | only if `SEC_TRAILER_PRESENT`; else required sender zero-fill (`+0.0`) |
| Footer (Band 7) | `1020..1023` | integer-as-float checks + footer sanity + CRC |

Policy defaults and profile-level override points are summarized in [Section 16.1](#161-normative-defaults-vs-profile-overrides).

---

## 3) Versioning and parser selection

### Magic-based version detection

| Version | magic (dec) | magic (hex) |
|--------:|------------:|------------:|
| v1.0    | 56065       | `0xDB01`    |
| v1.1    | 56081       | `0xDB11`    |

Clients MUST select parser from cell 0 (`magic`) and reject unknown values.

In v1.1+, `version` is advisory metadata only. Binary layout selection MUST use `magic` only and MUST NOT depend on `version`.

```js
// decodeU16 enforces the canonical integer-as-float decode rule (Section 28.4)
const magic = decodeU16(frame[0]);
if (magic === 0xDB01) parseV10(frame);
else if (magic === 0xDB11) parseV11(frame);
else reject(frame);
```

---

## 4) Sync header (Band 0, cells[0..8])

| Cell | Name            | Type         | Meaning |
|----:|------------------|--------------|---------|
| 0   | `magic`          | u16-as-float | protocol magic (`0xDB11`) |
| 1   | `version`        | u16-as-float | compact semantic version (`major*10 + minor`, e.g. `11`; not general SemVer). Major and minor MUST each be single-digit (0-9). |
| 2   | `seq_lo`         | u24-as-float | frame sequence low part |
| 3   | `seq_hi`         | u24-as-float | frame sequence high part |
| 4   | `unix_day`       | u24-as-float | floor(unix_sec / 86400) |
| 5   | `sec_of_day`     | u24-as-float | unix_sec % 86400 |
| 6   | `ms`             | u24-as-float | 0..999 |
| 7   | `flags_profile`  | u24-as-float | `(profile_id << 16) | flags16` |
| 8   | `tick_rate`      | u16-as-float | frames per second (0..65535; 0 = paused/unspecified) |

### `version` and `tick_rate` decoding

```js
const ver   = decodeU16(frame[1]);             // e.g. 11 (Section 28.4)
const major = Math.floor(ver / 10);           // 1
const minor = ver % 10;                       // 1
const fps   = decodeU16(frame[8]);             // e.g. 2, 30, 120, 240
```

`major*10 + minor` is intentionally constrained in v1.x (single-digit major/minor), so values like `1.10` are out of scope for this encoding and require a future versioning scheme.

### `flags_profile` decoding

```js
const fp        = decodeU24(frame[7]);         // u24-as-float (Section 28.4)
const flags16   = fp & 0xFFFF;                 // lower 16 bits
const profileId = (fp >>> 16) & 0xFF;          // upper 8 bits
// Bitwise ops are safe here because fp is <= 0xFFFFFF (fits in 24 bits).
```

### `flags_profile` wire layout (normative)

`flags_profile` is a `u24-as-float` field with this fixed bit layout:

| u24 bits | Full mask (`fp`) | Field | Encoding |
|---|---|---|---|
| `0..15` | `0x00FFFF` | `flags16` | low 16-bit flag bitset |
| `16..23` | `0xFF0000` | `profile_id` | high 8-bit profile identifier |

Authoritative extraction rules:
- `flags16 = fp & 0x00FFFF`
- `profile_id = (fp & 0xFF0000) >>> 16`
- `SEC_TRAILER_PRESENT` test: `(fp & 0x000020) != 0`

`tick_rate` is stored as a plain u16 with no packing - supporting rates up to 65535 FPS without encoding tricks.

**`tick_rate` range:** `tick_rate in [0..65535]`.

**`tick_rate = 0`:** means "paused or unspecified." Writers that cannot or do not report frame rate MUST use 0. Receivers MUST NOT divide by `tick_rate` without checking for zero first.

**Advisory semantics:** `tick_rate` is advisory - it declares the sender's intended publishing cadence but does not obligate receivers to synchronize to it. Timing-sensitive consumers MAY use it for interpolation or drift detection but MUST tolerate jitter.

### Standard flags (lower 16 bits)
Bit numbering in this table is relative to `flags16` (the low 16 bits of `flags_profile`).

| Bit | `flags16` mask | Name | Status | Meaning |
|---:|---|---|---|---|
| 0 | `0x0001` | `HAS_DIGITAL_A` | normative | Band 2 contains a valid message |
| 1 | `0x0002` | `HAS_DIGITAL_B` | normative | Band 3 contains a valid message |
| 2 | `0x0004` | `HAS_WAVEFORM` | normative | Band 5 carries waveform/digest |
| 3 | `0x0008` | `WAVEFORM_IS_FFT32` | normative | Band 5 starts with FFT32 digest |
| 4 | `0x0010` | `HAS_RESPONSE` | reserved legacy | v1.1 senders MUST write `0`, receivers MUST ignore |
| 5 | `0x0020` | `SEC_TRAILER_PRESENT` | normative | Band 6T is populated |
| 6..15 | `0xFFC0` | reserved | reserved | future use |

**Reserved-bit rule:** Senders MUST write all reserved flag bits as `0`. Receivers MUST ignore reserved/unknown bits (do not reject frames based on them). This applies to `flags_profile` bits 6-15, `msg_flags`, and any future bitfields.

### Reserved-term boundaries (normative)
- **Reserved bits** (inside a defined bitfield): senders MUST write `0`; receivers MUST ignore non-zero unknown/reserved bit values for forward compatibility.
- **Reserved cells** (whole cells declared "MUST be zero" by profile/class rules): hardened receivers MUST reject non-zero values (recommended code: `E_RESERVED_POLICY`).

**Flag coherence rules (normative):** The following inter-flag dependencies MUST be enforced by senders and checked by receivers:
- If `WAVEFORM_IS_FFT32` is set, `HAS_WAVEFORM` MUST also be set. A receiver that sees `WAVEFORM_IS_FFT32` without `HAS_WAVEFORM` MUST treat `WAVEFORM_IS_FFT32` as unset.
- If `SEC_TRAILER_PRESENT` is set, trailer field cell 1000 (`sec_profile`) MUST decode to a supported secure mode (`1` or `2`); frames violating this are rejected per [Section 8](#8-security-profiles).
- If `HAS_DIGITAL_A` or `HAS_DIGITAL_B` is set, then `chunk_total >= 1`, `chunk_index < chunk_total`, and `payload_len` MUST satisfy the profile's zero-length policy ([Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147)). Frames that assert the flag but fail these checks are invalid per [Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147).

---

## 5) Profiles (core vs semantics)

DBP core defines structure and encoding. Profiles define meaning.

- `profile_id = 0`: DBP-Core only (generic)
- `profile_id = 1..255`: application-specific profiles

`profile_id` is 8-bit by design in v1.x. Expanding beyond 255 profiles is a v2.0 concern.

Clients MAY decode generic channels from unknown profiles but MUST NOT issue profile-specific commands unless profile is supported.

---

## 6) Band specifications

### 6.1 Band 1 - Analog Control Channels (Band-1 lattice, cells[9..19])
11 continuous channels (`a0..a10`) reserved for profile semantics.

### 6.2 Bands 2 & 3 - Digital Channels A/B (cells[20..83], cells[84..147])
Each channel has:
- 8-cell message header
- 56-cell payload

Header fields (all integer fields are stored as integer-as-float and MUST satisfy [Section 28.4](#284-integer-as-float-canonical-decode-rule)):

| Offset | Field | Type | Meaning |
|------:|-------|------|---------|
| 0 | `msg_type` | u16-as-float | profile-defined type |
| 1 | `msg_flags` | u16-as-float | bitfield |
| 2 | `msg_id` | u24-as-float | message correlation id |
| 3 | `chunk_index` | u16-as-float | 0..N-1 |
| 4 | `chunk_total` | u16-as-float | total chunks |
| 5 | `payload_len` | u16-as-float | bytes in this chunk |
| 6 | `payload_crc_lo` | u16-as-float | CRC32 low 16 |
| 7 | `payload_crc_hi` | u16-as-float | CRC32 high 16 |

Payload packing is 3 bytes per cell (`u24` exact in Float32):

```text
cell = b0 + (b1 << 8) + (b2 << 16)
```

Normative: digital payload bytes are a logical expansion of the decoded u24 integer value in each payload cell, not the raw IEEE-754 bytes of the Float32 cell.

When expanding payload cells to bytes for CRC32/reassembly, bytes MUST be interpreted in little-endian byte order `[b0, b1, b2]` per cell.

Digital payload CRC scope (normative): `payload_crc_lo/hi` is CRC32/ISO-HDLC over the first `payload_len` bytes of the logical payload byte stream after u24->bytes expansion.

Digital CRC recombination rule (normative):

$$
\operatorname{payload\_crc32} = \operatorname{payload\_crc\_lo} + \operatorname{payload\_crc\_hi} \times 2^{16}
$$

(i.e. `payload_crc_lo + payload_crc_hi * 65536`).

Digital message validity (normative): when `HAS_DIGITAL_A` or `HAS_DIGITAL_B` is set, receivers MUST consider a channel message valid only if all of the following hold:
- `chunk_total >= 1`
- `chunk_index < chunk_total`
- `payload_len` is in `[1..168]`, unless the profile explicitly defines a zero-length message type
- payload tail zero rules from [Section 15](#15-digital-chunk-reassembly-contract) are satisfied
- `payload_crc_lo/hi` matches CRC32/ISO-HDLC over exactly the first `payload_len` payload bytes

If profile policy allows `payload_len == 0`, `payload_crc_lo/hi` MUST equal CRC32/ISO-HDLC of the empty byte string.

Payload tail bytes/cells that violate [Section 15](#15-digital-chunk-reassembly-contract) zero rules are invalid even if `payload_crc_lo/hi` matches.

If `HAS_DIGITAL_A` (or `HAS_DIGITAL_B`) is set but that channel fails [Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147)/[Section 15](#15-digital-chunk-reassembly-contract) validation, receivers MUST apply `digital_invalid_policy` ([Section 16](#16-profile-registry-and-capability-negotiation)):
- `ignore_channel` (default): treat that channel as absent for the frame and MUST NOT act on it.
- `reject_frame`: reject the full frame (recommended code: `E_DIGITAL_INVALID`).
- Receivers SHOULD increment a `digital_invalid` counter in either case.

**Numeric validity scope:** Digital header and payload cells are subject to the global numeric validity rule (finite + no subnormals) in addition to integer range checks ([Section 13](#13-receiver-validation-pipeline-normative)).

Base capacity (without adaptive borrowing):
- 56 cells x 3 bytes = 168 bytes per channel
- Two channels = 336 bytes per frame

Profiles MAY increase effective digital capacity using adaptive band borrowing ([Section 6.8](#68-adaptive-band-borrowing-abb-profile-extension-v11-compatible)).

### 6.3 Band 4 - Quantum Register (cells[148..275])
- 128 cells = 64 qubits
- Each qubit uses `[alpha, beta]`
- `alpha` and `beta` are on-wire Float32 values (little-endian IEEE 754 single-precision in their cells).
- Normalization MUST hold: $|\alpha^2 + \beta^2 - 1| \leq \varepsilon$ (recommended $\varepsilon = 10^{-4}$ for Float32). Writers MUST normalize before writing.
- Normalization checks SHOULD be evaluated with Float32-aware tolerance/rounding (for example `Math.fround`-based arithmetic in JS).
- Amplitude sign convention MUST be profile-defined:
    - `nonnegative` (default): writers SHOULD encode `alpha, beta >= 0` for probability-only semantics.
    - `signed-semantic`: sign MAY carry additional profile meaning and MUST be interpreted consistently by all participants.
- Reader policy MUST be profile-defined as one of `{reject | renormalize | clamp+renormalize}` for qubits violating normalization. Normalization violations indicate a non-conformant writer; readers MAY recover per profile policy for robustness.
- Optional numeric hygiene: if `|alpha|` or `|beta|` slightly exceeds `1` due to numeric drift, writers MAY clamp into `[-1, 1]` and then renormalize.
- If subnormal flushing changes a qubit's amplitudes, writers MUST renormalize the pair before publish (or apply the profile's writer-side `clamp+renormalize` policy).

**Wire conformance (core):** Quantum-band cells MUST satisfy the global numeric validity rule (finite + no subnormals), and writers/readers MUST apply the profile-declared normalization policy.

**Interpretation-only semantics (non-wire conformance):** Collapse, entanglement propagation behavior, freshness, and observation semantics are profile interpretation rules ([Section 22](#22-quantum-register-detailed-specification)) and are not directly verifiable from wire bytes alone.

Scalar extraction rule:
- `p = beta^2` (probability of observing `|1>`)

Measurement rule:
- returns 1 with probability `beta^2`
- returns 0 with probability `alpha^2`

Entanglement rule (profile interpretation rule):
- Single-hop correlation only
- A<->B MAY influence B on collapse
- A<->B<->C MUST NOT auto-cascade from A to C

These are profile-level interpretation semantics, not core wire-level conformance checks, unless a profile defines an explicit on-wire entanglement map.

Core interoperability recommendation:
- Reserve qubit 62 for freshness
- Reserve qubit 63 for observation density/count mapping

### 6.4 Band 5 - Analog Waveform / Digest (cells[276..659])
Modes:
- Waveform mode: 384 sample floats
- FFT32 digest mode: first 32 cells used as spectral digest
- In FFT32 digest mode, writers SHOULD zero-fill cells `308..659` for deterministic diffs and encoder parity.
- Open/S1 numeric policy warning: values in the Float32 subnormal range are flushed to `+0.0` on wire ([Section 14.3](#143-zero-fill-policy)), so ultra-low-amplitude samples are quantized away unless the profile uses scaled encoding/digest semantics.

Bandwidth guidance:
- If signal has not changed materially, writer SHOULD clear `HAS_WAVEFORM` and zero-fill Band 5
- Readers SHOULD reuse last valid waveform/digest when flag is not set

### 6.5 Band 6 - Client Slot (cells[660..999])
Recommended generic layout:

Band 6 is generally semantic/application payload, but in hardened MUX profiles it is also profile-structural because the fixed MCB (`660..683`) controls authenticated lease interpretation.

All integer fields in Band 6 are stored as integer-as-float and MUST satisfy [Section 28.4](#284-integer-as-float-canonical-decode-rule).

| Offset | Name | Type | Meaning |
|------:|------|------|---------|
| 0 | `client_kind` | u16-as-float | client class |
| 1 | `client_id_lo` | u16-as-float | stable id low |
| 2 | `client_id_hi` | u16-as-float | stable id high |
| 3 | `last_seq_lo` | u24-as-float | last downlink seq low |
| 4 | `last_seq_hi` | u24-as-float | last downlink seq high |
| 5 | `cmd_seq` | u24-as-float | monotonic command counter |
| 6 | `cmd_id` | u16-as-float | command identifier |
| 7..30 | `cmd_params` | float | profile-defined |
| 31..339 | reserved | - | future |

`cmd_seq` is a 24-bit unsigned counter modulo $2^{24}$. Writers and receivers that use `cmd_seq` ordering MUST compare it with modular arithmetic (serial-number arithmetic, RFC 1982 style, with $M = 2^{24}$), or rotate session identity (`client_id`) before wrap.

Broadcast downlink rule:
- In shared downlink frames, Band 6 MUST be zero-filled unless an ABB-enabled profile explicitly leases Band 6 slices per [Section 6.8](#68-adaptive-band-borrowing-abb-profile-extension-v11-compatible).
- In per-client downlink frames (non-broadcast), Band 6 MAY carry profile-defined per-client state.

### 6.6 Band 6T - Security Trailer (cells[1000..1019])

Band 6T is a distinct trailer band, not a subrange of Band 6.

All integer fields in Band 6T are stored as u16-as-float and MUST satisfy [Section 28.4](#284-integer-as-float-canonical-decode-rule).

| Cell(s) | Name | Type | Meaning |
|-------:|------|------|---------|
| 1000 | `sec_profile` | u16-as-float | Trailer security profile selector; meaningful only when `SEC_TRAILER_PRESENT=1` (`1=S1`, `2=S2`) |
| 1001 | `key_id` | u16-as-float | active key/session id |
| 1002 | `sec_counter_lo` | u16-as-float | anti-replay low |
| 1003 | `sec_counter_hi` | u16-as-float | anti-replay high |
| 1004..1019 | `sec_words[0..15]` | u16-as-float | security payload when trailer is present (layout depends on `sec_profile`) |

Counter-source clarification (normative):
- S1 uses `sec_counter = sec_counter_lo + sec_counter_hi * 65536` as the canonical replay counter.
- S2 suites that use `nonce96 = session_salt32 || sec_counter64_le` use `ctr64 = LE_U64(nonce96[4..11])` as the canonical replay counter source.
- In those S2 suites, `sec_counter_lo/hi` MUST mirror `ctr64` low 32 bits for telemetry/back-compat and MUST NOT be used as the sole replay source.

`sec_profile` trailer contract clarification (normative):
- If `SEC_TRAILER_PRESENT = 0`, effective `sec_profile = 0` (Open), the on-wire trailer field in cell 1000 is not interpreted as a profile selector, and cells `1000..1019` MUST be written as `+0.0`.
- If `SEC_TRAILER_PRESENT = 1`, cell 1000 is interpreted as trailer `sec_profile` and receivers MUST require `sec_profile in {1,2}`; any other value (including `0`) MUST be rejected as `E_SEC_PROFILE`.

**S1 trailer packing rule (`sec_profile = 1`):** The raw HMAC output bytes `tag_bytes[0..31]` are packed into 16 u16 words in **little-endian** order:

```
tag_u16[i] = tag_bytes[2*i] | (tag_bytes[2*i + 1] << 8)
```

Each `tag_u16[i]` is stored as a u16-as-float in cells 1004 through 1019.

**S2 trailer packing rule (`sec_profile = 2`):** `sec_words[0..15]` is split as:
- `sec_words[0..5]`: `nonce96` (12-byte string; if constructed from integer fields, those fields MUST be serialized little-endian)
- `sec_words[6..13]`: `aead_tag128` (16 bytes)
- `sec_words[14..15]`: reserved in base S2; MUST be `0` unless explicitly assigned by negotiated profile class (for example `dbp-hardened-s2-mux`)

S2 nonce packing (normative): `nonce96` is a 12-byte string `nonce_bytes[0..11]` packed into 6 u16 words in little-endian order:

```
nonce_u16[i] = nonce_bytes[2*i] | (nonce_bytes[2*i + 1] << 8)    // i = 0..5
```

and stored as u16-as-float in `sec_words[0..5]`.

S2 tag packing (normative): `aead_tag128` bytes `tag_bytes[0..15]` are packed in little-endian order:

```
tag_u16[i] = tag_bytes[2*i] | (tag_bytes[2*i + 1] << 8)          // i = 0..7
```

and stored as u16-as-float in `sec_words[6..13]`.

**Hardened S2 suite extension (`profile_class = dbp-hardened-s2-mux`):**
- `sec_words[14]`: `suite_id` (u16-as-float)
- `sec_words[15]`: `key_epoch` (u16-as-float, monotonic per writer identity)
- In this profile class, `sec_words[14..15]` MUST be non-reserved and MUST be validated as part of trailer semantics.
- In all other profile classes, `sec_words[14..15]` remain reserved and MUST be `0`; receivers MUST reject non-zero values (`E_RESERVED_POLICY` or profile-equivalent).
- In S2, `sec_words[14..15]` are policy-binding trailer fields and are authenticated via AAD coverage ([Section 8](#8-security-profiles)). Any tampering MUST cause AEAD verification failure.

Precedence rule (normative): if and only if `profile_class == dbp-hardened-s2-mux`, cells `1018..1019` are interpreted as `suite_id/key_epoch`. Otherwise, cells `1018..1019` are reserved and MUST be `0`; any non-zero value MUST be rejected as `E_RESERVED_POLICY`.

`key_epoch` defaulting rule: for profiles that do not carry explicit `key_epoch`, receivers MUST treat `key_epoch = 0` for replay/nonce partitioning and sticky-policy state.

Receiver validation note (normative): when `SEC_TRAILER_PRESENT = 1`, receivers MUST apply u16-as-float canonical checks ([Section 28.4](#284-integer-as-float-canonical-decode-rule)) to all Band 6T cells `1000..1019`, including all 16 `sec_words` cells, before interpreting trailer semantics.

### 6.7 Band 7 - Frame Check (cells[1020..1023])

| Cell | Field | Type | Meaning |
|----:|-------|------|---------|
| 1020 | `crc_lo` | u16-as-float | CRC32 low - cells[0..1019] (bytes[0..4079]) |
| 1021 | `crc_hi` | u16-as-float | CRC32 high - cells[0..1019] (bytes[0..4079]) |
| 1022 | `byte_size` | u16-as-float | MUST be 4096 (total wire frame size including all bands 0-7) |
| 1023 | `magic_echo` | u16-as-float | MUST equal header `magic` |

CRC32 detects accidental corruption; it is not a cryptographic security primitive.

**CRC flavor (normative):** All CRC32 values in DBP (frame-level Band 7 and digital-channel payload CRC) use **CRC-32/ISO-HDLC** (a.k.a. Ethernet / ZIP CRC32): polynomial `0x04C11DB7`, init `0xFFFFFFFF`, xorout `0xFFFFFFFF`, reflected input and output. **Check value:** `CRC32("123456789") = 0xCBF43926`.

Band 7 clarification (normative): Band 7 fields are not covered by frame CRC; they are verified by direct equality checks.

### 6.8 Adaptive Band Borrowing (ABB) profile extension (v1.1-compatible)

ABB allows profiles to reuse logically unused donor bands for additional payload lanes while preserving the fixed 1024-cell frame shape.

ABB goals:
- Increase bidirectional digital throughput when some bands are idle.
- Support variable analog/digital/quantum mix per frame.
- Preserve core interoperability and wire compatibility.

**Core compatibility rule:** ABB MUST NOT change frame length, cell offsets, endian rules, or Band 7 behavior. ABB is a profile-level interpretation overlay only.

#### 6.8.1 Donor bands and borrow eligibility

Profiles MAY designate any of the following donor bands:
- Band 4 (`148..275`) when quantum payload is disabled by profile policy for that frame/session.
- Band 5 (`276..659`) when `HAS_WAVEFORM = 0` and waveform/digest is not present.
- Band 6 (`660..999`) when not needed for per-client state in that direction.

A donor band is borrow-eligible only when all donor preconditions are true and the donor's native semantics are inactive for that frame.

For `dbp-hardened-s2-mux`, donor preconditions MUST be explicit in authenticated (decrypted) MCB metadata:
- If donor band is 4 (quantum), slice `flags8` MUST declare `quantum_inactive=1` for that frame, or the slice is invalid.
- If donor band is 5 (waveform), receivers MUST also verify native inactivity (`HAS_WAVEFORM=0`) in addition to MCB flags.

#### 6.8.2 Borrow manifest (normative)

Every ABB frame MUST provide an authenticated manifest describing borrowed slices. The manifest MUST be carried in a profile-defined location and MUST be covered by S1/S2 integrity protection.

Manifest placement MUST be in an always-authenticated region:
- S1: in bytes covered by HMAC (`bytes[0..4015]`).
- S2: either in cleartext AAD-covered metadata (cells `0..8`, `1000..1003`, and/or `1018..1019`) or in ciphertext-covered region (`cells[9..999]`) validated after decrypt. Cells `1018..1019` MAY be used for manifest metadata only in profile classes that explicitly allocate them (for example `dbp-hardened-s2-mux`); otherwise they remain reserved-zero and non-zero MUST reject as `E_RESERVED_POLICY`.
- ABB manifest MUST NOT be placed in Band 7 (cells `1020..1023`).

Minimum required manifest fields:
- `lease_seq` (binds manifest to frame sequence)
- `direction` (`downlink` or `uplink`)
- One or more `slice` entries: `{donor_band, start_cell, cell_count, lane_type}`
- `slice_crc32` (CRC over manifest slice table)

`lane_type` is profile-defined and SHOULD be one of `{digital_u24, analog_f32, quantum_pair}`.

`dbp-hardened-s2-mux` lane-type registry (normative):
- `1 = digital_u24`
- `2 = analog_f32`
- `3 = quantum_pair`
- `4 = opaque_bytes` (S2-only)

#### 6.8.3 Receiver validation for ABB slices

Before consuming borrowed data, receivers MUST verify:
1. ABB is enabled by supported profile contract.
2. Manifest integrity and frame binding (`lease_seq` matches current frame sequence).
3. Slice bounds are in-range and non-overlapping.
4. Donor preconditions are true for each slice.
5. Native donor data is ignored only when a valid lease is present.

Per-slice bounds and donor-band rule (normative MUST-reject set):
- Donor band id MUST be one of `{4,5,6}`. Any other `donor_band` value MUST reject ABB for the frame (`E_ABB_MANIFEST` or profile-equivalent).
- Let `end_cell = start_cell + cell_count` (half-open range `[start_cell, end_cell)`). For each slice, `[start_cell, end_cell)` MUST be fully contained in the donor band's canonical range:
  - `donor_band=4` -> cells `[148, 276)`
  - `donor_band=5` -> cells `[276, 660)`
  - `donor_band=6` -> cells `[660, 1000)`
- Slices MUST NOT target structural regions (Band 0, Band 6T, Band 7). Any slice that intersects structural cells MUST reject ABB for the frame.
- In `dbp-hardened-s2-mux`, cells `660..683` are reserved for fixed MCB and MUST NOT be leased/claimed by any slice. Any intersection with `660..683` MUST reject the frame as `E_MCB_INVALID`.

If any ABB validation fails, receivers MUST treat ABB slices as invalid. In permissive ABB profiles, receivers MAY fall back to native donor semantics for that frame; in hardened classes (including `dbp-hardened-s2-mux`), manifest/MCB validity failures MUST reject the frame (`E_ABB_MANIFEST` or `E_MCB_INVALID`).

#### 6.8.4 Security model for ABB

ABB security is inherited from S1/S2 because leased bytes remain inside authenticated frame bytes:
- In S1, leased bytes are covered by HMAC input (`bytes[0..4015]`) and frame CRC.
- In S2, leased bytes are covered by AEAD ciphertext scope (`cells[9..999]`) and frame CRC.

Profiles MUST NOT enable ABB in Open mode (`sec_profile = 0`).

Profiles using ABB on untrusted links SHOULD require `sec_profile = 2`.

`dbp-hardened-s2-mux` profiles MUST enable ABB only when `sec_profile = 2`; ABB interpretation MUST be disabled for Open/S1 frames.

#### 6.8.5 Effective digital capacity with ABB (u24 packing)

If borrowed lanes use `digital_u24` packing, theoretical per-frame digital payload is:

| Source | Cells | Bytes |
|-------|------:|------:|
| Base Band 2+3 payload | 112 | 336 |
| Band 4 borrowed (max) | 128 | 384 |
| Band 5 borrowed (max) | 384 | 1152 |
| Band 6 borrowed (max) | 340 | 1020 |
| **Total (max)** | **964** | **2892** |

`dbp-hardened-s2-mux` adjustment (normative for that class): fixed MCB reservation `cells[660..683]` consumes 24 Band 6 cells, so effective Band 6 borrow max is `316` cells (`948` bytes with `digital_u24`). The corresponding hardened total is `940` cells (`2820` bytes) when Band 4 and Band 5 are also fully borrowable.

Actual usable capacity is profile- and manifest-dependent.

#### 6.8.6 Standard MUX Control Block (MCB) (normative for `dbp-hardened-s2-mux`)

**S2 timing invariant (MUST):** MCB fields MUST be parsed and interpreted only after S2 AEAD verification + decryption succeeds.

To make ABB deterministic and interoperable, `dbp-hardened-s2-mux` frames MUST place a fixed MCB in Band 6 cells `660..683` (24 cells):

- Header (cells `660..667`):
    - `660 mcb_magic` (u16-as-float)
    - `661 mcb_version` (u16-as-float)
    - `662 lease_seq_lo` (u24-as-float)
    - `663 lease_seq_hi` (u24-as-float)
    - `664 dir` (u16-as-float)
    - `665 slice_count` (u16-as-float, max 8)
    - `666 mcb_crc_lo` (u16-as-float)
    - `667 mcb_crc_hi` (u16-as-float)
- Slice table (cells `668..683`): up to 8 fixed-size entries, 2 cells per entry:
    - `desc0` (u24-as-float): `(donor_band << 16) | (lane_type << 8) | flags8`
    - `desc1` (u24-as-float): `(start_cell10 << 12) | cell_count12`.
      - `start_cell10 = (desc1 >>> 12) & 0x3FF` (10-bit domain `0..1023`).
      - `(desc1 >>> 22) MUST be 0` (reserved high bits in the 12-bit start slot).
      - `cell_count12` MUST be in `1..(1024-start_cell10)` and MUST fit in 12 bits.
      - Receivers MUST reject non-zero reserved high bits, zero `cell_count12`, and any out-of-range slice.

`flags8` bit assignments (normative defaults):
- bit 0: `quantum_inactive` (required when `donor_band=4`)
- bit 1: `lane_compressed`
- bit 2: `renew_required`
- bits 3..7: reserved (MUST be `0`)

MCB constants (normative defaults):
- `mcb_magic = 0x4D43`
- `mcb_version = 1`
- `dir = 0` for downlink, `dir = 1` for uplink; other values MUST be rejected.

MCB integrity and placement rules:
- In `dbp-hardened-s2-mux`, this MCB location is mandatory and replaces profile-defined ABB manifest placement.
- MCB MUST be authenticated by S2 integrity; `mcb_crc32` is optional for security but SHOULD be used for debugging and telemetry.
- In S2, MCB SHOULD remain inside ciphertext scope; if a cleartext pointer is used, that pointer MUST be AAD-authenticated.
- MCB fields MUST be parsed/validated only after S2 AEAD verification + decryption succeeds.
- In `dbp-hardened-s2-mux`, MCB integer fields MUST satisfy [Section 28.4](#284-integer-as-float-canonical-decode-rule) on decrypted plaintext before slice interpretation.

`mcb_crc32` scope (normative if present):
- CRC flavor is CRC32/ISO-HDLC.
- Recombine as `mcb_crc32 = mcb_crc_lo + mcb_crc_hi * 65536`.
- Coverage is bytes for cells `660..683` excluding cells `666..667` (CRC holder fields).

Packed descriptor decoder example (reference):

```js
function decodeMcbSlice(desc0_u24, desc1_u24) {
    const donorBand = (desc0_u24 >>> 16) & 0xFF;
    const laneType  = (desc0_u24 >>> 8)  & 0xFF;
    const flags8    =  desc0_u24         & 0xFF;

    const startCell10 = (desc1_u24 >>> 12) & 0x3FF;
    const cellCount   =  desc1_u24         & 0xFFF;

    if ((desc1_u24 >>> 22) !== 0) throw new Error('invalid MCB: start_cell high bits must be zero');
    if (cellCount === 0) throw new Error('invalid MCB: zero-length slice');
    if (cellCount > (1024 - startCell10)) throw new Error('invalid MCB: out-of-range slice');

    return { donorBand, laneType, flags8, startCell: startCell10, cellCount };
}

function decodeMcbTable(frame) {
    const slices = [];
    const sliceCount = decodeU16(frame[665]);
    if (sliceCount > 8) throw new Error('invalid MCB: slice_count > 8');

    for (let i = 0; i < sliceCount; i++) {
        const desc0 = decodeU24(frame[668 + i * 2]);
        const desc1 = decodeU24(frame[669 + i * 2]);
        slices.push(decodeMcbSlice(desc0, desc1));
    }
    return slices;
}
```

Implementations MUST parse MCB entries in fixed order and MUST avoid data-dependent control flow prior to authentication success.

#### 6.8.7 Preemption contract (normative)

- ABB leases are per-frame only unless explicitly renewed in the next frame.
- Native band semantics always take priority over leased interpretation.
- If a donor band becomes natively active in a frame (for example `HAS_WAVEFORM=1`), any colliding lease for that donor band is invalid for that frame.
- Receivers MUST preempt leased interpretation deterministically and fall back to native semantics when preemption occurs.

#### 6.8.8 Multi-lane message layer (normative for `dbp-hardened-s2-mux`)

To make ABB payload transport drop-in implementable, `dbp-hardened-s2-mux` defines one canonical lane-fragment header:

- Name: `DBP-LH1` (Lane Header v1)
- Size: fixed `32` bytes
- Byte order: little-endian for all integer fields
- Placement: first bytes of each leased lane fragment byte-stream

`DBP-LH1` wire layout:

| Bytes | Field | Type | Rule |
|---|---|---|---|
| `0..1` | `lane_magic` | u16 | MUST be `0x4C48` |
| `2` | `lane_version` | u8 | MUST be `1` |
| `3` | `lane_flags` | u8 | bit0=`FRAG_START`, bit1=`FRAG_END`, bits2..7 reserved=0 |
| `4..5` | `lane_id` | u16 | lane namespace id |
| `6..7` | `lane_type` | u16 | MUST match MCB lane type for the slice |
| `8..11` | `msg_id` | u32 | message id within lane namespace |
| `12..13` | `frag_index` | u16 | `0..frag_total-1` |
| `14..15` | `frag_total` | u16 | MUST be `>=1` |
| `16..17` | `frag_len` | u16 | payload bytes after header for this fragment |
| `18..19` | reserved | u16 | MUST be `0` |
| `20..23` | `total_len` | u32 | full reassembled message length in bytes |
| `24..27` | `total_crc32` | u32 | CRC32/ISO-HDLC over full reassembled message |
| `28..31` | `msg_nonce32` | u32 | Per-message nonce (stable across all fragments of one message) |

`msg_nonce32` definition (normative):
- In S2 mode, senders MUST set `msg_nonce32` to a per-message value that remains constant across all fragments of that message, including fragments carried in different frames.
- In S2 mode, `msg_nonce32` MUST be generated independently of per-frame `nonce96` (MUST NOT be derived from `nonce96`, `sec_counter`, or `CRC32(nonce96)`).
- For security and collision resistance, S2 senders SHOULD generate `msg_nonce32` from a CSPRNG (32-bit uniform) and SHOULD avoid active-key-domain reuse of the same `{lane_id,msg_id,msg_nonce32}` tuple.
- In non-S2 profiles that reuse `DBP-LH1`, `msg_nonce32` MAY be `0` unless profile policy requires multi-frame collision hardening.

Fragmentation rules (normative):
1. `frag_index < frag_total` MUST hold.
2. `FRAG_START` MUST be set iff `frag_index == 0`.
3. `FRAG_END` MUST be set iff `frag_index == frag_total - 1`.
4. All fragments of one message MUST carry identical `{lane_id, lane_type, msg_id, frag_total, total_len, total_crc32, msg_nonce32}`.
5. Fragment payload bytes are concatenated in `frag_index` order to reconstruct the message.
6. Header bytes are not part of `total_len` or `total_crc32` coverage.

Lane byte-stream rules (normative):
- `digital_u24` lanes: lane bytes are produced by u24->bytes expansion (`3 bytes/cell`, little-endian `[b0,b1,b2]`).
- `opaque_bytes` lanes: lane bytes are the raw `4 bytes/cell` payload bytes.
- `analog_f32`/`quantum_pair` lanes MAY use `DBP-LH1` for fragmentation metadata, but payload interpretation remains profile-defined.

Reassembly algorithm (normative):
1. Key in-progress message state by `(lane_id, msg_id, msg_nonce32)`.
2. On each fragment, validate `DBP-LH1` fields and equality constraints above.
3. Reject duplicate `frag_index` for the same key.
4. When all indices `0..frag_total-1` are present, concatenate payloads in order.
5. Verify `len(message) == total_len`.
6. Verify `CRC32/ISO-HDLC(message) == total_crc32`.
7. Deliver only on successful checks; otherwise discard and emit ABB reject telemetry (`E_ABB_MANIFEST` or profile-equivalent).

Multi-frame note (normative): fragments of one message MAY span multiple DBP frames; receivers MUST continue reassembly across frame boundaries while `(lane_id,msg_id,msg_nonce32)` remains constant and timeout policy is not exceeded.

Reassembly timeout defaults (normative default, profile-overridable):
- `reassembly_timeout_ms = max(50, ceil(1000 * 3 / tick_rate))` when `tick_rate > 0`.
- If `tick_rate == 0`, default timeout is `1000 ms`.
- On timeout, partial state MUST be discarded.

#### 6.8.9 S2-only `opaque_bytes` lanes (optional, high-throughput)

`opaque_bytes` allows 4-byte-per-cell payload use in leased slices under S2.

Rules:
- `opaque_bytes` MUST NOT be used in Open or S1.
- Slices marked `opaque_bytes` carry arbitrary bytes and are not interpreted as Float32 values.
- Normative: `opaque_bytes` lane bytes are sourced from decrypted plaintext bytes of leased cells (`4 bytes/cell`, wire byte order), not from any Float32 numeric interpretation of those cells.
- In S2, implementations MUST retain decrypted plaintext as a byte buffer at least until authenticated `opaque_bytes` slices are extracted and consumed by lane processing/reassembly.
- Implementations MUST NOT round-trip decrypted leased-cell bytes through Float32 parsing/serialization before `opaque_bytes` extraction.
- Receiver order is normative: AEAD verify+decrypt -> parse/validate authenticated ABB manifest/MCB -> derive `opaque_bytes` slices -> apply finite/subnormal checks only to non-opaque decrypted cells.
- In S2, after decrypt and before any Float32 interpretation of plaintext cells `9..999`, implementations MUST compute the exclusion mask from authenticated MCB/manifest metadata and MUST NOT run vectorized float-class scans over excluded cells.
- After S2 decrypt, finite/subnormal numeric checks apply only to decrypted regions not claimed as `opaque_bytes` by an authenticated MCB/manifest.
- Decrypted `opaque_bytes` slices may contain byte patterns that decode to `NaN`, `Infinity`, or subnormal values if reinterpreted as Float32.
- Consumers MUST mask/exclude authenticated `opaque_bytes` slices before whole-frame Float32/vector processing and MUST NOT treat decrypted cells `9..999` as uniformly numeric-safe without that exclusion.

Throughput note (informational): compared with `digital_u24` (3 bytes/cell), `opaque_bytes` yields 4 bytes/cell in leased slices (about 33% higher lane payload density).

Optional payload compression guidance: profiles MAY compress opaque-lane fragments before encryption (e.g., `zstd`/`lz4`) for large payloads. If attackers can influence plaintext and observe size/timing, profiles SHOULD use fixed fragment sizing to reduce compression side-channel leakage.

#### 6.8.9.1 Sparse Witness Block (`WSB2`) over ABB `opaque_bytes` (profile option)

This profile option defines a dense-frame to sparse-witness mapping that preserves DBP fixed-shape transport while avoiding semantic work on absent rows.

Design invariants:
- DBP wire shape remains fixed at `4096` bytes (`1024` Float32 cells).
- Structural fields remain non-witness and non-borrowable.
- Sparse witness payload is carried only inside authenticated ABB slices, typically lane type `opaque_bytes` (`lane_type=4`) in S2.

Selected deployment mode for sparse witness transport:
- Option B: carry sparse witness bytes inside ABB-leased slices using `opaque_bytes`.

`WSB2` wire payload format (little-endian), carried inside leased lane payload bytes:
- fixed header (`16` bytes):
    - `magic_u32` = ASCII `WSB2`
    - `version_u16` = `1`
    - `overlay_id_u16` = profile-defined semantic overlay id
    - `rows_u16` = `R`
    - `cols_u16` = `8`
    - `present_u16` = `K`
    - `flags_u16` = `0` (reserved)
- body:
    - `bitmap[ceil(R/8)]` bits, row order `0..R-1`
    - packed witness bytes `data[K][8]` as raw little-endian Float32 (`K * 32` bytes)
    - optional profile CRC32 over `bitmap || data`

Normative profile constraints for `WSB2`:
- `cols_u16` MUST be `8`.
- `present_u16` MUST equal popcount of the bitmap.
- `data` byte length MUST equal `present_u16 * 8 * 4`.
- Rows with bitmap bit `0` are absent and semantically equivalent to token-free-zero witness rows.
- Receivers MUST validate `WSB2` length against lane fragment length before decode.
- `WSB2` parsing MUST occur only after S2 AEAD verification/decryption and authenticated ABB lease validation.

Capacity formula:
- `wsb2_bytes = 16 + ceil(R/8) + (K * 32)` (+ optional per-profile CRC)

Implementation guidance (receiver-local, non-wire):
- Build per-update sparse indices once using:
    - `bitmap[R]`
    - `row_to_dense[R]` (`-1` for absent)
    - `data[K][8]`
- This preserves constant-time row lookup (`row -> row_to_dense[row]`) without runtime rank/popcount in hot loops.

Reference implementations:
- JavaScript: `protocol/wsb2_ref.mjs`
- Python: `protocol/wsb2_ref.py`

#### 6.8.10 Worked ABB examples (normative behavior examples)

Example A: borrow Band 5 slice as `digital_u24` for one frame
- Preconditions: `HAS_WAVEFORM=0`, valid authenticated MCB lease: `{donor_band=5, lane_type=1, start_cell=300, cell_count=40}`.
- Lane byte capacity: `40 cells * 3 = 120` bytes.
- Fragment writes:
  - bytes `0..31`: `DBP-LH1` header (`frag_total=1`, `frag_index=0`, `FRAG_START|FRAG_END=1`).
  - bytes `32..(31+frag_len)`: digital payload fragment.
- Receiver:
  - verifies MCB + donor inactivity;
  - decodes lane bytes from u24 packing;
  - validates `DBP-LH1`;
  - accepts fragment as complete message (single-fragment path).

Example B: borrow Band 6 slice as `opaque_bytes` in S2
- Preconditions: `sec_profile=2`, authenticated lease `{donor_band=6, lane_type=4, start_cell=700, cell_count=24}`.
- Lane byte capacity: `24 cells * 4 = 96` bytes.
- Sender writes `DBP-LH1` + opaque fragment bytes in the leased region before S2 encryption.
- Receiver order is mandatory:
  1. AEAD verify+decrypt;
  2. parse authenticated MCB/manifest;
  3. derive `opaque_bytes` exclusion mask;
  4. process lane bytes and reassembly;
  5. run Float32 numeric checks only on non-opaque decrypted cells.

Example C: preemption when native waveform becomes active
- Frame `N`: valid lease borrows Band 5 slice for lane payload.
- Frame `N+1`: header sets `HAS_WAVEFORM=1` while a colliding Band 5 lease is still declared.
- Required receiver behavior:
  - native Band 5 waveform semantics win;
  - colliding lease for Band 5 is ignored for frame `N+1`;
  - partial ABB reassembly state MAY remain for non-colliding fragments, but colliding fragment is dropped and SHOULD emit ABB telemetry.

---

## 7) Transport model

DBP is transport-agnostic. Common deployment patterns:

1. **Static file relay (pull):** clients poll binary frame endpoint with validators (`ETag` preferred)
2. **SSE relay (push):** one process fans out frame updates
3. **WebSocket/native pub-sub:** lower-latency full-duplex fanout

Suggested transport media type (informational): `application/vnd.dbp.frame`.

Writers SHOULD use atomic replacement (`write temp -> rename`) when publishing frames.

---

## 8) Security profiles

Canonical rule references (normative): byte scopes are defined in [Section 0.5.1](#051-canonical-byte-scopes), numeric class policy in [Section 0.5.2](#052-numeric-class-policy-canonical-matrix), and structural integer decode in [Section 0.5.3](#053-integer-as-float-canonical-decode).

### Threat assumptions
Adversary may intercept, replay, inject, and flood traffic.

### Profiles
- `0` Open: CRC only (accidental corruption detection)
- `1` S1: authenticity + anti-replay (MAC + counter)
- `2` S2: authenticity + confidentiality (AEAD profile; optional in v1.1 deployments)

### Security posture and threat coverage (informational)

At this protocol stage, DBP defines three wire-security modes with the following guarantees:
- Open: no cryptographic protection.
- S1: integrity/authenticity + replay defense; no payload confidentiality.
- S2: confidentiality + integrity/authenticity for the protected scope ([Section 8](#8-security-profiles)).

When S2 is required (with downgrade resistance enforced), DBP is designed to be strong against common network adversaries:
- passive eavesdropping,
- in-flight tampering,
- frame injection/forgery,
- replay (with enforced monotonic/window policy).

Wire crypto does not eliminate endpoint/system risks. Implementations remain exposed to:
- endpoint compromise and key theft,
- side-channel leakage,
- traffic analysis/metadata leakage,
- denial-of-service,
- operational/legal/physical coercion paths.

### State-grade and quantum-capable adversaries (informational)

For "harvest now, decrypt later" resilience, deployments SHOULD combine S2 with post-quantum (or hybrid) key establishment/authentication, as already referenced in this specification:
- key establishment: ML-KEM (FIPS 203),
- signatures/identity: ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).

Symmetric choices in this spec (e.g., AES-256, HMAC-SHA-256) remain appropriate under known quantum search models, but protocol strength still depends on nonce discipline, key lifecycle, downgrade resistance, and endpoint hardening.

Minimum state-grade deployment bar (recommended):
1. Require S2 on production links; disable Open/S1 except controlled dev/internal exceptions.
2. Use PQ or hybrid key establishment for session keys.
3. Guarantee nonce/counter non-repetition across restart.
4. Separate keys by direction and writer identity.
5. Maintain crypto agility (versioned suites / rotation-ready policy).
6. Harden endpoints and implementations against side channels.

**Hardened-link requirement (normative for untrusted networks):**
- Deployments that traverse public, partner, or otherwise untrusted infrastructure MUST use `sec_profile = 2` (S2) for downlink frames carrying sensitive control or telemetry.
- `sec_profile = 1` MAY be used only on trusted internal links with equivalent transport confidentiality controls and documented risk acceptance.

**Downgrade resistance (normative):**
- Receivers operating in hardened mode MUST maintain per-peer security policy state.
- If a peer/session is previously accepted under `sec_profile = 2`, subsequent frames for that peer/session MUST NOT silently downgrade to `sec_profile = 1` or `0`.
- Any downgrade attempt MUST be rejected unless an explicit administrative re-authorization event is recorded.

**Sticky S2 enforcement state machine (normative for hardened mode):**
- Receivers MUST persist `requires_s2=true` per `(writer_identity, key_epoch)` once any S2 frame is accepted for that tuple.
- While `requires_s2=true`, any frame from that tuple with `sec_profile != 2` MUST be hard-rejected (`E_POLICY_DOWNGRADE`).
- An unexpected `SEC_TRAILER_PRESENT=0` from a tuple with `requires_s2=true` MUST be treated as incident telemetry and MUST emit `DBP_SEC_DOWNGRADE_ATTEMPT`.
- Clearing `requires_s2` MUST require explicit administrative re-authorization or explicit key-epoch rollover policy.

### SEC_TRAILER_PRESENT flag contract

- Effective-mode rule (normative): `SEC_TRAILER_PRESENT=0` defines effective `sec_profile=0` (Open); `SEC_TRAILER_PRESENT=1` means secure trailer mode and requires cell 1000 (`sec_profile`) to select secure mode.
- Sender rule (normative): if effective mode is Open, sender MUST clear `SEC_TRAILER_PRESENT` and MUST write cells `1000..1019` as `+0.0`. If effective mode is secure, sender MUST set `SEC_TRAILER_PRESENT` and write trailer fields per the selected secure profile.
- Receiver rule when trailer present (`SEC_TRAILER_PRESENT=1`): validate/decode cell 1000 (`sec_profile`) as u16-as-float and require `sec_profile in {1,2}`. `sec_profile = 0` with trailer present is malformed and MUST be rejected. Receivers SHOULD support `sec_profile = 1` (S1); profiles that require S1 MUST reject receivers without S1 support. Receivers MUST reject `sec_profile = 2` (S2) unless they explicitly implement S2. Unknown values (>= 3) MUST be rejected.
- Receiver rule when trailer absent (`SEC_TRAILER_PRESENT=0`): effective `sec_profile=0`; receivers MUST NOT interpret cell 1000 as a trailer profile selector and MUST NOT interpret Band 6T as an active security trailer. Receivers MAY enforce a zero-hygiene assertion over cells `1000..1019` per profile policy.

**Secure key-candidate selection and bounded trial policy (normative for S1/S2):**
- Receivers MUST resolve `key_id` to candidate key slots using bounded direct lookup (for example fixed slot table or hash map), scoped by tuple/policy state.
- Receivers MUST bound cryptographic key attempts per frame to a small constant `K`; RECOMMENDED default `K <= 2` (current `key_id` plus optional `key_id-1` grace candidate).
- Receivers MUST NOT linearly scan a keyring (or any unbounded key set) to find a matching S1 tag or S2 AEAD verification result.
- If the frame `key_id` is outside the bounded candidate set for the tuple/policy, receivers MUST reject without additional key attempts.

CRC32 is REQUIRED in all modes (`sec_profile` 0, 1, and 2). CRC mismatch is always a hard reject, even if S1 HMAC or S2 AEAD verification succeeds. CRC remains mandatory in all modes for cheap corruption detection and consistent operational telemetry across transports/storage; MAC/AEAD does not replace that role. Tradeoff note: CRC-first fail-fast allows an active attacker to force rejects by corrupting footer/check bytes (a DoS equivalent to dropping packets), which is an accepted design choice. Timing-oracle hardening option: implementations concerned about verification timing oracles MAY still execute MAC/AEAD verification work when CRC fails, but MUST reject the frame regardless of cryptographic result.
Telemetry classification note (operational): because CRC is evaluated before S1/S2 cryptographic verification, corruption of secure trailer/tag bytes (cells `1004..1019`) will usually surface as `E_CRC`. `E_S1_TAG`/`E_S2_TAG` are expected when CRC passes and cryptographic verification then fails.

### Canonical byte representation (normative)

- MAC and CRC computations MUST run over exact wire bytes (little-endian IEEE 754 binary32 per cell), never host-native reinterpretations.
- Senders MUST canonicalize `-0.0` -> `+0.0` for structural integer-as-float fields before MAC/CRC computation (see [Section 28.4.1](#2841-strict-00-profile-behavior-for-structural-integer-fields)). For semantic float fields, senders SHOULD canonicalize `-0.0` -> `+0.0`; profiles MAY explicitly permit preserving semantic `-0.0`.
- Subnormals MUST NOT appear on wire for cleartext-interpreted Float32 regions. Senders MUST flush subnormal cleartext values to `+0.0` before MAC/CRC and publish. In S2, ciphertext cells `9..999` are opaque bytes on wire; subnormal/NaN/Inf checks for that region are applied to decrypted plaintext.
- Receivers MUST verify MAC/CRC over the received raw bytes before any canonicalization of cell values. MAC and CRC MUST be computed over the original raw byte buffer exactly as transported, before any canonicalization, normalization, or re-serialization. Receivers MAY inspect bytes or decode floats for validation/fail-fast logic, provided MAC/CRC are still computed over the unchanged original received bytes. Implementations MUST NOT re-pack, normalize, or regenerate bytes before verification.
- Open-mode equivalence note: Open mode still enforces byte-exact integrity via CRC. Even when semantic decode treats `-0.0` and `+0.0` as equivalent values, flipping only the sign bit changes wire bytes and causes CRC mismatch unless the sender recomputes Band 7.
- Common implementation bug to avoid: do not decode floats and re-encode before integrity checks; authenticate/hash the received wire bytes directly.

Float32 subnormal definition (normative): a value `x` is subnormal iff `x != 0` and `abs(x) < 2^-126`.

**Magnitude floor implication:** Values with $0 < |x| < 2^{-126}$ (approx. $1.175 \times 10^{-38}$) will be coerced to `+0.0` by compliant senders. This affects very small analog Band 5 magnitudes and very small qubit amplitudes at extreme normalization edges. Do not rely on DBP to transport magnitudes below this floor.

Reference canonicalization snippet:

```js
function canonicalizeForWire(frame) {
    const MIN_NORMAL_F32 = 1.17549435e-38; // 2^-126
    for (let i = 0; i < frame.length; i++) {
        const v = frame[i];
        // Policy choice: either throw (drop frame) or sanitize to 0.0.
        // This reference implementation drops frames on non-finite input.
        if (!Number.isFinite(v)) throw new Error('non-finite cell');
        if (v === 0 || Math.abs(v) < MIN_NORMAL_F32) frame[i] = 0; // +0.0 canonical
    }
}
```

### S1 rules - authentication

Verify-before-normalize rule (normative): receivers MUST verify MAC/CRC on raw received bytes before any `-0.0` canonicalization or float re-encoding.

**Default algorithm:** HMAC-SHA-256 with a 32-byte (256-bit) key. The key MUST be raw bytes (not a UTF-8 string); provisioning is out-of-band and profile-defined. Profiles MAY override the algorithm, but any conformant S1 implementation MUST support HMAC-SHA-256 for interoperability.

**Extreme-adversary S1 hardening (normative for hardened deployments):**
- Implementations MUST support per-writer (or per-device) keys; a single shared global key across unrelated writers MUST NOT be the only available mode.
- Anti-replay state MUST be tracked per replay-domain tuple `(writer_identity, key_epoch, key_id, direction, channel)`. DBP v1.x interoperability default is key-scoped identity (writer identity derived from authenticated key context). If a profile intentionally shares one key context across multiple writers, it MUST carry an explicit `writer_id` in authenticated metadata (S1 MAC scope, S2 AAD scope) and include it in replay tuple partitioning. For profiles without explicit `key_epoch`/direction/channel fields, use defaults `key_epoch=0`, `direction=0`, `channel=0`.
- Receivers MUST persist anti-replay state across restart, or MUST force `key_id` rotation before accepting new frames after restart.
- Key rotation SHOULD be short-lived (hours to days, not months), and MUST be immediate on compromise signals.

**Counter composition:** The 32-bit anti-replay counter is composed from two u16 cells:

$$\text{sec\_counter} = \text{sec\_counter\_lo} + \text{sec\_counter\_hi} \times 2^{16}$$

(i.e. `sec_counter_lo + sec_counter_hi * 65536`). Both cells are stored as u16-as-float values and MUST satisfy the canonical decode rule ([Section 28.4](#284-integer-as-float-canonical-decode-rule)).

Writers MUST rotate to a new `key_id` before `sec_counter` wraps. A `(key_id, key_bytes)` pair MUST NOT be reused once retired.

**MAC input:** This scope is a normative application of [Section 0.5.1](#051-canonical-byte-scopes) and MUST match it byte-for-byte. The MAC MUST be computed over the **wire-format bytes** (little-endian IEEE 754 binary32 for each cell), not native host byte order. The input spans cells `0..1003` (`4016 bytes`). This covers Bands `0..6` and the security metadata cells (`sec_profile`, `key_id`, `sec_counter_lo/hi` - cells `1000..1003`). The tag cells (`1004..1019`) and Band 7 (`1020..1023`) are excluded - tag cells because the tag is the MAC output, and Band 7 because CRC is a non-cryptographic integrity check. On big-endian hosts, implementations MUST byteswap to little-endian before computing MAC or CRC.

**MAC domain separation (normative):** Implementations MUST compute HMAC over `mac_domain_tag || bytes[0..4015]`. The required default is `mac_domain_tag = "DBP-S1\0"` - defined as an explicit byte sequence: `44 42 50 2D 53 31 00` (ASCII `DBP-S1` + `0x00`), **length 7 bytes**. Profiles MAY override this tag, but it MUST be a fixed, non-empty byte string agreed by sender and receiver. Empty-domain HMAC input (`"" || bytes`) MUST NOT be used.

**Counted-byte-string requirement:** Implementations MUST treat `mac_domain_tag` as a counted byte string (pointer + explicit length). Do NOT use NUL-terminated string APIs (e.g. C `strlen` / `strcat`) to pass this value - the tag contains an embedded `0x00` byte, so NUL-terminated handling will silently produce the wrong HMAC input. (Node.js `Buffer.from("DBP-S1\0", "ascii")` is correct; `Buffer.from("DBP-S1\0")` as a UTF-8 string is also correct and yields 7 bytes.)

**Tag length:** The full HMAC-SHA-256 output (256 bits) is stored as sixteen u16 values in cells `1004..1019` using little-endian word packing (see [Section 6.6](#66-band-6t-security-trailer-cells10001019)). The full 256-bit tag provides 128-bit forgery resistance even against quantum-capable adversaries (Grover's bound).

**Sender MUST follow this ordering:**
1. Build frame content (zero-fill unused bands)
2. Canonicalize negative zero (see [Section 14.4](#144-atomic-publish-policy))
3. Write security metadata cells (`sec_profile`, `key_id`, `sec_counter_lo/hi`)
4. Compute MAC over `mac_domain_tag ||` cells `0..1003` (bytes `0..4015`) -> write `tag_u16[0..15]` into cells `1004..1019`
5. Compute CRC32 over cells `0..1019` (bytes `0..4079`) -> write Band 7 (cells `1020..1023`)
6. Atomic publish

This ordering guarantees that CRC covers the MAC tag (useful for corruption telemetry) and MAC covers only the frame content it authenticates.

**Anti-replay:**
- **Strict monotonic (default):** Receivers MUST track the highest accepted `(sec_counter)` per replay-domain tuple `(writer_identity, key_epoch, key_id, direction, channel)` and reject any frame with counter `<=` the last accepted value for that tuple. For profiles without explicit `key_epoch`/direction/channel fields, use defaults `key_epoch=0`, `direction=0`, `channel=0`. This is sufficient for polling and SSE transports.
- **Windowed (optional):** For transports that may reorder frames (e.g. multi-relay WebSocket), receivers MAY accept counters within a sliding window of width $W$ above the last accepted counter. The window size $W$ MUST be declared in the profile contract and MUST be bounded (`1..4096`). Hardened defaults are: strict-monotonic mode when no reordering is expected, or windowed mode with `W = 64` when reordering is expected and no explicit profile override exists. Window state MUST be tracked per replay-domain tuple `(writer_identity, key_epoch, key_id, direction, channel)`. Frames below the window floor are rejected unconditionally. Within the window, receivers MUST reject any counter value that has already been accepted for that tuple (implementations SHOULD track accepted counters via a per-tuple bitset or equivalent structure).
- **Verify-then-commit rule (normative):** Receivers MAY evaluate replay eligibility before MAC verification as a cheap drop path, but MUST commit/advance replay state only after successful MAC verification. Frames failing MAC MUST NOT mutate replay state.

**Key rotation:**
- Receivers MUST accept the current `key_id` and MAY accept `key_id - 1` during a grace period.
- **Grace policy (default):** receivers MAY accept `key_id - 1` only within `G` seconds after first accepting the new `key_id`, with default `G = 30s`. After grace expiry, only the current `key_id` is accepted. Profiles MAY override `G` or disable grace entirely.
- If `key_id == 0`, there is no `key_id - 1` grace candidate.
- All other key IDs MUST be rejected.
- S1 verification MUST follow the bounded key-trial policy above; receivers MUST NOT attempt additional key candidates beyond the bounded set even when HMAC verification fails.
- Anti-replay counters MUST reset to zero when a new `key_id` is first accepted. The counter namespace is per replay-domain tuple - a counter value valid under one tuple has no relationship to the same counter under another tuple.
- Senders MUST assign `key_id` monotonically for the deployment lifetime (or include an explicit epoch in profile policy) to prevent replay acceptance from retired key eras.
- If `key_id` would wrap (u16 overflow), profiles MUST define an out-of-band epoch/deployment identity before wrap to prevent replay acceptance from a previous key era.

### S2 rules - confidentiality (AEAD profile)

Verify-before-normalize rule (normative): receivers MUST verify AEAD/CRC on raw received bytes before any `-0.0` canonicalization or float re-encoding.

S2 provides confidentiality + integrity + replay resistance for extreme-adversary deployments.

**Required S2 primitives:**
- Implementations MUST support `AES-256-GCM`.
- Implementations SHOULD support `ChaCha20-Poly1305` (IETF / RFC 8439 variant, 96-bit nonce) for software-only environments.
- Session keys MUST be derived via `HKDF-SHA-256` from an external authenticated handshake secret.

**Nonce length rule (normative):**
- DBP v1.x carries exactly one AEAD nonce on wire: `nonce96` (12 bytes) stored in `sec_words[0..5]` ([Section 6.6](#66-band-6t-security-trailer-cells10001019)).
- All S2 suites in the v1.x `suite_id` registry MUST use a 96-bit AEAD nonce, and that nonce MUST equal this `nonce96`.
- AEAD constructions that require a 192-bit nonce input (for example `XChaCha20-Poly1305`) are out of scope for DBP v1.x and MUST NOT be negotiated via `suite_id`.

**S2 suite registry (normative):**
- S2 implementations MUST bind cryptographic behavior to `suite_id` (from `sec_words[14]` in `dbp-hardened-s2-mux`, otherwise profile default).
- `suite_id` identifies `{KDF, AEAD, nonce_mode, header_policy, ratchet_mode}`.
- Receivers MUST reject unknown `suite_id` values before any AEAD key trial.
- S2 verification MUST follow the bounded key-trial policy above; receivers MUST NOT scan keyrings or try unbounded key candidates on AEAD failure.

Reference `suite_id` registry (normative defaults for `dbp-hardened-s2-mux`):

| `suite_id` | KDF | AEAD | Nonce len | Nonce source | Nonce mode | AAD cells (wire order) | Header policy | Ratchet mode |
|---:|---|---|---|---|---|---|---|---|
| 1 | `HKDF-SHA-256` | `AES-256-GCM` | 96-bit | direct `nonce96` from `sec_words[0..5]` | counter-based 96-bit (RECOMMENDED: `session_salt32||ctr64`) | `0..8`, then `1000..1003`, then `1018..1019` | standard clear header | off |
| 2 | `HKDF-SHA-256` | `ChaCha20-Poly1305` (RFC 8439) | 96-bit | direct `nonce96` from `sec_words[0..5]` | counter-based 96-bit (RECOMMENDED: `session_salt32||ctr64`) | `0..8`, then `1000..1003`, then `1018..1019` | standard clear header | off |
| 3 | `HKDF-SHA-256` | `AES-256-GCM` | 96-bit | direct `nonce96` from `sec_words[0..5]` | counter-based 96-bit (RECOMMENDED: `session_salt32||ctr64`) | `0..8`, then `1000..1003`, then `1018..1019` | `minimal` (historical alias: silent-header variant) | off |
| 4 | `HKDF-SHA-256` | `ChaCha20-Poly1305` (RFC 8439) | 96-bit | direct `nonce96` from `sec_words[0..5]` | counter-based 96-bit (RECOMMENDED: `session_salt32||ctr64`) | `0..8`, then `1000..1003`, then `1018..1019` | `minimal` (historical alias: silent-header variant) | off |
| 5 | `HKDF-SHA-256` | `AES-256-GCM` | 96-bit | direct `nonce96` from `sec_words[0..5]` | counter-based 96-bit (RECOMMENDED: `session_salt32||ctr64`) | `0..8`, then `1000..1003`, then `1018..1019` | standard clear header | per-frame symmetric ratchet |
| 6 | `HKDF-SHA-256` | `ChaCha20-Poly1305` (RFC 8439) | 96-bit | direct `nonce96` from `sec_words[0..5]` | counter-based 96-bit (RECOMMENDED: `session_salt32||ctr64`) | `0..8`, then `1000..1003`, then `1018..1019` | standard clear header | per-frame symmetric ratchet |

Profiles MAY define additional suite IDs, but MUST publish exact semantics for all suite dimensions above (KDF, AEAD, nonce length/source/mode, AAD cell ranges, header policy, ratchet mode).

`XChaCha20-Poly1305` suites (192-bit nonce constructions) are RESERVED and NOT DEFINED in DBP v1.x.

Header policy mode definitions (normative for suite registry semantics):
- `standard`: existing clear header semantics; activity/profile flags in normal cleartext locations.
- `constant_flags`: clear header `HAS_*` indicators are fixed policy constants; real activity map is carried in authenticated ciphertext metadata.
- `minimal`: only router-essential cleartext remains; profile/activity semantics are carried in authenticated ciphertext metadata.

**Key-establishment requirement for S2:**
- S2 deployments MUST use authenticated key establishment with post-quantum or hybrid post-quantum + classical exchange.
- `ML-KEM-768` (FIPS 203) is RECOMMENDED for PQ KEM capability.
- For identity and software/update signing around S2 systems, `ML-DSA` (FIPS 204) or `SLH-DSA` (FIPS 205) is RECOMMENDED.

**DBP-HS1 handshake profile (normative for `dbp-hardened-v1` and `dbp-hardened-s2-mux`):**
- DBP-HS1 is an out-of-band handshake profile that produces S2 traffic keys and policy-binding metadata.
- Wire frames do not carry DBP-HS1 messages; they carry only resulting `key_id`/`key_epoch`/nonce state.
- All DBP-HS1 multi-byte integers are little-endian.
- `writer_identity_mode` default is `key-scoped`: one active handshake key context maps to one writer identity.

DBP-HS1 message envelope (all messages):
- Prefix bytes: ASCII `DBP-HS1\0`.
- `msg_type` (u8): `1=ClientHello`, `2=ServerHello`, `3=Finish`.
- `version` (u8): MUST be `1`.
- `flags` (u16): MUST be `0` in v1.x.

`ClientHello` body (normative field order):
1. `handshake_id` (u32)
2. `profile_id` (u8)
3. `suite_id` (u16)
4. `key_epoch` (u16) proposed epoch
5. `key_id` (u16) initial key id for this epoch (default `1`)
6. `direction_mask` (u8, bit0=downlink, bit1=uplink)
7. `channel_id` (u8)
8. `writer_identity_len` (u16) + `writer_identity_utf8` bytes
9. `client_random32` (32 bytes)
10. `client_classical_public_len` (u16) + bytes (for example X25519 public key)
11. `pq_kem_ciphertext_len` (u16) + bytes (for example ML-KEM encapsulation ciphertext)
12. `options_mask` (u16, MUST be 0 in v1.x)

HS1 PQ-KEM directionality contract (normative):
- DBP-HS1 v1.x assumes the server PQ KEM public key is available to the client before `ClientHello` (pre-provisioned, pinned, or fetched from an authenticated directory).
- `ClientHello` carries the client-to-server KEM encapsulation ciphertext; the server decapsulates it to obtain `pq_shared_secret` for the hybrid key schedule.
- Profiles that do not satisfy this precondition MUST define an equivalent authenticated key-discovery/bootstrap step before DBP-HS1 messages are exchanged.

`ServerHello` body (normative field order):
1. `handshake_id` (u32)
2. `profile_id` (u8)
3. `suite_id` (u16)
4. `key_epoch` (u16) accepted epoch
5. `key_id` (u16) accepted initial key id
6. `direction_mask` (u8)
7. `channel_id` (u8)
8. `server_random32` (32 bytes)
9. `server_classical_public_len` (u16) + bytes
10. `server_auth_data_len` (u16) + bytes (signature/cert/auth blob; profile-defined semantics)
11. `options_mask` (u16, MUST be 0 in v1.x)

Transcript and key schedule (normative):
- Transcript bytes: `T = client_hello_raw || server_hello_raw`.
- Transcript hash: `TH = SHA-256(T)`.
- Required field-equality checks before deriving keys: `handshake_id`, `profile_id`, `suite_id`, `key_epoch`, `key_id`, `direction_mask`, `channel_id`; any mismatch MUST fail handshake.
- Context bytes (binding context):
  - `profile_id (u8) || suite_id (u16) || key_epoch (u16) || key_id (u16) || direction_mask (u8) || channel_id (u8) || writer_identity_len (u16) || writer_identity_utf8`.
- Hybrid IKM bytes:
  - ASCII `DBP-HS1-IKM\0` || `len(pq_ss)` (u16) || `pq_shared_secret` || `len(ecdh_ss)` (u16) || `ecdh_shared_secret`.
- HKDF salt:
  - `salt = SHA-256("DBP-HS1-SALT\0" || client_random32 || server_random32)`.
- Derivations (HKDF-SHA-256):
  - `downlink_key(32)` info = `"DBP-S2-DOWNLINK-KEY\0" || TH || context`
  - `uplink_key(32)` info = `"DBP-S2-UPLINK-KEY\0" || TH || context`
  - `downlink_salt32(4)` info = `"DBP-S2-DOWNLINK-SALT32\0" || TH || context`
  - `uplink_salt32(4)` info = `"DBP-S2-UPLINK-SALT32\0" || TH || context`
  - `master_secret(32)` info = `"DBP-HS1-MASTER\0" || TH || context`
  - `confirm_key(32)` info = `"DBP-HS1-CONFIRM-KEY\0" || TH || context`

`Finish` body (normative):
1. `handshake_id` (u32)
2. `transcript_hash32` (32 bytes, MUST equal `TH`)
3. `confirm_tag32` (32 bytes)

`confirm_tag32` definition (normative):
- `confirm_tag32 = HMAC-SHA-256(confirm_key, "DBP-HS1-FINISH\0" || TH || context)`.
- Receiver MUST verify `Finish` with constant-time compare.
- Any transcript-hash or confirm-tag mismatch MUST fail handshake.

Handshake output contract (normative):
- Successful DBP-HS1 MUST output `{writer_identity, suite_id, key_epoch, key_id, downlink_key, uplink_key, downlink_salt32, uplink_salt32, transcript_hash}`.
- S2 traffic MUST NOT start until this output contract is committed on both peers.
- Profiles using a non-DBP-HS1 mechanism MUST produce equivalent outputs and MUST bind at least the same context fields with equivalent cryptographic strength.

`key_epoch` persistence and advancement (normative):
- Receiver MUST persist per-writer state: `last_key_epoch`, `last_transcript_hash`, and `requires_s2`.
- For hardened classes, accepted `key_epoch` MUST be exactly `last_key_epoch + 1` (bootstrap minimum: `key_epoch >= 1`).
- Reusing or rolling back `key_epoch` MUST be rejected as `E_KEY_EPOCH`.
- After successful handshake, receiver MUST set `requires_s2=true` for that writer tuple.
- If durable state cannot be guaranteed, implementations MUST fail closed (do not accept frames for that tuple) until administrative recovery.

**S2 wire behavior (v1.1-compatible):**
- `sec_profile = 2`, `SEC_TRAILER_PRESENT = 1`.
- Cells `1004..1019` use S2 trailer packing from [Section 6.6](#66-band-6t-security-trailer-cells10001019).
- `crc_lo/crc_hi` in Band 7 remain required and are computed over on-wire bytes `0..4079` exactly as in S1 (that is, over ciphertext bytes for cells `9..999`).
- For `dbp-hardened-s2-mux`, `key_epoch` from `sec_words[15]` MUST be monotonic per `writer_identity`; rollback MUST be rejected unless explicit rollover policy is in force.

**S2 authenticated scope and ciphertext scope:**
- Scope definitions in this subsection are a normative application of [Section 0.5.1](#051-canonical-byte-scopes) and MUST match it byte-for-byte.
- Cleartext header for routing/interoperability: Band 0 (cells `0..8`) and security trailer metadata/policy cells `1000..1003` and `1018..1019`.
- `AAD` MUST be wire bytes for cells `0..8`, then `1000..1003`, then `1018..1019` (in that order).
- Conformance vectors MUST publish `aad_hex` exactly from this concatenation order; implementations SHOULD compute/log `aad_crc32` during development to detect AAD-construction bugs quickly.
- This AAD binding makes trailer policy fields (`suite_id`, `key_epoch` in hardened profiles; reserved-zero in other profiles) cryptographically integrity-protected.
- Any cleartext policy-selecting field (for example `suite_id`, `key_epoch`, or profile-defined equivalents) MUST be covered by AAD and MUST NOT be integrity-protected only as ciphertext content.
- Ciphertext MUST cover cells `9..999` (Bands `1..6`).
- In S2, cells `9..999` are encrypted/decrypted as raw 3964 wire bytes; the plaintext representation for those cells is the normal DBP Float32 little-endian wire encoding.
- Cells `9..999` MUST be treated as opaque ciphertext bytes until AEAD verification succeeds and decryption completes.
- Implementations MUST process `bytes[36..3999]` as opaque bytes in S2 and MUST NOT run Float32 decoding/validation on that range before successful AEAD verification + decryption.
- After S2 AEAD success, implementations MUST retain decrypted plaintext as a byte buffer until authenticated `opaque_bytes` slice extraction/processing (if any) is complete.
- Implementations MUST NOT round-trip decrypted `bytes[36..3999]` through Float32 parse/serialize prior to `opaque_bytes` extraction, because value-level canonicalization (for example NaN payload normalization) can destroy byte-exact opaque payloads.
- Receivers MUST apply finite/subnormal and band-level numeric checks to decrypted plaintext for cells `9..999` before accepting decoded band semantics.

Routing visibility design note (informational): because Band 1 is inside S2 ciphertext scope, relays/routers can only inspect cleartext routing metadata in Band 0 and trailer cleartext cells (`1000..1003`, plus policy words `1018..1019`). Profiles that require route-by-control-field semantics SHOULD place or duplicate a minimal routing scalar in Band 0.

**S2 nonce discipline:**
- For counter-based suites, senders MUST construct `nonce96` so it is unique per `(traffic_key, direction)` domain.
- Nonce MUST be unique per `(key_epoch, key_id, writer_identity, direction, channel)` domain.
- RECOMMENDED default construction for new profiles: `nonce96 = session_salt32 || sec_counter64_le`.
  - `session_salt32` MUST be fixed per active `(key_epoch, key_id, direction, channel)` domain and MUST change when that domain rotates.
  - `sec_counter64` MUST start at zero for a newly activated domain and increment by 1 per emitted S2 frame in that domain.
- In suites using this 64-bit construction, define `salt32 = LE_U32(nonce96[0..3])` and `ctr64 = LE_U64(nonce96[4..11])`.
- In suites using this 64-bit construction, the canonical replay counter source MUST be `ctr64`.
- In suites using this 64-bit construction, `sec_counter` in cells `1002..1003` MUST be a mirror value for telemetry/back-compat only and MUST equal `ctr64 & 0xFFFFFFFF`.
- Receivers using this 64-bit construction MUST reconstruct `ctr64` from `nonce96` for replay checks and MUST reject frames where `sec_counter_lo/hi` do not match `ctr64` low 32 bits.
- Profiles MAY define an alternate deterministic construction, but MUST publish exact field layout and uniqueness bounds.
- Reuse of `(key, nonce)` MUST be treated as a critical protocol failure.
- Senders MUST rotate key material before counter wrap for the chosen construction.
- Receivers SHOULD alarm on rollback/reuse indicators for the profile's published counter tuple.
- **Authenticated-only nonce policy actions (normative):** nonce-reuse alarms, replay-state commits, and tuple quarantine actions (for example `E_S2_NONCE_REUSE`) MUST be based only on authenticated frames (successful AEAD verification). Unauthenticated frames MUST NOT advance replay state or trigger nonce-reuse quarantine.

**AEAD interoperability profile (normative, suite IDs 1..6):**
- For `suite_id in {1,2,3,4,5,6}` (AES-256-GCM and ChaCha20-Poly1305 suites), AEAD nonce input MUST be exactly the 12-byte `nonce96` reconstructed from `sec_words[0..5]` using [Section 6.6](#66-band-6t-security-trailer-cells10001019) little-endian u16 packing.
- Receivers MUST use this trailer-derived `nonce96` directly for AEAD verification and MUST NOT recompute, expand, or transform nonce bytes from header fields as an alternate input.
- Legacy deterministic construction (profile MAY continue to use for compatibility) composes `nonce96` as:
    - `nonce[0..1] = key_id_u16_le` (from cell `1001`)
    - `nonce[2..5] = sec_counter_u32_le` (from cells `1002..1003`, low u16 then high u16)
    - `nonce[6..9] = writer_or_stream_id_u32_le` (profile/key-context scoped)
    - `nonce[10..11] = dir_chan_u16_le` (`dir` in low byte, `channel` in high byte)
- Profiles that do not multiplex per-channel MUST set `channel = 0`; downlink MUST use `dir = 0`, uplink MUST use `dir = 1`.
- Conformance fixtures MUST publish authoritative `nonce96_hex`. Fixtures that claim deterministic composition MUST additionally publish source fields (`key_id`, `sec_counter`, `writer_or_stream_id`, `dir`, `channel`) and composition mode.

**S2 nonce persistence across restart (normative):**
- Senders MUST persist nonce/counter state for active `(writer_identity, key_epoch, key_id, direction, channel)` domains across process restart.
- If persistence cannot be guaranteed, senders MUST activate a new `key_id` before emitting any S2 frame after restart.
- If persistence cannot be guaranteed in hardened mode, senders MUST activate a new `key_epoch` before first post-restart S2 frame.
- Receivers SHOULD alarm on nonce rollback indicators (e.g., repeated `(key_epoch, key_id, ctr64)` tuples from the same writer domain).

**S2 replay window algorithm (normative default for hardened classes):**
- Receivers MUST track replay state per tuple `(writer_identity, key_epoch, key_id, direction, channel)`. Hardened default is a sliding window with width `W = 64`; profiles MAY override with bounded `W (1..4096)`.
- For suites using `nonce96 = session_salt32 || sec_counter64_le`, replay tracking MUST use `ctr64 = LE_U64(nonce96[4..11])` as the counter source; `sec_counter_lo/hi` are mirror/telemetry only.
- Profiles MAY define a different monotonic counter source, but MUST publish it normatively.
- Receivers MAY evaluate replay-window eligibility before AEAD verification as a cheap drop path, but MUST commit replay-window state only after successful AEAD verification.
- Recommended acceptance algorithm:

```text
state: max_ctr (uint64), seen_bits (W-bit bitmap), initialized (bool)
accept(counter):
  if !initialized:
    max_ctr = counter; seen_bits = 1; initialized = true; return ACCEPT
  if counter > max_ctr:
    shift = counter - max_ctr
    seen_bits = (shift >= W) ? 0 : ((seen_bits << shift) & ((1<<W)-1))
    seen_bits |= 1
    max_ctr = counter
    return ACCEPT
  delta = max_ctr - counter
  if delta >= W: return REJECT_OLD
  bit = 1 << delta
  if (seen_bits & bit) != 0: return REJECT_REPLAY
  seen_bits |= bit
  return ACCEPT
```

**Optional symmetric ratchet mode (recommended for extreme-adversary posture):**
- Suites MAY enable per-frame ratcheting.
- Sender chain advance:

$$
\operatorname{chain\_key}_{t+1} = \operatorname{HKDF}(\operatorname{chain\_key}_t,\; "dbp ratchet" \parallel \operatorname{frame\_seq} \parallel \operatorname{direction})
$$

- Traffic key for frame $t$ MUST be derived from `chain_key_t` under suite-defined KDF labels.
- Ratchet state is per-direction and bound to `(writer_identity, key_epoch, key_id)`.
- Receivers MAY fast-forward ratchet state up to a profile-defined `MAX_SKIP` window when sequence gaps occur.
- If observed sequence advance exceeds `MAX_SKIP`, receivers MUST reject the frame and require re-handshake/resync for that tuple.

**Nonce persistence guidance (normative):**
- Selecting `AES-256-GCM` vs `ChaCha20-Poly1305` does not change the core requirement: `(key, nonce)` pairs MUST NOT repeat.
- If a sender cannot guarantee persistence of nonce/counter state across restart, it MUST rotate to a new `key_id` (and in hardened mode MUST also advance `key_epoch`) before emitting any S2 frame after restart ([Section 8](#8-security-profiles), "S2 nonce persistence across restart").

**Stream identity binding (normative):**
- Interoperability default (and hardened requirement) is key-scoped identity: one active S2 key context maps to exactly one writer identity.
- Under this default, `writer_identity` is derived from authenticated key context (`key_epoch` + `key_id` + key slot/credential identity + direction/channel partition), and receivers MUST track anti-replay/nonce uniqueness per `(writer_identity, key_epoch, key_id, direction, channel)`.
- Hardened profile classes (`dbp-hardened-v1`, `dbp-hardened-s2-mux`) MUST NOT share one active S2 key context across multiple writers.
- Explicit `writer_id` mode is a non-default profile extension for non-hardened/shared-key environments; when used, `writer_id` MUST be authenticated (S1 MAC scope / S2 AAD scope) and MUST be part of replay/nonce partitioning.

Metadata-minimization option (informational): for `dbp-hardened-s2-mux`, profiles SHOULD use the `minimal` header policy (historical alias: "silent header"), where only router-essential fields remain cleartext and activity/profile signaling is carried in authenticated ciphertext metadata (or kept constant in cleartext and refined inside ciphertext).

**Recommended interim transport posture:** Even with S2, use **TLS 1.3** transport protection. Hybrid PQ TLS key exchange is RECOMMENDED as implementations mature.

### HTTP Uplink Compact Transport Profile (authentication)

This is not a DBP frame; it is a profile-defined transport message that reuses Band 6 layout.

In S1 mode, the uplink POST body contains Band 6 only (340 cells = 1360 bytes). The in-frame security trailer (Band 6T) is a **downlink-only** construct; uplink POSTs do not include it.

Uplink authentication SHOULD use transport-layer mechanisms:
- **TLS** provides integrity and confidentiality for the POST body.
- **Application-layer MAC** (optional): compute a MAC over the POST body bytes and transmit as an HTTP header (e.g. `X-DBP-Tag: <base64>`). This provides defense-in-depth when TLS termination is handled by an untrusted intermediary.

In extreme-adversary deployments, ingress SHOULD enforce allow-lists and rate limits before expensive MAC/AEAD verification to reduce CPU-amplification DoS.

Hardened uplink option (recommended):
- Profiles MAY require full-frame S2-protected uplink using the same `suite_id`/`key_epoch` policy family.
- If full-frame S2 uplink is not used, hardened profiles SHOULD require application-layer MAC even when TLS is present (to reduce trust in intermediary terminators).

### Key establishment guidance
Hardened profile classes MUST use DBP-HS1 (or an equivalent profile-defined handshake that satisfies the DBP-HS1 output contract in this section).

Session/group keys SHOULD be established with post-quantum KEM (e.g. ML-KEM-768) plus classical ECDH hybridization where practical.

For transport channels, TLS 1.3 with hybrid classical + PQ key exchange is RECOMMENDED when available; avoid ad-hoc handshake designs that do not bind the DBP-HS1 context fields.

### Key lifecycle policy (hardened deployments)

Implementations in hardened mode MUST implement explicit key states:
- `pre-active`: provisioned but not used for emission
- `active`: currently used for emission and acceptance
- `draining`: no new emissions; accept-only during grace window
- `revoked`: reject-only

Required lifecycle controls:
- Normal rotation interval SHOULD be <= 24h for internet-facing deployments (profiles MAY tighten).
- Emergency rotation on compromise signal MUST complete within profile-defined RTO (recommended <= 5 minutes).
- Receivers MUST reject frames signed with `revoked` keys immediately.
- Reuse of retired `(key_id, key_material)` pairs MUST NOT occur.

---

## 9) Duotronic math layer (optional but compatible)

DBP is a fixed-offset Float32 frame; polygon witness encoding is an optional profile-level semantic layer, not used for structural fields (Band 0, Band 6T, Band 7 - see [Section 36](#36-header-encoding-caveat-raw-fractions-vs-polygon-encoding)).

DBP can carry raw floats directly, but it also supports a higher-level lattice math model where each logical value is represented as an 8-feature witness vector.

### 9.1 Witness cell model (8 features)
Suggested feature order:
1. `value_norm`
2. `n_sides_norm`
3. `center_on`
4. `activation_density`
5. `kind_flag`
6. `band_position`
7. `parity`
8. `degeneracy`

### 9.2 Token-free zero
All-zero witness means absence of signal. This supports sparse diffs and efficient skip logic.

### 9.3 Witness lattice model
Common lattice shapes:
- 16 cells x 8 features = 128 floats (512 bytes)
- 128 cells x 8 features = 1024 floats (4096 bytes)

### 9.4 Modular conversion bridge
For integer domain `[0..M_max]` using one-based bridge:

$$
\mathrm{encode:}\; v_{norm} = \frac{m+1}{M_{max}+1}
$$

$$
\mathrm{decode:}\; m = \max\left(0,\operatorname{round}(v_{norm}(M_{max}+1)) - 1\right)
$$

This avoids collision between explicit zero values and token-free-zero absence.

`M_max` is the inclusive maximum value (domain size is `M_max + 1`). Profiles that reason in symbol counts may equivalently define `N = M_max + 1`.

### 9.5 Witness families (optional)
- **Even-range family:** good for smooth continuous values
- **Pronic-chain family:** good for discrete/count-like values

Profiles MAY choose either or both; `kind_flag` identifies family used.

### 9.6 Witness deployment security contract (normative profile guidance)

Witness-carried semantics are often state-bearing and MAY be command-affecting in profile logic. For that reason:
- Profiles that interpret witness payloads as sensitive state, control hints, or command inputs MUST require secure transport mode (`sec_profile in {1,2}`), and SHOULD require `sec_profile = 2` on untrusted links.
- Such profiles MUST NOT accept witness interpretation in Open mode (`sec_profile = 0`).
- If a frame arrives in Open mode while witness interpretation is security-required, receivers MUST treat witness content as inactive for that frame, MUST emit security telemetry (recommended event: `DBP_WITNESS_INSECURE_MODE`), and SHOULD increment a `witness_insecure_mode` counter.

### 9.7 Duotronic primitive `D = (p, q)` (normative profile option)

Profiles that adopt the Duotronic primitive model MUST treat each logical value as an ordered pair:
- `p`: primary magnitude term (the value-bearing component).
- `q`: corrective/context term (stability, uncertainty, or compensating component).

Operational meaning requirements:
- Profiles MUST declare what `p` and `q` represent (units, sign semantics, and interpretation domain).
- `p` and `q` are semantic payload values only; they MUST NOT be used for structural fields (Band `0`, Band `6T`, Band `7`).
- If a profile uses `D`, it MUST define whether `D` is carried directly as raw floats or transformed into witness features.

### 9.8 Projection rule `N = p - lambda*q` (normative default)

Projected scalar from primitive pair:

`N_lambda(D) = p - lambda * q`

Projection defaults:
- Default `lambda = 1.0`.
- Profiles MAY override `lambda`, but MUST publish the numeric value and rationale.
- If a profile uses dynamic `lambda`, it MUST be authenticated metadata and MUST declare bounds `[lambda_min..lambda_max]`.

### 9.9 Stability term `S(p, q)` (bounded, explicit)

Default bounded stability term:

`S(p, q; eps) = clamp01(1 - abs(q) / (abs(p) + abs(q) + eps))`

with default `eps = 1e-9` and `clamp01(x) = min(1, max(0, x))`.

Properties:
- `S` is always in `[0, 1]`.
- `S = 1` when `q = 0` (fully stable under this model).
- `S` trends toward `0` as `|q|` dominates `|p|`.

Profiles MAY define an alternate bounded stability function, but MUST keep output in `[0,1]` and document exact formula.

### 9.10 Composition rules for `D` (add/multiply/normalize)

Let `D1 = (p1, q1)` and `D2 = (p2, q2)`.

Default composition operators:
- Add: `D_add = (p1 + p2, q1 + q2)`
- Multiply (first-order propagation): `D_mul = (p1 * p2, p1 * q2 + p2 * q1)`

Normalization/saturation contract:
- Profiles MUST declare bounds `p_range` and `q_range`.
- Default normalized bounds are `[-1, 1]` for both terms when no profile override exists.
- After composition, implementations SHOULD apply per-term saturation:
  - `p' = clamp(p, p_min, p_max)`
  - `q' = clamp(q, q_min, q_max)`
- Profiles MUST define whether saturation is `clamp`, `reject`, or `rescale`.

### 9.11 Constraints and calibration contract

Profiles that use `D` MUST publish:
1. Allowed ranges for `p` and `q`.
2. Calibration mapping from real-world signal `x` into `p` and `q`.
3. Reverse mapping (if required by the application).

Recommended linear calibration template:
- `p = (x - x_offset) / x_scale`
- `q = (x_ref - x) / q_scale` (or profile-equivalent residual/uncertainty term)

Token-free-zero interaction (normative clarity):
- Token-free-zero (`all 8 witness features = 0`) means **absence/inactive semantic signal**.
- Real numeric zero is a **present value** and MUST NOT be encoded as all-zero witness.
- If `D` is carried directly (non-witness), real zero is `D = (0,0)` in an active slot; absence MUST be indicated by profile gating/lease/validity state, not by numeric ambiguity.

### 9.12 Bridge: `D = (p, q)` vs 8-feature witness

Bridge requirement:
- A profile MUST explicitly choose one of:
  1. **Direct `D` carriage**: two raw Float32 terms (`p`, `q`) with projection/stability evaluated by receiver logic.
  2. **Witness projection carriage**: store witness features derived from `D` and recover profile-level semantics from witness fields.

Recommended witness bridge mapping (informational default):
- `value_norm` derived from projected scalar `N_lambda(D)` via profile normalization/bridge.
- `activation_density` and/or `degeneracy` encode stability context from `S(p,q)` and `1-S(p,q)`.
- `kind_flag` identifies the witness family/profile mapping used.

If a profile claims reversible `D <-> witness` conversion, it MUST define the exact forward and inverse equations and required numeric tolerances.

### 9.13 Dense overlay and sparse transport (selected profile path)

This specification uses the following interoperability stance:
- semantic overlay remains conceptually dense (`R x 8` witness rows),
- transport remains fixed-shape DBP frame,
- sparse transport, when enabled, uses ABB Option B (`WSB2` inside authenticated `opaque_bytes` leased slices).

Operational behavior:
- Token-free-zero rows remain the canonical absence marker.
- Receivers SHOULD skip semantic compute for absent rows.
- Profiles MAY materialize a dense view from `WSB2` for downstream consumers that require dense indexing.

Example sizing (`R=64`, `K=8`):
- dense witness bytes: `64 * 8 * 4 = 2048`
- `WSB2` bytes: `16 + 8 + (8 * 32) = 280`

Profile switching heuristic (informational default):
- if `K >= 0.6 * R`, dense carriage may be simpler;
- if `K < 0.6 * R`, sparse `WSB2` carriage is usually more efficient.

---

## 10) Vector integration

A DBP frame is directly usable as a Float32 vector in Open/S1, and after decrypt in S2.

Recommended practice:
- store full frames at low sampling rate for replay
- store compact derived state vectors at higher rate for similarity search
- compare full frames with weighted band distances when needed

This keeps protocol telemetry and vector-search infrastructure aligned.

---

## 11) Sustainability policy

DBP v1.1 is the intended final major refinement of fixed-offset Float32 packing.

If new requirements demand repeated multi-cell packing workarounds, that is a migration trigger for v2.0 schema-based wire format (e.g., FlatBuffers/Cap'n Proto class solutions).

---

## 12) Minimal implementation checklist (v1.1)

- Implement magic-based parser split (`0xDB01` / `0xDB11`)
- Enforce mode-dependent numeric validity checks (`Open/S1: full-frame`, `S2: cleartext structural pre-decrypt + plaintext cells[9..999] post-decrypt`)
- Implement exact-safe split timestamp fields
- Implement CRC32 verification for Band 7
- Implement flags/profile parsing and unknown-profile behavior
- Implement digital channel chunking and payload CRC checks
- Implement waveform gating flags and reuse logic
- Implement security trailer verification (`sec_profile`, `key_id`, counters, HMAC/AEAD tag`, and S2 decrypt flow)
- For hardened S2+MUX: enforce `suite_id`/`key_epoch` policy, fixed MCB parsing, lease preemption, and optional `opaque_bytes` lane handling
- Use atomic frame publishing semantics

### 12.1 Implementer constants header (reference)

```text
DBP_CELLS = 1024
DBP_BYTES = 4096

BAND0_START=0;   BAND0_LEN=9
BAND1_START=9;   BAND1_LEN=11
BAND2_START=20;  BAND2_LEN=64
BAND3_START=84;  BAND3_LEN=64
BAND4_START=148; BAND4_LEN=128
BAND5_START=276; BAND5_LEN=384
BAND6_START=660; BAND6_LEN=340
BAND6T_START=1000; BAND6T_LEN=20
BAND7_START=1020; BAND7_LEN=4

CRC_INPUT_CELLS = 0..1019   (bytes[0..4079])
MAC_INPUT_CELLS = 0..1003   (bytes[0..4015])
```

### 12.2 Golden decoder flow (reference pseudocode)

For normative defaults and profile-level override points used during validation, see [Section 16.1](#161-normative-defaults-vs-profile-overrides).

```text
validate_shape(4096 bytes)
if !SEC_TRAILER_PRESENT:
  effective_sec_profile = 0
  trailer_sec_profile = null   // cell1000 not interpreted as trailer selector
if  SEC_TRAILER_PRESENT:
  trailer_sec_profile = validate/decode cell1000 as u16
  require trailer_sec_profile in {1,2}
  effective_sec_profile = trailer_sec_profile
if effective_sec_profile!=2: validate_finite_and_no_subnormals(all cells)
if effective_sec_profile==2: validate_finite_and_no_subnormals(cleartext structural cells[0..8], 1000..1019, 1020..1023)
validate_integer_as_float(Band0, Band7; Band6T[1000..1019] if SEC_TRAILER_PRESENT)
magic = decode_u16(cell0); dispatch_parser_by_magic(magic)
parse version/tick_rate + validate sec_of_day/ms ranges
validate footer (byte_size, magic_echo)
verify CRC over bytes[0..4079]
enforce sticky-S2 downgrade policy state (reject effective_sec_profile!=2 for tuples requiring S2, including trailer-removed attempts)
if SEC_TRAILER_PRESENT and effective_sec_profile==1: verify security profile + anti-replay + HMAC over mac_domain_tag || bytes[0..4015]
if SEC_TRAILER_PRESENT and effective_sec_profile==2: verify security profile + anti-replay + AEAD tag over AAD/ciphertext scope in Section 8, then decrypt cells[9..999]
if effective_sec_profile==2 and profile_supports_opaque_bytes: parse_and_validate_authenticated_manifest_or_mcb(decrypted plaintext)
if effective_sec_profile==2: validate_finite_and_no_subnormals(decrypted cells[9..999], excluding authenticated opaque_bytes slices)
if !SEC_TRAILER_PRESENT: optional 6T zero hygiene assert
decode bands (digital validity checks, payload CRC, band-specific semantics)
```

### 12.3 Interop byte-range checklist

- MAC input (S1): cells `0..1003` = bytes `0..4015`
- CRC input (frame): cells `0..1019` = bytes `0..4079`
- Tag cells: `1004..1019`
- Footer cells: `1020..1023`

### 12.4 Hardened deployment checklist (quantum-resilient)

- Use authenticated PQ/hybrid key establishment for session keys (ML-KEM recommended).
- Keep S1 enabled for authenticity even when transport confidentiality is enabled (defense-in-depth).
- Prefer S2 (`sec_profile = 2`) for confidentiality-sensitive links and stored captures.
- Use per-writer keys; avoid single global fleet keys.
- Persist anti-replay state per `(writer_identity, key_epoch, key_id, direction, channel)` or rotate `key_id`/`key_epoch` on restart.
- Rotate keys frequently (hours/days) and immediately on compromise telemetry.
- Protect long-term keys in TPM/HSM/secure-element when available.
- Sign firmware/config/update artifacts with ML-DSA or SLH-DSA.
- Enforce ingress allow-lists + rate limiting before crypto verification under load.
- Use constant-time tag comparison for MAC/AEAD verification.
- Fail-closed: any security validation error MUST reject the frame.
- Isolate writer authority: relay/fanout tiers MUST NOT hold writer signing/MAC keys.
- Bind negotiated cryptographic context to transport/session identity and reject cross-session key/context reuse.

### 12.5 Conformance classes (deployment tiers)

| Class | Minimum requirements |
|------|-----------------------|
| `DBP-Core` | Sections 1..7 validity + CRC + parser split + digital checks |
| `DBP-Secure-S1` | `DBP-Core` + full S1 verification + anti-replay + key rotation policy |
| `DBP-Hardened-S2` | `DBP-Secure-S1` + S2 AEAD + downgrade resistance + nonce persistence + DBP-HS1 (or equivalent output-contract handshake) + replay window default `W=64` + strict structural `-0.0` rejection + hardened checklist ([Section 12.4](#124-hardened-deployment-checklist-quantum-resilient)) |
| `DBP-Adaptive-ABB` | `DBP-Hardened-S2` + ABB manifest validation + donor-precondition enforcement ([Section 6.8](#68-adaptive-band-borrowing-abb-profile-extension-v11-compatible)) |
| `DBP-Hardened-S2+MUX` | `DBP-Adaptive-ABB` + `suite_id/key_epoch` enforcement + fixed MCB ([Section 6.8.6](#686-standard-mux-control-block-mcb-normative-for-dbp-hardened-s2-mux)) + preemption contract + optional `opaque_bytes` lane handling |

Implementations SHOULD publish the highest class they satisfy.

---

## 13) Receiver validation pipeline (normative)

Receivers MUST validate incoming frames in the following fail-fast sequence. Any step that fails MUST cause the frame to be rejected. Implementations MAY continue constant-work cryptographic verification after an earlier failure for timing-oracle hardening, but such optional work MUST NOT change reject outcome.
Core summary for these rules is in [Section 0.2](#02-core-validation-rules-normative-summary). Canonical byte scopes are in [Section 0.5.1](#051-canonical-byte-scopes), numeric class policy in [Section 0.5.2](#052-numeric-class-policy-canonical-matrix), and structural integer decode in [Section 0.5.3](#053-integer-as-float-canonical-decode).
Integrity ordering rule (normative): receivers MUST verify CRC/MAC/AEAD over the original received wire bytes before any `-0.0` normalization, float canonicalization, or byte re-serialization.

### 13.0 Numeric class policy reference

Receivers MUST enforce the canonical numeric matrix from [Section 0.5.2](#052-numeric-class-policy-canonical-matrix). This section applies that matrix in ordered fail-fast steps.

1. **Shape check:** exactly 4096 bytes / 1024 Float32 cells
2. **Preflight structural decode and mode select:**
    - Canonical-decode minimum selector fields as integer-as-float ([Section 0.5.3](#053-integer-as-float-canonical-decode)): `magic` (cell 0) and `flags_profile` (cell 7).
    - Derive `SEC_TRAILER_PRESENT` from decoded `flags_profile`.
    - If `SEC_TRAILER_PRESENT` is clear, set effective `sec_profile = 0` (Open) for validation flow; cells `1000..1019` are trailer-hygiene zeros and cell 1000 is not interpreted as a trailer selector.
    - If `SEC_TRAILER_PRESENT` is set, canonical-decode trailer field cell 1000 (`sec_profile`) and require `sec_profile in {1,2}`.
3. **Magic check:** `0xDB01` or `0xDB11`; reject unknown values.
4. **Footer sanity precheck:** canonical-decode `byte_size` (cell 1022) and `magic_echo` (cell 1023) as integer-as-float ([Section 0.5.3](#053-integer-as-float-canonical-decode)), then require `byte_size == 4096` and `magic_echo == magic`.
5. **Finite/subnormal validity check (pre-crypto scope):**
    - If effective `sec_profile != 2`, reject any frame containing `NaN`, `Infinity`, or subnormal Float32 values in any cell.
    - If effective `sec_profile = 2`, treat cells `9..999` as opaque ciphertext until AEAD verification + decryption. Before decrypt, enforce finite/subnormal checks only on cleartext structural cells (`0..8`, `1000..1019`, `1020..1023`).
    - Numeric validity remains independent of authenticity: any required numeric check failure causes rejection even if CRC/MAC/AEAD checks pass.
6. **Structural integer-as-float check (full):** validate integer-as-float fields in Band 0 and Band 7 unconditionally; if `SEC_TRAILER_PRESENT` is set, validate all Band 6T integer-as-float fields (`1000..1019`, including all 16 `sec_words` cells). All checked fields MUST satisfy the canonical decode rule ([Section 0.5.3](#053-integer-as-float-canonical-decode)).
7. **Version parse:** decode `version` and `tick_rate`; also validate header time-field ranges (`sec_of_day in [0..86399]`, `ms in [0..999]`). Profile policy MAY add stricter `unix_day` sanity bounds. Time-field range failures MUST reject as `E_TIME_RANGE`.
8. **CRC32 check:** verify CRC32 over cells `0..1019` (bytes `0..4079`). This is intentionally before cryptographic verification to provide cheap corruption detection/telemetry and fail-fast behavior. Tradeoff: an active attacker can corrupt footer/check bytes and force pre-crypto reject (DoS equivalent to packet drop). CRC mismatch is always a hard reject, even in secure modes, and implementations MUST NOT bypass this check when MAC/AEAD succeeds.
    - **Mandatory rationale:** CRC is a required transport/storage corruption detector and operational signal, and remains enforced even when S1/S2 authentication succeeds.
    - **Timing-oracle hardening option:** implementations MAY perform MAC/AEAD verification work even when CRC fails, but frame disposition MUST remain reject (`E_CRC`) and MUST NOT be upgraded to accept.
9. **Security policy gate (downgrade/sticky-S2):** enforce per-peer policy state before acceptance.
    - If tuple policy requires S2 (sticky-S2), any frame with `SEC_TRAILER_PRESENT=0` or effective `sec_profile != 2` MUST be rejected (`E_POLICY_DOWNGRADE`) and emit `DBP_SEC_DOWNGRADE_ATTEMPT`.
    - This gate applies even when `SEC_TRAILER_PRESENT` is clear.
10. **Security check (S1/S2):** if `SEC_TRAILER_PRESENT` flag is set, verify anti-replay and the profile-specific authenticity/integrity tag per [Section 8](#8-security-profiles).
    - In S1 mode, receivers MAY verify HMAC first (security-first fail-fast) or anti-replay first (cheap-drop fail-fast), as long as both checks are enforced before accepting the frame.
    - In S2 mode, receivers MUST validate AEAD tag over the S2 AAD/ciphertext scope and then decrypt cells `9..999` before accepting the frame.
    - Receivers MAY run replay/nonce eligibility checks before tag verification, but MUST commit replay/nonce state only after successful MAC/AEAD verification (verify-then-commit).
    - Nonce-reuse alarms/quarantine (`E_S2_NONCE_REUSE`) MUST be emitted only for authenticated S2 frames (AEAD success).
11. **Post-decrypt numeric check (S2):**
    - Before any Float32 interpretation of decrypted plaintext cells `9..999`, receivers MUST compute the authenticated `opaque_bytes` exclusion mask from decrypted MCB/manifest metadata and MUST NOT run vectorized float-class scans over excluded cells.
    - Receivers MUST keep decrypted cells `9..999` as a byte buffer through authenticated manifest/MCB parsing and `opaque_bytes` extraction, and MUST NOT round-trip decrypted bytes through Float32 parse/serialize before opaque extraction completes.
    - After successful S2 AEAD verification + decrypt, receivers MUST execute this order:
        1. parse/validate authenticated ABB manifest or MCB on decrypted plaintext;
        2. derive authenticated `opaque_bytes` exclusion slices;
        3. enforce finite/subnormal checks on plaintext cells `9..999` excluding those slices.
    - If `opaque_bytes` is not active for the frame, step 2 yields an empty exclusion set and checks apply to full plaintext `9..999`.
12. **6T hygiene (optional, post-integrity):** if `SEC_TRAILER_PRESENT` is clear, receivers MAY assert that cells `1000..1019` are all `+0.0` as a sanity check (writers are required to zero-fill per [Section 14.3](#143-zero-fill-policy)).
13. **Band decoding:** only after all integrity checks pass.
    - In S2 mode, band decoding MUST use decrypted plaintext for cells `9..999`.
    - In `dbp-hardened-s2-mux`, receivers MUST validate MCB integer-as-float fields ([Section 28.4](#284-integer-as-float-canonical-decode-rule)), constants (`mcb_magic`, `mcb_version`, `dir`), and bounds on decrypted MCB plaintext before applying lease semantics.
    - In S2 mode with authenticated ABB `opaque_bytes` lanes, receivers MUST skip Float32 semantic decoding for those leased slices and treat them as raw bytes.
    - If `HAS_DIGITAL_A` or `HAS_DIGITAL_B` is set, receivers MUST validate that digital channel header integer fields (cells `0..7` within the channel) satisfy the canonical decode rule ([Section 28.4](#284-integer-as-float-canonical-decode-rule)) before use. Each payload cell (cells `8..63` within the channel) MUST also be a valid u24-as-float (finite, integral, 0..0xFFFFFF).
    - If a digital channel fails [Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147)/[Section 15](#15-digital-chunk-reassembly-contract) validation, receivers MUST enforce `digital_invalid_policy`: default `ignore_channel` (treat channel absent for the frame and do not act on it), or `reject_frame` if configured (recommended reject code: `E_DIGITAL_INVALID`).
    - If a receiver consumes Band 6 (per-client downlink or server-side uplink), it MUST apply [Section 28.4](#284-integer-as-float-canonical-decode-rule) to Band 6 integer fields before use.

### Failure handling

Receivers MUST implement the following on frame rejection:
- **Preserve last-good frame:** continuity-sensitive consumers MUST continue using the last successfully validated frame.
- **Count errors:** implementations SHOULD maintain per-category error counters (shape, finite, magic, crc, security) for operational telemetry.
- **No error propagation:** invalid frames MUST NOT be forwarded, stored, or partially decoded.
- **Rate limiting:** if error rate exceeds a threshold (e.g. >50% of frames over a 10-second window), receivers SHOULD back off polling or close the connection and alert the operator.
- **Digital anomaly alerting:** if `HAS_DIGITAL_A/B` is asserted but channel validation fails repeatedly (e.g. `digital_invalid > 1%` of frames over 60s), receivers SHOULD treat this as an integration defect or abuse signal and alert operators.

### 13.1 DoS cost controls (normative)

Receivers on untrusted links MUST apply cheap checks before expensive cryptography:
- Pre-check order MUST start with shape, magic, and footer sanity before HMAC/AEAD verification.
- Ingress MUST enforce rate limits keyed by source and `writer_identity` where available.
- Cryptographic key attempts per frame MUST be bounded to a small constant per [Section 8](#8-security-profiles) (secure key-candidate selection); implementations MUST NOT linearly scan keyrings.
- Implementations MUST cap concurrent in-flight ABB reassembly/fragment state per source.

### 13.2 Security reject-code registry (normative)

Receivers MUST emit a stable machine-readable reject code for each rejected frame. Default operational handling is below:

| Code | Meaning | Receiver action | Counter name | Recommended security event |
|------|---------|-----------------|--------------|----------------------------|
| `E_SHAPE` | Frame is not exactly 4096 bytes | drop frame | `reject_shape` | `DBP_SEC_SHAPE_REJECT` |
| `E_NONFINITE` | One or more cells contain `NaN`/`Infinity` | drop frame | `reject_nonfinite` | `DBP_SEC_NUMERIC_INVALID` |
| `E_SUBNORMAL` | One or more cells are subnormal | drop frame | `reject_subnormal` | `DBP_SEC_NUMERIC_INVALID` |
| `E_INT_FIELD` | Integer-as-float field failed canonical decode ([Section 28.4](#284-integer-as-float-canonical-decode-rule)) | drop frame | `reject_int_field` | `DBP_SEC_STRUCT_INVALID` |
| `E_TIME_RANGE` | Header time-field out of range (`sec_of_day` or `ms`) | drop frame | `reject_time_range` | `DBP_SEC_STRUCT_INVALID` |
| `E_MAGIC` | Unknown `magic` | drop frame | `reject_magic` | `DBP_SEC_PROTOCOL_MISMATCH` |
| `E_FOOTER` | Footer sanity failed (`byte_size`/`magic_echo`) | drop frame | `reject_footer` | `DBP_SEC_STRUCT_INVALID` |
| `E_CRC` | Frame CRC mismatch (any corruption in `bytes[0..4079]`, including S1/S2 trailer/tag bytes) | drop frame | `reject_crc` | `DBP_SEC_INTEGRITY_FAIL` |
| `E_SEC_PROFILE` | Invalid/unsupported `sec_profile` or trailer contract | drop frame | `reject_sec_profile` | `DBP_SEC_PROFILE_INVALID` |
| `E_REPLAY` | Anti-replay check failed | drop frame | `reject_replay` | `DBP_SEC_REPLAY_REJECT` |
| `E_S1_TAG` | S1 HMAC verification failed (after CRC passes) | drop frame | `reject_s1_tag` | `DBP_SEC_TAG_MISMATCH` |
| `E_S2_TAG` | S2 AEAD tag verification failed (after CRC passes) | drop frame | `reject_s2_tag` | `DBP_SEC_TAG_MISMATCH` |
| `E_S2_NONCE_REUSE` | Authenticated S2 nonce uniqueness violation | drop + quarantine tuple | `reject_s2_nonce_reuse` | `DBP_SEC_NONCE_REUSE` |
| `E_S2_SUITE` | Unknown or policy-disallowed `suite_id` | drop frame | `reject_s2_suite` | `DBP_SEC_S2_SUITE_REJECT` |
| `E_KEY_EPOCH` | Non-monotonic or invalid `key_epoch` transition | drop frame | `reject_key_epoch` | `DBP_SEC_KEY_EPOCH_ROLLBACK` |
| `E_POLICY_DOWNGRADE` | Security-profile downgrade attempt rejected | drop + incident alert | `reject_policy_downgrade` | `DBP_SEC_DOWNGRADE_ATTEMPT` |
| `E_RESERVED_POLICY` | Reserved-cell policy violation (strict modes) | drop frame (or warn in permissive mode) | `reject_reserved_policy` | `DBP_SEC_RESERVED_POLICY` |
| `E_ABB_MANIFEST` | ABB manifest missing/invalid/inconsistent | drop ABB interpretation for frame (or drop frame in strict profile) | `reject_abb_manifest` | `DBP_SEC_ABB_MANIFEST_INVALID` |
| `E_ABB_DONOR_STATE` | ABB donor precondition violation | drop ABB interpretation for frame | `reject_abb_donor_state` | `DBP_SEC_ABB_DONOR_STATE` |
| `E_MCB_INVALID` | MUX Control Block invalid/out-of-bounds/inconsistent | drop frame in hardened MUX profiles | `reject_mcb_invalid` | `DBP_SEC_MCB_INVALID` |
| `E_PROFILE_UNSUPPORTED` | `profile_id` unsupported for profile-required semantics | drop profile-specific actions; optionally drop frame per policy | `reject_profile_unsupported` | `DBP_PROFILE_UNSUPPORTED` |
| `E_DIGITAL_INVALID` | Digital channel validity failure with policy `reject_frame` | drop frame | `reject_digital_invalid` | `DBP_SEC_STRUCT_INVALID` |
| `E_WITNESS_INSECURE_MODE` | Witness semantics received in insecure mode where profile requires security | drop witness interpretation for frame | `reject_witness_insecure_mode` | `DBP_WITNESS_INSECURE_MODE` |

Profiles MAY add profile-specific codes, but MUST preserve this base code set and semantics for cross-implementation telemetry compatibility.

### Security observability (recommended)

Implementations SHOULD emit structured security events with at least the set below (plus code-specific events from [Section 13.2](#132-security-reject-code-registry-normative) when available):
- `DBP_SEC_REPLAY_REJECT`
- `DBP_SEC_TAG_MISMATCH`
- `DBP_SEC_NONCE_REUSE`
- `DBP_SEC_DOWNGRADE_ATTEMPT`
- `DBP_SEC_S2_SUITE_REJECT`
- `DBP_SEC_KEY_EPOCH_ROLLBACK`
- `DBP_PROFILE_UNSUPPORTED`
- `DBP_WITNESS_INSECURE_MODE`
- `DBP_SEC_KEY_REVOKED`
- `DBP_SEC_KEY_STATE_INVALID`
- `DBP_SEC_S2_REQUIRED_LINK_POLICY`

Each event SHOULD include `(writer_identity, key_epoch, key_id, sec_profile, seq_lo, seq_hi, transport, timestamp)` when available, and MAY include raw `writer_id` when explicitly carried by profile metadata.

---

## 14) Sender behavior and timing

Canonical rule references (normative): byte scopes are defined in [Section 0.5.1](#051-canonical-byte-scopes), numeric class policy in [Section 0.5.2](#052-numeric-class-policy-canonical-matrix), and structural integer decode in [Section 0.5.3](#053-integer-as-float-canonical-decode).

### 14.1 Monotonic sequencing
- `seq_lo/seq_hi` MUST represent one monotonic 48-bit unsigned frame counter composed as $\text{seq} = \text{seq\_lo} + \text{seq\_hi} \times 2^{24}$ (i.e. `seq_lo + seq_hi * 16777216`). The counter is modulo $2^{48}$; writers MUST wrap to 0 after `0xFFFFFFFFFFFF`.
- **Modular comparison (serial-number arithmetic, RFC 1982 style):** given $M = 2^{48}$, sequence $a$ is newer than $b$ iff $0 < (a - b) \bmod M < M/2$. Readers that do not implement modular comparison MUST treat monotonicity as best-effort across wrap.
- Writers SHOULD increment sequence only for accepted/published frames

### 14.2 Clock fields
- `unix_day`, `sec_of_day`, and `ms` SHOULD be sampled atomically from one clock read
- Writers MUST keep `ms` in `[0..999]`

### 14.3 Zero-fill policy
- Unused or invalidated optional bands SHOULD be zero-filled
- If `HAS_WAVEFORM` is not set, Band 5 SHOULD be zero-filled
- Writers MUST sanitize non-finite computed samples (especially Band 5) to `0.0` before publish, or drop the frame (see [Section 0.2](#02-core-validation-rules-normative-summary)).
- Writers SHOULD expose sanitization telemetry (counter/flag) via profile-defined Band 1 fields or digital messages.
- Subnormals MUST NOT appear on wire for cleartext-interpreted Float32 regions. Writers MUST flush subnormal cleartext values to `+0.0` before MAC/CRC and publish. In S2, cells `9..999` are ciphertext bytes and are validated for numeric hygiene after decrypt (see [Section 0.2](#02-core-validation-rules-normative-summary)).
- If `SEC_TRAILER_PRESENT` is clear, writers MUST zero-fill Band 6T (cells[1000..1019]). This ensures deterministic CRC over cells[0..1019] and prevents stale tag bytes from causing telemetry confusion.
- In shared downlink mode, Band 6 MUST be zero-filled unless an ABB-enabled profile explicitly leases Band 6 slices per [Section 6.8](#68-adaptive-band-borrowing-abb-profile-extension-v11-compatible). In per-client downlink frames, Band 6 MAY carry profile-defined state.
- Senders MUST write all reserved cells as `+0.0`, unless explicitly defined by an active profile.
- Reserved-cell receiver behavior defaults are normative by conformance class (table below).
- Reserved-cell checks treat `-0.0` as zero for reserved-float hygiene; strict structural-integer policy is separate and defined in [Section 28.4.1](#2841-strict-00-profile-behavior-for-structural-integer-fields).
- Reserved bits vs reserved cells terminology is defined only in [Section 4](#reserved-term-boundaries-normative); this section defines mode/class enforcement for reserved cells only.

Normative reserved-cell handling by mode/class:

| Mode | Reserved-cell policy |
|------|-----------------------|
| Open (`sec_profile=0`) | Warn + telemetry (`reserved_cell_nonzero`); accept by default |
| S1 (`sec_profile=1`) | Warn + telemetry by default; profile MAY escalate to reject |
| S2 (`sec_profile=2`, non-hardened class) | Warn + telemetry by default; profile MAY escalate to reject. Exception: outside `dbp-hardened-s2-mux`, cells `1018..1019` (`sec_words[14..15]`) are reserved structural policy cells and MUST reject on non-zero (`E_RESERVED_POLICY`). |
| Hardened classes (`dbp-hardened-v1`, `dbp-hardened-s2-mux`) | MUST reject non-zero reserved structural cells (`E_RESERVED_POLICY`) |

### 14.4 Atomic publish policy
- Writers MUST normalize `-0.0` to `+0.0` for structural integer-as-float fields before MAC/CRC computation. For semantic float cells, writers SHOULD normalize `-0.0` to `+0.0` unless profile policy preserves semantic `-0.0`. In JS:

```js
for (let i = 0; i < 1024; i++) {
    if (frame[i] === 0) frame[i] = 0; // converts -0 to +0
}
```

- In languages without JS-style `x === 0` canonicalization behavior, implementations SHOULD normalize negative zero explicitly (for example via `copysign`/sign-bit masking or equivalent deterministic method) for required structural fields and any semantic fields they choose to normalize.

- **Receiver `-0.0` treatment:** CRC and MAC MUST be verified over the raw bytes as received (no normalization before verification). After successful verification, receivers MAY canonicalize `-0.0` -> `+0.0` for downstream processing or diffing.
- Publish sequence MUST follow the ordering defined in [Section 8](#8-security-profiles) (S1 rules): build -> canonicalize required structural fields (and optional semantic fields) -> security metadata -> MAC -> CRC -> atomic replace.
- Even in `sec_profile = 0` (Open mode), the CRC step MUST be last before publish.
- Partial writes MUST NOT be exposed to readers.

---

## 15) Digital chunk reassembly contract

For channels A/B, receivers SHOULD use `(channel, msg_type, msg_id, chunk_total)` as a reassembly key.

Sender `msg_id` reuse policy:
- `msg_id` MUST be unique for at least a profile-defined horizon (`T` seconds or `N` frames), or
- `msg_id` MUST be a monotonic u24 counter modulo $2^{24}$ with profile-defined wrap handling.

Required receiver checks:
- `chunk_total >= 1`
- `chunk_index < chunk_total`
- `payload_len` is in `[1..168]`, unless profile policy explicitly allows `payload_len == 0`
- payload CRC32 covers exactly `payload_len` bytes (starting at payload cell 0). `payload_len` counts bytes of the logical payload byte stream (after u24 packing expansion), not the number of payload cells. Let `used_cells = ceil(payload_len / 3)`: payload cells `[used_cells..55]` MUST be zero. If `payload_len % 3 != 0`, the unused high byte(s) in the final used u24 payload cell MUST be zero.
- recombine digital CRC field halves as `payload_crc32 = payload_crc_lo + payload_crc_hi * 65536`
- payload CRC32 field (`payload_crc_lo/hi`) matches that computed value

If profile policy allows `payload_len == 0`, payload CRC MUST be CRC32/ISO-HDLC of the empty byte string.

Reassembly collision safety:
- If a new chunk arrives for an existing reassembly key but has incompatible metadata (e.g. different `chunk_total` or inconsistent `(payload_len, payload_crc)` pattern), receivers SHOULD drop the old buffer, start a new buffer with the new chunk, and increment/log a collision counter.

Message-level commitment extension (recommended):
- Profiles that use `chunk_total > 1` SHOULD define at least one message-level commitment field (`msg_len_total` or `msg_crc32_total`), and SHOULD include both when feasible.
- Profiles SHOULD define message-level commitment fields for chunked payloads:
    - `msg_len_total` (u24, total logical message bytes), and/or
    - `msg_crc32_total` (u16 low/high split over full logical message bytes), and optionally
    - `msg_nonce` (u24 random nonce to harden collision resistance).
- Because Band 2/3 header cells `0..7` are fully allocated in v1.1, these fields MUST be carried in a profile-defined extension (for example, a fixed prefix in chunk 0 payload bytes), and MAY be echoed in every chunk.
- When present, receivers SHOULD extend the reassembly identity to include these commitment fields and MUST require commitment consistency across all chunks before completion.

Completion rule:
- Message is complete only when all chunk indices `[0..chunk_total-1]` are present and valid.

Timeout and eviction guidance:
- Receivers SHOULD evict incomplete reassembly buffers after a bounded timeout.
- Receivers SHOULD cap concurrent in-flight message buffers to prevent memory abuse.

---

## 16) Profile registry and capability negotiation

To keep DBP broadly reusable, profiles SHOULD publish a short machine-readable contract.

Suggested profile contract fields:
- `profile_id` (1..255)
- `profile_name`
- `profile_version` (semantic)
- `supported_cmd_ids`
- `band1_map` (names/ranges/units)
- `digital_msg_types`
- `digital_invalid_policy` (`ignore_channel` or `reject_frame`; default `ignore_channel`)
- `security_requirements` (Open/S1/S2)

Negotiation guidance:
- A receiver MAY expose `supported_profiles` and `supported_security_profiles` out-of-band.
- A sender SHOULD avoid profile-specific commands unless support is confirmed.
- If `profile_id` is unknown, receivers MAY continue core decode (bands/CRC/security) but MUST NOT execute profile-specific actions.
- Profiles that require strict profile match MUST reject unknown `profile_id` with `E_PROFILE_UNSUPPORTED`.
- Default interoperability behavior is fail-safe subset execution: accept transport/core semantics, ignore unsupported profile semantics.

### 16.1 Normative defaults vs profile overrides

| Topic | Default behavior | Profile override allowed? | Reference |
|------|-------------------|---------------------------|-----------|
| Digital channel invalid while `HAS_DIGITAL_*` set | Apply `digital_invalid_policy`; default `ignore_channel` (ignore channel for frame, do not act) | Yes - set `digital_invalid_policy=reject_frame` | [Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147), [Section 13](#13-receiver-validation-pipeline-normative), [Section 16.4](#164-profile-contract-schema-requirements) |
| Digital payload CRC scope | CRC32/ISO-HDLC over first `payload_len` bytes after u24->bytes expansion | No | [Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147), [Section 15](#15-digital-chunk-reassembly-contract) |
| `msg_id` reuse horizon | Unique for profile-defined `T`/`N`, or monotonic u24 modulo counter | Yes - horizon/wrap policy is profile-defined | [Section 15](#15-digital-chunk-reassembly-contract) |
| Reassembly collision handling | Drop old buffer, start fresh, increment/log collision counter | Yes - stricter rejection/alert policy | [Section 15](#15-digital-chunk-reassembly-contract) |
| Qubit normalization violation | Reader applies profile policy `{reject | renormalize | clamp+renormalize}` | Yes - policy is profile-defined | [Section 6.3](#63-band-4-quantum-register-cells148275), [Section 22.9](#229-normalization-enforcement) |
| Integer `-0.0` handling | Compatibility mode accepts as zero | Yes - hardened classes MUST reject in Bands 0/6T/7; non-hardened profiles MAY opt in | [Section 28.4](#284-integer-as-float-canonical-decode-rule) |
| Subnormal handling | Open/S1: subnormals forbidden on wire; S2: enforce on cleartext structural cells and decrypted plaintext for `9..999` | No | [Section 8](#8-security-profiles), [Section 13](#13-receiver-validation-pipeline-normative), [Section 14.3](#143-zero-fill-policy) |
| S1 verification order | Enforce both anti-replay and MAC before accept | Yes - receiver may choose MAC-first or anti-replay-first fail-fast | [Section 13](#13-receiver-validation-pipeline-normative), [Section 8](#8-security-profiles) |
| S1 MAC domain tag | Fixed non-empty required default tag `"DBP-S1\0"` | Yes - profiles MAY override with another fixed non-empty tag | [Section 8](#8-security-profiles) |
| Key rotation grace | Accept previous key only during default grace window `G = 30s` | Yes - profile may override `G` or disable grace | [Section 8](#8-security-profiles) |
| Untrusted-link security profile | S2 required in hardened mode | Yes - non-hardened profiles may allow S1 with risk acceptance | [Section 8](#8-security-profiles), [Section 16.2](#162-dbp-hardened-profile-v1-normative-template) |
| Replay identity binding | Track per `(writer_identity, key_epoch, key_id, direction, channel)` (use `key_epoch=0` when absent); interoperability default is key-scoped identity | Yes - explicit `writer_id` mode is allowed only as a declared non-hardened extension with authenticated coverage | [Section 8](#8-security-profiles), [Section 16.2](#162-dbp-hardened-profile-v1-normative-template) |
| Zero-length digital payload | Disallowed unless explicitly enabled by profile | Yes - profile may allow with empty-payload CRC rule | [Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147), [Section 15](#15-digital-chunk-reassembly-contract) |
| Digital message commitment fields | None required by default | Yes - profile SHOULD add `msg_len_total` / `msg_crc32_total` (and optional `msg_nonce`) | [Section 15](#15-digital-chunk-reassembly-contract) |
| Quantum amplitude sign policy | `nonnegative` default semantics | Yes - profile may declare `signed-semantic` | [Section 6.3](#63-band-4-quantum-register-cells148275), [Section 22](#22-quantum-register-detailed-specification) |
| S2 replay window width | Strict monotonic unless profile enables windowing | Yes - hardened default `W=64` when windowed mode is used | [Section 8](#8-security-profiles) |
| `suite_id` + `key_epoch` (S2) | Not required outside hardened MUX class | Yes - required for `dbp-hardened-s2-mux` | [Section 6.6](#66-band-6t-security-trailer-cells10001019), [Section 8](#8-security-profiles), [Section 16.3](#163-dbp-hardened-s2-mux-profile-normative-template) |
| Handshake profile (hardened classes) | DBP-HS1 transcript/key-schedule contract | Yes - equivalent handshake allowed only if it satisfies DBP-HS1 output contract and bindings | [Section 8](#8-security-profiles) |
| ABB manifest placement | Profile-defined authenticated location | Yes - fixed MCB required in `dbp-hardened-s2-mux` | [Section 6.8.2](#682-borrow-manifest-normative), [Section 6.8.6](#686-standard-mux-control-block-mcb-normative-for-dbp-hardened-s2-mux) |
| `opaque_bytes` lane type | Disabled | Yes - S2-only in `dbp-hardened-s2-mux` | [Section 6.8.9](#689-s2-only-opaquebytes-lanes-optional-high-throughput), [Section 13](#13-receiver-validation-pipeline-normative) |

### 16.2 DBP Hardened Profile v1 (normative template)

Profiles that claim `dbp-hardened-v1` MUST satisfy all of the following:

1. **Algorithms**
    - S1: `HMAC-SHA-256` with 256-bit keys.
    - S2: `AES-256-GCM` mandatory; `ChaCha20-Poly1305` (IETF / RFC 8439, 96-bit nonce) optional.
    - KDF: `HKDF-SHA-256`.
2. **Link policy**
    - Untrusted/public links: S2 required.
    - Trusted internal links: S1 allowed only with documented exception policy.
3. **Identity and replay**
    - Stable authenticated writer identity required.
    - `writer_identity_mode` MUST be `key-scoped` (one active key context per writer identity).
    - Replay and nonce tracking per `(writer_identity, key_id, direction, channel)`.
    - If windowed replay mode is enabled, default `W=64` applies unless profile overrides it explicitly.
    - Replay state persistence across restart, or forced pre-accept key rotation.
4. **Policy strictness defaults**
    - Hardened receivers MUST reject non-zero reserved structural cells (`E_RESERVED_POLICY`) as defined by [Section 4](#reserved-term-boundaries-normative).
    - Hardened receivers MUST reject structural integer `-0.0` values in Bands `0`, `6T`, and `7`.
5. **Key lifecycle**
    - Implement `pre-active|active|draining|revoked` states.
    - Normal rotation <= 24h (internet-facing default).
    - Emergency rotation RTO <= 5 minutes (recommended).
6. **Implementation safeguards**
    - Constant-time tag comparison.
    - Fail-closed verification path.
    - Relay tier without writer keys.
7. **Monitoring and response**
    - Emit security events from [Section 13](#13-receiver-validation-pipeline-normative).
    - Alert on repeated tag mismatch/replay/nonce-reuse.
    - Quarantine writer identities exceeding policy thresholds.

Canonical generic profile contract example (JSON):

```json
{
    "profile_id": 7,
    "profile_name": "example-control",
    "profile_version": "1.2.0",
    "digital_invalid_policy": "ignore_channel",
    "security": {
        "downlink": "s1",
        "uplink": "tls+mac",
        "mac_domain_tag": "DBP-S1\\u0000"
    },
    "band1_map": { "a0": "throttle", "a1": "gain" },
    "digital_msg_types": [1, 2, 3],
    "qubit_assignments": { "freshness": 62, "observation": 63 },
    "quantum": {
        "epsilon": 1e-4,
        "amplitude_sign_policy": "nonnegative"
    }
}
```

Canonical hardened profile contract example (JSON):

```json
{
    "profile_id": 17,
    "profile_name": "example-hardened-control",
    "profile_version": "1.0.0",
    "profile_class": "dbp-hardened-v1",
    "digital_invalid_policy": "reject_frame",
    "security": {
        "downlink": "s2",
        "uplink": "tls+s1-mac",
        "s2_cipher": "AES-256-GCM",
        "kdf": "HKDF-SHA-256",
        "kem": "ML-KEM-768",
        "key_scope": "per-writer",
        "handshake_profile": "dbp-hs1",
        "mac_domain_tag": "DBP-S1\\u0000",
        "rotation": {
            "normal_hours": 24,
            "emergency_rto_seconds": 300
        }
    },
    "identity": {
        "writer_identity_mode": "key-scoped",
        "replay_scope": "writer_identity,key_epoch,key_id,direction,channel"
    },
    "security_events": [
        "DBP_SEC_REPLAY_REJECT",
        "DBP_SEC_TAG_MISMATCH",
        "DBP_SEC_NONCE_REUSE"
    ]
}
```

### 16.3 DBP Hardened S2 + MUX Profile (normative template)

Profiles that claim `dbp-hardened-s2-mux` MUST satisfy all of the following:

1. **Security floor**
    - `security.downlink = s2` only.
    - Sticky S2 policy enabled (no downgrade after acceptance for `(writer_identity, key_epoch)`).
    - `digital_invalid_policy` MUST be declared; `reject_frame` is RECOMMENDED for command-bearing profiles.
2. **Suite/epoch agility**
    - `suite_id` present and enforced.
    - `key_epoch` present, monotonic, and validated.
3. **Handshake and key derivation**
    - DBP-HS1 handshake profile from [Section 8](#8-security-profiles) (or equivalent output-contract handshake) is required.
    - Handshake transcript MUST bind `writer_identity`, `suite_id`, `key_epoch`, `key_id`, `direction_mask`, `channel_id`, and profile id.
4. **Identity handle requirement**
    - `writer_identity_mode` MUST be `key-scoped`.
    - Replay/nonce partitioning MUST include `(writer_identity,key_epoch,key_id,direction,channel)`.
5. **MUX requirements**
    - Fixed MCB at cells `660..683` with max 8 slice entries.
    - Preemption contract enabled.
    - `lane_type` registry includes optional `opaque_bytes` (S2-only).
6. **Operational controls**
    - DoS cost controls from [Section 13.1](#131-dos-cost-controls-normative) enabled.
    - Required security telemetry includes downgrade/suite/epoch events.

Canonical hardened S2+MUX profile contract example (JSON):

```json
{
    "profile_id": 23,
    "profile_name": "example-hardened-s2-mux",
    "profile_version": "1.0.0",
    "profile_class": "dbp-hardened-s2-mux",
    "digital_invalid_policy": "reject_frame",
    "security": {
        "downlink": "s2",
        "uplink": "tls+s1-mac",
        "suite_id": 2,
        "s2_cipher": "ChaCha20-Poly1305",
        "kdf": "HKDF-SHA-256",
        "handshake_profile": "dbp-hs1",
        "hybrid_handshake": "ml-kem-768+x25519",
        "replay_window": 64,
        "sticky_s2": true
    },
    "identity": {
        "writer_identity_mode": "key-scoped",
        "replay_scope": "writer_identity,key_epoch,key_id,direction,channel"
    },
    "adaptive_mux": {
        "enabled": true,
        "mcb_location": "band6:660-683",
        "slice_max": 8,
        "lane_types": ["digital_u24", "analog_f32", "quantum_pair", "opaque_bytes"],
        "preemption": "native_wins"
    }
}
```

### 16.4 Profile contract schema requirements

Profile contracts SHOULD be validated against a machine-readable schema.

Reference artifact set (repository contract):
- Schema file: `protocol/profiles/schema/dbp-profile.schema.json`
- Registry contracts: `protocol/profiles/dbp-core.json`, `protocol/profiles/dbp-hardened-v1.json`, `protocol/profiles/dbp-hardened-s2-mux.json`
- Validator script: `protocol/scripts/validate_profiles.mjs`
- CI gate: `.github/workflows/profile-contracts.yml` runs `npm --prefix protocol run profiles:validate` and MUST fail on malformed profile contracts.

Minimum schema requirements:
- `profile_id` integer in `[1..255]`
- `profile_name` non-empty string
- `profile_version` semantic-version string
- `digital_invalid_policy` enum `{ignore_channel,reject_frame}` (default if omitted: `ignore_channel`)
- `security.downlink` enum: `{open,s1,s2}`
- `security.uplink` enum: `{tls,tls+mac,tls+s1-mac}`
- If `profile_class = dbp-hardened-v1`, then:
    - `digital_invalid_policy` MUST be present (explicit policy selection required)
    - `security.downlink` MUST equal `s2`
    - `identity.writer_identity_mode` MUST equal `key-scoped`
    - `identity.replay_scope` MUST include `writer_identity,key_id,direction,channel`
    - `security.key_scope` MUST equal `per-writer`
    - `security.handshake_profile` MUST equal `dbp-hs1` (or declare equivalent output-contract handshake)
    - `security.rotation.normal_hours` and `security.rotation.emergency_rto_seconds` MUST be present

- If `profile_class = dbp-hardened-s2-mux`, then:
    - `digital_invalid_policy` MUST be present (explicit policy selection required)
    - `security.downlink` MUST equal `s2`
    - `security.suite_id` MUST be present
    - `security.handshake_profile` MUST equal `dbp-hs1` (or declare equivalent output-contract handshake)
    - `identity.replay_scope` MUST include `writer_identity,key_epoch,key_id,direction,channel`
    - `security.key_scope` MUST equal `per-writer`
    - `adaptive_mux.enabled` MUST equal `true`
    - `adaptive_mux.mcb_location` MUST equal `band6:660-683`
    - `adaptive_mux.slice_max` MUST be in `[1..8]`
    - if ratchet mode is enabled by `suite_id`, profile MUST define `security.ratchet_max_skip`
    - if `opaque_bytes` is present in `adaptive_mux.lane_types`, profile MUST declare `security.downlink = s2`

- If profile enables ABB, contract MUST define:
    - `adaptive_mux.enabled = true`
    - `adaptive_mux.manifest_location`
    - `adaptive_mux.allowed_donor_bands`
    - `adaptive_mux.lane_types`
    - `adaptive_mux.fallback_policy` (`ignore_abb` or `reject_frame`)

Implementations SHOULD reject malformed contracts before runtime activation.

---

## 17) Conformance test matrix (minimum)

Implementations SHOULD include repeatable tests for:

1. **Endian conformance:** round-trip known frame bytes on little/big-endian hosts
2. **Numeric rejection:** Open/S1 frames containing `NaN/Inf/subnormals` are rejected; S2 enforces this on decrypted plaintext for cells `9..999` and on cleartext structural cells pre-decrypt
3. **Magic split:** parser dispatches correctly between `0xDB01` and `0xDB11`
4. **Header decode:** version, tick_rate, and split timestamp decode accurately
5. **CRC check:** corrupted payload bytes fail CRC
6. **Digital chunking:** out-of-order chunks reassemble correctly
7. **Quantum normalization:** qubit pairs violating $|\alpha^2+\beta^2 - 1| \leq \varepsilon$ ([Section 6.3](#63-band-4-quantum-register-cells148275)) are rejected or renormalized per policy
8. **Replay defense (S1/S2 when implemented):** repeated or stale counters are rejected
9. **Waveform gating:** reader reuses prior waveform when flag is clear
10. **Replay durability:** anti-replay state survives restart or `key_id` is rotated on restart
11. **S2 nonce safety:** duplicate nonce under same key is detected/rejected in tests
12. **S2 scope checks:** AAD/ciphertext boundaries match [Section 8](#8-security-profiles) and tampering is detected
13. **Key-state enforcement:** `revoked` keys are rejected and `draining` windows are honored
14. **Rotation race handling:** overlapping key rollover does not admit stale-frame replay
15. **Constant-time verify path:** tag verification behavior does not branch on partial match
16. **Hardened-link policy:** untrusted link configuration rejects S1-only emitters
17. **ABB manifest integrity:** invalid/missing manifest is rejected or ignored per fallback policy
18. **ABB donor checks:** donor preconditions are enforced before borrowed-slice decode
19. **Sticky S2 policy:** once peer tuple is marked S2-required, `sec_profile!=2` is rejected and incident telemetry is emitted
20. **Suite agility checks:** unknown/disallowed `suite_id` is rejected deterministically
21. **Key-epoch monotonicity:** rollback or invalid `key_epoch` transitions are rejected per policy
22. **MCB structural checks:** fixed-location MCB bounds, CRC, and slice-table decoding are validated
23. **Preemption contract:** native-band activation deterministically preempts colliding leases
24. **Opaque-lane scope:** S2 `opaque_bytes` slices bypass Float32 numeric checks while non-opaque plaintext still enforces finite/subnormal policy
25. **Ratchet skip handling:** receiver fast-forward and `MAX_SKIP` rejection/resync behavior is deterministic across sequence gaps
26. **MCB timing safety:** MCB parsing/validation is not performed before successful S2 AEAD verify+decrypt
27. **HS1 transcript binding:** transcript mismatch on bound fields fails handshake deterministically
28. **HS1 key-epoch persistence:** handshake acceptance enforces persisted monotonic `key_epoch` policy

### 17.1 Deterministic conformance vector (v1.1 + S1)

Use this vector to validate end-to-end packing, MAC scope, tag packing, and CRC ordering.

Companion full byte dump (machine-readable fixture):
- See [dbp_s1_fixture.json](dbp_s1_fixture.json).

**Frame setup (all unspecified cells are `+0.0`):**
- Band 0: `magic=56081`, `version=11`, `seq_lo=1`, `seq_hi=0`, `unix_day=20000`, `sec_of_day=12345`, `ms=678`, `flags_profile=32` (`SEC_TRAILER_PRESENT`), `tick_rate=2`
- Band 6T metadata: `sec_profile=1`, `key_id=1`, `sec_counter_lo=1`, `sec_counter_hi=0`
- S1 key bytes: 32 bytes of `0x11`
- `mac_domain_tag` bytes: ASCII `"DBP-S1\0"`

**Computation order:**
1. Compute HMAC-SHA-256 over `mac_domain_tag ||` wire bytes for cells `0..1003` (bytes `0..4015`)
2. Pack tag into `tag_u16[16]` (cells `1004..1019`) via little-endian word packing
3. Compute CRC32/ISO-HDLC over cells `0..1019` (bytes `0..4079`)
4. Write `crc_lo`, `crc_hi`, `byte_size=4096`, `magic_echo=56081`

**Expected outputs:**
- `fixture_id`: `dbp-v1.1-s1-hmac-fixture-1`
- `tag_bytes` (hex): `8c4ae150702ce62e421f78fb27d556845b5722397832020601952473c6959e66`
- `tag_u16[16]` (decimal): `19084,20705,11376,12006,8002,64376,54567,33878,22363,14626,12920,1538,38145,29476,38342,26270`
- `CRC32` (hex): `0x0015E7B9`
- `crc_lo`: `59321`
- `crc_hi`: `21`
- Full frame SHA-256 (4096 bytes): `fdcec2cd421b091e281ee15e6ae2916c8ce04052d898812280fb62fd1d087fc0`
- First 64 bytes (hex): `00115b47000030410000803f0000000000409c4600e4404600802944000000420000004000000000000000000000000000000000000000000000000000000000`
- Full frame bytes (hex): see fixture field `outputs.frame_hex`.

If any value differs, re-check endianness, canonical integer-as-float decoding, MAC/CRC byte ranges, and the "verify before canonicalization" rule for `-0.0`.

### 17.2 Deterministic conformance vector (v1.1 + Open mode)

Use this vector to validate the no-trailer path (effective `sec_profile = 0`) and deterministic CRC behavior when Band 6T is zero-filled.

**Frame setup (all unspecified cells are `+0.0`):**
- Band 0: `magic=56081`, `version=11`, `seq_lo=2`, `seq_hi=0`, `unix_day=20000`, `sec_of_day=12346`, `ms=679`, `flags_profile=0` (`SEC_TRAILER_PRESENT` clear), `tick_rate=2`
- Band 6T: all cells `1000..1019` are `+0.0`

**Computation order:**
1. Canonicalize `-0.0` to `+0.0` (deterministic writer hygiene; see [Section 14.4](#144-atomic-publish-policy))
2. Ensure Band 6T is zero-filled because `SEC_TRAILER_PRESENT` is clear
3. Compute CRC32/ISO-HDLC over cells `0..1019` (bytes `0..4079`)
4. Write `crc_lo`, `crc_hi`, `byte_size=4096`, `magic_echo=56081`

**Expected outputs:**
- `CRC32` (hex): `0x374F4EED`
- `crc_lo`: `20205`
- `crc_hi`: `14159`
- Full frame SHA-256 (4096 bytes): `777c131b7c0d49385f4e1e5e1c739dee4981fafec8787fa142fb0476f4dcb7c8`
- First 64 bytes (hex): `00115b4700003041000000400000000000409c4600e8404600c02944000000000000004000000000000000000000000000000000000000000000000000000000`

If any value differs, re-check Band 6T zero-fill behavior, footer write order, CRC input span (`0..4079`), and little-endian wire serialization.

### 17.3 Reference verifier recommendation

Implementations SHOULD ship a tiny reference verifier (e.g., Node.js script) that reconstructs deterministic vectors, computes HMAC-SHA-256 over `mac_domain_tag || bytes[0..4015]`, computes CRC32/ISO-HDLC over bytes `0..4079`, and checks expected tag/CRC outputs. CI SHOULD run this verifier on every change affecting protocol logic or fixtures and MUST fail on mismatches to prevent vector drift. For v1.1, the verifier SHOULD load both [dbp_s1_fixture.json](dbp_s1_fixture.json) and [dbp_s2_fixture.json](dbp_s2_fixture.json) as authoritative machine-readable vector sources.

### 17.4 Deterministic conformance vector (v1.1 + S2 AES-256-GCM fixture)

Use fixture id `dbp-v1.1-s2-aes256gcm-fixture-1` for end-to-end validation of S2 AAD scope, ciphertext scope, nonce/tag packing, and CRC ordering.

Companion full byte dump (AAD + full ciphertext hex):
- See [dbp_s2_fixture.json](dbp_s2_fixture.json).

**Frame setup (all unspecified plaintext cells are `+0.0` before S2 encryption):**
- Band 0: `magic=56081`, `version=11`, `seq_lo=3`, `seq_hi=0`, `unix_day=20000`, `sec_of_day=12347`, `ms=680`, `flags_profile=32` (`SEC_TRAILER_PRESENT`), `tick_rate=2`
- Band 6T metadata: `sec_profile=2`, `key_id=1`, `sec_counter_lo=1`, `sec_counter_hi=0`
- Replay semantics: for counter-based suites, canonical replay source is `ctr64 = LE_U64(nonce96[4..11])`; `sec_counter_lo/hi` are low-32 mirror telemetry (`ctr64 & 0xFFFFFFFF`). This fixture uses `nonce_source_mode=explicit`, so mirror equality is documented but not the primary fixture pass criterion.

**KDF + AEAD inputs:**
- Cipher: `AES-256-GCM`
- HKDF: `hash=SHA-256`
- `ikm_hex`: `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`
- `salt_utf8`: `dbp-s2-fixture-salt-v1`
- `info_utf8`: `dbp-s2-fixture-aes-256-gcm-key`
- `nonce96_hex`: `0001000100cafe0100010001`

**AAD and ciphertext scope (normative):**
- `AAD` byte range: cells `0..8`, `1000..1003`, and `1018..1019` (60 bytes)
- `AAD` exact concatenation order: `bytes(cells[0..8]) || bytes(cells[1000..1003]) || bytes(cells[1018..1019])`
- `AAD` hex (60 bytes): `00115b4700003041000040400000000000409c4600ec404600002a440000004200000040000000400000803f0000803f000000000000000000000000`
- `AAD` SHA-256: `6dc5620a73d7717ddfebecbfd2dd1201a706586efec627fbb956e66d7a3a6f4a`
- `Ciphertext` byte range: cells `9..999` (3964 bytes)
- `Ciphertext` first 64 bytes (hex): `0d473591fe4314fb8a81f8a56d308b6c540937691f09cd784d2a4a77aa8541be39c195e11ee9fb845dff699d6f7c275e97ca9987793b555c0a01968b815a5563`
- `Ciphertext` SHA-256: `64b9f5c0f903c60167a39455545df3ee2e6d79853b1fed27bef8d2f4491cf9c4`

**Computation order:**
1. Build cleartext frame and write cells `1000..1003`
2. Derive 32-byte AEAD key using HKDF inputs above
3. Encrypt cells `9..999` with AES-256-GCM using AAD over cells `0..8` + `1000..1003` + `1018..1019`
4. Write `sec_words[0..5]` from `nonce96` and `sec_words[6..13]` from `aead_tag128` (little-endian u16 packing)
5. Write `sec_words[14..15] = 0`
6. Compute CRC32/ISO-HDLC over bytes `0..4079` (cells `0..1019`, ciphertext on wire)
7. Write footer (`crc_lo`, `crc_hi`, `byte_size=4096`, `magic_echo=56081`)

**Expected outputs:**
- `fixture_id`: `dbp-v1.1-s2-aes256gcm-fixture-1`
- `nonce96_hex`: `0001000100cafe0100010001`
- `aead_tag128_hex`: `37cb5231f0c9ec15b8e567420b54b2cf`
- `sec_words[0..13]` (decimal): `256,256,51712,510,256,256,52023,12626,51696,5612,58808,16999,21515,53170`
- `ciphertext_first64_hex`: `0d473591fe4314fb8a81f8a56d308b6c540937691f09cd784d2a4a77aa8541be39c195e11ee9fb845dff699d6f7c275e97ca9987793b555c0a01968b815a5563`
- Full ciphertext bytes (hex): see fixture field `ciphertext.hex`.
- `CRC32` (hex): `0xDAA5DE96`
- `crc_lo`: `56982`
- `crc_hi`: `55973`
- Full frame SHA-256 (4096 bytes): `72736e5165fdd502bc84e977ef3bddfd1c0a49b42176ca3083d5b01c3cd7d8b8`
- First 64 bytes (hex): `00115b4700003041000040400000000000409c4600ec404600002a4400000042000000400d473591fe4314fb8a81f8a56d308b6c540937691f09cd784d2a4a77`

Verification rule:
- Two independent implementations MUST reproduce identical `sec_words[0..13]`, footer CRC, and frame SHA-256 from the fixture inputs above.
- For counter-based suite operation outside explicit-nonce fixture mode, implementations MUST use `ctr64 = LE_U64(nonce96[4..11])` as replay source and treat `sec_counter_lo/hi` as low-32 mirror telemetry only.

### 17.5 Deterministic policy vector (`suite_id` / `key_epoch`, `dbp-hardened-s2-mux`)

Use this vector to validate trailer decode and hardened policy decisions (suite acceptance, epoch monotonicity, sticky-S2 behavior).

**Assumed receiver state before case evaluation:**
- `profile_class = dbp-hardened-s2-mux`
- known/allowed suites: `{1,2,3,4,5,6}`
- last accepted tuple state for `writer_identity = W1`: `requires_s2=true`, `last_key_epoch=41`

**Common frame skeleton for all cases:**
- `SEC_TRAILER_PRESENT=1` unless explicitly stated otherwise
- `sec_profile=2` unless explicitly stated otherwise
- `key_id=7`
- replay counter source strictly increasing (`ctr64` for `session_salt32||sec_counter64_le` suites; otherwise profile-defined monotonic source)

**Cases (expected result is normative):**

| Case | Trailer fields | Expected decision | Expected code/event |
|---|---|---|---|
| A (valid advance) | `sec_words[14]=6` (`suite_id=6`), `sec_words[15]=42` (`key_epoch=42`) | Accept (all other checks pass) | none |
| B (unknown suite) | `sec_words[14]=99`, `sec_words[15]=42` | Reject | `E_S2_SUITE`, `DBP_SEC_S2_SUITE_REJECT` |
| C (epoch rollback) | `sec_words[14]=6`, `sec_words[15]=40` | Reject | `E_KEY_EPOCH`, `DBP_SEC_KEY_EPOCH_ROLLBACK` |
| D (epoch repeat policy violation) | `sec_words[14]=6`, `sec_words[15]=41` with policy requiring strictly increasing epoch per acceptance window | Reject | `E_KEY_EPOCH` |
| E (downgrade attempt) | `SEC_TRAILER_PRESENT=1`, `sec_profile=1`, previous `requires_s2=true` | Reject | `E_POLICY_DOWNGRADE`, `DBP_SEC_DOWNGRADE_ATTEMPT` |
| F (trailer removed) | `SEC_TRAILER_PRESENT=0`, previous `requires_s2=true` | Reject | `E_POLICY_DOWNGRADE`, `DBP_SEC_DOWNGRADE_ATTEMPT` |

Decoder checks for this vector:
- `suite_id = decodeU16(frame[1018])` from `sec_words[14]`
- `key_epoch = decodeU16(frame[1019])` from `sec_words[15]`
- apply sticky-S2 and epoch monotonic policy before accepting band semantics.

### 17.6 Wire image examples (human-auditable)

The following first-64-byte wire images are canonical quick-audit snapshots for each primary mode:

| Mode | First 64 bytes hex |
|------|---------------------|
| Open (`sec_profile=0`) | `00115b4700003041000000400000000000409c4600e8404600c02944000000000000004000000000000000000000000000000000000000000000000000000000` |
| S1 (`sec_profile=1`) | `00115b47000030410000803f0000000000409c4600e4404600802944000000420000004000000000000000000000000000000000000000000000000000000000` |
| S2 (`sec_profile=2`) | `00115b4700003041000040400000000000409c4600ec404600002a4400000042000000400d473591fe4314fb8a81f8a56d308b6c540937691f09cd784d2a4a77` |

All three examples use:
- little-endian Float32 wire encoding;
- cell-aligned offsets (`cell i -> bytes[4*i..4*i+3]`);
- footer-integrity ordering from [Section 14.4](#144-atomic-publish-policy).

### 17.7 One-command smoke test (reference workflow)

Minimal smoke test for CI (fixture files and `dbp_verify.mjs` present in `protocol/`):

```bash
cd protocol && node dbp_verify.mjs
```

Passing output MUST include:
- S1 deterministic `tag_hex` and `crc_hex` from [Section 17.1](#171-deterministic-conformance-vector-v11-s1)
- `s2_fixture_ok dbp-v1.1-s2-aes256gcm-fixture-1`
- policy-vector `A..F` pass lines from [Section 17.5](#175-deterministic-policy-vector-suiteid-keyepoch-dbp-hardened-s2-mux)
- `HS1 handshake fixture (dbp-v1.1-hs1-hybrid-fixture-1)`

### 17.8 Minimum passing matrix

| Decoder capability | Minimum required passing vectors/tests |
|-------------------|----------------------------------------|
| Open-only decoder | [Section 17.2](#172-deterministic-conformance-vector-v11-open-mode) + shape/magic/footer/CRC rejects (`E_SHAPE`, `E_MAGIC`, `E_FOOTER`, `E_CRC`) |
| S1-capable decoder | Open-only set + [Section 17.1](#171-deterministic-conformance-vector-v11-s1) + replay checks (`E_REPLAY`) + S1 tag checks (`E_S1_TAG`) |
| S2-capable decoder | S1-capable set + [Section 17.4](#174-deterministic-conformance-vector-v11-s2-aes-256-gcm-fixture) + [Section 17.5](#175-deterministic-policy-vector-suiteid-keyepoch-dbp-hardened-s2-mux) + S2 nonce/suite/epoch policy checks (`E_S2_NONCE_REUSE`, `E_S2_SUITE`, `E_KEY_EPOCH`, `E_POLICY_DOWNGRADE`) |
| Hardened S2+MUX decoder | S2-capable set + HS1 handshake fixture/vector checks + ABB/MCB tests (`E_ABB_MANIFEST`, `E_ABB_DONOR_STATE`, `E_MCB_INVALID`) + `opaque_bytes` ordering checks |

### 17.9 Fixture versioning policy (normative)

- Deterministic fixtures MUST be versioned with explicit `fixture_id` carrying protocol line and mode (for example `dbp-v1.1-s2-aes256gcm-fixture-1`).
- Any normative change to authenticated scope, nonce packing, trailer semantics, integrity byte ranges, or handshake transcript/key-schedule rules MUST mint a new fixture id/version; existing fixture ids are immutable.
- Implementations SHOULD retain previous fixture generations for backward regression testing when rolling parser/security updates.

### 17.10 Deterministic handshake vector (DBP-HS1 hybrid fixture)

Use fixture id `dbp-v1.1-hs1-hybrid-fixture-1` for deterministic validation of transcript binding, HKDF labels, and Finish confirmation tags.

Companion fixture:
- See [dbp_handshake_fixture.json](dbp_handshake_fixture.json).

Required checks:
1. Re-encode `ClientHello` and `ServerHello` bytes exactly from fixture inputs.
2. Recompute `transcript_sha256 = SHA-256(client_hello_raw || server_hello_raw)`.
3. Recompute DBP-HS1 context bytes and key schedule outputs (`downlink_key`, `uplink_key`, `downlink_salt32`, `uplink_salt32`, `confirm_tag`).
4. Rebuild `Finish` and verify transcript hash + confirm tag with constant-time compare.

Expected outputs are fixture-authoritative. Any mismatch is a conformance failure.

---

## 18) Versioning notes (first publication)

- This document defines the first published implementation.
- Parser selection MUST rely on `magic` parser split, not heuristics.
- Unknown future profile IDs SHOULD be treated as generic/core-only unless explicitly supported.
- Future revisions SHOULD preserve deterministic conformance vectors for regression verification.
- Draft clarification: S2 AAD scope binds trailer policy cells `1018..1019` (`suite_id`/`key_epoch` in hardened profiles), and deterministic S2 fixture outputs are updated accordingly.

---

## 19) Security hardening checklist (operational)

- Use TLS for all transports
- Enforce strict origin policy (avoid permissive wildcard origins in production)
- Rate-limit uplink writes per client identity and source
- Rotate keys (`key_id`) on schedule and incident response
- Bind replay windows to replay domain `(writer_identity,key_epoch,key_id,direction,channel)` + counter monotonicity
- Log verification failures with coarse-grained reason codes
- Use short key lifetimes for internet-facing links (default <= 24h) and test emergency rotation drills
- Persist anti-replay/nonce state to durable storage or force key rotation on restart
- Alarm on `E_S2_NONCE_REUSE`, repeated `E_S2_TAG`, and downgrade attempts (`E_POLICY_DOWNGRADE`)
- Keep relay/fanout tiers keyless; only trusted writer tier may hold signing/encryption keys
- Verify ABB manifest integrity/bounds before donor-band decode and enforce fallback policy deterministically

---

## 20) v2.0 migration trigger and scope

DBP v1.1 is intentionally constrained. Move to v2.0 when one or more conditions hold:

- repeated need for new multi-cell packing tricks
- requirement for richer nested structures than digital chunk lanes can safely carry
- need for larger authenticated trailers or multiple independent crypto envelopes
- requirement for strong typed evolution with optional fields

Recommended v2.0 direction:
- schema-based binary format with explicit field IDs and versioned optional fields
- retain conceptual bands at semantic level for continuity where useful

---

## 21) How DBP compares to other protocols

| Protocol | Model | Strengths | DBP difference |
|----------|-------|-----------|----------------|
| HTTP/SSE | request/response + server push | ubiquitous, text-friendly | DBP: binary, multiplexed, fixed-size |
| WebSocket | full-duplex frames | low-latency, binary capable | DBP: structured bands, no framing negotiation |
| MQTT | pub/sub topics | lightweight IoT messaging | DBP: continuous signal, not message-oriented |
| gRPC/Protobuf | RPC + streaming | schema-strict, code generation | DBP: fixed-offset, zero-allocation, no codegen required |
| CAN Bus | automotive signal bus | real-time, deterministic | DBP: software-only, larger frame, quantum register |
| **DBP** | **positional multiplexed signal** | **all three signal types simultaneously** | - |

DBP's closest conceptual relatives are radio-frequency multiplexing and CAN bus arbitration - data is separated by position within a continuous frame, not by message boundaries or topic strings.

---

## 22) Quantum register - detailed specification

### 22.1 State representation

Each qubit occupies two consecutive cells:

$$
|\psi\rangle = \alpha|0\rangle + \beta|1\rangle
$$

- Cell `148 + 2*q` = $\alpha$ (amplitude of $|0\rangle$)
- Cell `148 + 2*q + 1` = $\beta$ (amplitude of $|1\rangle$)

Amplitude sign convention is profile-defined ([Section 6.3](#63-band-4-quantum-register-cells148275)). In the default `nonnegative` policy, writers SHOULD encode `alpha, beta >= 0` for equivalent probabilities.

where `q` is the qubit index (0..63).

### 22.2 Writing a probability into a qubit

Given a scalar probability `p` (0.0 to 1.0) that a condition is true:

Writers MUST clamp `p` into `[0, 1]` before encoding to avoid `NaN` from `sqrt` of a negative value (which would violate [Section 1](#1-design-goals-and-constraints) hard constraints).

```
alpha = sqrt(1.0 - p)
beta = sqrt(p)
```

### 22.3 Reading a scalar from a qubit

Clients MUST use $\beta^2$ to recover the probability. Do NOT use $\beta$ directly.

```js
function getQubitProbability(frame, qubitIndex) {
    const beta = frame[148 + 2 * qubitIndex + 1];
    return beta * beta;  // beta^2 = probability of |1>
}
```

### 22.4 Freshness decay model (qubit 62)

Freshness indicates how recently the register was recomputed:

$$
\mathrm{freshness} = 0.5^{\,\mathrm{age} / T_{half}}
$$

where $T_{half}$ is a profile-defined half-life (e.g. 30 seconds). Clients SHOULD discount predictions when freshness is low.

```
age = now - last_computed_at
freshness = pow(0.5, age / half_life)
cell[272] = sqrt(1.0 - freshness)   // alpha
cell[273] = sqrt(freshness)          // beta
```

### 22.5 Observation count (qubit 63)

Encodes writer-maintained observation density/count telemetry as a saturating probability from receiver `measure()` / `sample()` activity reports:

$$
p = \frac{\min(\mathrm{count},\, N_{max})}{N_{max}}
$$

where $N_{max}$ is a profile-defined ceiling (e.g. 1000). High observation count ($\beta \to 1$) indicates a well-exercised register.

This is not auto-mutated by receiver-local `measure()` calls. If profiles want client observations reflected on the bus, clients MUST transmit measurement events via profile-defined uplink and the writer MUST re-emit updated telemetry.

### 22.6 Measurement - formal collapse rules

1. **Probabilistic sample/collapse:** `sample(q)` (a.k.a. `measure(q)`) returns 1 with probability $\beta^2$, else 0. Post-sample the qubit is in a classical interpretation state - subsequent reads return the interpreted value. **Collapse is a receiver-local interpretation step;** it does not mutate the shared frame. The interpreted/collapsed state only propagates if the profile explicitly writes it back into a subsequent frame.

**Interpretation-only semantics (non-normative for core wire conformance):** Rules 2 and 3 below describe receiver-local interpretation behavior. They impose no requirements on the wire frame itself and are not enforceable from wire bytes alone.

2. **Correlated partner collapse (profile-defined interpretation):** If qubit `q` has an entangled partner `r` with correlation strength $C$ (0.0-1.0):
   - $C > 0.5$: partner collapses to the **same** result with probability $C$
   - $C < 0.5$: partner collapses to the **opposite** result with probability $1 - C$
   - $C = 0.5$: no correlation (maximally uncorrelated)

3. **No transitive chaining (profile-defined interpretation):** If A<->B and B<->C, collapsing A affects B but MUST NOT propagate automatically to C.

4. **Observation telemetry ownership:** receiver-local `sample()/measure()` does not mutate the shared frame. Any change to qubit 63 requires an explicit profile write-back path via writer logic.

### 22.7 Correlation strength `C`

`C` is **not transmitted** in the frame. It is defined out-of-band by the profile (static config or config endpoint). If dynamic correlation is needed, a profile MAY reserve a dedicated cell or digital message for per-pair `C` values.

Because entanglement topology and `C` are out-of-band in v1.1, these collapse/correlation rules are not core wire-level conformance checks by themselves.

### 22.8 Measurement determinism

`sample()`/`measure()` uses client-side randomness by default. Two clients sampling the same qubit may get different results - acceptable for UI predictions but NOT for shared-state consensus.

This is a profile interpretation behavior, not a core wire-conformance rule, unless a profile explicitly defines synchronized sampling/write-back semantics.

- For per-client stable UX determinism, seed PRNG with `(frame_seq, qubit_id, client_id)`.
- For shared deterministic outcomes across clients, seed PRNG with `(frame_seq, qubit_id)` (exclude `client_id`).

### 22.9 Normalization enforcement

Writers MUST ensure $|\alpha^2 + \beta^2 - 1| \leq \varepsilon$ (recommended $\varepsilon = 10^{-4}$ for Float32) for every qubit (see [Section 6.3](#63-band-4-quantum-register-cells148275)). Readers MUST apply the profile-defined policy `{reject | renormalize | clamp+renormalize}` when this constraint is violated.

Renormalization (if permitted by profile):

```js
const mag = Math.sqrt(alpha * alpha + beta * beta);
if (mag > 0) { alpha /= mag; beta /= mag; }
else { alpha = 1.0; beta = 0.0; }  // default to |0>
```

---

## 23) Transport layer - detailed architecture

### 23.1 Phase 1 - Static file relay (pull)

```
Writer (1 process)          Static server (nginx)         Clients (N)
+----------------+           +--------------------+        +---------------+
| Build frame    |--write--->| /dbp/live/frame.bin|<---GET-| Conditional   |
| every tick     |           | 4096 bytes         |--304/-->| poll (ETag)  |
| (atomic swap)  |           | ETag + Last-Modified| 200   | every Nms     |
+----------------+           +--------------------+        +---------------+
```

**Cache validation:** Clients SHOULD prefer `If-None-Match` (ETag) over `If-Modified-Since`. ETag changes atomically on every `rename()` and is reliable at any frame rate. `Last-Modified` has ~1-second mtime granularity and will miss sub-second updates.

**Cost model:**
- 304 responses are ~100 bytes
- At 200 clients x 2 FPS = 400 req/s of tiny static responses - trivial for nginx
- Writer costs 1 process per tick regardless of client count

**Crash recovery:** If writer crashes between write and rename, orphaned `.tmp` files may remain. Writers SHOULD clean up stale temp files on startup.

### 23.2 Phase 2 - SSE relay (push fanout)

A lightweight process watches the static file and broadcasts changes:

```
Writer -> frame.bin -> [file watcher] -> SSE broadcast -> N clients
```

- One relay process handles ~5,000-10,000 concurrent SSE connections
- Latency: <50ms from write to all clients
- Memory: ~5-20MB for the relay process
- Beyond ~10k clients: use multiple relay instances behind a load balancer with shared message bus (e.g. Redis pub/sub)

### 23.3 Phase 3 - Native pub/sub (nchan, WebSocket)

For 100k+ clients:
- Writer POSTs frame to nchan internal pub endpoint
- nchan distributes natively to SSE/WebSocket/long-poll subscribers
- Requires nchan-enabled nginx or a dedicated WebSocket server (Go, Rust, Node.js)

### 23.4 Base64 transport (SSE/text channels)

When transporting via text-only channels (SSE `data:` field, JSON embedding), the frame is base64-encoded:

Canonical length formula: `base64_len(n) = 4 x ceil(n / 3)`.

For a full DBP frame: `base64_len(4096) = 4 x ceil(4096/3) = 4 x 1366 = 5464` characters.

### 23.5 Nginx location block (reference)

```nginx
location = /dbp/live/frame.bin {
    alias /path/to/frame.bin;

    etag on;
    if_modified_since exact;
    add_header Cache-Control "no-cache, must-revalidate";
    add_header X-Content-Type-Options "nosniff";
    add_header Access-Control-Allow-Origin "https://yourdomain.example";
    add_header Access-Control-Expose-Headers "ETag, Last-Modified";

    default_type application/octet-stream;
}
```

### 23.6 HTTP Uplink Compact Transport Profile

```
POST /dbp/uplink
Content-Type: application/octet-stream
Body: Float32Array(340).buffer  (1360 bytes, Band 6 only)
```

This compact uplink payload is not a DBP frame; it is a profile-defined transport message that reuses Band 6 layout.

Servers MAY accept full 4096-byte frames or Band 6-only payloads.

For ABB-enabled profiles, full-frame uplink SHOULD be supported so clients can borrow donor bands symmetrically and increase bi-directional throughput.

In S1 mode, uplink authentication is handled at the transport layer (see [Section 8](#8-security-profiles), "HTTP Uplink Compact Transport Profile (authentication)"), not via in-frame trailer.

---

## 24) Optimistic local state (latency masking)

For pull-based transports, there is inherent latency between a command and its visible effect. Clients SHOULD apply optimistic updates immediately and reconcile when the server confirms.

### Pattern

```js
// Issue command with optimistic local update
function issueCommand(field, value) {
    this._optimistic[field] = {
        value: value,
        seq: this._lastFrameSeq  // frame seq at command time
    };
    this.sendUplink(cmdId, value);
}

// Reconcile on frame arrival
function onFrame(frame) {
    const serverSeq = readSeq(frame);
    for (const key of Object.keys(this._optimistic)) {
        if (this._optimistic[key].seq < serverSeq) {
            delete this._optimistic[key];  // server has caught up
        }
    }
    this._lastFrameSeq = serverSeq;
}

// UI reads optimistic value first
function getValue(field) {
    return this._optimistic[field]?.value ?? this._serverState[field];
}
```

Optimistic state is cleared only when the server's sequence number advances past the command's origin sequence, preventing premature clearing from stale or out-of-order frames.

---

## 25) Multi-client broadcast rules

### 25.1 Downlink isolation

The shared downlink frame represents **global state only**. Writers MUST NOT embed any single client's uplink data into the broadcast frame - doing so leaks one client's state to all others.

### 25.2 Per-client responses

Per-client acknowledgements and results SHOULD be delivered via the POST response body (the HTTP response to the uplink), NOT via the shared downlink.

### 25.3 Per-client confidential data

If a profile requires per-client encrypted data in broadcast, use the digital channels with per-client AEAD envelopes (keyed per-client). Only the intended client can decrypt.

---

## 26) Desync detection and recovery

### 26.1 Mechanism

The uplink includes `last_seq_lo/hi` - the last downlink sequence the client received. The server compares this to its current sequence.

### 26.2 Detection

If the gap exceeds a threshold (e.g. ~10 frames), the client is desynced.

### 26.3 Recovery options

- **Full state push:** server sends a complete frame with all bands populated (waveform included, all flags set)
- **Resync flag:** define a flags bit to signal "this is a full-state resync frame"
- **Out-of-band:** return full state in the uplink POST response body

### 26.4 Uplink integrity

Uplink integrity is delegated to the transport layer:
- **TLS** protects the POST body against corruption and tampering in transit.
- **S1 application-layer MAC** (optional, see [Section 8](#8-security-profiles)) provides defense-in-depth via `X-DBP-Tag` HTTP header.
- **HTTP-layer checksums** (e.g. `Content-MD5`) MAY be used for cheap corruption telemetry on non-TLS links.

A dedicated in-frame uplink CRC is **not specified** - it would conflict with the `cmd_params` cell range in Band 6, and transport-layer integrity is more robust.

---

## 27) Scaling characteristics

| Metric | Value |
|--------|-------|
| Frame size | 4096 bytes (1024 x Float32) |
| Frame rate | configurable (2 FPS typical, up to 30+) |
| Bandwidth per client (2 FPS) | ~8 KB/s raw; ~200 B/s actual (mostly 304s) |
| Server-side writers needed | 1 per deployment |
| Concurrent readers | limited only by static server (thousands+) |
| Analog capacity | 395 continuous float channels (Bands 1 + 5) |
| Digital capacity | 336 bytes per frame (2 x 168-byte channels) |
| Quantum registers | 64 qubits (128 float cells) |
| Uplink capacity | 340 float cells per POST |
| Latency (Phase 1 poll) | <= poll interval (e.g. 500ms) |
| Latency (Phase 2 SSE) | <50ms |
| Latency (Phase 3 WS) | <10ms |

### 27.1 ABB throughput envelope (illustrative)

The following figures are illustrative estimates for `digital_u24` ABB payloads at 2 FPS.

| Mode | Digital bytes/frame | Approx bytes/sec |
|------|--------------------:|-----------------:|
| Base only (Bands 2+3) | 336 | 672 |
| Base + Band 5 lease | 1488 | 2976 |
| Base + Bands 4+5 | 1872 | 3744 |
| Base + Bands 4+5+6 | 2892 | 5784 |

Profiles SHOULD cap borrowed capacity by policy to avoid starving native analog/quantum semantics.

### Sequence number lifespan

| FPS | Wrap time (48-bit counter) |
|----:|----------------------------|
| 2   | ~4.5 million years         |
| 30  | ~297,000 years             |
| 60  | ~148,000 years             |

---

## 28) Float32 precision - detailed caveats

### 28.1 The core constraint

Float32 has a 23-bit mantissa (24-bit significand). All integers through $2^{24}$ are exactly representable, but contiguous integer exactness for protocol packing is the u24 range (`0..2^{24}-1`).

### 28.2 What this means for DBP

- **Sequence numbers** in a single cell would wrap at ~97 days at 2 FPS. v1.1 solves this with the `seq_lo/seq_hi` split.
- **Unix timestamps** (~1.7e9) cannot be stored in a single Float32 cell with sub-second precision. v1.1 solves this with `unix_day / sec_of_day / ms`.
- **CRC32 values** (up to ~4.3e9) exceed the exactness limit. v1.1 stores them as two u16 halves.

### 28.3 Safe integer ranges for common cell types

| Type label | Stored as | Exact range | Bits |
|------------|-----------|-------------|------|
| u16-as-float | Float32 | 0..65,535 | 16 |
| u24-as-float | Float32 | 0..16,777,215 | 24 |
| raw float | Float32 | +/-3.4e38 (with precision loss) | 24 significand |

### 28.4 Integer-as-float canonical decode rule

For all `u16-as-float` and `u24-as-float` fields, receivers MUST verify all of the following before casting:

1. **Finite:** the value is not `NaN` or `Infinity`.
2. **Not subnormal:** subnormal values MUST be rejected.
3. **Zero handling:** `+0.0` is valid zero; `-0.0` is accepted as zero by default unless a strict profile requires rejection for structural integer fields (Section 28.4.1).
   - Strict `-0.0` rejection MUST be implemented from the Float32 wire bit pattern (or an equivalent bit-exact representation), not from numeric-zero comparisons alone.
4. **Integral:** `x == trunc(x)` (no fractional part).
5. **In range:** `0 <= x <= 65535` for u16, `0 <= x <= 16777215` for u24.
6. **Round-trip exactness:** let `n = trunc(x)`. Decode is valid only if Float32 re-encoding of `n` equals the original decoded Float32 value `x`.

A value failing any check MUST be treated as frame corruption. This rule is referenced throughout the spec wherever integer-as-float cells appear.

Sender rule (normative): Senders MUST encode integer-as-float fields by assigning the integer numeric value and allowing normal Float32 conversion semantics. Senders MUST NOT generate these fields via bit-pattern reinterpretation/casting tricks.
Receiver rule (normative): Receivers MUST apply this canonical numeric decode rule to decoded float values and MUST NOT accept alternate integer encodings that require bit-pattern reinterpretation.

`round-trip exactness` test definition (normative):
- Decoder input `x` is already a decoded IEEE754 Float32 numeric value from wire bytes.
- Compute `n = trunc(x)` after finite/subnormal and range checks.
- Accept only if `Float32(n) == x`.
- Exactness MUST be evaluated at Float32 precision and MUST NOT rely on Float64 equality alone.
- JavaScript reference test: `Math.fround(n) === x`.
- C/C++ reference test: `(float)n == x`.

Implementation note (recommended, non-normative):
- If only a numeric Float32 value is available, use `x != 0 && abs(x) < 2^-126` as the subnormal predicate.
- For strict decoders, detect `subnormal`/`NaN`/`Infinity` from raw Float32 exponent/mantissa bits on the 32-bit wire word before numeric conversion, especially on SIMD/vectorized paths.

Strict `-0.0` wire-bit check (reference):

```text
bits = read_le_u32(cell_bytes)
is_neg_zero = ((bits & 0x7FFFFFFF) == 0) && ((bits & 0x80000000) != 0)
if strict_negzero && is_neg_zero: reject
```

```js
const MIN_NORMAL_F32 = 1.17549435e-38;

function decodeU16(x, { strictNegZero = false } = {}) {
    if (!Number.isFinite(x)) throw new Error('invalid u16-as-float (non-finite)');
    if (x !== 0 && Math.abs(x) < MIN_NORMAL_F32) throw new Error('invalid u16-as-float (subnormal)');
    if (strictNegZero && Object.is(x, -0)) throw new Error('invalid u16-as-float (-0.0)');
    if (x !== Math.trunc(x)) throw new Error('invalid u16-as-float (fractional)');
    if (x < 0 || x > 0xFFFF) throw new Error('invalid u16-as-float (range)');
    const n = Math.trunc(x);
    if (Math.fround(n) !== x) throw new Error('invalid u16-as-float (non-exact)');
    return n;
}

function decodeU24(x, { strictNegZero = false } = {}) {
    if (!Number.isFinite(x)) throw new Error('invalid u24-as-float (non-finite)');
    if (x !== 0 && Math.abs(x) < MIN_NORMAL_F32) throw new Error('invalid u24-as-float (subnormal)');
    if (strictNegZero && Object.is(x, -0)) throw new Error('invalid u24-as-float (-0.0)');
    if (x !== Math.trunc(x)) throw new Error('invalid u24-as-float (fractional)');
    if (x < 0 || x > 0xFFFFFF) throw new Error('invalid u24-as-float (range)');
    const n = Math.trunc(x);
    if (Math.fround(n) !== x) throw new Error('invalid u24-as-float (non-exact)');
    return n >>> 0;
}
```

Implementer-friendly C-like checks:

```c
#include <math.h>
#include <stdint.h>

#define MIN_NORMAL_F32 1.17549435e-38f

static inline int is_negzero_f(float x) {
  return (x == 0.0f) && signbit(x);
}

bool is_valid_u16_as_float(float x, int strict_negzero) {
  if (!isfinite(x)) return false;
  if (x != 0.0f && fabsf(x) < MIN_NORMAL_F32) return false;
  if (strict_negzero && is_negzero_f(x)) return false;
  if (truncf(x) != x) return false;
  if (x < 0.0f || x > 65535.0f) return false;
  uint32_t n = (uint32_t)x;
  return ((float)n == x);
}

bool is_valid_u24_as_float(float x, int strict_negzero) {
  if (!isfinite(x)) return false;
  if (x != 0.0f && fabsf(x) < MIN_NORMAL_F32) return false;
  if (strict_negzero && is_negzero_f(x)) return false;
  if (truncf(x) != x) return false;
  if (x < 0.0f || x > 16777215.0f) return false;
  uint32_t n = (uint32_t)x;
  return ((float)n == x);
}
```

Worked examples:
- Valid: `x = 42.0` -> valid for `u16-as-float` and `u24-as-float`.
- Valid u24 max: `x = 16777215.0` (`0xFFFFFF`) -> valid.
- Invalid (fractional): `x = 42.5` -> reject.
- Invalid (non-exact): `x = 65535.000004` -> reject.
- Invalid (out of u24 range): `x = 16777216.0` (`0x1000000`) -> reject.

### 28.4.1 Strict `-0.0` profile behavior for structural integer fields

Default behavior is compatibility mode: `-0.0` is accepted as numeric zero for integer-as-float decode.

Profiles MAY enable strict structural-integer mode. In strict mode:
- Receivers MUST reject `-0.0` in structural integer fields.
- Strict-mode `-0.0` detection MUST use Float32 wire bits (sign=1, exponent=0, mantissa=0), or an equivalent bit-exact representation preserved from wire decode.
- Structural integer fields include at minimum Band 0 (`cells[0..8]`), Band 6T (`cells[1000..1019]`), and Band 7 (`cells[1020..1023]`).
- Hardened classes (`dbp-hardened-v1`, `dbp-hardened-s2-mux`) MUST enable strict structural-integer mode.
- Profiles MAY add additional structural integer fields (for example fixed MCB integer fields) and MUST document them.
- Senders SHOULD emit `+0.0` only for structural integer fields to avoid strict-mode rejection.
- Definitive rule: `-0.0` is permitted only as a semantic float value; in hardened classes it is forbidden for all structural integer-as-float fields.

Verification ordering rule (normative): integrity checks (CRC, S1 HMAC, S2 AEAD) MUST run on received raw bytes before any `-0.0` canonicalization or float re-encoding.

### 28.4.2 u24 corner-case policy (`0xFFFFFF`, clamping, and rejection)

- `0xFFFFFF` (`16777215`) MUST decode as valid u24.
- Any value above `0xFFFFFF` MUST be rejected; decoders MUST NOT clamp.
- Fractional values near bounds MUST be rejected (for example `16777215.5`).
- Sender-side clamping MAY be used for semantic float fields only when profile-defined (for example analog normalization), but MUST NOT be used as a substitute for integer-as-float validation.

If a decoded u16/u24 value is later used in bitwise operations, implementations SHOULD coerce explicitly (for example `value & 0xFFFF` or `value >>> 0`) to avoid language-specific signedness pitfalls.

### 28.5 Policy

All DBP integer-as-float fields MUST stay within u24 range per cell. If a value needs more bits, split it across multiple cells. If you find yourself splitting often, that's a v2.0 trigger.

---

## 29) Compression and bandwidth

### 29.1 Frame sparsity

In typical operation, many bands are zero-filled per frame (no waveform change, no active digital message, no uplink in downlink). A frame with ~60% zero cells compresses dramatically:

The following compression/bandwidth figures are illustrative estimates, not normative guarantees.

| Scenario | Raw size | gzip | brotli |
|----------|----------|------|--------|
| Full frame (all bands active) | 4096 B | ~2800 B | ~2500 B |
| Typical (waveform gated, 1 digital) | 4096 B | ~1200 B | ~900 B |
| Sparse (header + lattice only) | 4096 B | ~400 B | ~300 B |

### 29.2 Bandwidth estimates (2 FPS)

| Client count | Raw | With gzip (typical) | With 304s (~80% cache hits) |
|-------------|-----|---------------------|----------------------------|
| 1 | 8 KB/s | ~2.4 KB/s | ~0.5 KB/s |
| 100 | 800 KB/s | ~240 KB/s | ~50 KB/s |
| 1,000 | 8 MB/s | ~2.4 MB/s | ~500 KB/s |

### 29.3 Adaptive frame rate

Writers MAY skip emitting frames when no state has changed. Clients polling with ETag receive 304s automatically. This is transparent to the protocol - clients MUST NOT assume consecutive sequence numbers.

---

## 30) Frame diff and sparsity model

### 30.1 Diff computation

Comparing two frames is a single-pass operation:

```js
function frameDiff(prev, curr) {
    const changed = [];
    for (let i = 0; i < 1024; i++) {
        if (prev[i] !== curr[i]) changed.push(i);
    }
    return changed;
}
```

### 30.2 Band-level change detection

Higher-level diff can report which bands changed:

```js
function bandChanged(prev, curr, bandStart, bandLength) {
    for (let i = bandStart; i < bandStart + bandLength; i++) {
        if (prev[i] !== curr[i]) return true;
    }
    return false;
}
```

### 30.3 Skip rendering on zero-diff

If no cells changed between frames, the receiver SHOULD skip all processing and rendering. This is analogous to the token-free-zero concept: absence of change costs nothing.

### 30.4 Selective re-rendering

When only specific bands change, receivers SHOULD update only the affected subsystems:
- Band 1 changed -> update control state
- Band 2 changed -> process digital message
- Band 4 changed -> update quantum predictions
- Band 5 changed -> update waveform display

---

## 31) Encoding walkthrough examples

### 31.1 Writing a u24 integer into a Float32 cell

```js
// Encode: integer -> Float32 cell
const value = 12345;
frame[cellIndex] = value;  // direct assignment, exact for 0..16,777,215

// Decode: Float32 cell -> integer
const recovered = frame[cellIndex];  // exact
```

### 31.2 Packing 3 bytes into one cell (u24 byte packing)

```js
// Encode
const b0 = 0x48, b1 = 0x65, b2 = 0x6C;  // "Hel"
frame[cellIndex] = b0 + (b1 << 8) + (b2 << 16);  // 7,103,816

// Decode
const val = decodeU24(frame[cellIndex]);  // canonical integer decode (Section 28.4)
const b0_out = val & 0xFF;           // 0x48 'H'
const b1_out = (val >> 8) & 0xFF;    // 0x65 'e'
const b2_out = (val >> 16) & 0xFF;   // 0x6C 'l'
```

### 31.3 Encoding a qubit from a probability

```js
// Encode: probability p -> qubit pair
const p = 0.67;
frame[148 + 2*q]     = Math.sqrt(1.0 - p);  // alpha
frame[148 + 2*q + 1] = Math.sqrt(p);         // beta

// Decode: qubit pair -> probability
const beta = frame[148 + 2*q + 1];
const p_recovered = beta * beta;  // 0.67
```

### 31.4 Split timestamp encoding

```js
// Encode
const now = Date.now();
const unix_sec = Math.floor(now / 1000);
frame[4] = Math.floor(unix_sec / 86400);  // unix_day
frame[5] = unix_sec % 86400;              // sec_of_day
frame[6] = now % 1000;                    // ms

// Decode
const unixDay   = decodeU24(frame[4]);
const secOfDay  = decodeU24(frame[5]);
const ms        = decodeU24(frame[6]);
const unix_sec_out = unixDay * 86400 + secOfDay;
const unix_ms_out  = unix_sec_out * 1000 + ms;
```

### 31.5 CRC32 split encoding

```js
// Encode
const crc = crc32(frameBytes.slice(0, 4080));
frame[1020] = crc & 0xFFFF;
frame[1021] = (crc >> 16) & 0xFFFF;

// Decode & verify (canonical decode + unsigned 32-bit handling)
const lo = decodeU16(frame[1020]);
const hi = decodeU16(frame[1021]);
const stored = (hi * 65536 + lo) >>> 0;
const computed = crc32(frameBytes.slice(0, 4080));
if (stored !== computed) reject(frame);
```

### 31.6 Sequence number split encoding

```js
// Encode (48-bit counter)
frame[2] = frameSeq % 16_777_216;                 // seq_lo
frame[3] = Math.floor(frameSeq / 16_777_216);     // seq_hi

// Decode
const seqLo = decodeU24(frame[2]);
const seqHi = decodeU24(frame[3]);
const frameSeq = seqHi * 16_777_216 + seqLo;
```

### 31.7 Polygon witness encoding (duotronic math layer)

```
Input: integer value = 2039, domain max M = 4096

1. One-based bridge:
   v_norm = (2039 + 1) / (4096 + 1) = 0.4978

2. Find polygon witness (pronic-chain family):
   Pronic numbers: 0, 2, 6, 12, 20, 30, 42, 56, ...
   Quantized digit: floor(0.4978 x 64) = 31
   n = 6 (pronic(6) = 42 >= 31)

3. Build 8-feature witness cell:
   [0.4978, 0.094, 1.0, 0.738, 1.0, 0.667, 0.0, 1.0]
    ^        ^      ^     ^      ^     ^      ^    ^
   value  n_sides center density kind  band  parity degen

Each cell = 8 x Float32 = 32 bytes
```

---

## 32) Vector database integration - detailed

### 32.1 Frames as vectors

A DBP frame is always 4096 wire bytes. In Open/S1, and in S2 after decryption, it is a 1024-dimensional Float32 vector structurally identical to a vector database embedding. Frames can be stored, indexed, and queried using standard vector infrastructure.

| Aspect | Vector DB embedding | DBP frame |
|--------|-------------------|-----------|
| Shape | Float32[N] (typically 384-1536) | Float32[1024] |
| Meaning | semantic position | multiplexed signal state |
| Query model | nearest neighbors | band-offset read |
| Lifecycle | persistent | ephemeral per tick |
| Distance metric | cosine, L2 | band-weighted L2, cosine |

### 32.2 Use cases

1. **Session replay:** store every Nth frame; replay by sequence range
2. **Temporal pattern matching:** find historical frames with similar state ("find moments like this")
3. **Band-specific search:** extract a band sub-vector and search only that dimension
4. **Embedding fusion:** concatenate application-domain embeddings with DBP band vectors for cross-modal queries
5. **Anomaly detection:** flag frames far from any historical cluster

### 32.3 Band distance metrics

| Band | Dimension | Recommended metric | Rationale |
|------|-----------|-------------------|-----------|
| Lattice (1) | 11 | L2 (Euclidean) | magnitude matters |
| Digital (2, 3) | 64 each | Hamming / exact | discrete packed bytes |
| Quantum (4) | 128 | Cosine (signed-semantic) or L2 on probability vector `[beta^2]` (nonnegative) | avoid sign-convention drift |
| Waveform (5) | 384 | L2 or DTW | signal shape |
| Full frame | 1024 | Weighted L2 | weight per band by intent |

### 32.4 Weighted frame distance

```js
function weightedDistance(a, b, weights) {
    let sum = 0;
    const bands = [
        { start: 9,   len: 11,  w: weights.lattice   ?? 1.0 },
        { start: 148, len: 128, w: weights.quantum    ?? 2.0 },
        { start: 276, len: 384, w: weights.waveform   ?? 0.5 },
    ];
    for (const band of bands) {
        for (let i = band.start; i < band.start + band.len; i++) {
            sum += band.w * (a[i] - b[i]) ** 2;
        }
    }
    return Math.sqrt(sum);
}
```

Band weights can be static or learned from user interaction data over time.

### 32.5 Compact state vectors

Instead of storing full 1024-d frames, derive a compact state vector for cheaper indexing:

| Component | Source | Dims |
|-----------|--------|------|
| Lattice | Band 1 (cells[9..19]) | 11 |
| Qubit probabilities | $\beta^2$ for each qubit | 64 |
| FFT digest | Band 5 first 32 cells | 32 |
| **Total** | | **108** |

This yields meaningful similarity at ~10% of the storage and indexing cost.

### 32.6 Storage volume estimates (2 FPS continuous)

| Retention | Frames | Full-frame size | Compact vector size |
|-----------|--------|----------------|-------------------|
| 1 hour | 7,200 | ~28 MB | ~3 MB |
| 1 day | 172,800 | ~675 MB | ~70 MB |
| 1 week | 1,209,600 | ~4.6 GB | ~480 MB |

### 32.7 Sampling strategies

| Strategy | Rate | Daily volume (full) | Use case |
|----------|------|-------------------|----------|
| Every frame | 2/s | ~675 MB | full-fidelity replay |
| Every other | 1/s | ~340 MB | standard replay |
| Key frames only | ~0.1/s | ~34 MB | pattern matching |
| On state change | varies | ~5-50 MB | event-driven |

### 32.8 Retention policy example

```sql
-- Keep last 7 days at full resolution, downsample older to every 100th frame
DELETE FROM dbp_frame_log
WHERE timestamp_real < unixepoch() - 604800
  AND frame_seq % 100 != 0;
```

### 32.9 Reference storage schema

```sql
CREATE TABLE dbp_frame_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    frame_seq INTEGER NOT NULL,
    timestamp_real REAL NOT NULL,
    frame_raw BLOB NOT NULL,         -- 4096 bytes
    lattice_vec BLOB,                -- 11 floats (44 bytes)
    quantum_vec BLOB,                -- 128 floats (512 bytes)
    waveform_vec BLOB,               -- 384 floats (1536 bytes)
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_dbp_frame_seq ON dbp_frame_log(frame_seq);

-- Vector indices (sqlite-vec syntax)
CREATE VIRTUAL TABLE dbp_lattice_idx USING vec0(
    id INTEGER PRIMARY KEY, lattice_vec FLOAT[11]
);
CREATE VIRTUAL TABLE dbp_quantum_idx USING vec0(
    id INTEGER PRIMARY KEY, quantum_vec FLOAT[128]
);
```

---

## 33) Strengths and limitations

### What DBP is good for

| Strength | Why |
|----------|-----|
| **Fixed-size binary frames** | Exactly 4096 bytes. No delimiters, no framing ambiguity, no schema negotiation. |
| **Constant-time field access** | Any band/cell is a direct array index. Zero parsing overhead. |
| **Sparsity-based diff** | Single-pass comparison. Zero cells = no change = skip processing. |
| **Multiplexing** | One frame carries analog, digital, and quantum data simultaneously. |
| **Compression-friendly** | Sparse frames compress 4-10x under gzip/brotli. |
| **Vector-compatible** | Open/S1 frames (and decrypted S2 frames) are directly usable as a 1024-d vector for similarity search. |
| **Self-describing cells** | Witness metadata (when using duotronic math) makes cells introspectable. |
| **Deterministic encoding** | Same inputs with canonical Float32 rounding produce the same output. Values derived from platform math (DSP, transcendentals, time) may drift across implementations. |
| **Transport independence** | Works over files, SSE, WebSocket, or any binary-capable channel. |
| **Profile extensibility** | Core protocol never changes; new applications add profiles. |

### What DBP is NOT good for

| Limitation | Why |
|-----------|-----|
| **Small payloads** | A 5-field status message is ~50 bytes in JSON but always 4096 in DBP. Fixed cost. |
| **Large payloads** | Digital channels carry at most 336 bytes per frame. Chunking helps but adds latency. |
| **Human readability** | Binary Float32 arrays are opaque without tooling. |
| **Interoperability** | No external system speaks DBP. Every integration boundary needs a codec. |
| **Schema evolution** | Adding fields to v1.x means stealing cells from reserved space. |
| **Arbitrary precision** | Float32 limits exact integers to $2^{24}$. |
| **Polygon witness overhead** | When using duotronic math: 8x storage expansion (1 scalar -> 8 features). |

### Bottom line

DBP's value is **architectural unification** - one fixed-size binary format for real-time communication, vector storage, and probabilistic state. The fixed overhead is justified when you need zero-allocation decoding, multiplexed signal types, and vector-compatible frames (direct on-wire for Open/S1, post-decrypt for S2).

---

## 34) Known v1.0 limitations (resolved in v1.1)

| Issue | Impact | v1.1 resolution |
|-------|--------|----------------|
| `frame_seq` wraps at ~97 days (2 FPS) | counter ambiguity | split into `seq_lo/seq_hi` (48-bit) |
| `server_time` loses precision in Float32 | ~128s granularity | split into `unix_day/sec_of_day/ms` |
| Weighted-sum checksum is fragile | rounding, NaN propagation | replaced with CRC32 |
| No waveform gating | wasted bandwidth | `HAS_WAVEFORM` flag + zero-fill |
| No per-band presence flags | ambiguous "is this band active?" | flags bitfield in header |
| Header only 4 cells | no room for split fields | expanded to 9 cells (0-8) |
| Band 1 had 16 cells | 4 became header | Band 1 now 11 cells (9-19) |

### v1.0 -> v1.1 header cell migration

| Cell | v1.0 usage | v1.1 usage |
|------|------------|------------|
| 0 | `magic` (`0xDB01`) | `magic` (`0xDB11`) |
| 1 | `frame_seq` | `version` |
| 2 | `server_time_coarse` | `seq_lo` |
| 3 | `version_fps` | `seq_hi` |
| 4 | (Band 1 data) | `unix_day` |
| 5 | (Band 1 data) | `sec_of_day` |
| 6 | (Band 1 data) | `ms` |
| 7 | (Band 1 data) | `flags_profile` |
| 8 | (Band 1 data) | `tick_rate` |

All other band offsets (20+) remain unchanged between v1.0 and v1.1.

---

## 35) Naming philosophy - "Quantum Register"

The quantum register uses quantum mechanics as a **computational metaphor** for probabilistic state on classical hardware. It does not involve actual quantum computing, quantum networking, or quantum data transport.

Complex amplitudes are explicitly out of scope in v1.x; the register uses real-valued amplitudes only.

The naming is intentional - the register genuinely implements:
- **Superposition:** continuous amplitude pairs, not just 0/1
- **Sampling:** probabilistic observation weighted by amplitude (quantum-collapse metaphor)
- **Entanglement:** correlated partner collapse with configurable strength

These behaviors run on classical CPUs using standard Float32 arithmetic.

Alternative names considered: "Predictive Register", "Probabilistic State Model". "Quantum" is retained because it accurately describes the computational model, even though the substrate is classical.

**Distinct from post-quantum security:** DBP's security profiles ([Section 8](#8-security-profiles)) reference post-quantum *cryptography* (ML-KEM, ML-DSA) - resistance to quantum attackers. That is an entirely separate concern from the quantum-inspired register, which is a state representation tool.

---

## 36) Header encoding caveat - raw fractions vs polygon encoding

When packing control fields (magic, flags, bitmasks, routing identifiers) into Float32 cells, implementations MUST use raw integer-as-float assignment, NOT polygon witness encoding.

Polygon encoding quantizes values through polygon-family digit selection, which corrupts bitwise fields. Example failure:

```
Input bitmask: 63 (0x3F = 0b00111111)
-> polygon encode -> denormalize -> 65 (0x41 = 0b01000001)
Result: video and text flags lost, metadata flag spuriously set
```

Never-witness-encode fence (normative):
- Band 0 (`cells[0..8]`) MUST use raw integer-as-float only.
- Band 6T (`cells[1000..1019]`) MUST use raw integer-as-float only.
- Band 7 (`cells[1020..1023]`) MUST use raw integer-as-float only.
- Any field validated with Section 28.4 canonical integer decode MUST be raw integer-as-float and MUST NOT use polygon witness encoding.

Witness encoding allowance (normative):
- Polygon witness encoding is allowed only for profile-defined semantic values where quantization is explicitly acceptable.
- Witness encoding MUST NOT be applied to structural routing/security/checksum/control fields.

Receiver behavior on violation:
- If a forbidden structural field fails canonical integer-as-float decode (including witness-quantized drift), receivers MUST reject the frame as structural corruption (`E_BAD_STRUCT` or profile-equivalent).

---

## 37) Text packing via digital channels

### 37.1 Chars-per-cell calculation

Each Float32 cell stores a u24 integer -> 3 bytes -> 3 ASCII bytes, or 1-3 UTF-8 bytes. Some Unicode code points require 4 UTF-8 bytes and therefore span multiple cells.

For a 64-cell digital channel:

$$
64 \times 3 = 192 \text{ total bytes if all cells carried payload}
$$

In DBP, the first 8 cells are channel header ([Section 6.2](#62-bands-2-3-digital-channels-ab-cells2083-84147)), so only 56 payload cells remain: 56 x 3 = **168 usable payload bytes per channel**.

### 37.2 Encoding text into digital cells

```js
function textToDigitalCells(text, channelStart, frame) {
    const bytes = new TextEncoder().encode(text);
    if (bytes.length > 168) throw new Error("chunk payload exceeds 168 bytes");

    const payloadStart = channelStart + 8;  // skip digital header cells[0..7]
    const usedCells = Math.ceil(bytes.length / 3);

    let cellIdx = payloadStart;
    for (let i = 0; i < usedCells * 3; i += 3) {
        const b0 = bytes[i]     ?? 0;
        const b1 = bytes[i + 1] ?? 0;
        const b2 = bytes[i + 2] ?? 0;
        frame[cellIdx++] = b0 + (b1 << 8) + (b2 << 16);
    }

    // Zero-fill payload tail cells per Section 15
    for (let i = usedCells; i < 56; i++) {
        frame[payloadStart + i] = 0;
    }
}
```

### 37.3 Decoding digital cells to text

```js
function digitalCellsToText(frame, channelStart, byteCount) {
    if (byteCount < 0 || byteCount > 168) throw new Error("invalid payload_len");

    const bytes = [];
    const payloadStart = channelStart + 8;  // skip digital header cells[0..7]
    for (let i = 0; i < Math.ceil(byteCount / 3); i++) {
        const val = decodeU24(frame[payloadStart + i]);
        bytes.push(val & 0xFF);
        if (bytes.length < byteCount) bytes.push((val >> 8) & 0xFF);
        if (bytes.length < byteCount) bytes.push((val >> 16) & 0xFF);
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
}
```

### 37.4 Multi-frame text chunking

Large text payloads (>168 bytes) use the chunking protocol ([Section 15](#15-digital-chunk-reassembly-contract)):

- `total_chunks = ceil(text_bytes.length / 168)`
- Each chunk uses one frame's digital channel
- Receiver assembles all chunks by `msg_type` and `chunk_index`
- Final message is the concatenation of all chunk payloads

**Throughput at 2 FPS:**

| Channels used | Bytes/frame | Bytes/second | Text chars/sec |
|--------------|-------------|-------------|----------------|
| 1 | 168 | 336 | ~336 ASCII |
| 2 (both channels) | 336 | 672 | ~672 ASCII |

---

## 38) Complexity debt philosophy

DBP accepts intentional complexity debt in exchange for architectural simplicity:

1. **Fixed frame size** - Wastes bytes when data is sparse but eliminates framing ambiguity, length-prefix parsing, and buffer management.

2. **Float32 for everything** - Requires integer-as-float encoding tricks for discrete data but enables zero-allocation typed-array decoding and direct vector-database compatibility.

3. **Bands at fixed offsets** - Some bands may be unused in a given application, wasting cells, but any implementation can read any band without negotiation or capability discovery.

4. **Quantum metaphor** - More complex than a simple bitmask/probability-map, but provides collapse, entanglement, and freshness semantics that are genuinely useful for predictive state.

The debt is manageable because the frame structure is fixed and fully documented. No runtime surprises. No schema negotiation. The cost is paid once at design time, not continuously at runtime.

**When the debt becomes unmanageable:** If applications routinely need >80% of bands to be profile-customized, or if most cells are wasted, the protocol should migrate to a schema-based format ([Section 20](#20-v20-migration-trigger-and-scope)).

---

## 39) Implementation notes

### 39.1 Endianness

The frame MUST be transported in **little-endian** byte order. This is the native byte order for all modern x86, ARM, and WASM platforms. Implementations on big-endian platforms MUST byte-swap on read/write.

JS portability note: when computing MAC/CRC, hash the little-endian wire byte stream. On big-endian JS hosts, serialize cells explicitly with `DataView.setFloat32(offset, value, true)`.

### 39.2 Zero-copy access in JavaScript

WARNING: If you do not know host endianness, assume nothing - decode with `DataView.getFloat32(offset, true)`.

```js
// Zero-allocation decode
const buffer = await response.arrayBuffer();
// WARNING: TypedArray uses native endianness; this is zero-copy correct only on little-endian hosts.
// On big-endian hosts, decode via DataView.getFloat32(offset, true) or reserialize to little-endian first.
const frame = new Float32Array(buffer);
// Direct indexing - no parsing
const magic = decodeU16(frame[0]);   // canonical decode (Section 28.4)
const seqLo = decodeU24(frame[2]);   // seq_lo is u24
```

### 39.3 Zero-copy access in C

```c
// Memory-mapped or network buffer
float* frame = (float*)buffer;

// Canonical decode helpers - finite + integral + range checks per Section 28.4
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

static inline int is_negzero_f(float v) {
    return v == 0.0f && signbit(v);
}

static inline uint32_t decode_u16_f(float v, int strict_negzero) {
    if (!isfinite(v)) abort();
    if (strict_negzero && is_negzero_f(v)) abort();
    if (v < 0.0f || v > 65535.0f) abort();
    uint32_t n = (uint32_t)v;
    if ((float)n != v) abort();
    return n;
}

static inline uint32_t decode_u24_f(float v, int strict_negzero) {
    if (!isfinite(v)) abort();
    if (strict_negzero && is_negzero_f(v)) abort();
    if (v < 0.0f || v > 16777215.0f) abort();
    uint32_t n = (uint32_t)v;
    if ((float)n != v) abort();
    return n;
}

uint32_t magic_u16 = decode_u16_f(frame[0], /*strict_negzero=*/0);
uint32_t fp_u24    = decode_u24_f(frame[7], /*strict_negzero=*/0);  // flags_profile is u24-as-float
uint32_t flags16   = fp_u24 & 0xFFFF;
uint32_t profileId = (fp_u24 >> 16) & 0xFF;
```

### 39.4 Zero-copy access in Python

```python
import struct
frame = struct.unpack_from('<1024f', buffer)
# or via numpy
import numpy as np
frame = np.frombuffer(buffer, dtype=np.float32)
```

### 39.5 Zero-copy access in Rust

```rust
let frame: &[f32; 1024] = bytemuck::cast_ref(&buffer);
```

### 39.6 Atomic write (POSIX)

```bash
# Write to temp, then atomically rename
dd if=/dev/stdin of=/path/frame.bin.tmp bs=4096 count=1
mv /path/frame.bin.tmp /path/frame.bin
```

```python
import os, tempfile
fd, tmp = tempfile.mkstemp(dir='/path/')
os.write(fd, frame_bytes)
os.close(fd)
os.rename(tmp, '/path/frame.bin')
```

---

## 40) Reference Verifier

Section 40 is a shipped reference-verifier contract for deterministic conformance checks.

Repository artifact expectation:
- Implementations SHOULD ship a runnable verifier script at `protocol/dbp_verify.mjs` (or an equivalent path documented in project README/CI).
- The verifier MUST be kept in sync with Section 17 vectors and fixture ids.

Scope of the reference verifier:
1. Rebuild Section 17.1 S1 deterministic vector and assert expected tag/CRC outputs.
2. Load `dbp_s2_fixture.json` and assert Section 17.4 fixture outputs.
3. Run Section 17.5 policy vector cases (`A..F`) and assert expected decisions.
4. Load `dbp_handshake_fixture.json` and assert Section 17.10 DBP-HS1 transcript/key-schedule outputs.
5. Exit non-zero on any mismatch.

Implementation note: the embedded snippet below illustrates core S1/S2 verifier mechanics. The repository verifier (`protocol/dbp_verify.mjs`) is authoritative and includes HS1 fixture checks from Section 17.10.

Non-goals (informational): this verifier is a conformance harness, not a full production receiver; it does not implement full online S2 decrypt path for arbitrary traffic, durable replay-window storage, or sticky-policy persistence across process restart.

```
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = path.join(SCRIPT_DIR, "dbp_s2_fixture.json");

// --- CRC32/ISO-HDLC (reflected) ---
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32IsoHdlc(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function writeF32LE(dv, byteOffset, f) { dv.setFloat32(byteOffset, f, true); }
function u16ToFloat(n) { return n; }
function u24ToFloat(n) { return n; }

function buildVectorS1() {
  const buf = new ArrayBuffer(4096);
  const dv = new DataView(buf);
  const frame = new Float32Array(buf);

  // all zero by default; write header
  frame[0] = u16ToFloat(56081);
  frame[1] = u16ToFloat(11);
  frame[2] = u24ToFloat(1);
  frame[3] = u24ToFloat(0);
  frame[4] = u24ToFloat(20000);
  frame[5] = u24ToFloat(12345);
  frame[6] = u24ToFloat(678);
  frame[7] = u24ToFloat(32);     // SEC_TRAILER_PRESENT, profile_id=0
  frame[8] = u16ToFloat(2);

  // canonicalize -0.0 -> +0.0
  for (let i = 0; i < 1024; i++) if (frame[i] === 0) frame[i] = 0;

  // security metadata (cells[1000..1003])
  frame[1000] = u16ToFloat(1);
  frame[1001] = u16ToFloat(1);
  frame[1002] = u16ToFloat(1);
  frame[1003] = u16ToFloat(0);

    // MAC over mac_domain_tag || bytes[0..4015] (cells[0..1003])
    const macDomainTag = Buffer.from("DBP-S1\0", "ascii");
    const macInput = Buffer.from(buf, 0, 4016);
  const key = Buffer.alloc(32, 0x11);
    const tag = crypto.createHmac("sha256", key).update(macDomainTag).update(macInput).digest(); // 32 bytes

  // pack tag into u16 words little-endian into cells[1004..1019]
  for (let i = 0; i < 16; i++) {
    const lo = tag[2*i];
    const hi = tag[2*i + 1];
    frame[1004 + i] = u16ToFloat(lo | (hi << 8));
  }

  // CRC over bytes[0..4079] (cells[0..1019])
  const crc = crc32IsoHdlc(new Uint8Array(buf, 0, 4080));
  frame[1020] = u16ToFloat(crc & 0xFFFF);
  frame[1021] = u16ToFloat((crc >>> 16) & 0xFFFF);
  frame[1022] = u16ToFloat(4096);
  frame[1023] = u16ToFloat(56081);

  return { buf, frame, tag, crc };
}

const { tag, crc } = buildVectorS1();
if (tag.toString("hex") !== "8c4ae150702ce62e421f78fb27d556845b5722397832020601952473c6959e66") {
  throw new Error("S1 tag mismatch");
}
if (crc !== 0x0015E7B9) {
  throw new Error("S1 CRC mismatch");
}
console.log("s1_vector_ok", "tag_hex=" + tag.toString("hex"), "crc_hex=0x" + crc.toString(16).padStart(8, "0"));

// Deterministic S2 fixture verification (Section 17.4)
function verifyS2Fixture() {
    const fx = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
    if (fx.fixture_id !== "dbp-v1.1-s2-aes256gcm-fixture-1") throw new Error("unexpected fixture id");
    if (fx.outputs.crc32_hex.toUpperCase() !== "0XDAA5DE96") throw new Error("CRC mismatch");
    if (fx.outputs.aead_tag128_hex !== "37cb5231f0c9ec15b8e567420b54b2cf") throw new Error("AEAD tag mismatch");
    if (fx.outputs.frame_sha256 !== "72736e5165fdd502bc84e977ef3bddfd1c0a49b42176ca3083d5b01c3cd7d8b8") throw new Error("frame sha mismatch");
    console.log("s2_fixture_ok", fx.fixture_id);
}
verifyS2Fixture();

// Optional: policy-vector checker from Section 17.5 (suite_id/key_epoch/sticky-S2)
function evaluateS2PolicyCase(input, state) {
    // Sticky-S2 enforcement first
    if (state.requiresS2 && (!input.secTrailerPresent || input.secProfile !== 2)) {
        return { accept: false, code: "E_POLICY_DOWNGRADE", event: "DBP_SEC_DOWNGRADE_ATTEMPT" };
    }

    if (input.secTrailerPresent) {
        if (input.secProfile !== 2) {
            return { accept: false, code: "E_POLICY_DOWNGRADE", event: "DBP_SEC_DOWNGRADE_ATTEMPT" };
        }
        if (!state.allowedSuites.has(input.suiteId)) {
            return { accept: false, code: "E_S2_SUITE", event: "DBP_SEC_S2_SUITE_REJECT" };
        }

        // Strict monotonic policy for this checker (profile may permit explicit rollover windows)
        if (input.keyEpoch <= state.lastKeyEpoch) {
            return { accept: false, code: "E_KEY_EPOCH", event: "DBP_SEC_KEY_EPOCH_ROLLBACK" };
        }
    }

    return { accept: true, code: null, event: null };
}

function runPolicyVector175() {
    const baseState = {
        requiresS2: true,
        lastKeyEpoch: 41,
        allowedSuites: new Set([1, 2, 3, 4, 5, 6])
    };

    const cases = [
        { id: "A", input: { secTrailerPresent: true, secProfile: 2, suiteId: 6, keyEpoch: 42 }, expectedCode: null },
        { id: "B", input: { secTrailerPresent: true, secProfile: 2, suiteId: 99, keyEpoch: 42 }, expectedCode: "E_S2_SUITE" },
        { id: "C", input: { secTrailerPresent: true, secProfile: 2, suiteId: 6, keyEpoch: 40 }, expectedCode: "E_KEY_EPOCH" },
        { id: "D", input: { secTrailerPresent: true, secProfile: 2, suiteId: 6, keyEpoch: 41 }, expectedCode: "E_KEY_EPOCH" },
        { id: "E", input: { secTrailerPresent: true, secProfile: 1, suiteId: 6, keyEpoch: 42 }, expectedCode: "E_POLICY_DOWNGRADE" },
        { id: "F", input: { secTrailerPresent: false, secProfile: 0, suiteId: 0, keyEpoch: 42 }, expectedCode: "E_POLICY_DOWNGRADE" }
    ];

    for (const c of cases) {
        const out = evaluateS2PolicyCase(c.input, baseState);
        const got = out.code;
        const want = c.expectedCode;
        if (got !== want) {
            throw new Error(`policy-vector ${c.id} mismatch: got=${got}, want=${want}`);
        }
        console.log("policy-vector", c.id, "ok", got ?? "ACCEPT");
    }
}

runPolicyVector175();
```

## 41) Wire Map Appendix (single-page quick reference)

This appendix consolidates the v1.1 wire layout, structural/semantic split, and mode-dependent check timing.
Canonical definitions remain in [Section 0.5.1](#051-canonical-byte-scopes), [Section 0.5.2](#052-numeric-class-policy-canonical-matrix), and [Section 0.5.3](#053-integer-as-float-canonical-decode).

### 41.1 Band map

| Region | Cells | Bytes | Structural or semantic | S2 ciphertext scope |
|------|------:|------:|------------------------|---------------------|
| Band 0 (header) | `0..8` | `0..35` | Structural | Cleartext |
| Band 1 (lattice) | `9..19` | `36..79` | Semantic | Ciphertext |
| Band 2 (Digital A) | `20..83` | `80..335` | Semantic | Ciphertext |
| Band 3 (Digital B) | `84..147` | `336..591` | Semantic | Ciphertext |
| Band 4 (quantum) | `148..275` | `592..1103` | Semantic | Ciphertext |
| Band 5 (waveform/digest) | `276..659` | `1104..2639` | Semantic | Ciphertext |
| Band 6 (client slot / MUX) | `660..999` | `2640..3999` | Semantic/profile-structural | Ciphertext |
| Band 6T (security trailer) | `1000..1019` | `4000..4079` | Structural | Cleartext |
| Band 7 (footer) | `1020..1023` | `4080..4095` | Structural | Cleartext |

### 41.2 Check timing by mode

| Check class | Open/S1 (`sec_profile != 2`) | S2 (`sec_profile = 2`) pre-AEAD/decrypt | S2 post-AEAD/decrypt |
|-------------|-------------------------------|------------------------------------------|-----------------------|
| Shape (4096 bytes) | MUST | MUST | n/a |
| Structural int decode (`magic`, `flags_profile`) | MUST preflight | MUST preflight | n/a |
| `sec_profile` decode (`1000`) when trailer-present | MUST | MUST | n/a |
| Finite/subnormal checks on cleartext structural cells (`0..8`, `1000..1019`, `1020..1023`) | MUST | MUST | n/a |
| Finite/subnormal checks on semantic region (`9..999`) | MUST | MUST NOT pre-decrypt | MUST on decrypted plaintext except authenticated `opaque_bytes` slices |
| Integer-as-float checks for Band 6T (`1000..1019`) | if trailer-present | if trailer-present | n/a |
| CRC check (`bytes[0..4079]`) | MUST | MUST | n/a |
| S1 HMAC / S2 AEAD | MUST in secure mode | MUST (AEAD) | MUST complete before semantic decode |
| ABB/MCB parse for `opaque_bytes` exclusion | n/a | MUST NOT pre-decrypt | MUST run before finite/subnormal checks on decrypted `9..999` |
| Band semantic decode | after integrity checks | MUST NOT before decrypt | after decrypt and required checks |

### 41.3 Integrity byte ranges

- S1 MAC input: `bytes[0..4015]` (cells `0..1003`) with domain tag prefix.
- Frame CRC input: `bytes[0..4079]` (cells `0..1019`).
- S2 AAD: wire bytes for cells `0..8`, then `1000..1003`, then `1018..1019`.
- S2 ciphertext payload: wire bytes for cells `9..999`.
### 41.4 Single-page implementation checklist

1. Parse exactly 4096 bytes and preflight-decode `magic` + `flags_profile`.
2. Validate footer sanity (`byte_size=4096`, `magic_echo==magic`) before expensive checks.
3. Enforce structural integer-as-float checks on header/trailer/footer fields.
4. Verify CRC over `bytes[0..4079]` in all modes (hard reject on mismatch).
5. In secure modes, verify S1/S2 authenticity over raw received bytes before any normalization.
6. In S2, decrypt `cells[9..999]`, derive authenticated `opaque_bytes` mask, then run post-decrypt numeric checks.
7. Decode band semantics only after all required checks pass.

## 42) Glossary

| Term | Definition |
|------|-----------|
| **Band** | A contiguous range of Float32 cells within a frame, dedicated to one signal type. |
| **Cell** | A single Float32 slot within the frame (index 0-1023). |
| **Chunk** | A segment of a multi-frame digital message, identified by `chunk_index` / `total_chunks`. |
| **Collapse / sample()** | Receiver-local probabilistic observation of a qubit, resolving superposition into a definite 0 or 1 interpretation. |
| **Compact state vector** | A reduced-dimensionality extraction of key band features for cheaper vector search. |
| **CRC32** | 32-bit cyclic redundancy check stored as two u16 halves in Band 7. |
| **DBP** | Duotronic Bus Protocol - the subject of this specification. |
| **Duotronic primitive `D=(p,q)`** | Optional profile-level semantic value model with primary term `p` and corrective/context term `q`; defined in [Section 9](#9-duotronic-math-layer-optional-but-compatible). |
| **Downlink** | Server-to-client frame broadcast (the shared signal). |
| **Entanglement** | Correlation between two qubits such that measuring one influences the other's collapse. |
| **Frame** | 4096 wire bytes. In Open/S1 (and in S2 after decryption), may be interpreted as `Float32Array(1024)`. Structural integer fields remain Float32 numeric carriers and MUST be canonical-decoded per Section 28.4 (not bit-cast integer lanes). The atomic unit of DBP communication. |
| **Frame diff** | A comparison of two frames yielding a list of changed cell indices. |
| **Freshness** | A decay metric indicating how recently the quantum register was recomputed. |
| **Gated** | A band marked as inactive via flags (zero-filled, receivers skip processing). |
| **Lattice** | Band 1 (11 cells, cells[9..19]). General-purpose control/status channel for analog floats. |
| **Lease** | An authenticated ABB allocation that temporarily assigns a donor-band slice to a declared lane type for one frame unless renewed. |
| **Magic number** | Cell 0. Identifies the frame as DBP and indicates the protocol version. |
| **`opaque_bytes` lane** | S2-only ABB lane type where leased cells are treated as raw bytes, excluded from Float32 semantic checks after authenticated mask derivation. |
| **Observation count** | Qubit 63. Writer-maintained telemetry for observation density/count (not auto-mutated by receiver-local `measure()`). |
| **Optimistic state** | Client-side predicted state applied immediately, reconciled when server confirms. |
| **Polygon witness** | An 8-feature geometric metadata cell from the duotronic math layer ([Section 9](#9-duotronic-math-layer-optional-but-compatible)). |
| **Profile** | An application-level contract defining band semantics, qubit assignments, digital message types, and security level. |
| **`key_epoch`** | Hardened S2 policy epoch (`sec_words[15]`) used for suite/key-era partitioning and replay isolation; must be monotonic per writer identity in hardened mode. |
| **Pronic number** | $n(n+1)$: the polygon family used for quantized digit encoding. |
| **Quantum register** | Band 4. 64 qubits (128 cells) encoding probabilistic state as alpha/beta amplitude pairs. |
| **Qubit** | A pair of Float32 cells representing a quantum-inspired probability via $\alpha$ and $\beta$ amplitudes. |
| **Raw fraction** | A direct float value (0.0-1.0 or integer-as-float) stored without polygon encoding. |
| **Projection `N_lambda(D)`** | Scalar projection from a Duotronic pair: `N = p - lambda*q` with default `lambda=1.0` unless profile override. |
| **Receiver** | Any process that consumes DBP frames (client-side). |
| **Security trailer** | Band 6T (cells[1000..1019], 20 cells). Counter, key ID, and 256-bit MAC tag. |
| **Sender** | Any process that produces DBP frames (server-side writer). |
| **`writer_identity`** | Replay/nonce partition identity bound to authenticated key context (interoperability default). Explicit writer ID mode is a declared non-hardened extension and must be authenticated. |
| **Sparsity** | The proportion of zero-valued cells in a frame. Higher sparsity = better compression. |
| **Stability term `S(p,q)`** | Bounded `[0,1]` score derived from Duotronic pair terms; default formula in [Section 9](#9-duotronic-math-layer-optional-but-compatible). |
| **Superposition** | A qubit state where both $|0\rangle$ and $|1\rangle$ amplitudes are non-zero. |
| **u24** | An unsigned 24-bit integer stored as a Float32 (exact for 0-16,777,215). |
| **Uplink** | Client-to-server command frame (Band 6 content, sent via POST). |
| **Waveform** | Band 5 (384 cells). Continuous signal data (audio, sensor, telemetry, etc.). |
| **WSB2** | Witness Sparse Block v2 payload format carried in ABB leased lane bytes for sparse witness transport. |
| **Writer** | The single process responsible for building and emitting downlink frames. |

### 42.1 Synonym guide (primary terms)

Use these primary terms in implementation docs and code comments to avoid ambiguity:

| Preferred term | Acceptable aliases | Guidance |
|----------------|--------------------|----------|
| `cell` | slot, float slot | Use `cell` for all on-wire index references (`0..1023`). |
| `band` | region | Use `band` for fixed protocol ranges (`Band 0..7`). |
| `slice` | lane segment, leased range | Use `slice` for ABB-leased contiguous ranges; use `lane_type` only for semantics. |
| `frame` | packet (transport colloquial) | Use `frame` for the 4096-byte DBP atomic unit. |
| `profile` | application schema | Use `profile` for semantics contract; avoid calling it wire format. |

---

*End of specification*
