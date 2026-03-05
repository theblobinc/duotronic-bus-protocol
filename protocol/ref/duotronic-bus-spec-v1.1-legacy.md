# Duotronic Bus Protocol (DBP)
**Last updated:** 2026-03-03  
**Protocol line:** v1.x (fixed-offset Float32 frame, optional polygon witness semantics)  
**Recommended version:** v1.1  
**Wire format:** IEEE 754 binary32 (single-precision float), little-endian byte order

DBP is a bi-directional multiplexed signal bus for transporting three classes of state in one frame:
- Analog (continuous floats)
- Digital (byte-packed payloads carried inside float cells)
- Quantum-inspired (probabilistic register using amplitude pairs)

It is transport-agnostic and application-agnostic. The core protocol defines shape and rules; application profiles define field semantics.

---

## 0) Normative language
The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are requirement levels.

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
- Valid frames MUST NOT contain `NaN`, `Infinity`, or subnormal Float32 values
- All integers `0..16,777,215` (`2^24 - 1`) are exactly representable per u24 cell. `2^24` itself is representable, but not every integer above it is exact in Float32.

Byte interval notation used in this specification:
- `bytes[a..b]` means an inclusive byte interval (includes both `a` and `b`).
- `[a, b)` denotes a half-open interval (includes `a`, excludes `b`) when explicitly used.

---

## 2) Frame shape (v1.1)

A DBP frame is `Float32Array(1024)` = **4096 bytes**.

```
Band 0:   Cells [0–8]        SYNC HEADER                 9 cells     36 bytes
Band 1:   Cells [9–19]       ANALOG CONTROL LATTICE     11 cells     44 bytes
Band 2:   Cells [20–83]      DIGITAL CHANNEL A          64 cells    256 bytes
Band 3:   Cells [84–147]     DIGITAL CHANNEL B          64 cells    256 bytes
Band 4:   Cells [148–275]    QUANTUM REGISTER          128 cells    512 bytes
Band 5:   Cells [276–659]    ANALOG WAVEFORM/DIGEST    384 cells   1536 bytes
Band 6:   Cells [660–999]    CLIENT SLOT               340 cells   1360 bytes
Band 6T:  Cells [1000–1019]  SECURITY TRAILER           20 cells     80 bytes
Band 7:   Cells [1020–1023]  FRAME CHECK                 4 cells     16 bytes
--------------------------------------------------------------------------
Total:    1024 cells = 4096 bytes
```

### 2.1 Offsets at a glance (implementation quick reference)

| Region | Cells | Required checks before use |
|--------|-------|----------------------------|
| Header (Band 0) | `0..8` | finite + integer-as-float (§28.4), magic/version/time ranges |
| Digital A (Band 2) | `20..83` | if `HAS_DIGITAL_A`: header u16/u24 checks + payload u24 checks |
| Digital B (Band 3) | `84..147` | if `HAS_DIGITAL_B`: header u16/u24 checks + payload u24 checks |
| Quantum (Band 4) | `148..275` | finite + normalization policy (§6.3/§22.9) |
| Client Slot (Band 6) | `660..999` | apply §28.4 to integer fields if consumed |
| Security trailer (Band 6T) | `1000..1019` | only if `SEC_TRAILER_PRESENT`; else zero-fill/optional hygiene assert |
| Footer (Band 7) | `1020..1023` | integer-as-float checks + footer sanity + CRC |

Policy defaults and profile-level override points are summarized in §16.1.

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
// decodeU16 enforces the canonical integer-as-float decode rule (§28.4)
const magic = decodeU16(frame[0]);
if (magic === 0xDB01) parseV10(frame);
else if (magic === 0xDB11) parseV11(frame);
else reject(frame);
```

---

## 4) Sync header (Band 0, cells 0–8)

| Cell | Name            | Type         | Meaning |
|----:|------------------|--------------|---------|
| 0   | `magic`          | u16-as-float | protocol magic (`0xDB11`) |
| 1   | `version`        | u16-as-float | compact semantic version (`major*10 + minor`, e.g. `11`; not general SemVer). Major and minor MUST each be single-digit (0–9). |
| 2   | `seq_lo`         | u24-as-float | frame sequence low part |
| 3   | `seq_hi`         | u24-as-float | frame sequence high part |
| 4   | `unix_day`       | u24-as-float | floor(unix_sec / 86400) |
| 5   | `sec_of_day`     | u24-as-float | unix_sec % 86400 |
| 6   | `ms`             | u24-as-float | 0..999 |
| 7   | `flags_profile`  | u24-as-float | `(profile_id << 16) | flags16` |
| 8   | `tick_rate`      | u16-as-float | frames per second (1..65535; 0 = paused/unspecified) |

### `version` and `tick_rate` decoding

```js
const ver   = decodeU16(frame[1]);             // e.g. 11 (§28.4)
const major = Math.floor(ver / 10);           // 1
const minor = ver % 10;                       // 1
const fps   = decodeU16(frame[8]);             // e.g. 2, 30, 120, 240
```

`major*10 + minor` is intentionally constrained in v1.x (single-digit major/minor), so values like `1.10` are out of scope for this encoding and require a future versioning scheme.

### `flags_profile` decoding

```js
const fp        = decodeU24(frame[7]);         // u24-as-float (§28.4)
const flags16   = fp & 0xFFFF;                 // lower 16 bits
const profileId = (fp >>> 16) & 0xFF;          // upper 8 bits
// Bitwise ops are safe here because fp is ≤ 0xFFFFFF (fits in 24 bits).
```

`tick_rate` is stored as a plain u16 with no packing — supporting rates up to 65535 FPS without encoding tricks.

**`tick_rate` range:** `tick_rate ∈ [0..65535]`.

**`tick_rate = 0`:** means "paused or unspecified." Writers that cannot or do not report frame rate MUST use 0. Receivers MUST NOT divide by `tick_rate` without checking for zero first.

**Advisory semantics:** `tick_rate` is advisory — it declares the sender's intended publishing cadence but does not obligate receivers to synchronize to it. Timing-sensitive consumers MAY use it for interpolation or drift detection but MUST tolerate jitter.

### Standard flags (lower 16 bits)
| Bit | Name | Meaning |
|---:|------|---------|
| 0 | `HAS_DIGITAL_A` | Band 2 contains a valid message |
| 1 | `HAS_DIGITAL_B` | Band 3 contains a valid message |
| 2 | `HAS_WAVEFORM` | Band 5 carries waveform/digest |
| 3 | `WAVEFORM_IS_FFT32` | Band 5 starts with FFT32 digest |
| 4 | `HAS_RESPONSE` | deprecated legacy hint; v1.1 senders MUST write `0`, receivers MUST ignore |
| 5 | `SEC_TRAILER_PRESENT` | Band 6T is populated |
| 6..15 | reserved | future use |

**Reserved-bit rule:** Senders MUST write all reserved flag bits as `0`. Receivers MUST ignore reserved/unknown bits (do not reject frames based on them). This applies to `flags_profile` bits 6–15, `msg_flags`, and any future bitfields.

**Flag coherence rules (normative):** The following inter-flag dependencies MUST be enforced by senders and checked by receivers:
- If `WAVEFORM_IS_FFT32` is set, `HAS_WAVEFORM` MUST also be set. A receiver that sees `WAVEFORM_IS_FFT32` without `HAS_WAVEFORM` MUST treat `WAVEFORM_IS_FFT32` as unset.
- If `SEC_TRAILER_PRESENT` is set, `sec_profile` MUST be non-zero and a supported profile; frames violating this are rejected per §8.
- If `HAS_DIGITAL_A` or `HAS_DIGITAL_B` is set, then `chunk_total >= 1`, `chunk_index < chunk_total`, and `payload_len` MUST satisfy the profile's zero-length policy (§6.2). Frames that assert the flag but fail these checks are invalid per §6.2.

---

## 5) Profiles (core vs semantics)

DBP core defines structure and encoding. Profiles define meaning.

- `profile_id = 0`: DBP-Core only (generic)
- `profile_id = 1..255`: application-specific profiles

`profile_id` is 8-bit by design in v1.x. Expanding beyond 255 profiles is a v2.0 concern.

Clients MAY decode generic channels from unknown profiles but MUST NOT issue profile-specific commands unless profile is supported.

---

## 6) Band specifications

### 6.1 Band 1 — Analog Control Channels (Band-1 lattice, cells 9–19)
11 continuous channels (`a0..a10`) reserved for profile semantics.

### 6.2 Bands 2 & 3 — Digital Channels A/B (cells 20–83, 84–147)
Each channel has:
- 8-cell message header
- 56-cell payload

Header fields (all integer fields are stored as integer-as-float and MUST satisfy §28.4):

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

When expanding payload cells to bytes for CRC32/reassembly, bytes MUST be interpreted in little-endian byte order `[b0, b1, b2]` per cell.

Digital payload CRC scope (normative): `payload_crc_lo/hi` is CRC32/ISO-HDLC over the first `payload_len` bytes of the logical payload byte stream after u24→bytes expansion.

Digital message validity (normative): when `HAS_DIGITAL_A` or `HAS_DIGITAL_B` is set, receivers MUST consider a channel message valid only if all of the following hold:
- `chunk_total >= 1`
- `chunk_index < chunk_total`
- `payload_len` is in `[1..168]`, unless the profile explicitly defines a zero-length message type
- payload tail zero rules from §15 are satisfied
- `payload_crc_lo/hi` matches CRC32/ISO-HDLC over exactly the first `payload_len` payload bytes

If profile policy allows `payload_len == 0`, `payload_crc_lo/hi` MUST equal CRC32/ISO-HDLC of the empty byte string.

If `HAS_DIGITAL_A` (or `HAS_DIGITAL_B`) is set but that channel fails §6.2/§15 validation, receivers MUST ignore that channel payload for the frame and MUST NOT act on it. Receivers SHOULD increment a `digital_invalid` counter. Profiles MAY require full-frame rejection when digital integrity is mission-critical.

**Numeric validity scope:** Digital header and payload cells are subject to the global numeric validity rule (finite + no subnormals) in addition to integer range checks (§13 step 2).

Capacity:
- 56 cells × 3 bytes = 168 bytes per channel
- Two channels = 336 bytes per frame

### 6.3 Band 4 — Quantum Register (cells 148–275)
- 128 cells = 64 qubits
- Each qubit uses `[α, β]`
- Normalization MUST hold: $|\alpha^2 + \beta^2 - 1| \leq \varepsilon$ (recommended $\varepsilon = 10^{-4}$ for Float32). Writers MUST normalize before writing.
- Amplitude sign convention MUST be profile-defined:
    - `nonnegative` (default): writers SHOULD encode `α, β >= 0` for probability-only semantics.
    - `signed-semantic`: sign MAY carry additional profile meaning and MUST be interpreted consistently by all participants.
- Reader policy MUST be profile-defined as one of `{reject | renormalize | clamp+renormalize}` for qubits violating normalization. Normalization violations indicate a non-conformant writer; readers MAY recover per profile policy for robustness.
- Optional numeric hygiene: if `|α|` or `|β|` slightly exceeds `1` due to numeric drift, writers MAY clamp into `[-1, 1]` and then renormalize.

**Wire conformance (core):** Quantum-band cells MUST satisfy the global numeric validity rule (finite + no subnormals), and writers/readers MUST apply the profile-declared normalization policy.

**Interpretation-only semantics (non-wire conformance):** Collapse, entanglement propagation behavior, freshness, and observation semantics are profile interpretation rules (§22) and are not directly verifiable from wire bytes alone.

Scalar extraction rule:
- `p = β²` (probability of observing `|1⟩`)

Measurement rule:
- returns 1 with probability `β²`
- returns 0 with probability `α²`

Entanglement rule (profile interpretation rule):
- Single-hop correlation only
- A↔B MAY influence B on collapse
- A↔B↔C MUST NOT auto-cascade from A to C

These are profile-level interpretation semantics, not core wire-level conformance checks, unless a profile defines an explicit on-wire entanglement map.

Core interoperability recommendation:
- Reserve qubit 62 for freshness
- Reserve qubit 63 for observation density/count mapping

### 6.4 Band 5 — Analog Waveform / Digest (cells 276–659)
Modes:
- Waveform mode: 384 sample floats
- FFT32 digest mode: first 32 cells used as spectral digest
- In FFT32 digest mode, writers SHOULD zero-fill cells `308..659` for deterministic diffs and encoder parity.

Bandwidth guidance:
- If signal has not changed materially, writer SHOULD clear `HAS_WAVEFORM` and zero-fill Band 5
- Readers SHOULD reuse last valid waveform/digest when flag is not set

### 6.5 Band 6 — Client Slot (cells 660–999)
Recommended generic layout:

All integer fields in Band 6 are stored as integer-as-float and MUST satisfy §28.4.

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
| 31..339 | reserved | — | future |

`cmd_seq` is a 24-bit unsigned counter modulo $2^{24}$. Writers and receivers that use `cmd_seq` ordering MUST compare it with modular arithmetic (serial-number rule with $M = 2^{24}$), or rotate session identity (`client_id`) before wrap.

Broadcast downlink rule:
- In shared downlink frames, Band 6 MUST be zero-filled.
- In per-client downlink frames (non-broadcast), Band 6 MAY carry profile-defined per-client state.

### 6.6 Band 6T — Security Trailer (cells 1000–1019)

Band 6T is a distinct trailer band, not a subrange of Band 6.

All integer fields in Band 6T are stored as u16-as-float and MUST satisfy §28.4.

| Cell(s) | Name | Type | Meaning |
|-------:|------|------|---------|
| 1000 | `sec_profile` | u16-as-float | 0=open, 1=S1 auth, 2=S2 reserved |
| 1001 | `key_id` | u16-as-float | active key/session id |
| 1002 | `sec_counter_lo` | u16-as-float | anti-replay low |
| 1003 | `sec_counter_hi` | u16-as-float | anti-replay high |
| 1004..1019 | `tag_u16[16]` | u16-as-float | 256-bit MAC tag |

**Tag word packing rule:** The raw MAC output bytes `tag_bytes[0..31]` are packed into 16 u16 words in **little-endian** order:

```
tag_u16[i] = tag_bytes[2*i] | (tag_bytes[2*i + 1] << 8)
```

Each `tag_u16[i]` is stored as a u16-as-float in cells 1004 through 1019.

### 6.7 Band 7 — Frame Check (cells 1020–1023)

| Cell | Field | Type | Meaning |
|----:|-------|------|---------|
| 1020 | `crc_lo` | u16-as-float | CRC32 low — cells 0–1019 (bytes 0..4079) |
| 1021 | `crc_hi` | u16-as-float | CRC32 high — cells 0–1019 (bytes 0..4079) |
| 1022 | `byte_size` | u16-as-float | MUST be 4096 (total wire frame size including all bands 0–7) |
| 1023 | `magic_echo` | u16-as-float | MUST equal header `magic` |

CRC32 detects accidental corruption; it is not a cryptographic security primitive.

**CRC flavor (normative):** All CRC32 values in DBP (frame-level Band 7 and digital-channel payload CRC) use **CRC-32/ISO-HDLC** (a.k.a. Ethernet / ZIP CRC32): polynomial `0x04C11DB7`, init `0xFFFFFFFF`, xorout `0xFFFFFFFF`, reflected input and output. **Check value:** `CRC32("123456789") = 0xCBF43926`.

---

## 7) Transport model

DBP is transport-agnostic. Common deployment patterns:

1. **Static file relay (pull):** clients poll binary frame endpoint with validators (`ETag` preferred)
2. **SSE relay (push):** one process fans out frame updates
3. **WebSocket/native pub-sub:** lower-latency full-duplex fanout

Writers SHOULD use atomic replacement (`write temp -> rename`) when publishing frames.

---

## 8) Security profiles

### Threat assumptions
Adversary may intercept, replay, inject, and flood traffic.

### Profiles
- `0` Open: CRC only (accidental corruption detection)
- `1` S1: authenticity + anti-replay (MAC + counter)
- `2` S2: reserved for future use (authenticity + confidentiality)

### SEC_TRAILER_PRESENT flag contract

- If `sec_profile != 0`, the sender MUST set the `SEC_TRAILER_PRESENT` flag (bit 5 of `flags_profile`).
- If `sec_profile == 0`, the sender MUST clear `SEC_TRAILER_PRESENT`. (Open-with-trailer frames are undefined and MUST NOT be generated.)
- If `SEC_TRAILER_PRESENT` is set, the receiver MUST verify that `sec_profile` is a supported security profile and non-zero. `sec_profile = 0` with trailer present is malformed and MUST be rejected. Receivers SHOULD support `sec_profile = 1` (S1); profiles that require S1 MUST reject receivers without S1 support. Receivers MUST reject `sec_profile = 2` (S2) unless they explicitly implement S2. Unknown values (≥ 3) MUST be rejected.
- If `SEC_TRAILER_PRESENT` is clear, the receiver MUST NOT read or validate Band 6T.

CRC32 remains REQUIRED in S1 mode. CRC and MAC serve different purposes: CRC is cheap corruption detection/telemetry, while MAC provides authenticity and anti-forgery.

### Canonical byte representation (normative)

- MAC and CRC computations MUST run over exact wire bytes (little-endian IEEE 754 binary32 per cell), never host-native reinterpretations.
- Senders MUST canonicalize `-0.0` → `+0.0` before MAC/CRC computation.
- Subnormals MUST NOT appear on wire. Senders MUST flush subnormal values to `+0.0` before MAC/CRC and publish. Receivers MUST treat frames containing subnormals as invalid.
- Receivers MUST verify MAC/CRC over received raw bytes before any canonicalization of cell values. More precisely: MAC and CRC MUST be computed over the original raw byte buffer exactly as transported, prior to any canonicalization, normalization, or re-serialization. Receivers MAY inspect bytes or decode floats for validation/fail-fast logic, provided MAC/CRC are still computed over the unchanged original received bytes. Do not re-pack, normalize, or regenerate bytes before verification.

Float32 subnormal definition (normative): a value `x` is subnormal iff `x != 0` and `abs(x) < 2^-126`.

**Magnitude floor implication:** Values with $0 < |x| < 2^{-126}$ (approx. $1.175 \times 10^{-38}$) will be coerced to `+0.0` by compliant senders. This affects very small analog Band 5 magnitudes and very small qubit amplitudes at extreme normalization edges. Do not rely on DBP to transport magnitudes below this floor.

Reference canonicalization snippet:

```js
function canonicalizeForWire(frame) {
    const MIN_NORMAL_F32 = 1.17549435e-38; // 2^-126
    for (let i = 0; i < frame.length; i++) {
        const v = frame[i];
        if (!Number.isFinite(v)) throw new Error('non-finite cell');
        if (v === 0 || Math.abs(v) < MIN_NORMAL_F32) frame[i] = 0; // +0.0 canonical
    }
}
```

### S1 rules — authentication

**Default algorithm:** HMAC-SHA-256 with a 32-byte (256-bit) key. The key MUST be raw bytes (not a UTF-8 string); provisioning is out-of-band and profile-defined. Profiles MAY override the algorithm, but any conformant S1 implementation MUST support HMAC-SHA-256 for interoperability.

**Counter composition:** The 32-bit anti-replay counter is composed from two u16 cells:

$$\text{sec\_counter} = \text{sec\_counter\_lo} + \text{sec\_counter\_hi} \times 2^{16}$$

(i.e. `sec_counter_lo + sec_counter_hi * 65536`). Both cells are stored as u16-as-float values and MUST satisfy the canonical decode rule (§28.4).

Writers MUST rotate to a new `key_id` before `sec_counter` wraps. A `(key_id, key_bytes)` pair MUST NOT be reused once retired.

**MAC input:** The MAC MUST be computed over the **wire-format bytes** (little-endian IEEE 754 binary32 for each cell), not native host byte order. The input spans cells 0 through 1003 inclusive (cells 0–1003 = **4016 bytes**). This covers Bands 0–6 and the security metadata cells (`sec_profile`, `key_id`, `sec_counter_lo/hi` — cells 1000–1003). The tag cells (1004–1019) and Band 7 (CRC, cells 1020–1023) are excluded — the tag cells because the tag is the MAC output, and Band 7 because CRC is a non-cryptographic integrity check. On big-endian hosts, implementations MUST byteswap to little-endian before computing MAC or CRC.

**MAC domain separation (normative):** Implementations MUST compute HMAC over `mac_domain_tag || bytes[0..4015]`. The required default is `mac_domain_tag = "DBP-S1\0"` — defined as an explicit byte sequence: `44 42 50 2D 53 31 00` (ASCII `DBP-S1` + `0x00`), **length 7 bytes**. Profiles MAY override this tag, but it MUST be a fixed, non-empty byte string agreed by sender and receiver. Empty-domain HMAC input (`"" || bytes`) MUST NOT be used.

**Counted-byte-string requirement:** Implementations MUST treat `mac_domain_tag` as a counted byte string (pointer + explicit length). Do NOT use NUL-terminated string APIs (e.g. C `strlen` / `strcat`) to pass this value — the tag contains an embedded `0x00` byte, so NUL-terminated handling will silently produce the wrong HMAC input. (Node.js `Buffer.from("DBP-S1\0", "ascii")` is correct; `Buffer.from("DBP-S1\0")` as a UTF-8 string is also correct and yields 7 bytes.)

**Tag length:** The full HMAC-SHA-256 output (256 bits) is stored as sixteen u16 values in cells 1004–1019 using little-endian word packing (see §6.6). The full 256-bit tag provides 128-bit forgery resistance even against quantum-capable adversaries (Grover's bound).

**Sender MUST follow this ordering:**
1. Build frame content (zero-fill unused bands)
2. Canonicalize negative zero (see §14.4)
3. Write security metadata cells (`sec_profile`, `key_id`, `sec_counter_lo/hi`)
4. Compute MAC over `mac_domain_tag ||` cells 0–1003 (bytes 0–4015) → write `tag_u16[0..15]` into cells 1004–1019
5. Compute CRC32 over cells 0–1019 (bytes 0–4079) → write Band 7 (cells 1020–1023)
6. Atomic publish

This ordering guarantees that CRC covers the MAC tag (useful for corruption telemetry) and MAC covers only the frame content it authenticates.

**Anti-replay:**
- **Strict monotonic (default):** Receivers MUST track the highest accepted `(key_id, sec_counter)` pair **per `key_id`** and reject any frame with a counter ≤ the last accepted value for that `key_id`. This is sufficient for polling and SSE transports.
- **Windowed (optional):** For transports that may reorder frames (e.g. multi-relay WebSocket), receivers MAY accept counters within a sliding window of width $W$ above the last accepted counter. The window size $W$ MUST be declared in the profile contract and MUST be bounded (recommended: $W \leq 64$). Window state MUST be tracked **per `key_id`**. Frames below the window floor are rejected unconditionally. Within the window, receivers MUST reject any `(key_id, sec_counter)` value that has already been accepted (implementations SHOULD track accepted counters via a per-`key_id` bitset or equivalent structure).

**Key rotation:**
- Receivers MUST accept the current `key_id` and MAY accept `key_id - 1` during a grace period.
- **Grace policy (default):** receivers MAY accept `key_id - 1` only within `G` seconds after first accepting the new `key_id`, with default `G = 30s`. After grace expiry, only the current `key_id` is accepted. Profiles MAY override `G` or disable grace entirely.
- If `key_id == 0`, there is no `key_id - 1` grace candidate.
- All other key IDs MUST be rejected.
- Anti-replay counters MUST reset to zero when a new `key_id` is first accepted. The counter namespace is per-key — a counter value valid under `key_id = 5` has no relationship to the same counter value under `key_id = 6`.
- Senders MUST assign `key_id` monotonically for the deployment lifetime (or include an explicit epoch in profile policy) to prevent replay acceptance from retired key eras.
- If `key_id` would wrap (u16 overflow), profiles MUST define an out-of-band epoch/deployment identity before wrap to prevent replay acceptance from a previous key era.

### S2 rules — confidentiality (deferred)

S2 is reserved but **not fully specified** in v1.x. A complete S2 envelope requires defining:
- nonce size and in-frame layout
- ciphertext boundaries (which bands are encrypted)
- additional authenticated data (AAD) composition
- per-receiver key distribution

These are v2.0 concerns.

**Recommended interim approach:** Use **TLS** for transport confidentiality, combined with S1 for frame-level authenticity. Deliver per-client confidential data in POST response bodies (not in the shared downlink frame). This cleanly separates bus integrity (S1) from channel confidentiality (TLS).

### Uplink authentication

In S1 mode, the uplink POST body contains Band 6 only (340 cells = 1360 bytes). The in-frame security trailer (Band 6T) is a **downlink-only** construct; uplink POSTs do not include it.

Uplink authentication SHOULD use transport-layer mechanisms:
- **TLS** provides integrity and confidentiality for the POST body.
- **Application-layer MAC** (optional): compute a MAC over the POST body bytes and transmit as an HTTP header (e.g. `X-DBP-Tag: <base64>`). This provides defense-in-depth when TLS termination is handled by an untrusted intermediary.

### Key establishment guidance
Session/group keys SHOULD be established with post-quantum KEM (e.g. ML-KEM-768) or hybrid PQ + classical exchange where practical.

---

## 9) Duotronic math layer (optional but compatible)

DBP is a fixed-offset Float32 frame; polygon witness encoding is an optional profile-level semantic layer, not used for structural fields (Band 0, Band 6T, Band 7 — see §36).

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
- 16 cells × 8 features = 128 floats (512 bytes)
- 128 cells × 8 features = 1024 floats (4096 bytes)

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

---

## 10) Vector integration

A DBP frame is directly usable as a Float32 vector.

Recommended practice:
- store full frames at low sampling rate for replay
- store compact derived state vectors at higher rate for similarity search
- compare full frames with weighted band distances when needed

This keeps protocol telemetry and vector-search infrastructure aligned.

---

## 11) Sustainability policy

DBP v1.1 is the intended final major refinement of fixed-offset Float32 packing.

If new requirements demand repeated multi-cell packing workarounds, that is a migration trigger for v2.0 schema-based wire format (e.g., FlatBuffers/Cap’n Proto class solutions).

---

## 12) Minimal implementation checklist (v1.1)

- Implement magic-based parser split (`0xDB01` / `0xDB11`)
- Enforce numeric validity checks (`no NaN/Inf/subnormals`)
- Implement exact-safe split timestamp fields
- Implement CRC32 verification for Band 7
- Implement flags/profile parsing and unknown-profile behavior
- Implement digital channel chunking and payload CRC checks
- Implement waveform gating flags and reuse logic
- Implement optional security trailer verification (`sec_profile`, `key_id`, counters, tag)
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

CRC_INPUT_CELLS = 0..1019   (bytes 0..4079)
MAC_INPUT_CELLS = 0..1003   (bytes 0..4015)
```

### 12.2 Golden decoder flow (reference pseudocode)

For normative defaults and profile-level override points used during validation, see §16.1.

```text
validate_shape(4096 bytes)
validate_finite_and_no_subnormals(all cells)
validate_integer_as_float(Band0, Band7; Band6T only if SEC_TRAILER_PRESENT)
magic = decode_u16(cell0); dispatch_parser_by_magic(magic)
parse version/tick_rate + validate sec_of_day/ms ranges
validate footer (byte_size, magic_echo)
verify CRC over bytes 0..4079
if SEC_TRAILER_PRESENT: verify security profile + anti-replay + MAC over mac_domain_tag || bytes 0..4015
if !SEC_TRAILER_PRESENT: optional 6T zero hygiene assert
decode bands (digital validity checks, payload CRC, band-specific semantics)
```

### 12.3 Interop byte-range checklist

- MAC input (S1): cells `0..1003` = bytes `0..4015`
- CRC input (frame): cells `0..1019` = bytes `0..4079`
- Tag cells: `1004..1019`
- Footer cells: `1020..1023`

---

## 13) Receiver validation pipeline (normative)

Receivers MUST validate incoming frames in the following fail-fast sequence. Any step that fails MUST cause the frame to be rejected before subsequent steps execute.

1. **Shape check:** exactly 4096 bytes / 1024 Float32 cells
2. **Finite/subnormal validity check:** reject any cell containing `NaN`, `Infinity`, or subnormal Float32 values
    - Receivers MUST reject frames containing `NaN/Inf/subnormals`. This check MAY be performed before CRC/MAC for fail-fast, but MUST be enforced before accept. Numeric validity is independent of authenticity: MAC-valid frames with invalid numeric cells are still invalid.
3. **Integer-as-float check:** validate integer-as-float fields in Band 0 and Band 7 unconditionally; validate Band 6T fields only if `SEC_TRAILER_PRESENT` is set. All checked fields MUST satisfy the canonical decode rule (§28.4)
4. **Magic check:** `0xDB01` or `0xDB11`; reject unknown values
5. **Version parse:** decode `version` and `tick_rate`; also validate header time-field ranges (`sec_of_day ∈ [0..86399]`, `ms ∈ [0..999]`). Profile policy MAY add stricter `unix_day` sanity bounds.
6. **Footer sanity:** `byte_size == 4096`, `magic_echo == magic`
7. **CRC32 check:** verify CRC32 over cells 0–1019 (bytes `0..4079`)
8. **Security check (S1/S2):** if `SEC_TRAILER_PRESENT` flag is set, verify MAC tag and anti-replay counter per §8
    - In S1 mode, receivers MAY verify MAC first (security-first fail-fast) or anti-replay first (cheap-drop fail-fast), as long as both checks are enforced before accepting the frame.
9. **6T hygiene (optional, post-integrity):** if `SEC_TRAILER_PRESENT` is clear, receivers MAY assert that cells 1000–1019 are all `+0.0` as a sanity check (writers are required to zero-fill per §14.3).
10. **Band decoding:** only after all integrity checks pass.
    - If `HAS_DIGITAL_A` or `HAS_DIGITAL_B` is set, receivers MUST validate that digital channel header integer fields (cells 0–7 within the channel) satisfy the canonical decode rule (§28.4) before use. Each payload cell (cells 8–63 within the channel) MUST also be a valid u24-as-float (finite, integral, 0..0xFFFFFF).
    - If a digital channel fails §6.2/§15 validation, receivers MUST treat that channel as absent for the frame and MUST NOT execute actions derived from it (unless profile policy upgrades this to full-frame rejection).
    - If a receiver consumes Band 6 (per-client downlink or server-side uplink), it MUST apply §28.4 to Band 6 integer fields before use.

### Failure handling

Receivers MUST implement the following on frame rejection:
- **Preserve last-good frame:** continuity-sensitive consumers MUST continue using the last successfully validated frame.
- **Count errors:** implementations SHOULD maintain per-category error counters (shape, finite, magic, crc, security) for operational telemetry.
- **No error propagation:** invalid frames MUST NOT be forwarded, stored, or partially decoded.
- **Rate limiting:** if error rate exceeds a threshold (e.g. >50% of frames over a 10-second window), receivers SHOULD back off polling or close the connection and alert the operator.
- **Digital anomaly alerting:** if `HAS_DIGITAL_A/B` is asserted but channel validation fails repeatedly (e.g. `digital_invalid > 1%` of frames over 60s), receivers SHOULD treat this as an integration defect or abuse signal and alert operators.

---

## 14) Sender behavior and timing

### 14.1 Monotonic sequencing
- `seq_lo/seq_hi` MUST represent one monotonic 48-bit unsigned frame counter composed as $\text{seq} = \text{seq\_lo} + \text{seq\_hi} \times 2^{24}$ (i.e. `seq_lo + seq_hi * 16777216`). The counter is modulo $2^{48}$; writers MUST wrap to 0 after `0xFFFFFFFFFFFF`.
- **Modular comparison:** given $M = 2^{48}$, sequence $a$ is newer than $b$ iff $0 < (a - b) \bmod M < M/2$. Readers that do not implement modular comparison MUST treat monotonicity as best-effort across wrap.
- Writers SHOULD increment sequence only for accepted/published frames

### 14.2 Clock fields
- `unix_day`, `sec_of_day`, and `ms` SHOULD be sampled atomically from one clock read
- Writers MUST keep `ms` in `[0..999]`

### 14.3 Zero-fill policy
- Unused or invalidated optional bands SHOULD be zero-filled
- If `HAS_WAVEFORM` is not set, Band 5 SHOULD be zero-filled
- Writers MUST sanitize non-finite computed samples (especially Band 5) to `0.0` before publish, or drop the frame.
- Writers SHOULD expose sanitization telemetry (counter/flag) via profile-defined Band 1 fields or digital messages.
- Subnormals MUST NOT appear on wire. Writers MUST flush subnormals to `+0.0` before MAC/CRC and publish.
- If `SEC_TRAILER_PRESENT` is clear, writers MUST zero-fill Band 6T (cells 1000–1019). This ensures deterministic CRC over cells 0–1019 and prevents stale tag bytes from causing telemetry confusion.
- In shared downlink mode, Band 6 MUST be zero-filled (see §6.5). In per-client downlink frames, Band 6 MAY carry profile-defined state.
- Senders MUST write all reserved cells as `+0.0`, unless explicitly defined by an active profile.
- Receivers in strict mode MAY reject frames where reserved cells are non-zero.
- **Reserved-cell receiver default:** the recommended default is to warn and increment a `reserved_cell_nonzero` telemetry counter on non-zero reserved cells, but accept the frame. Security-hardened deployments (especially public or untrusted endpoints) SHOULD reject frames with non-zero reserved cells.

### 14.4 Atomic publish policy
- Writers SHOULD normalize `-0.0` to `+0.0` for all float cells before MAC/CRC computation, regardless of `sec_profile`. In JS:

```js
for (let i = 0; i < 1024; i++) {
    if (frame[i] === 0) frame[i] = 0; // converts -0 to +0
}
```

- In languages without JS-style `x === 0` canonicalization behavior, implementations SHOULD normalize negative zero explicitly (for example via `copysign`/sign-bit masking or equivalent deterministic method) before MAC/CRC.

- **Receiver `-0.0` treatment:** CRC and MAC MUST be verified over the raw bytes as received (no normalization before verification). After successful verification, receivers MAY canonicalize `-0.0` → `+0.0` for downstream processing or diffing.
- Publish sequence MUST follow the ordering defined in §8 (S1 rules): build → canonicalize → security metadata → MAC → CRC → atomic replace.
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
- `security_requirements` (Open/S1/S2)

Negotiation guidance:
- A receiver MAY expose `supported_profiles` and `supported_security_profiles` out-of-band.
- A sender SHOULD avoid profile-specific commands unless support is confirmed.

Canonical profile contract example (JSON):

```json
{
    "profile_id": 7,
    "profile_name": "example-control",
    "profile_version": "1.2.0",
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

### 16.1 Normative defaults vs profile overrides

| Topic | Default behavior | Profile override allowed? | Reference |
|------|-------------------|---------------------------|-----------|
| Digital channel invalid while `HAS_DIGITAL_*` set | Ignore that channel for the frame; do not act on it | Yes — profile MAY require full-frame rejection | §6.2, §13 |
| Digital payload CRC scope | CRC32/ISO-HDLC over first `payload_len` bytes after u24→bytes expansion | No | §6.2, §15 |
| `msg_id` reuse horizon | Unique for profile-defined `T`/`N`, or monotonic u24 modulo counter | Yes — horizon/wrap policy is profile-defined | §15 |
| Reassembly collision handling | Drop old buffer, start fresh, increment/log collision counter | Yes — stricter rejection/alert policy | §15 |
| Qubit normalization violation | Reader applies profile policy `{reject | renormalize | clamp+renormalize}` | Yes — policy is profile-defined | §6.3, §22.9 |
| Integer `-0.0` handling | Accept as zero in default mode | Yes — strict mode MAY reject in Bands 0/6T/7 | §28.4 |
| Subnormal handling | Subnormals forbidden on wire; writer flushes to `+0.0`, receiver rejects subnormal-containing frames | No | §8, §13, §14.3 |
| S1 verification order | Enforce both anti-replay and MAC before accept | Yes — receiver may choose MAC-first or anti-replay-first fail-fast | §13, §8 |
| S1 MAC domain tag | Fixed non-empty required default tag `"DBP-S1\0"` | Yes — profiles MAY override with another fixed non-empty tag | §8 |
| Key rotation grace | Accept previous key only during default grace window `G = 30s` | Yes — profile may override `G` or disable grace | §8 |
| Zero-length digital payload | Disallowed unless explicitly enabled by profile | Yes — profile may allow with empty-payload CRC rule | §6.2, §15 |
| Digital message commitment fields | None required by default | Yes — profile SHOULD add `msg_len_total` / `msg_crc32_total` (and optional `msg_nonce`) | §15 |
| Quantum amplitude sign policy | `nonnegative` default semantics | Yes — profile may declare `signed-semantic` | §6.3, §22 |

---

## 17) Conformance test matrix (minimum)

Implementations SHOULD include repeatable tests for:

1. **Endian conformance:** round-trip known frame bytes on little/big-endian hosts
2. **Numeric rejection:** frames containing `NaN/Inf/subnormals` are rejected
3. **Magic split:** parser dispatches correctly between `0xDB01` and `0xDB11`
4. **Header decode:** version, tick_rate, and split timestamp decode accurately
5. **CRC check:** corrupted payload bytes fail CRC
6. **Digital chunking:** out-of-order chunks reassemble correctly
7. **Quantum normalization:** qubit pairs violating $|\alpha^2+\beta^2 - 1| \leq \varepsilon$ (§6.3) are rejected or renormalized per policy
8. **Replay defense (S1/S2 when implemented):** repeated or stale counters are rejected
9. **Waveform gating:** reader reuses prior waveform when flag is clear

### 17.1 Deterministic conformance vector (v1.1 + S1)

Use this vector to validate end-to-end packing, MAC scope, tag packing, and CRC ordering.

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
- `tag_bytes` (hex): `8c4ae150702ce62e421f78fb27d556845b5722397832020601952473c6959e66`
- `tag_u16[16]` (decimal): `19084,20705,11376,12006,8002,64376,54567,33878,22363,14626,12920,1538,38145,29476,38342,26270`
- `CRC32` (hex): `0x0015E7B9`
- `crc_lo`: `59321`
- `crc_hi`: `21`
- Full frame SHA-256 (4096 bytes): `fdcec2cd421b091e281ee15e6ae2916c8ce04052d898812280fb62fd1d087fc0`
- First 64 bytes (hex): `00115b47000030410000803f0000000000409c4600e4404600802944000000420000004000000000000000000000000000000000000000000000000000000000`

If any value differs, re-check endianness, canonical integer-as-float decoding, MAC/CRC byte ranges, and the “verify before canonicalization” rule for `-0.0`.

### 17.2 Deterministic conformance vector (v1.1 + Open mode)

Use this vector to validate the no-trailer path (`sec_profile = 0`) and deterministic CRC behavior when Band 6T is zero-filled.

**Frame setup (all unspecified cells are `+0.0`):**
- Band 0: `magic=56081`, `version=11`, `seq_lo=2`, `seq_hi=0`, `unix_day=20000`, `sec_of_day=12346`, `ms=679`, `flags_profile=0` (`SEC_TRAILER_PRESENT` clear), `tick_rate=2`
- Band 6T: all cells `1000..1019` are `+0.0`

**Computation order:**
1. Canonicalize `-0.0` to `+0.0` (deterministic writer hygiene; see §14.4)
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

Implementations SHOULD ship a tiny reference verifier (e.g., Node.js script) that reconstructs deterministic vectors, computes HMAC-SHA-256 over `mac_domain_tag || bytes[0..4015]`, computes CRC32/ISO-HDLC over bytes `0..4079`, and checks expected tag/CRC outputs. This prevents cross-implementation drift.

---

## 18) Versioning notes (first publication)

- This document defines the first published implementation.
- Parser selection MUST rely on `magic` parser split, not heuristics.
- Unknown future profile IDs SHOULD be treated as generic/core-only unless explicitly supported.
- Future revisions SHOULD preserve deterministic conformance vectors for regression verification.

---

## 19) Security hardening checklist (operational)

- Use TLS for all transports
- Enforce strict origin policy (avoid permissive wildcard origins in production)
- Rate-limit uplink writes per client identity and source
- Rotate keys (`key_id`) on schedule and incident response
- Bind replay windows to `key_id` + counter monotonicity
- Log verification failures with coarse-grained reason codes

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
| **DBP** | **positional multiplexed signal** | **all three signal types simultaneously** | — |

DBP's closest conceptual relatives are radio-frequency multiplexing and CAN bus arbitration — data is separated by position within a continuous frame, not by message boundaries or topic strings.

---

## 22) Quantum register — detailed specification

### 22.1 State representation

Each qubit occupies two consecutive cells:

$$
|\psi\rangle = \alpha|0\rangle + \beta|1\rangle
$$

- Cell `148 + 2*q` = $\alpha$ (amplitude of $|0\rangle$)
- Cell `148 + 2*q + 1` = $\beta$ (amplitude of $|1\rangle$)

Amplitude sign convention is profile-defined (§6.3). In the default `nonnegative` policy, writers SHOULD encode `α, β >= 0` for equivalent probabilities.

where `q` is the qubit index (0..63).

### 22.2 Writing a probability into a qubit

Given a scalar probability `p` (0.0 to 1.0) that a condition is true:

Writers MUST clamp `p` into `[0, 1]` before encoding to avoid `NaN` from `sqrt` of a negative value (which would violate §1 hard constraints).

```
α = sqrt(1.0 - p)
β = sqrt(p)
```

### 22.3 Reading a scalar from a qubit

Clients MUST use $\beta^2$ to recover the probability. Do NOT use $\beta$ directly.

```js
function getQubitProbability(frame, qubitIndex) {
    const beta = frame[148 + 2 * qubitIndex + 1];
    return beta * beta;  // β² = probability of |1⟩
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
cell[272] = sqrt(1.0 - freshness)   // α
cell[273] = sqrt(freshness)          // β
```

### 22.5 Observation count (qubit 63)

Encodes writer-maintained observation density/count telemetry as a saturating probability from receiver `measure()` / `sample()` activity reports:

$$
p = \frac{\min(\mathrm{count},\, N_{max})}{N_{max}}
$$

where $N_{max}$ is a profile-defined ceiling (e.g. 1000). High observation count ($\beta \to 1$) indicates a well-exercised register.

This is not auto-mutated by receiver-local `measure()` calls. If profiles want client observations reflected on the bus, clients MUST transmit measurement events via profile-defined uplink and the writer MUST re-emit updated telemetry.

### 22.6 Measurement — formal collapse rules

1. **Probabilistic sample/collapse:** `sample(q)` (a.k.a. `measure(q)`) returns 1 with probability $\beta^2$, else 0. Post-sample the qubit is in a classical interpretation state — subsequent reads return the interpreted value. **Collapse is a receiver-local interpretation step;** it does not mutate the shared frame. The interpreted/collapsed state only propagates if the profile explicitly writes it back into a subsequent frame.

**Interpretation-only semantics (non-normative for core wire conformance):** Rules 2 and 3 below describe receiver-local interpretation behavior. They impose no requirements on the wire frame itself and are not enforceable from wire bytes alone.

2. **Correlated partner collapse (profile-defined interpretation):** If qubit `q` has an entangled partner `r` with correlation strength $C$ (0.0–1.0):
   - $C > 0.5$: partner collapses to the **same** result with probability $C$
   - $C < 0.5$: partner collapses to the **opposite** result with probability $1 - C$
   - $C = 0.5$: no correlation (maximally uncorrelated)

3. **No transitive chaining (profile-defined interpretation):** If A↔B and B↔C, collapsing A affects B but MUST NOT propagate automatically to C.

4. **Observation telemetry ownership:** receiver-local `sample()/measure()` does not mutate the shared frame. Any change to qubit 63 requires an explicit profile write-back path via writer logic.

### 22.7 Correlation strength `C`

`C` is **not transmitted** in the frame. It is defined out-of-band by the profile (static config or config endpoint). If dynamic correlation is needed, a profile MAY reserve a dedicated cell or digital message for per-pair `C` values.

Because entanglement topology and `C` are out-of-band in v1.1, these collapse/correlation rules are not core wire-level conformance checks by themselves.

### 22.8 Measurement determinism

`sample()`/`measure()` uses client-side randomness by default. Two clients sampling the same qubit may get different results — acceptable for UI predictions but NOT for shared-state consensus.

- For per-client stable UX determinism, seed PRNG with `(frame_seq, qubit_id, client_id)`.
- For shared deterministic outcomes across clients, seed PRNG with `(frame_seq, qubit_id)` (exclude `client_id`).

### 22.9 Normalization enforcement

Writers MUST ensure $|\alpha^2 + \beta^2 - 1| \leq \varepsilon$ (recommended $\varepsilon = 10^{-4}$ for Float32) for every qubit (see §6.3). Readers MUST apply the profile-defined policy `{reject | renormalize | clamp+renormalize}` when this constraint is violated.

Renormalization (if permitted by profile):

```js
const mag = Math.sqrt(alpha * alpha + beta * beta);
if (mag > 0) { alpha /= mag; beta /= mag; }
else { alpha = 1.0; beta = 0.0; }  // default to |0⟩
```

---

## 23) Transport layer — detailed architecture

### 23.1 Phase 1 — Static file relay (pull)

```
Writer (1 process)          Static server (nginx)         Clients (N)
┌──────────────┐           ┌────────────────────┐        ┌───────────────┐
│ Build frame   │──write──▶│ /dbp/live/frame.bin │◀──GET─│ Conditional   │
│ every tick    │           │ 4096 bytes          │─304/─▶│ poll (ETag)   │
│ (atomic swap) │           │ ETag + Last-Modified│ 200   │ every Nms     │
└──────────────┘           └────────────────────┘        └───────────────┘
```

**Cache validation:** Clients SHOULD prefer `If-None-Match` (ETag) over `If-Modified-Since`. ETag changes atomically on every `rename()` and is reliable at any frame rate. `Last-Modified` has ~1-second mtime granularity and will miss sub-second updates.

**Cost model:**
- 304 responses are ~100 bytes
- At 200 clients × 2 FPS = 400 req/s of tiny static responses — trivial for nginx
- Writer costs 1 process per tick regardless of client count

**Crash recovery:** If writer crashes between write and rename, orphaned `.tmp` files may remain. Writers SHOULD clean up stale temp files on startup.

### 23.2 Phase 2 — SSE relay (push fanout)

A lightweight process watches the static file and broadcasts changes:

```
Writer → frame.bin → [file watcher] → SSE broadcast → N clients
```

- One relay process handles ~5,000–10,000 concurrent SSE connections
- Latency: <50ms from write to all clients
- Memory: ~5–20MB for the relay process
- Beyond ~10k clients: use multiple relay instances behind a load balancer with shared message bus (e.g. Redis pub/sub)

### 23.3 Phase 3 — Native pub/sub (nchan, WebSocket)

For 100k+ clients:
- Writer POSTs frame to nchan internal pub endpoint
- nchan distributes natively to SSE/WebSocket/long-poll subscribers
- Requires nchan-enabled nginx or a dedicated WebSocket server (Go, Rust, Node.js)

### 23.4 Base64 transport (SSE/text channels)

When transporting via text-only channels (SSE `data:` field, JSON embedding), the frame is base64-encoded:

Canonical length formula: `base64_len(n) = 4 × ceil(n / 3)`.

For a full DBP frame: `base64_len(4096) = 4 × ceil(4096/3) = 4 × 1366 = 5464` characters.

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

### 23.6 Uplink transport

```
POST /dbp/uplink
Content-Type: application/octet-stream
Body: Float32Array(340).buffer  (1360 bytes, Band 6 only)
```

Servers MAY accept full 4096-byte frames or Band 6-only payloads.

In S1 mode, uplink authentication is handled at the transport layer (see §8, "Uplink authentication"), not via in-frame trailer.

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

The shared downlink frame represents **global state only**. Writers MUST NOT embed any single client's uplink data into the broadcast frame — doing so leaks one client's state to all others.

### 25.2 Per-client responses

Per-client acknowledgements and results SHOULD be delivered via the POST response body (the HTTP response to the uplink), NOT via the shared downlink.

### 25.3 Per-client confidential data

If a profile requires per-client encrypted data in broadcast, use the digital channels with per-client AEAD envelopes (keyed per-client). Only the intended client can decrypt.

---

## 26) Desync detection and recovery

### 26.1 Mechanism

The uplink includes `last_seq_lo/hi` — the last downlink sequence the client received. The server compares this to its current sequence.

### 26.2 Detection

If the gap exceeds a threshold (e.g. ~10 frames), the client is desynced.

### 26.3 Recovery options

- **Full state push:** server sends a complete frame with all bands populated (waveform included, all flags set)
- **Resync flag:** define a flags bit to signal "this is a full-state resync frame"
- **Out-of-band:** return full state in the uplink POST response body

### 26.4 Uplink integrity

Uplink integrity is delegated to the transport layer:
- **TLS** protects the POST body against corruption and tampering in transit.
- **S1 application-layer MAC** (optional, see §8) provides defense-in-depth via `X-DBP-Tag` HTTP header.
- **HTTP-layer checksums** (e.g. `Content-MD5`) MAY be used for cheap corruption telemetry on non-TLS links.

A dedicated in-frame uplink CRC is **not specified** — it would conflict with the `cmd_params` cell range in Band 6, and transport-layer integrity is more robust.

---

## 27) Scaling characteristics

| Metric | Value |
|--------|-------|
| Frame size | 4096 bytes (1024 × Float32) |
| Frame rate | configurable (2 FPS typical, up to 30+) |
| Bandwidth per client (2 FPS) | ~8 KB/s raw; ~200 B/s actual (mostly 304s) |
| Server-side writers needed | 1 per deployment |
| Concurrent readers | limited only by static server (thousands+) |
| Analog capacity | 395 continuous float channels (Bands 1 + 5) |
| Digital capacity | 336 bytes per frame (2 × 168-byte channels) |
| Quantum registers | 64 qubits (128 float cells) |
| Uplink capacity | 340 float cells per POST |
| Latency (Phase 1 poll) | ≤ poll interval (e.g. 500ms) |
| Latency (Phase 2 SSE) | <50ms |
| Latency (Phase 3 WS) | <10ms |

### Sequence number lifespan

| FPS | Wrap time (48-bit counter) |
|----:|----------------------------|
| 2   | ~4.5 million years         |
| 30  | ~297,000 years             |
| 60  | ~148,000 years             |

---

## 28) Float32 precision — detailed caveats

### 28.1 The core constraint

Float32 has a 23-bit mantissa (24-bit significand). All integers through $2^{24}$ are exactly representable, but contiguous integer exactness for protocol packing is the u24 range (`0..2^{24}-1`).

### 28.2 What this means for DBP

- **Sequence numbers** in a single cell would wrap at ~97 days at 2 FPS. v1.1 solves this with the `seq_lo/seq_hi` split.
- **Unix timestamps** (~1.7 × 10⁹) cannot be stored in a single Float32 cell with sub-second precision. v1.1 solves this with `unix_day / sec_of_day / ms`.
- **CRC32 values** (up to ~4.3 × 10⁹) exceed the exactness limit. v1.1 stores them as two u16 halves.

### 28.3 Safe integer ranges for common cell types

| Type label | Stored as | Exact range | Bits |
|------------|-----------|-------------|------|
| u16-as-float | Float32 | 0..65,535 | 16 |
| u24-as-float | Float32 | 0..16,777,215 | 24 |
| raw float | Float32 | ±3.4 × 10³⁸ (with precision loss) | 24 significand |

### 28.4 Integer-as-float canonical decode rule

For all `u16-as-float` and `u24-as-float` fields, receivers MUST verify all three conditions before casting:

1. **Finite:** the value is not `NaN` or `Infinity`
2. **Integral:** `Math.floor(x) === x` (no fractional part)
3. **In range:** `0 ≤ x ≤ 65535` for u16, `0 ≤ x ≤ 16777215` for u24

A value failing any check MUST be treated as frame corruption. This rule is referenced throughout the spec wherever integer-as-float cells appear.

Sender rule (normative): Senders MUST encode integer-as-float fields by assigning the integer numeric value and allowing normal Float32 conversion/rounding semantics. Senders MUST NOT generate these fields via bit-pattern reinterpretation/casting tricks.

```js
function decodeU16(x) {
    if (!Number.isFinite(x) || x !== Math.floor(x) || x < 0 || x > 0xFFFF)
        throw new Error('invalid u16-as-float');
    return x;               // returns integer-valued Number (keeps u16 values >= 0x8000 positive)
}
function decodeU24(x) {
    if (!Number.isFinite(x) || x !== Math.floor(x) || x < 0 || x > 0xFFFFFF)
        throw new Error('invalid u24-as-float');
    return x >>> 0;         // returns integer-valued Number
}
```

`-0.0` note: default mode MUST accept `-0.0` as numeric zero for integer-as-float fields. Strict mode MAY reject `-0.0` in structural integer fields (Bands 0, 6T, and 7) as additional hygiene.

If a decoded u16 value is later used in bitwise operations, implementations SHOULD coerce explicitly (e.g. `value & 0xFFFF` or `value >>> 0`) to avoid language-specific signedness pitfalls.

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

Writers MAY skip emitting frames when no state has changed. Clients polling with ETag receive 304s automatically. This is transparent to the protocol — clients MUST NOT assume consecutive sequence numbers.

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
- Band 1 changed → update control state
- Band 2 changed → process digital message
- Band 4 changed → update quantum predictions
- Band 5 changed → update waveform display

---

## 31) Encoding walkthrough examples

### 31.1 Writing a u24 integer into a Float32 cell

```js
// Encode: integer → Float32 cell
const value = 12345;
frame[cellIndex] = value;  // direct assignment, exact for 0..16,777,215

// Decode: Float32 cell → integer
const recovered = frame[cellIndex];  // exact
```

### 31.2 Packing 3 bytes into one cell (u24 byte packing)

```js
// Encode
const b0 = 0x48, b1 = 0x65, b2 = 0x6C;  // "Hel"
frame[cellIndex] = b0 + (b1 << 8) + (b2 << 16);  // 7,103,816

// Decode
const val = decodeU24(frame[cellIndex]);  // canonical integer decode (§28.4)
const b0_out = val & 0xFF;           // 0x48 'H'
const b1_out = (val >> 8) & 0xFF;    // 0x65 'e'
const b2_out = (val >> 16) & 0xFF;   // 0x6C 'l'
```

### 31.3 Encoding a qubit from a probability

```js
// Encode: probability p → qubit pair
const p = 0.67;
frame[148 + 2*q]     = Math.sqrt(1.0 - p);  // α
frame[148 + 2*q + 1] = Math.sqrt(p);         // β

// Decode: qubit pair → probability
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
   Quantized digit: floor(0.4978 × 64) = 31
   n = 6 (pronic(6) = 42 >= 31)

3. Build 8-feature witness cell:
   [0.4978, 0.094, 1.0, 0.738, 1.0, 0.667, 0.0, 1.0]
    ↑        ↑      ↑     ↑      ↑     ↑      ↑    ↑
   value  n_sides center density kind  band  parity degen

Each cell = 8 × Float32 = 32 bytes
```

---

## 32) Vector database integration — detailed

### 32.1 Frames as vectors

A DBP frame is a 1024-dimensional Float32 vector — structurally identical to a vector database embedding. Frames can be stored, indexed, and queried using standard vector infrastructure.

| Aspect | Vector DB embedding | DBP frame |
|--------|-------------------|-----------|
| Shape | Float32[N] (typically 384–1536) | Float32[1024] |
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
| Quantum (4) | 128 | Cosine (signed-semantic) or L2 on probability vector `[β²]` (nonnegative) | avoid sign-convention drift |
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
| Lattice | Band 1 (cells 9–19) | 11 |
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
| On state change | varies | ~5–50 MB | event-driven |

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
| **Compression-friendly** | Sparse frames compress 4–10× under gzip/brotli. |
| **Vector-compatible** | Frame is directly usable as a 1024-d vector for similarity search. |
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
| **Polygon witness overhead** | When using duotronic math: 8× storage expansion (1 scalar → 8 features). |

### Bottom line

DBP's value is **architectural unification** — one fixed-size binary format for real-time communication, vector storage, and probabilistic state. The fixed overhead is justified when you need zero-allocation decoding, multiplexed signal types, and vector-compatible frames.

---

## 34) Known v1.0 limitations (resolved in v1.1)

| Issue | Impact | v1.1 resolution |
|-------|--------|----------------|
| `frame_seq` wraps at ~97 days (2 FPS) | counter ambiguity | split into `seq_lo/seq_hi` (48-bit) |
| `server_time` loses precision in Float32 | ~128s granularity | split into `unix_day/sec_of_day/ms` |
| Weighted-sum checksum is fragile | rounding, NaN propagation | replaced with CRC32 |
| No waveform gating | wasted bandwidth | `HAS_WAVEFORM` flag + zero-fill |
| No per-band presence flags | ambiguous "is this band active?" | flags bitfield in header |
| Header only 4 cells | no room for split fields | expanded to 9 cells (0–8) |
| Band 1 had 16 cells | 4 became header | Band 1 now 11 cells (9–19) |

### v1.0 → v1.1 header cell migration

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

## 35) Naming philosophy — "Quantum Register"

The quantum register uses quantum mechanics as a **computational metaphor** for probabilistic state on classical hardware. It does not involve actual quantum computing, quantum networking, or quantum data transport.

Complex amplitudes are explicitly out of scope in v1.x; the register uses real-valued amplitudes only.

The naming is intentional — the register genuinely implements:
- **Superposition:** continuous amplitude pairs, not just 0/1
- **Sampling:** probabilistic observation weighted by amplitude (quantum-collapse metaphor)
- **Entanglement:** correlated partner collapse with configurable strength

These behaviors run on classical CPUs using standard Float32 arithmetic.

Alternative names considered: "Predictive Register", "Probabilistic State Model". "Quantum" is retained because it accurately describes the computational model, even though the substrate is classical.

**Distinct from post-quantum security:** DBP's security profiles (§8) reference post-quantum *cryptography* (ML-KEM, ML-DSA) — resistance to quantum attackers. That is an entirely separate concern from the quantum-inspired register, which is a state representation tool.

---

## 36) Header encoding caveat — raw fractions vs polygon encoding

When packing control fields (magic, flags, bitmasks, routing identifiers) into Float32 cells, implementations MUST use **raw integer assignment**, NOT polygon witness encoding.

Polygon encoding quantizes values through polygon-family digit selection, which corrupts bitwise fields. Example failure:

```
Input bitmask: 63 (0x3F = 0b00111111)
→ polygon encode → denormalize → 65 (0x41 = 0b01000001)
Result: video and text flags lost, metadata flag spuriously set
```

**Rule:** All Band 0 (header), Band 6T (security), and Band 7 (CRC) fields use raw integer-as-float storage. Polygon witness encoding is only for profile-defined semantic values where quantization is acceptable.

---

## 37) Text packing via digital channels

### 37.1 Chars-per-cell calculation

Each Float32 cell stores a u24 integer → 3 bytes → 3 ASCII bytes, or 1–3 UTF-8 bytes. Some Unicode code points require 4 UTF-8 bytes and therefore span multiple cells.

For a 64-cell digital channel:

$$
64 \times 3 = 192 \text{ total bytes if all cells carried payload}
$$

In DBP, the first 8 cells are channel header (§6.2), so only 56 payload cells remain: 56 × 3 = **168 usable payload bytes per channel**.

### 37.2 Encoding text into digital cells

```js
function textToDigitalCells(text, channelStart, frame) {
    const bytes = new TextEncoder().encode(text);
    if (bytes.length > 168) throw new Error("chunk payload exceeds 168 bytes");

    const payloadStart = channelStart + 8;  // skip digital header cells 0..7
    const usedCells = Math.ceil(bytes.length / 3);

    let cellIdx = payloadStart;
    for (let i = 0; i < usedCells * 3; i += 3) {
        const b0 = bytes[i]     ?? 0;
        const b1 = bytes[i + 1] ?? 0;
        const b2 = bytes[i + 2] ?? 0;
        frame[cellIdx++] = b0 + (b1 << 8) + (b2 << 16);
    }

    // Zero-fill payload tail cells per §15
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
    const payloadStart = channelStart + 8;  // skip digital header cells 0..7
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

Large text payloads (>168 bytes) use the chunking protocol (§15):

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

1. **Fixed frame size** — Wastes bytes when data is sparse but eliminates framing ambiguity, length-prefix parsing, and buffer management.

2. **Float32 for everything** — Requires integer-as-float encoding tricks for discrete data but enables zero-allocation typed-array decoding and direct vector-database compatibility.

3. **Bands at fixed offsets** — Some bands may be unused in a given application, wasting cells, but any implementation can read any band without negotiation or capability discovery.

4. **Quantum metaphor** — More complex than a simple bitmask/probability-map, but provides collapse, entanglement, and freshness semantics that are genuinely useful for predictive state.

The debt is manageable because the frame structure is fixed and fully documented. No runtime surprises. No schema negotiation. The cost is paid once at design time, not continuously at runtime.

**When the debt becomes unmanageable:** If applications routinely need >80% of bands to be profile-customized, or if most cells are wasted, the protocol should migrate to a schema-based format (§20).

---

## 39) Implementation notes

### 39.1 Endianness

The frame MUST be transported in **little-endian** byte order. This is the native byte order for all modern x86, ARM, and WASM platforms. Implementations on big-endian platforms MUST byte-swap on read/write.

JS portability note: when computing MAC/CRC, hash the little-endian wire byte stream. On big-endian JS hosts, serialize cells explicitly with `DataView.setFloat32(offset, value, true)`.

### 39.2 Zero-copy access in JavaScript

WARNING: If you do not know host endianness, assume nothing — decode with `DataView.getFloat32(offset, true)`.

```js
// Zero-allocation decode
const buffer = await response.arrayBuffer();
// WARNING: TypedArray uses native endianness; this is zero-copy correct only on little-endian hosts.
// On big-endian hosts, decode via DataView.getFloat32(offset, true) or reserialize to little-endian first.
const frame = new Float32Array(buffer);
// Direct indexing — no parsing
const magic = decodeU16(frame[0]);   // canonical decode (§28.4)
const seqLo = decodeU24(frame[2]);   // seq_lo is u24
```

### 39.3 Zero-copy access in C

```c
// Memory-mapped or network buffer
float* frame = (float*)buffer;

// Canonical decode helpers — finite + integral + range checks per §28.4
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
This is a minimal Node.js verifier skeleton (no dependencies beyond built-in crypto):

```
import crypto from "crypto";

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

  // security metadata (cells 1000..1003)
  frame[1000] = u16ToFloat(1);
  frame[1001] = u16ToFloat(1);
  frame[1002] = u16ToFloat(1);
  frame[1003] = u16ToFloat(0);

    // MAC over mac_domain_tag || bytes 0..4015 (cells 0..1003)
    const macDomainTag = Buffer.from("DBP-S1\0", "ascii");
    const macInput = Buffer.from(buf, 0, 4016);
  const key = Buffer.alloc(32, 0x11);
    const tag = crypto.createHmac("sha256", key).update(macDomainTag).update(macInput).digest(); // 32 bytes

  // pack tag into u16 words little-endian into cells 1004..1019
  for (let i = 0; i < 16; i++) {
    const lo = tag[2*i];
    const hi = tag[2*i + 1];
    frame[1004 + i] = u16ToFloat(lo | (hi << 8));
  }

  // CRC over bytes 0..4079 (cells 0..1019)
  const crc = crc32IsoHdlc(new Uint8Array(buf, 0, 4080));
  frame[1020] = u16ToFloat(crc & 0xFFFF);
  frame[1021] = u16ToFloat((crc >>> 16) & 0xFFFF);
  frame[1022] = u16ToFloat(4096);
  frame[1023] = u16ToFloat(56081);

  return { buf, frame, tag, crc };
}

const { tag, crc } = buildVectorS1();
console.log("tag_hex", tag.toString("hex"));
console.log("crc_hex", "0x" + crc.toString(16).padStart(8, "0"));
```

## 41) Glossary

| Term | Definition |
|------|-----------|
| **Band** | A contiguous range of Float32 cells within a frame, dedicated to one signal type. |
| **Cell** | A single Float32 slot within the frame (index 0–1023). |
| **Chunk** | A segment of a multi-frame digital message, identified by `chunk_index` / `total_chunks`. |
| **Collapse / sample()** | Receiver-local probabilistic observation of a qubit, resolving superposition into a definite 0 or 1 interpretation. |
| **Compact state vector** | A reduced-dimensionality extraction of key band features for cheaper vector search. |
| **CRC32** | 32-bit cyclic redundancy check stored as two u16 halves in Band 7. |
| **DBP** | Duotronic Bus Protocol — the subject of this specification. |
| **Downlink** | Server-to-client frame broadcast (the shared signal). |
| **Entanglement** | Correlation between two qubits such that measuring one influences the other's collapse. |
| **Frame** | A `Float32Array(1024)` = 4096 bytes. The atomic unit of DBP communication. |
| **Frame diff** | A comparison of two frames yielding a list of changed cell indices. |
| **Freshness** | A decay metric indicating how recently the quantum register was recomputed. |
| **Gated** | A band marked as inactive via flags (zero-filled, receivers skip processing). |
| **Lattice** | Band 1 (11 cells, cells 9–19). General-purpose control/status channel for analog floats. |
| **Magic number** | Cell 0. Identifies the frame as DBP and indicates the protocol version. |
| **Observation count** | Qubit 63. Writer-maintained telemetry for observation density/count (not auto-mutated by receiver-local `measure()`). |
| **Optimistic state** | Client-side predicted state applied immediately, reconciled when server confirms. |
| **Polygon witness** | An 8-feature geometric metadata cell from the duotronic math layer (§9). |
| **Profile** | An application-level contract defining band semantics, qubit assignments, digital message types, and security level. |
| **Pronic number** | $n(n+1)$: the polygon family used for quantized digit encoding. |
| **Quantum register** | Band 4. 64 qubits (128 cells) encoding probabilistic state as α/β amplitude pairs. |
| **Qubit** | A pair of Float32 cells representing a quantum-inspired probability via $\alpha$ and $\beta$ amplitudes. |
| **Raw fraction** | A direct float value (0.0–1.0 or integer-as-float) stored without polygon encoding. |
| **Receiver** | Any process that consumes DBP frames (client-side). |
| **Security trailer** | Band 6T (cells 1000–1019, 20 cells). Counter, key ID, and 256-bit MAC tag. |
| **Sender** | Any process that produces DBP frames (server-side writer). |
| **Sparsity** | The proportion of zero-valued cells in a frame. Higher sparsity = better compression. |
| **Superposition** | A qubit state where both $|0\rangle$ and $|1\rangle$ amplitudes are non-zero. |
| **u24** | An unsigned 24-bit integer stored as a Float32 (exact for 0–16,777,215). |
| **Uplink** | Client-to-server command frame (Band 6 content, sent via POST). |
| **Waveform** | Band 5 (384 cells). Continuous signal data (audio, sensor, telemetry, etc.). |
| **Writer** | The single process responsible for building and emitting downlink frames. |

---

*End of specification*

