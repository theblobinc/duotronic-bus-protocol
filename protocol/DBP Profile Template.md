# DBP Profile Template (v1.1 baseline)

> **Purpose:** This template is a *profile contract* for the Duotronic Bus Protocol (DBP).  
> DBP core defines the fixed 4096-byte Float32 frame. **Profiles define semantics.**  
> Fill this in for each application that rides on DBP.

---

## 0) Profile metadata

- **Profile name:** `<NAME>`
- **profile_id (0–255):** `<ID>`
- **Profile version (semver):** `<X.Y.Z>`
- **DBP baseline:** v1.1 (`magic = 0xDB11`)
- **Transport(s):** `static file | SSE | WebSocket | ...`
- **Tick rate expectation:** `<fps>` (0 = paused/unspecified)
- **Security requirement:** `Open | S1 (HMAC) | S2 (reserved)`

### Compatibility
- **Readers MUST:** accept DBP v1.1 frames and ignore unknown reserved bits.
- **Writers MUST:** zero-fill unused bands and reserved fields.

---

## 1) Normative language

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are requirement levels.

---

## 2) Threat model (profile-specific)

- **Adversary capabilities:** `intercept | replay | inject | flood | ...`
- **Integrity requirements:** `CRC-only | MAC required | ...`
- **Replay tolerance:** `strict monotonic | windowed W=<N> | none`
- **Key rotation policy:** `<schedule / on incident / manual>`

---

## 3) Frame-level rules (profile additions)

Byte interval notation used in this template:
- `bytes[a..b]` means an inclusive byte interval (includes both `a` and `b`).
- `[a, b)` denotes a half-open interval (includes `a`, excludes `b`) when explicitly used.

### 3.1 Finite-value rule
- Writers MUST NOT emit `NaN`, `Infinity`, or subnormal Float32 values in any cell.
- Receivers MUST reject frames containing any `NaN`, `Infinity`, or subnormal Float32 values.

### 3.2 Integer-as-float canonical rule
For any `u16-as-float` or `u24-as-float` fields used by this profile, receivers MUST validate:
1) finite, 2) integral, 3) in-range.

Sender rule: senders MUST write integer-as-float fields by assigning integer numeric values (normal Float32 conversion). Senders MUST NOT use bit-pattern reinterpretation/casting tricks.

### 3.3 `-0.0` canonicalization rule
- Writers SHOULD canonicalize `-0.0` → `+0.0` for all cells **before** MAC/CRC computation.
- Receivers MUST verify CRC/MAC over the original raw byte buffer exactly as transported, prior to canonicalization, normalization, or re-serialization.
- Receivers MAY inspect bytes or decode floats for fail-fast validation, provided CRC/MAC are still computed over the unchanged original received bytes.
- Receivers MAY canonicalize `-0.0` → `+0.0` after verification for downstream diffing.

---

## 4) Band map (semantic contract)

> DBP core defines offsets; this section defines *meaning*.

### Band 1 (cells 9–19) — Analog Control Lattice

| Cell | Name | Units | Range | Meaning |
|---:|------|-------|-------|---------|
| 9 | `a0` | `<unit>` | `<min..max>` | `<meaning>` |
| ... | | | | |
| 19 | `a10` | `<unit>` | `<min..max>` | `<meaning>` |

**Rules:**
- If a channel is undefined in this profile, writers MUST write `+0.0`.
- Receivers MUST treat undefined channels as reserved.

---

### Band 2 (cells 20–83) — Digital Channel A
### Band 3 (cells 84–147) — Digital Channel B

#### Message types
| msg_type (u16) | Name | Payload format | Notes |
|---:|------|---------------|------|
| 1 | `<TYPE>` | `<json / msgpack / custom>` | `<notes>` |

#### Command/response correlation
- `msg_id` is the correlation key across channels and frames.
- `chunk_index` / `chunk_total` define reassembly.

**Rules:**
- payload bytes MUST be packed as u24 triples (3 bytes per cell).
- payload_len MUST be ≤ 168 per channel chunk.
- payload CRC MUST be CRC-32/ISO-HDLC over exactly `payload_len` bytes.

---

### Band 4 (cells 148–275) — Quantum-inspired Register (probabilistic state)

> **Important:** This is a *classical* probabilistic register. It is not actual quantum transport.

**Wire conformance (core):** Quantum-band cells MUST satisfy global numeric validity (`finite + no subnormals`) and the profile-declared normalization policy.

**Interpretation-only semantics (non-normative for core wire conformance):** Collapse, entanglement behavior, freshness interpretation, and observation semantics are profile interpretation rules and are not directly verifiable from wire bytes alone.

#### Probability encoding
- Each qubit is `[α, β]` with `p(|1⟩) = β²`.
- Writers MUST normalize so `|α² + β² - 1| ≤ ε`.

**Profile parameter:** `ε = <DEFAULT 1e-5>`

#### Qubit assignments
| Qubit | Name | Meaning | Producer | Consumer |
|---:|------|---------|----------|----------|
| 0 | `<q0>` | `<meaning>` | `<writer>` | `<reader>` |
| ... | | | | |
| 62 | `freshness` | recommended | writer | readers |
| 63 | `observation_density` | recommended | reader-local or writer | readers |

**Rules:**
- If a qubit is undefined, writers MUST write `α=1.0, β=0.0`.
- If a qubit violates normalization beyond ε, receivers MUST follow the policy below.

#### Normalization policy (choose one)
- [ ] **Reject:** receiver rejects the entire frame if any qubit violates ε.
- [ ] **Renormalize:** receiver renormalizes each offending qubit and continues.

---

### Band 5 (cells 276–659) — Waveform / Digest

- **Mode selection:** `HAS_WAVEFORM` and `WAVEFORM_IS_FFT32`.
- **Waveform mode:** 384 float samples
- **FFT32 mode:** first 32 cells are spectrum digest, remaining cells profile-defined or zero.

**Rules:**
- If `HAS_WAVEFORM` is clear, writers SHOULD zero-fill Band 5.
- Receivers SHOULD reuse last-good waveform/digest when `HAS_WAVEFORM` is clear.

---

### Band 6 (cells 660–999) — Client Slot (uplink / per-client downlink)

#### Uplink command schema
| Offset | Name | Type | Meaning |
|---:|------|------|---------|
| 660 | `client_kind` | u16-as-float | `<meaning>` |
| 661..662 | `client_id` | u16-as-float | `<meaning>` |
| 666 | `cmd_id` | u16-as-float | `<meaning>` |
| 667..690 | `cmd_params` | float | `<meaning>` |

**Rules:**
- Broadcast downlink frames MUST zero-fill Band 6.
- Per-client downlink frames MAY populate Band 6, but MUST NOT leak other clients’ state.

---

## 5) Security contract (profile decisions)

### Open (sec_profile=0)
- CRC32 is required.
- No authentication.

### S1 (sec_profile=1) — Authenticity + anti-replay
- Baseline algorithm: **HMAC-SHA-256**.
- MAC input: `bytes[0..4015]` (cells `0..1003`, 4016 bytes).
- MAC domain tag default: bytes `44 42 50 2D 53 31 00` (ASCII `DBP-S1` + `0x00`, length 7).
- Implementations MUST treat `mac_domain_tag` as a counted byte string; do NOT use NUL-terminated APIs.
- Tag storage: cells `1004..1019` as sixteen u16 words (little-endian packing).
- Anti-replay: `<strict monotonic | windowed W=N>` tracked per key_id.

**Rules:**
- If S1 is required, receivers MUST reject frames missing `SEC_TRAILER_PRESENT`.
- Writers MUST zero-fill Band 6T when `SEC_TRAILER_PRESENT` is clear.

---

## 6) Receiver validation pipeline (profile tightening)

Minimum fail-fast order:

1) Shape: exactly 4096 bytes (1024 Float32)
2) Numeric validity: reject any NaN/Inf/subnormal
3) Canonical integer checks (Band 0, Band 7; plus Band 6T if present)
4) Magic/version checks
5) Footer sanity: `byte_size==4096`, `magic_echo==magic`
6) CRC32 verify (cells 0–1019)
7) If S1: MAC verify and anti-replay
8) Decode bands (apply per-band rules)

---

## 7) Writer ordering (implementation-ready)

Writers SHOULD follow this exact order:

1) Build frame content (zero-fill unused bands)
2) Canonicalize `-0.0` → `+0.0` for all float cells
3) Write security metadata (if any): `sec_profile`, `key_id`, counter
4) Compute and write MAC tag (if S1)
5) Compute and write CRC32 footer
6) Atomic publish (write temp → rename)

---

## 8) Relay & cache patterns (practical deployment)

### Static file relay + ETag polling
- Server SHOULD enable ETag.
- Clients SHOULD use `If-None-Match` to get cheap 304s.
- Writers SHOULD publish by atomic rename to ensure ETag flips cleanly.

### SSE relay
- Relay watches the frame file and pushes deltas or full frames.
- Clients keep “last-good” frame and ignore invalid frames.

---

## 9) Appendix: Profile test requirements

Profiles SHOULD ship test fixtures:

- A set of valid frames (Open, S1)
- Corrupted-frame samples (bad CRC, bad MAC, NaN injection)
- A small “golden” DBP frame with known decoded values for each defined band.

---

*End of template.*
