# Duotronic Math v2
## A Long-Form Technical Paper on Witness Geometry, Semantic Encoding, and DBP Integration

Version: 2.0 draft
Date: 2026-03-05
Status: Reference paper

---

## Abstract

Duotronic Math is a semantic encoding framework that represents values as geometric witnesses instead of bare scalars. A value is carried as a structured object that includes magnitude, geometric family, activation pattern, and contextual metadata. This paper presents an implementation-focused v2 treatment with a normative reference profile: the witness model, family mathematics, encoding and decoding bridges, semantic operations, practical drawing methods, implementation code, and how the model integrates with the Duotronic Bus Protocol (DBP) without violating wire-level safety rules.

The key v2 position is explicit:
- Duotronic Math is a semantic layer.
- DBP remains the wire contract.
- Structural wire fields are never witness-encoded.

This paper is intentionally implementation-oriented. It includes formulas, pseudo-derivations, and runnable examples in JavaScript and Python.

---

## Normative Language (Applies Throughout)

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, and `MAY` in this paper indicate requirement levels.

- `MUST` / `MUST NOT`: mandatory for conformance.
- `SHOULD` / `SHOULD NOT`: strong recommendation.
- `MAY`: optional behavior.

---

## Table of Contents

0. Normative Language
1. Motivation and Design Goals
2. Conceptual Model
3. Witness Data Model
4. Token-Free Zero and Presence Semantics
5. Witness Family Mathematics
6. Normalization and Numeric Contracts
7. The One-Based Modular Bridge
8. Drawing a Digital Witness (Step by Step)
9. Reference Profile (Normative) and End-to-End Encoding
10. End-to-End Decoding Pipeline
11. The Duotronic Primitive `D = (p, q)`
12. Projection, Stability, and Composition
13. Calibration and Domain Mapping
14. Storage and Similarity Space
15. DBP Integration Rules
16. Security Semantics and Policy Gating
17. Implementation Patterns and Anti-Patterns
18. Reference Code (JavaScript)
19. Reference Code (Python)
20. Worked Examples
21. Conformance Checklist
22. Future Research Directions
23. Glossary

---

## 1) Motivation and Design Goals

Traditional transport of raw numbers is compact but semantically thin. A scalar like `0.4978` says nothing about:
- how it should be interpreted,
- whether it is present vs absent,
- whether it came from a discrete or continuous domain,
- what operation family produced it,
- whether uncertainty or correction should be propagated.

Duotronic Math addresses this by using a witness representation. A witness carries value plus metadata in a stable feature tuple.

v2 goals:
1. Preserve practical utility from v1-era docs (simple coding, direct visualization, easy debugging).
2. Add explicit contracts for semantic safety, reversibility, and policy behavior.
3. Integrate cleanly with DBP v1.x structural validation and security model.
4. Keep a deterministic path from domain value -> witness -> domain value.

---

## 2) Conceptual Model

A Duotronic witness is a geometric-semantic record of a value. Instead of saying "value is 42," it says:
- what normalized value was encoded,
- what polygon family was used,
- where inside that family band it sits,
- how activated the witness is,
- optional parity/degeneracy metadata.

The model is built around an overlay grid:
- rows: semantic cells,
- columns: witness features.

Terminology disambiguation:
- In this paper, `overlay grid` means semantic witness layout (`rows x 8 features`).
- In DBP contexts, `lattice` may refer to Band 1 control floats.

Common semantic overlays:
- `16 x 8` (compact pulse-style state overlays),
- `128 x 8` (larger semantic overlays).

DBP note:
- `16 x 8` fits cleanly into DBP semantic bands.
- `128 x 8` is a full-frame semantic format and is typically off-wire unless structural cells are explicitly excluded.

Important:
- these are semantic overlays,
- not DBP wire-shape definitions.

---

## 3) Witness Data Model

Recommended v2 feature order (8 features):

1. `value_norm`
2. `n_sides_norm`
3. `center_on`
4. `activation_density`
5. `kind_flag`
6. `band_position`
7. `parity`
8. `degeneracy`

### 3.1 Feature intent

- `value_norm`: normalized magnitude in the profile's numeric bridge domain.
- `n_sides_norm`: normalized polygon side count.
- `center_on`: witness center activation bit (0 or 1 in most profiles).
- `activation_density`: how much of the polygon perimeter/vertices are active.
- `kind_flag`: witness family identifier.
- `band_position`: quantized location within family range.
- `parity`: parity marker for family-specific invariants.
- `degeneracy`: number of equivalent encodings or ambiguity class.

Profiles may specialize semantics, but interoperability requires explicit field contracts.

### 3.2 Canonical storage / transport representation

Canonical storage and transport form is `float[8]` in fixed order:

```text
[value_norm, n_sides_norm, center_on, activation_density, kind_flag, band_position, parity, degeneracy]
```

Normative requirement:
- ordering is normative,
- keyed JSON is readability-only.

### 3.3 Developer-friendly JSON representation

```json
{
  "value_norm": 0.4978,
  "n_sides_norm": 0.09375,
  "center_on": 1,
  "activation_density": 0.738,
  "kind_flag": 1,
  "band_position": 0.667,
  "parity": 0,
  "degeneracy": 1
}
```

### 3.4 Conversion requirement

Implementations should provide explicit helpers:
- `array_to_object(float[8]) -> witness_object`
- `object_to_array(witness_object) -> float[8]`

---

## 4) Token-Free Zero and Presence Semantics

Token-free zero is a first-class absence marker.

Definition:
- all witness features are zero -> semantic absence.

Contrast:
- numeric zero as a real value is present and must be encoded as a non-zero witness tuple.

Why this matters:
- sparse diff pipelines become cheap,
- inactive channels are unambiguous,
- "no value" cannot be confused with "value = 0".

### 4.1 Presence predicate

```text
present(witness_f32) = any(feature_i != 0 for i in 0..7)
absent(witness_f32)  = not present(witness_f32)
```

Conformance requirement:
- presence/absence checks MUST be performed on Float32-decoded feature values (after Float32 cast), not higher-precision intermediates.

---

## 5) Witness Family Mathematics

v2 uses two primary families.

## 5.1 Even-Range family

For `n` sides, weights are:

```text
[2, 4, 6, ..., 2n]
```

Sum:

```text
S_even(n) = n(n + 1)
```

Typical use:
- smooth continuous values,
- progress-like quantities,
- densities and analog-derived semantics.

## 5.2 Pronic-Chain family

Built from pronic numbers:

```text
P(k) = k(k + 1)
```

Gap chain:

```text
P(k) - P(k-1) = 2k
```

Typical use:
- discrete ids,
- counters,
- queue index / track index style values.

## 5.3 Family selection contract

If multiple families are active:
- `kind_flag` must identify family,
- profile must define exact selection policy.

Example policy:
- integers -> pronic-chain,
- continuous ratios -> even-range.

Reference-profile interpretation note:
- family math primarily defines render/activation family behavior,
- numeric invertibility is governed by bridge/normalization contracts,
- family selection still affects `n`, activation layout, and `kind_flag`.

---

## 6) Normalization and Numeric Contracts

Witness fields are represented as finite Float32-compatible values in most implementations.

Recommended numeric constraints:
1. All witness feature values must be finite.
2. `value_norm`, `n_sides_norm`, `activation_density`, `band_position` should be in `[0, 1]` unless profile states otherwise.
3. `center_on` should be in `{0, 1}`.
4. `kind_flag`, `parity`, `degeneracy` should map to bounded profile-defined integer domains through a clear bridge.
5. In Open/S1 transports, witness values MUST NOT be subnormal Float32 values.

Invalid numeric values:
- if any witness feature is `NaN` or `+Inf` or `-Inf`, the row is invalid and invalid-witness policy applies.

Signed-domain mapping (reference profile):
- `value_norm = (x - x_min)/(x_max - x_min)` with published bounds,
- apply explicit clamp/reject policy when out of range.

Float32 canonicalization:
- encoders SHOULD cast each witness feature to Float32 before storage/transport,
- decoders SHOULD validate based on the Float32-decoded feature values.

Subnormal Float32 handling (Open/S1):
- a value is subnormal if `0 < abs(x) < 2^-126` for IEEE-754 Float32,
- encoder MUST flush subnormal witness features to `0.0` before transmit,
- decoder MUST treat a row containing subnormal feature values as invalid and apply invalid-witness policy.
- if encoder-side subnormal flushing yields token-free zero, the row MUST be treated as absent.

Strict present-witness invariants:
- if `present(witness_f32)`, then `kind_flag` must decode to a supported family id,
- if `present(witness_f32)`, then `degeneracy >= 1`,
- if `present(witness_f32)`, then side decode must yield `n >= 3`.

Float32 representation terms:
- `float32_cast_each(w)` means each feature is rounded/cast to IEEE-754 binary32 and handled as that binary32 value thereafter.
- `Float32-decoded feature values` means decoder logic operates on those binary32 values, not higher-precision intermediates.

For strict mode profiles, treat out-of-range feature values as semantic-invalid.

---

## 7) The One-Based Modular Bridge

Rounding operator used throughout this paper:

```text
round_half_up(x) = floor(x + 0.5)
```

Normative requirement:
- all decode steps that convert a normalized field into integer counts `m`, `n`, and `active_count` MUST use `round_half_up` unless explicitly specified otherwise.

Operator definitions (reference profile):

```text
clamp(lo, hi, x) = min(hi, max(lo, x))
clamp01(x) = min(1, max(0, x))
frac(x) = x - floor(x)
mod(a, n) = a - n*floor(a/n), for n > 0
```

Conformance notes:
- `band_position` canonical domain is `[0, 1)`.
- if an implementation computes `band_position = 1.0`, it MUST canonicalize to `0.0`.
- decoder MUST canonicalize `band_position == 1.0` to `0.0` before applying the `[0,1]` range contract.
- reference-profile integer path assumes non-negative `m`.

For integer domain `[0..M_max]`:

Encode:

```text
v_norm = (m + 1) / (M_max + 1)
```

Decode:

```text
m = min(M_max, max(0, round_half_up(v_norm * (M_max + 1)) - 1))
```

This one-based bridge ensures:
- explicit `m = 0` does not collapse to all-zero witness absence.

### 7.1 Symbol-count equivalent form

If a profile reasons in symbol count `N`, use:

```text
N = M_max + 1
encode: v_norm = (m + 1) / N
decode: m = min(M_max, max(0, round_half_up(v_norm * N) - 1))
```

---

## 8) Drawing a Digital Witness (Step by Step)

This section describes exactly how to draw a witness so humans can inspect semantic state.

Assume:
- `n` polygon sides,
- center `(cx, cy)`,
- radius `r`,
- clockwise vertex ordering.

Reference side normalization constants:
- `N_MIN = 3`
- `N_MAX = 64`

Canonical side normalization:

```text
encode: n_sides_norm = (n - N_MIN) / (N_MAX - N_MIN)
decode: n = N_MIN + round_half_up(n_sides_norm * (N_MAX - N_MIN))
```

### 8.1 Compute vertices

For vertex index `i in [0..n-1]`:

```text
theta_i = theta0 + 2*pi*i/n
x_i = cx + r*cos(theta_i)
y_i = cy + r*sin(theta_i)
```

`theta0 = -pi/2` is a common top-oriented start.

### 8.2 Map witness to draw parameters

Recommended mapping:
- edge alpha = `activation_density`,
- center dot visible if `center_on == 1`,
- stroke hue selected by `kind_flag`,
- stroke width scaled by `band_position`,
- dash pattern changed by `parity`,
- marker multiplicity/halo by `degeneracy`.

### 8.3 Minimal drawing recipe

1. Draw regular polygon outline with `n` sides.
2. Fill interior with low-opacity color proportional to `value_norm`.
3. If `center_on == 1`, draw center disk.
4. Add side highlights for active portion derived from `activation_density`.
5. Add text labels with `(family, value_norm, band_position)`.

### 8.4 JavaScript Canvas example

Representation note:
- this renderer expects object form (`w.value_norm`, `w.n_sides_norm`, ...),
- convert canonical `float[8]` to object form before drawing.

```javascript
function drawWitness(ctx, w, cx, cy, r) {
  const N_MIN = 3;
  const N_MAX = 64;
  const roundHalfUp = (x) => Math.floor(x + 0.5);
  const n = Math.min(N_MAX, Math.max(N_MIN, N_MIN + roundHalfUp(w.n_sides_norm * (N_MAX - N_MIN))));
  const theta0 = -Math.PI / 2;

  const pts = [];
  for (let i = 0; i < n; i++) {
    const t = theta0 + (2 * Math.PI * i) / n;
    pts.push({ x: cx + r * Math.cos(t), y: cy + r * Math.sin(t) });
  }

  const hue = w.kind_flag === 1 ? 210 : 30;
  const fillA = Math.max(0, Math.min(1, w.value_norm));
  const edgeA = Math.max(0, Math.min(1, w.activation_density));

  ctx.save();

  // Fill
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
  ctx.closePath();
  ctx.fillStyle = `hsla(${hue}, 70%, 50%, ${0.08 + 0.35 * fillA})`;
  ctx.fill();

  // Outline
  ctx.lineWidth = 1 + 3 * Math.max(0, Math.min(1, w.band_position));
  ctx.strokeStyle = `hsla(${hue}, 80%, 45%, ${0.25 + 0.75 * edgeA})`;
  if (w.parity % 2 === 1) ctx.setLineDash([6, 4]);
  ctx.stroke();

  // Center marker
  if (w.center_on >= 0.5) {
    ctx.beginPath();
    ctx.arc(cx, cy, Math.max(2, r * 0.08), 0, 2 * Math.PI);
    ctx.fillStyle = `hsla(${hue}, 90%, 40%, 0.9)`;
    ctx.fill();
  }

  // Degeneracy halo
  const d = Math.max(0, roundHalfUp(w.degeneracy));
  for (let k = 0; k < d - 1; k++) {
    const rr = r + 4 + k * 3;
    ctx.beginPath();
    ctx.arc(cx, cy, rr, 0, 2 * Math.PI);
    ctx.strokeStyle = `hsla(${hue}, 70%, 45%, 0.15)`;
    ctx.lineWidth = 1;
    ctx.setLineDash([]);
    ctx.stroke();
  }

  ctx.restore();
}
```

### 8.5 Python SVG example

```python
import math


def witness_svg(w, cx=120, cy=120, r=80):
    N_MIN = 3
    N_MAX = 64

    def round_half_up(x: float) -> int:
        return int(math.floor(x + 0.5))

    n = min(N_MAX, max(N_MIN, N_MIN + round_half_up(w["n_sides_norm"] * (N_MAX - N_MIN))))
    theta0 = -math.pi / 2
    pts = []
    for i in range(n):
        t = theta0 + 2 * math.pi * i / n
        x = cx + r * math.cos(t)
        y = cy + r * math.sin(t)
        pts.append((x, y))

    poly = " ".join(f"{x:.2f},{y:.2f}" for x, y in pts)
    fill_opacity = 0.08 + 0.35 * max(0.0, min(1.0, w["value_norm"]))
    edge_opacity = 0.25 + 0.75 * max(0.0, min(1.0, w["activation_density"]))

    center = ""
    if w["center_on"] >= 0.5:
        center = f'<circle cx="{cx}" cy="{cy}" r="6" fill="rgba(24,92,210,0.9)" />'

    return f"""
<svg width="240" height="240" xmlns="http://www.w3.org/2000/svg">
  <polygon points="{poly}" fill="rgba(42,120,230,{fill_opacity:.3f})"
           stroke="rgba(28,92,210,{edge_opacity:.3f})" stroke-width="3" />
  {center}
</svg>
"""
```

---

## 9) Reference Profile (Normative) and End-to-End Encoding

Input: domain value `x`.

Reference constants:
- `N_MIN = 3`, `N_MAX = 64`
- `KIND_EVEN = 1`, `KIND_PRONIC = 2`
- `N_EVEN = 16`, `N_PRONIC = 24`

### 9.0 Reference Profile Parameters (Normative)

- integer domains: `M_max` MUST be specified per field.
- continuous domains: `x_min` and `x_max` MUST be specified per field, or an explicit inverse mapping MUST be provided.
- recommended: publish profile parameters as a compact table or JSON schema for portability.

Canonical field rules (reference profile):
1. `value_norm`
  - integer domains: one-based bridge.
  - signed/continuous domains: `(x - x_min)/(x_max - x_min)` with published bounds.
2. `n_sides_norm`
  - deterministic reference-profile side-count rule:
    - if `kind_flag = KIND_EVEN`, then `n = N_EVEN`.
    - if `kind_flag = KIND_PRONIC`, then `n = N_PRONIC`.
  - encode with `N_MIN/N_MAX` normalization.
3. `center_on`
  - `1` for present witnesses, `0` for absent witness.
4. `activation_density`
  - canonical default `activation_density = clamp01(value_norm)`.
5. `kind_flag`
  - stored as float, decoded as integer via `kind_i = round_half_up(kind_flag)`.
  - valid decoded values: `1` (even-range), `2` (pronic-chain).
6. `band_position`
  - canonical integer-domain path:
    - `start_index = mod(m, n)`
    - `band_position = start_index / n`
  - canonical default for continuous domain: `frac(value_norm)`.
7. `parity`
  - reference profile default MUST be `0` unless an explicit profile override is published.
  - stored as float, decoded as integer via `parity_i = round_half_up(parity)`.
  - `0` = clockwise activation order,
  - `1` = counterclockwise activation order.
8. `degeneracy`
  - canonical default `1` for present witness,
  - stored as float, decoded as integer via `degeneracy_i = round_half_up(degeneracy)`,
  - `0` only for token-free zero,
  - if present, decoded `degeneracy_i` MUST satisfy `>= 1`.

Deterministic activation pattern from existing fields:
- `active_count = clamp(0, n, round_half_up(activation_density * n))`
- integer mode: `start_index = mod(min(n - 1, round_half_up(band_position * n)), n)` after canonicalizing `band_position == 1.0` to `0.0`
- continuous mode (render-control): `start_index = mod(floor(band_position * n), n)`
- direction controlled by `parity`

Note:
- continuous-mode `start_index` is a render-control parameter and is not part of the numeric reversibility contract.

Reversibility contract (reference profile):
- reversible core: `value_norm`, `n_sides_norm`, `kind_flag`.
- deterministic render controls: `center_on`, `activation_density`, `band_position`, `parity`.
- ambiguity metadata: `degeneracy` (not required for numeric inversion).

Encoding pipeline:
1. Select profile domain and family.
2. Convert `x` to `value_norm`.
3. Determine integer side count `n` then encode `n_sides_norm`.
4. Compute remaining fields by canonical rules above.
5. If value is absent, emit token-free zero.
6. Serialize as canonical `float[8]`.
7. If entering DBP frame, ensure witness is only written into semantic-eligible regions.

### 9.1 Canonical pseudocode (reference profile)

```text
encodeWitness(x, kind_flag, mode, params):
  if mode == absent:
    return [0,0,0,0,0,0,0,0]

  if kind_flag == KIND_EVEN: n = N_EVEN
  else if kind_flag == KIND_PRONIC: n = N_PRONIC
  else: invalid

  if mode == integer:
    m = params.m
    value_norm = (m + 1) / (M_max + 1)
    start_index = mod(m, n)
    band_position = start_index / n
  else:
    value_norm = clamp01((x - x_min)/(x_max - x_min))
    band_position = frac(value_norm)

  n_sides_norm = (n - N_MIN)/(N_MAX - N_MIN)
  center_on = 1
  activation_density = clamp01(value_norm)
  parity = 0
  degeneracy = 1

  w = [value_norm, n_sides_norm, center_on, activation_density,
       kind_flag, band_position, parity, degeneracy]
  return float32_cast_each(w)

decodeWitness(w):
  if all_zero(w): return absent

  validate finite, non-subnormal (Open/S1), and range contracts
  if w.band_position == 1.0: w.band_position = 0.0
  if w.n_sides_norm < 0 or w.n_sides_norm > 1: invalid

  center_i = round_half_up(w.center_on)
  kind_i = round_half_up(w.kind_flag)
  parity_i = round_half_up(w.parity)
  degeneracy_i = round_half_up(w.degeneracy)
  validate center_i/kind_i/parity_i/degeneracy_i invariants
  w.center_on = center_i

  n = N_MIN + round_half_up(w.n_sides_norm * (N_MAX - N_MIN))
  n = clamp(N_MIN, N_MAX, n)

  if mode == integer:
    m = min(M_max, max(0, round_half_up(w.value_norm * (M_max + 1)) - 1))
    start_index = mod(min(n - 1, round_half_up(w.band_position * n)), n)
  else:
    require x_min and x_max (or explicit inverse mapping) from active profile
    x_hat = x_min + w.value_norm * (x_max - x_min)
    start_index = mod(floor(w.band_position * n), n)

  return decoded semantic record
```

---

## 10) End-to-End Decoding Pipeline

Input: witness tuple `w`.

1. Presence test: token-free zero or present.
2. Validate finite/range contracts.
3. Resolve family from `kind_flag`.
4. Decode quantized fields via `round_half_up` where specified by profile rules.
5. Recover normalized value and decode through bridge.
6. Validate present-witness invariants.
7. Apply profile semantics (units, bounds, optional correction models).
8. Optionally render witness visualization for operator/debug tooling.

### 10.1 Invalid witness policy (reference profile)

If a witness row is present but invalid (for example unsupported `kind_flag`, `degeneracy < 1`, non-finite value, or range-contract violation):
- decoder MUST treat the row as inactive by replacing it with token-free zero,
- decoder MUST emit per-row validation telemetry/event metadata,
- decoder SHOULD continue frame processing unless active deployment policy requires hard reject.

This invalidity set includes `NaN`, `+Inf`, and `-Inf` feature values.

Reference-profile strict check:
- if `n_sides_norm` is outside `[0,1]`, the row is invalid and this policy applies.

---

## 11) The Duotronic Primitive `D = (p, q)`

v2 introduces optional semantic primitives where each logical value is a pair:
- `p`: primary value-bearing term,
- `q`: corrective/context term.

Use cases:
- uncertainty representation,
- confidence-weighted control,
- compensation or residual channels,
- robust composition in noisy domains.

Profiles must define:
- units of `p` and `q`,
- sign conventions,
- allowable ranges,
- whether `D` is carried directly or projected to witness fields.

---

## 12) Projection, Stability, and Composition

### 12.1 Projection

Default:

```text
N_lambda(D) = p - lambda*q
```

Default `lambda = 1.0`.

### 12.2 Stability

Default bounded function:

```text
S(p, q; eps) = clamp01(1 - abs(q)/(abs(p)+abs(q)+eps))
```

Defaults:
- `eps = 1e-9`,
- `S in [0, 1]`.

### 12.3 Composition

Given `D1=(p1,q1)` and `D2=(p2,q2)`:

```text
D_add = (p1+p2, q1+q2)
D_mul = (p1*p2, p1*q2 + p2*q1)
```

### 12.4 Post-operation policy

Profile must declare:
- clamp,
- reject,
- or rescale,
for out-of-range terms after composition.

---

## 13) Calibration and Domain Mapping

Profiles should publish deterministic forward/inverse mappings.

Reference linear template:

```text
p = (x - x_offset)/x_scale
q = (x_ref - x)/q_scale
```

Calibration contract should include:
1. source units,
2. output ranges,
3. quantization tolerance,
4. inverse reconstruction precision.

---

## 14) Storage and Similarity Space

Duotronic witnesses are naturally vector-friendly.

Recommended practices:
- store both raw witness vectors and derived scalar projections,
- index with cosine distance for semantic similarity,
- maintain family and profile tags alongside vectors,
- keep absence (`token-free zero`) explicit to avoid false similarity.

---

## 15) DBP Integration Rules

DBP remains strict wire authority; Duotronic math integrates through semantic payload policy.

Hard integration rules:
1. Never witness-encode structural fields.
2. Respect integer-as-float decode constraints for structural fields.
3. In secure profiles, semantic execution should be gated by security mode.
4. In S2 workflows, semantic interpretation of protected areas occurs after integrity/authentication and profile validation.

Structural fields (non-witness by definition):
- header cells,
- digital header A cells,
- digital header B cells,
- security trailer cells,
- CRC/footer cells,
- profile-defined integer-decoded structural cells.

Structural no-witness fence:
- Band 0 (`cells[0..8]`),
- Band 6T (`cells[1000..1019]`),
- Band 7 (`cells[1020..1023]`),
- any canonical integer-decoded structural field.

Band 6 nuance:
- Band 6 MAY be used for witness packing only when the active profile explicitly marks those cells semantic-safe and not integer-decoded structural fields.

DBP-safe witness packing capacities:

The table below reflects the DBP v1.x default band map.

| Region | Float32 cells | Witness capacity (`/8`) | DBP-safe |
|---|---:|---:|---|
| Band 4 | 128 | 16 | Yes |
| Band 5 | 384 | 48 | Yes |
| Band 4 + Band 5 | 512 | 64 | Yes |
| Full frame (`1024`) | 1024 | 128 | No (includes structural cells) |

`128 x 8 = 1024` is therefore an off-wire semantic buffer format unless a profile explicitly excludes structural cells before witness packing.

### 15.1 Dense overlay vs sparse transport (selected Option B)

Reference deployment choice:
- Keep the semantic model as a dense witness overlay (`R x 8`).
- Keep DBP transport fixed-shape (`4096` bytes / `1024` Float32 cells).
- Use ABB Option B for sparse transport when beneficial: carry sparse witness bytes in authenticated S2 `opaque_bytes` leased slices.

Rationale:
- DBP does not change on-wire frame size; zeros are still part of fixed-shape frame semantics.
- Sparse carriage reduces leased payload consumed by mostly-absent witness overlays.
- Receiver compute cost can scale with `K` (present rows) instead of `R` (total rows).

Reference sparse payload (`WSB2`) structure:
- header (`16` bytes): `magic='WSB2'`, `version`, `overlay_id`, `rows=R`, `cols=8`, `present=K`, `flags`.
- bitmap: `ceil(R/8)` bytes.
- packed data: `K` witness rows as raw little-endian Float32 `K * 8 * 4` bytes.

Sizing formula:
- dense bytes: `R * 8 * 4`
- sparse bytes: `16 + ceil(R/8) + (K * 8 * 4)` (+ optional profile CRC)

Example (`R=64`, `K=8`):
- dense `= 2048` bytes
- sparse `= 16 + 8 + 256 = 280` bytes

Interoperability rule:
- when sparse witness transport is used, profile contracts MUST publish the lane mapping and `WSB2` schema/version; decoders MUST treat rows with bitmap bit `0` as absent (token-free zero equivalent).

Reference implementations:
- JavaScript: `protocol/wsb2_ref.mjs`
- Python: `protocol/wsb2_ref.py`

---

## 16) Security Semantics and Policy Gating

When semantics influence control behavior:
- require secure transport mode,
- require S2 on untrusted links,
- disable semantic action in insecure mode.

Recommended strict behavior:
- treat insecure semantic payload as inactive,
- emit policy telemetry,
- maintain deterministic reject/event handling in hardened profiles.

---

## 17) Implementation Patterns and Anti-Patterns

### Good patterns

- Separate structural and semantic encoders.
- Implement explicit presence tests.
- Keep family selection deterministic.
- Version profile contracts.
- Add witness rendering utilities for observability.

### Anti-patterns

- Witness-encoding control bitmasks.
- Treating all-zero witness as numeric zero.
- Mixing family mappings without tagging.
- Applying semantic logic before security gating in secure profiles.

---

## 18) Reference Code (JavaScript)

### 18.1 One-based bridge helpers

```javascript
export function encodeOneBased(m, mMax) {
  return (m + 1) / (mMax + 1);
}

export function roundHalfUp(x) {
  return Math.floor(x + 0.5);
}

export function decodeOneBased(vNorm, mMax) {
  const N = mMax + 1;
  const q = roundHalfUp(vNorm * N);
  return Math.min(mMax, Math.max(0, q - 1));
}

export function encodeSides(n, nMin = 3, nMax = 64) {
  return (n - nMin) / (nMax - nMin);
}

export function decodeSides(nSidesNorm, nMin = 3, nMax = 64) {
  const n = nMin + roundHalfUp(nSidesNorm * (nMax - nMin));
  return Math.min(nMax, Math.max(nMin, n));
}
```

### 18.2 Token-free zero helpers

```javascript
export function isTokenFreeZero(w) {
  for (let i = 0; i < 8; i++) if (w[i] !== 0) return false;
  return true;
}

// Note: IEEE-754 -0 equals 0 in strict comparisons used above.

export function makeAbsentWitness() {
  return [0, 0, 0, 0, 0, 0, 0, 0];
}

export function witnessObjectToArray(w) {
  return [
    w.value_norm,
    w.n_sides_norm,
    w.center_on,
    w.activation_density,
    w.kind_flag,
    w.band_position,
    w.parity,
    w.degeneracy,
  ];
}

export function witnessArrayToObject(a) {
  return {
    value_norm: a[0],
    n_sides_norm: a[1],
    center_on: a[2],
    activation_density: a[3],
    kind_flag: a[4],
    band_position: a[5],
    parity: a[6],
    degeneracy: a[7],
  };
}
```

### 18.3 Primitive projection

```javascript
export function projectD(p, q, lambda = 1.0) {
  return p - lambda * q;
}

export function stabilityD(p, q, eps = 1e-9) {
  const den = Math.abs(p) + Math.abs(q) + eps;
  const s = 1 - Math.abs(q) / den;
  return Math.max(0, Math.min(1, s));
}
```

---

## 19) Reference Code (Python)

### 19.1 Bridge + token-free zero

```python
import math


def round_half_up(x: float) -> int:
    return int(math.floor(x + 0.5))


def encode_one_based(m: int, m_max: int) -> float:
    return (m + 1) / (m_max + 1)


def decode_one_based(v_norm: float, m_max: int) -> int:
    N = m_max + 1
    q = round_half_up(v_norm * N)
    return min(m_max, max(0, q - 1))


def encode_sides(n: int, n_min: int = 3, n_max: int = 64) -> float:
    return (n - n_min) / (n_max - n_min)


def decode_sides(n_sides_norm: float, n_min: int = 3, n_max: int = 64) -> int:
    n = n_min + round_half_up(n_sides_norm * (n_max - n_min))
    return min(n_max, max(n_min, n))


def is_token_free_zero(w: list[float]) -> bool:
    return all(v == 0.0 for v in w[:8])

# Note: IEEE-754 -0.0 compares equal to 0.0 in this predicate.


def witness_object_to_array(w: dict[str, float]) -> list[float]:
    return [
        w["value_norm"],
        w["n_sides_norm"],
        w["center_on"],
        w["activation_density"],
        w["kind_flag"],
        w["band_position"],
        w["parity"],
        w["degeneracy"],
    ]


def witness_array_to_object(a: list[float]) -> dict[str, float]:
    return {
        "value_norm": a[0],
        "n_sides_norm": a[1],
        "center_on": a[2],
        "activation_density": a[3],
        "kind_flag": a[4],
        "band_position": a[5],
        "parity": a[6],
        "degeneracy": a[7],
    }
```

### 19.2 Primitive operators

```python
def project_d(p: float, q: float, lam: float = 1.0) -> float:
    return p - lam * q


def stability_d(p: float, q: float, eps: float = 1e-9) -> float:
    s = 1.0 - abs(q) / (abs(p) + abs(q) + eps)
    return max(0.0, min(1.0, s))


def d_add(d1: tuple[float, float], d2: tuple[float, float]) -> tuple[float, float]:
    p1, q1 = d1
    p2, q2 = d2
    return (p1 + p2, q1 + q2)


def d_mul(d1: tuple[float, float], d2: tuple[float, float]) -> tuple[float, float]:
    p1, q1 = d1
    p2, q2 = d2
    return (p1 * p2, p1 * q2 + p2 * q1)
```

---

## 20) Worked Examples

## 20.1 Track index witness (discrete)

Input:
- `track = 2039`, `M_max = 4096`, family = pronic-chain.

Bridge:
- `value_norm = (2039 + 1) / (4096 + 1)`.

Witness (example):
```text
[value_norm, n_sides_norm, center_on, activation_density, kind_flag, band_position, parity, degeneracy]
```

Canonical vector (reference profile example):
```text
[0.49792531, 0.34426230, 1, 0.49792531, 2, 0.95833333, 0, 1]
```

## 20.2 Progress witness (continuous)

Input:
- `progress = 0.642`, family = even-range.

Set:
- `value_norm = 0.642`,
- smooth `activation_density`,
- family flag for even-range.

## 20.3 Absent slot

When a semantic channel is inactive:
```text
[0,0,0,0,0,0,0,0]
```

## 20.4 `D=(p,q)` example

Input:
- `p = 0.72`, `q = 0.08`, `lambda = 1.0`.

Projection:
- `N = 0.72 - 0.08 = 0.64`.

Stability:
- `S = 1 - 0.08 / (0.72 + 0.08 + 1e-9) ~ 0.90`.

## 20.5 Canonical boundary test vectors

Integer bridge (`M_max = 4096`):
1. `m = 0`
  - encode: `value_norm = 1/4097`
  - decode (`round_half_up`) -> `0`
2. `m = 4096`
  - encode: `value_norm = 1`
  - decode -> `4096`
3. `m = 2039`
  - encode: `value_norm = 2040/4097`
  - decode -> `2039`

Presence boundary:
1. absent: `[0,0,0,0,0,0,0,0]`
2. minimal present (reference profile):
  `[1/4097, 0.34426230, 1, 1/4097, 2, 0, 0, 1]` where `0.34426230 = (24 - 3)/61` for reference-profile `KIND_PRONIC`.

---

## 21) Conformance Checklist

1. Witness feature order documented.
2. Family selection policy documented.
3. Presence semantics (token-free zero) implemented.
4. One-based bridge implemented where integer domains apply.
5. `round_half_up` is used for normalized-to-integer decode paths (`m`, `n`, `active_count`), and for integer-mode `start_index`.
6. Canonical `float[8]` storage order is enforced.
7. Structural no-witness fence enforced.
8. `D=(p,q)` formulas documented if used.
9. Post-op clamp/reject/rescale policy documented.
10. Security gating behavior documented for semantic execution.
11. Visualization/debug path available (draw witness).
12. Test vectors cover boundary and reversibility cases.

### 21.1 Decoder Conformance Matrix (Reference Profile)

| Condition observed on decoded `float[8]` row | Required decoder action |
|---|---|
| All features are `0.0` (token-free zero) | Treat as absent row. |
| Any feature is `NaN`, `+Inf`, or `-Inf` | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| Any feature is subnormal Float32 in Open/S1 | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| `n_sides_norm` outside `[0,1]` | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| `band_position` outside `[0,1]` | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| `round_half_up(center_on)` not in `{0,1}` | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| `activation_density` outside `[0,1]` | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| Decoded `kind_i` unsupported | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| Decoded `parity_i` not in `{0,1}` | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| Present row with decoded `degeneracy_i < 1` | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |
| Non-canonical `band_position == 1.0` | Canonicalize to `0.0`, then continue decode. |
| Any other profile range/invariant violation | Mark row invalid, replace with token-free zero, emit per-row validation telemetry. |

Continuation rule:
- decoder SHOULD continue frame processing after row-level invalidation unless deployment policy requires hard reject.

---

## 22) Future Research Directions

- Formal invertibility conditions for witness mappings.
- Family optimization by entropy and perceptual stability.
- Error bounds for bridge quantization under Float32 rounding.
- Robust semantic composition under adversarial/noisy inputs.
- Automated witness-layout synthesis from profile schemas.

---

## 23) Glossary

- `witness`: an 8-feature semantic record for one encoded value.
- `overlay grid`: semantic arrangement of witness rows by feature columns.
- `family`: mapping class selected by `kind_flag`.
- `band_position`: normalized cyclic start position for activation mapping.
- `token-free zero`: all-zero witness tuple denoting absence.
- `structural fields`: DBP-reserved cells for framing, security metadata, and integrity behavior.
- `Open/S1`: DBP non-S2 security modes (see DBP v1.x security profile definitions).
- `S2`: DBP security mode requiring integrity/authentication validation before protected semantic interpretation (see DBP v1.x).

---

End of Duotronic Math v2 paper.
