# DBP Protocol Directory

## Current canonical line: DBP v3

DBP v3 is the canonical protocol for current and future development. Start with:

- [DBP v3 overview](./v3/README.md)
- [DBP v3 specification](./v3/docs/DBP-V3-SPEC.md)
- [DBP v3 wire ABI](./v3/docs/WIRE-ABI.md)
- [DBP v3 profile composition](./v3/docs/PROFILE-COMPOSITION.md)
- [DBP v3 release gates](./v3/docs/RELEASE-GATES.md)

Operational profiles are resolved and admitted using the v3 profile schemas,
registries, resolver, and runtime-specific resource checks. A valid JSON
document alone does not make a profile conformant or active.

## Historical protocol lines

- [DBP v1.x reference](./duotronic-bus.md) documents the fixed 4096-byte,
  1024-cell Float32 wire format. It is retained for existing implementations;
  it is not the specification for v3.
- [DBP v2 draft](./v2/README.md) is a historical draft built on the v1-shaped
  frame. Its profiles and migration notes do not define the current protocol.

Do not extend v1.x or v2 for new protocol work. Add new normative behavior to
the current v3 line, or to a later version explicitly based on v3.

## Root-level compatibility and reference material

- [DBP v1.x reference helper (JavaScript)](./dbp_ref.mjs) implements the
  fixed-shape Float32 frame, not the v3 wire ABI.
- [WSB2 JavaScript reference](./wsb2_ref.mjs) and
  [Python reference](./wsb2_ref.py) implement the optional sparse-witness
  payload used by v1.x/v2 ABB profiles. WSB2 is not a v3 frame or profile
  definition.
- [DBP v1.1 profile template](./DBP%20Profile%20Template.md) is retained for
  legacy integrations. Use v3 profile composition and admission materials for
  current work.
- [Witness example image](./digital-witness.png) and
  [DMW 0.1 arithmetic vectors](./dmw_test_vectors.json) illustrate the
  standalone historical digital-witness encoding. They are not DBP v3 wire
  conformance vectors or v3 Witness authority objects. For v3, see the
  [Witness Contract binding](./v3/docs/WITNESS-CONTRACT.md).

Compatibility material remains available so existing consumers are not
silently broken. Its presence does not imply that the older wire formats remain
the active development target.
