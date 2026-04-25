# Protocol v2

This directory contains the DBP v2 draft protocol line.

DBP v2 keeps the existing fixed 4096-byte frame model but upgrades the semantic boundary so DBP can serve as a first-class transport layer for Duotronics, Witness8, WSB2, DPFC object references, GCD-jump sparse event gates, and DW-SSM event contexts.

## Files

```text
protocol/v2/
  duotronic-bus-v2.md                         # Main v2 protocol specification
  migration-v1-to-v2.md                       # Practical migration plan
  profiles/
    dbp-duotronics-witness-authority-s2-v1.md # Recommended production profile
    dbp-full-duplex-witness-s2-mux-v1.md      # Full-duplex profile
  schemas/
    dbp-v2-profile.schema.json                # Profile schema skeleton
    wsb2-v2.schema.json                       # WSB2 v2 payload schema skeleton
  fixtures/
    dbp-v2-conformance-fixtures.yaml          # Draft conformance fixtures
  ref/
    dbp_v2_constants.mjs                      # Reference constants and helper names
    semantic-profile-example.json             # Example semantic profile descriptor
    source-alignment.md                       # How v2 aligns with Duotronics source docs
```

## Core idea

DBP v2 treats DBP as a transport complement to Duotronics:

```text
DBP frame validity != semantic validity != canonical identity != policy authority
```

The main protocol rule is transport-before-semantics:

```text
shape -> structural validation -> integrity/security -> replay -> decrypt -> lane manifest -> payload decode -> normalizer -> canonicalization -> policy gate
```

## Recommended implementation target

For production Duotronics integrations, target:

```text
dbp-duotronics-witness-authority-s2-v1
```

For bidirectional real-time systems, layer:

```text
dbp-full-duplex-witness-s2-mux-v1
```

on top of the S2 authority profile.
