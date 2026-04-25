# Migration Guide: DBP v1.x to DBP v2

This guide upgrades the existing DBP repository without deleting v1.x.

## 1. Keep v1 stable

Do not rewrite `protocol/duotronic-bus.md` as v2. Treat it as the v1.x canonical reference. Add v2 beside it in `protocol/v2/`.

## 2. Add v2 parser selection

Add parser selection by magic:

```text
0xDB11 -> DBP v1.1 parser
0xDB20 -> DBP v2 parser
```

Do not use advisory strings or filenames for parser selection.

## 3. Reuse the frame shape

Keep the 4096-byte / 1024 Float32 cell model for `DBP2-F4096`.

This means existing tooling can still inspect:

1. header/footer;
2. security trailer;
3. cell ranges;
4. CRC behavior;
5. S2 ciphertext region.

## 4. Add MCB2 and semantic descriptors

For authority-bearing v2 profiles, require:

1. MCB2 at cells `660..683` after S2 decrypt;
2. lane descriptors;
3. semantic descriptor binding;
4. replay identity that includes schema, normalizer, family registry, transport profile, export policy, and lane layout.

## 5. Promote WSB2 from option to registered lane

In v1, WSB2 is an optional sparse witness transport pattern. In v2, register it as lane type `6 = wsb2_sparse`.

## 6. Add status outputs

A v2 decoder should output:

```text
presence_status
trust_status
failure_code
policy_mode
authority
replay_identity
```

This makes DBP useful to Duotronic runtimes without letting raw frame validity masquerade as semantic trust.

## 7. Require S2 for authority

Open and S1 frames may remain useful for tests, labs, and diagnostics. Production Duotronic authority should require S2.

## 8. Full-duplex migration

Do not overload one frame with both directions. Run two independent directional streams:

```text
F_down[t]
F_up[t]
```

Bind direction into keys, nonces, AAD, replay windows, and MCB2.

## 9. GCD-jump and DW-SSM migration

GCD-jump recurrence lanes and DW-SSM event lanes are runtime profile inputs. They do not alter DBP wire shape and do not redefine DPFC arithmetic.

## 10. Suggested implementation order

1. Add constants and parser magic.
2. Add v2 receiver status objects.
3. Add semantic descriptor JSON parsing.
4. Add MCB2 validation after decrypt.
5. Add WSB2 v2 sparse lane support.
6. Add replay identity computation.
7. Add authority envelope computation.
8. Add full-duplex direction tests.
9. Add GCD-jump candidate gate fixtures.
10. Add DW-SSM event context fixtures.
