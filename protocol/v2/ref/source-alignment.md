# DBP v2 Source Alignment

DBP v2 is aligned with the current Duotronics witness-contract stack as a transport boundary.

## Alignment rules

1. DBP is a transport container, not a numeral family.
2. DBP structural fields are not witness numerals.
3. Witness8 rows are transport/implementation objects until decoded, validated, normalized, and canonicalized.
4. WSB2 inactive lanes mean absence, not numeric zero.
5. DPFC object references carried by DBP do not mutate DPFC arithmetic.
6. Normalizers are identity-affecting and must be versioned and replay-pinned.
7. GCD-jump recurrences are candidate sparse event gates, not authority.
8. DW-SSM state updates may consume canonical witness context, but raw untrusted evidence may not select authority.
9. L5 policy clamps dominate transport hints, learned gates, and recurrence gates.
10. Every identity-affecting semantic change must update replay identity.

## Practical stack

```text
DBP v2
  -> S2 transport validation
  -> MCB2 and lane descriptor validation
  -> WSB2 / Witness8 / DPFC-ref / adapter decode
  -> normalizer and registry lookup
  -> canonical witness identity
  -> policy shield
  -> L2/L2M/DW-SSM runtime use
```

## Complementary boundary

DBP v2 protects and organizes the bytes. Duotronics defines the meaning and trust path after those bytes pass validation.
