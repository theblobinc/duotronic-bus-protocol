# DBP v3 Draft 0.11 — Normative Wire ABI

All integer fields are unsigned little-endian. Receivers MUST reject non-member frame lengths.

## Frame family

| Name | Total | Header | Body | Trailer |
|---|---:|---:|---:|---:|
| F256 | 256 | 64 | 64 | 128 |
| F512 | 512 | 64 | 320 | 128 |
| F1024 | 1024 | 64 | 832 | 128 |
| F2048 | 2048 | 64 | 1856 | 128 |
| F4096 | 4096 | 64 | 3904 | 128 |

The selected frame size is known from the carrier datagram/record boundary and negotiated profile. It is also cryptographically transcript-bound. A peer MUST NOT silently substitute another size.

## Header (64 bytes)

| Offset | Width | Field |
|---:|---:|---|
| 0 | 4 | ASCII `DBP3` |
| 4 | 1 | major = 3 |
| 5 | 1 | minor = 4 |
| 6 | 2 | header length = 64 |
| 8 | 4 | flags |
| 12 | 2 | frame kind |
| 14 | 2 | profile id |
| 16 | 8 | one-origin sequence |
| 24 | 4 | one-origin session epoch/generation |
| 28 | 4 | one-origin stream id |
| 32 | 4 | one-origin frame message id |
| 36 | 8 | source time µs |
| 44 | 8 | observation time µs |
| 52 | 4 | time uncertainty µs |
| 56 | 2 | used body bytes |
| 58 | 2 | record count |
| 60 | 2 | path id |
| 62 | 1 | QoS class |
| 63 | 1 | priority |

## Trailer (128 bytes)

| Offset | Width | Field |
|---:|---:|---|
| +0 | 32 | SHAKE256-256 logical payload commitment |
| +32 | 32 | Witness/evidence commitment or zero |
| +64 | 16 | protected-carrier/session binding |
| +80 | 2 | security suite id |
| +82 | 2 | security mode |
| +84 | 4 | one-origin key epoch |
| +88 | 1 | FEC scheme |
| +89 | 1 | FEC k |
| +90 | 1 | FEC n |
| +91 | 1 | FEC shard index |
| +92 | 4 | reserved zero |
| +96 | 24 | authentication tag slot |
| +120 | 4 | CRC32 corruption precheck |
| +124 | 4 | `D3E4` fence |

Reserved bytes MUST be zero in canonical encodings. The CRC is never authentication.

## Record ABI

Records retain the 32-byte Draft 0.3 header. Payload is opaque bytes followed by zero padding to a four-byte boundary. Unknown non-critical types may be skipped; unknown critical types MUST reject the enclosing operation.
