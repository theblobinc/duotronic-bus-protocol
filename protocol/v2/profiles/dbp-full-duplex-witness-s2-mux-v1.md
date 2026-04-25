# DBP Full-Duplex Witness S2 MUX Profile v1

**Profile ID:** `dbp-full-duplex-witness-s2-mux-v1`  
**Base profile:** `dbp-duotronics-witness-authority-s2-v1`  
**Wire class:** `DBP2-F4096`  
**Security:** S2 required  
**Status:** Draft

---

## 1. Purpose

This profile makes DBP v2 full duplex by running two independent DBP frame streams over one full-duplex transport.

```text
server -> client: downlink frames, MCB2.direction = 0
client -> server: uplink frames, MCB2.direction = 1
```

The profile does not pack two writers into one frame. Each side writes its own frames and acknowledges the opposite stream.

---

## 2. Directional state

Each direction MUST maintain independent:

1. sequence counter;
2. replay window;
3. nonce namespace;
4. key or direction-bound key derivation;
5. lane layout;
6. command sequence;
7. ACK state;
8. policy telemetry;
9. sender zero-fill behavior.

A valid frame in one direction MUST NOT validate as a frame in the opposite direction.

---

## 3. ACK model

MCB2 cells `666..667` carry the last opposite-direction sequence observed.

```text
downlink frame ACKs latest accepted uplink seq
uplink frame ACKs latest accepted downlink seq
```

ACK fields are advisory for flow control but identity-affecting for replay traces when the active semantic profile declares ACK-bound replay.

---

## 4. Lane model

Recommended lane layout:

| Direction | Lane | Type | Purpose |
|---|---:|---|---|
| downlink | 1 | `semantic_descriptor` | active semantic profile binding |
| downlink | 2 | `witness8_dense` or `wsb2_sparse` | server state, targets, policy hints |
| downlink | 3 | `digital_u24` or `opaque_bytes` | server commands |
| uplink | 1 | `semantic_descriptor` | profile binding or descriptor hash |
| uplink | 2 | `witness8_dense` or `wsb2_sparse` | client observations and intents |
| uplink | 3 | `gcd_jump_gate` | candidate sparse event gates |
| uplink | 4 | `dw_ssm_event` | canonical event embedding when allowed |

Profiles MAY negotiate different lanes, but lane layout changes MUST change replay identity.

---

## 5. Security binding

Recommended derivation labels:

```text
DBP2-S2-downlink
DBP2-S2-uplink
```

AAD MUST include direction. Nonce construction MUST prevent cross-direction reuse.

---

## 6. Flow control

A receiver MAY apply flow control based on:

1. ACK lag;
2. replay window pressure;
3. policy mode;
4. semantic decode failure rate;
5. normalizer failure rate;
6. WSB2 active row count;
7. GCD-jump gate rate;
8. DW-SSM authority output.

Flow control MUST NOT silently drop authority-bearing semantic failure states. Failures must be logged or represented in telemetry.

---

## 7. Minimal full-duplex handshake

1. Open full-duplex transport.
2. Exchange supported DBP wire classes and security suites.
3. Establish S2 keys or direction-bound key derivation.
4. Exchange semantic descriptor hashes.
5. Start independent directional sequences.
6. Send first downlink and uplink frames with MCB2 direction and ACK fields.
7. Reject cross-direction replay.

---

## 8. Degraded behavior

If one direction fails validation, the opposite direction MAY continue in degraded mode if policy allows. The failed direction enters `transport_bypass` or `full_bypass` for authority-bearing semantic use.
