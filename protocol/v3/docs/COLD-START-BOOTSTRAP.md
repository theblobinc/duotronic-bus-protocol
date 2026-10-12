# Cold-start/bootstrap contention — DBP3-BOOTSTRAP-CONTENTION-1

Draft 0.11 defines a bounded cold-start contention profile for shared, half-duplex, or burst-constrained paths. A simultaneous power restore MUST NOT be interpreted as proof that all colliding peers are malicious.

States are `COLD -> DISCOVERY_BACKOFF -> ANNOUNCING -> NEGOTIATING -> ACTIVE`, with `BACKOFF_RETRY` after a detected collision/congestion event. The delay is derived from SHAKE256 over the principal ID, boot epoch, path ID, a fresh per-boot nonce, and retry attempt. It requires no synchronized wall clock and expands the bounded contention window after collisions.

Collision/congestion is path evidence. It does not by itself authorize peer quarantine. Authentication, replay, Witness and policy checks still apply once a peer announcement is received. Exhausting the configured retry bound fails closed with a bootstrap resource/contention error rather than switching to an unbounded retry loop.

The mechanism is transport-agnostic: deployments may map the resulting delay to radio MAC scheduling, shared serial links, multicast discovery, or other carriers. DBP does not claim to manipulate RF hardware directly.
