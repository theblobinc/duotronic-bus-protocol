# Bounded Reconciliation — Draft 0.11

"Bounded" means **bounded work and memory per reconciliation step**, not a finite history horizon.

Long-offline nodes remain mergeable. Production-scale reconciliation uses an immutable storage-backed `MergeSnapshot` contract. A snapshot exposes stable metadata plus bounded `read_segment()` access, so a node can reconcile a very large history without sorting or materializing all historical payloads in the protocol process.

The in-memory adapter exists for tests/small deployments and has a hard item ceiling. Exceeding that ceiling fails closed with `MergeResourceError` and directs the caller to a storage-backed snapshot; it never silently allocates an unbounded history list.

A cursor is bound to the snapshot digest and contains item index plus byte offset. Oversized historical objects are emitted as deterministic byte segments across pages. A cursor from one snapshot MUST NOT be applied to a changed snapshot; the caller restarts against the new snapshot or uses the object-transfer plane for changed large objects.

Revocations and authority chronology retain priority over state/message/bulk history when a snapshot is constructed. Each reconciliation call has item and byte ceilings, and the implementation may additionally apply deterministic work-unit/deadline admission.

This design avoids both failure modes:

- an unbounded reconnect spike that monopolizes CPU/RAM; and
- a finite merge horizon that permanently strands a long-offline node.
