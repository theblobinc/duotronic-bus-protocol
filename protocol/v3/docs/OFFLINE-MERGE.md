# Partition, offline merge and revocation

Disconnected partitions retain local chronology and custody evidence. On reunion, explicit revocations merge monotonically: a revocation observed by either partition cannot be silently resurrected by an older authority snapshot. Concurrent non-revocation state is resolved by application/Witness chronology, not arrival order. Conflicting commands remain separate transactions until a supersession/authority decision resolves them.
