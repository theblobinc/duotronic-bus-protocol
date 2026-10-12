# Conformance

A conformant implementation must pass fixed-frame shape/bounds tests, record overrun/trailing-byte tests, replay/duplicate tests, state-machine transition tests, capability transcript determinism tests, FEC recovery and insufficient-shard tests, command expiry/idempotency identity tests, receipt-chain progression tests, Witness authority negative tests, object chunk verification and profile resource-limit tests.

Protected-production conformance additionally requires the actual approved Xavi-Void provider test vectors; the included HMAC development provider cannot satisfy a production security claim.
