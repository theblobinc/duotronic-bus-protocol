# Profile Composition — Draft 0.11

Profiles are capability inheritance, not arbitrary JSON overlay merging.

`DBP3-COMMS-1 -> DBP3-AI-COMMS-1 -> DBP3-AI-FREE-1` is intentional. AI-FREE is not mutually exclusive with AI-COMMS; it extends it.

Before activation the resolver:

1. verifies required fields and dependency acyclicity;
2. prevents a protected parent from being weakened;
3. requires a coherent registered security suite;
4. resolves FEC policy through `registries/fec-policies.json` and the algorithm registry;
5. intersects supported frame sizes;
6. unions known records/features;
7. binds operational limits into a canonical resolved manifest;
8. computes a deterministic manifest digest;
9. requires runtime-specific resource admission separately.

Unknown critical records fail closed before dispatch. Unknown non-critical records can be skipped diagnostically.

Privacy and resilience are overlays with semantic constraints, not independent profiles that may override emergency/control reservations. Padding/cover traffic is subordinate to congestion ceilings; unauthenticated feedback cannot increase FEC/resource allocation.
