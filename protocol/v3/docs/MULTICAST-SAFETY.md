# Multicast / Group Safety — Draft 0.11

Group membership is admitted before traffic is scheduled. Members must satisfy the group's required security suite, share an admitted frame size, support the intended record type, and meet group FEC/recovery limits.

The sender computes a common frame size and bounded fragment plan using the most restrictive participating capability. Group policy caps members, fanout, message bytes, fragments, parallel recovery groups, recovery bytes and deterministic recovery work units.

A recipient that loses fragments performs recovery within its own bounded recovery budget. Its loss MUST NOT force every other group member to allocate a new unbounded FEC job. Recovery accounting is per recipient/path, not a group-wide amplification trigger.

Membership changes increment group and key epochs. A low-resource member that cannot satisfy the admitted group profile is rejected before membership rather than joining and failing under traffic.

Correlated failures from several members sharing the same path should be classified as path degradation before independent peer quarantine where evidence supports that classification. Hard cryptographic/security violations remain peer-scoped and fail closed.
