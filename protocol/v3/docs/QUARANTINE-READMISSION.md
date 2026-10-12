# Quarantine and Cryptographic Re-admission — Draft 0.11

Quarantine is a security boundary, not a temporary network backoff. A quarantined peer MUST NOT become active merely because a timer expired, the process rebooted, or a subsequently received frame parsed correctly.

## State sequence

```text
ACTIVE -> DEGRADED -> QUARANTINED
                         |
                         | cooldown only makes an attempt eligible
                         v
              CHALLENGE / VERIFIED PROOF
                         |
                         v
                     PROBATION
                         |
                         v
                       ACTIVE
```

Re-admission requires all of the following:

1. the local quarantine cooldown has elapsed;
2. a fresh, single-use challenge bound to peer identity and quarantine epoch;
3. a peer generation strictly newer than the last admitted generation;
4. a new protected-session commitment;
5. a Witness/authority reference suitable for the deployment policy;
6. an authenticator verified by the configured Xavi-Void/readmission verifier;
7. the required number of valid probation observations before returning to ACTIVE.

A failed proof consumes the pending challenge. A reboot does not clear the monotonic peer generation or quarantine epoch in deployments that require durable anti-thrashing behavior; those values must be persisted by the supervisor state store.

## Quorum safety

A supervisor MUST NOT leave a peer active solely to preserve quorum if the peer requires hard security quarantine. If quarantine makes the required witness quorum impossible, authority-bearing operations become pending or unavailable. The authorization threshold is never silently reduced.

Correlated malformed traffic from several peers sharing a path is handled separately: the path may be degraded/quarantined as a transport failure domain before independently blaming every peer. This limits cascading false peer quarantines during RF/link degradation without weakening hard-security isolation.
