# Threat Model

Consider malformed lengths, memory exhaustion, replay, reordering, transcript splicing, capability downgrade, compromised transport credentials, stale authority snapshots, revoked/superseded evidence, duplicate command execution, clock discontinuity, corrupted FEC shards, malicious or buggy media peers, partial partitions and metadata observation.

DBP mitigates these with fixed bounds, one-origin identities, replay windows, transcript commitments, idempotency, staged receipts, explicit authority bindings, post-FEC authentication, path isolation and fail-closed resource/policy behavior.

Out of scope for the base protocol: defeating total RF denial, guaranteeing a malicious endpoint executes honestly, physical device compromise, and replacing application-specific UTM safety policy.

## Communications-specific threats

DBP3-COMMS-1 treats downgrade, stale-device replay, stale group epochs, malicious floor capture, forged emergency priority, compromised relay custody, traffic analysis, media amplification, attachment decompression and false recording claims as explicit threats. Transport authentication alone MUST NOT grant emergency, moderation, recording-admission or command authority. Media adaptation and retransmission feedback are authenticated and bounded so peers cannot force unbounded bitrate/FEC escalation.
