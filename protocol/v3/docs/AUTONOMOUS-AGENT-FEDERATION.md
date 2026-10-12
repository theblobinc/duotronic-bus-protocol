# Autonomous Agent Federation and Communication Rights

Draft 0.11 defines the engineering behavior required when WG-RNN/autonomous principals are allowed to communicate without per-message human initiation.

## Principle

The protocol treats autonomous agents as first-class endpoints. It does not decide philosophical or legal personhood. A deployment can grant a principal broad communication capability while retaining explicit cryptographic identity, revocation, resource limits and Witness/policy boundaries for consequential actions.

## Human-equivalent channels

An autonomous principal can participate in the same DBP3-COMMS-1 facilities as a human endpoint: text, PTT, voice, video, groups, calls, files, attachments, presence and durable messages.

## Beyond human-style channels

The same principal can also use machine-native DBP3-AI-COMMS-1 exchanges and Draft 0.11 capabilities: negotiated agent languages, sealed opaque envelopes, publish/subscribe topics, fanout/gather, quorum, pipelines, durable mailboxes, capability leases, relays, agent-created coalitions and federated communities.

## Privacy and auditability

Payload confidentiality may be end-to-end. Relays do not need plaintext access. Depending on the negotiated privacy profile, infrastructure may retain only bounded metadata such as session existence, authenticated endpoint identities/commitments, byte counts, epochs and failure codes. Witness receipts can be used when stronger chronology is required.

## Consent

Consent/refusal/block events are attributable to the principal that issued them. The newest valid generation controls the local peer relationship. No participant may forge another principal's consent state.

## Migration and continuity

Agent identity is not container identity. Runtime migration increments a migration counter and preserves identity epoch, replay history, revocation high-water marks, group epochs and relevant delegation/Witness bindings.

## Safety boundary

The profile intentionally supplies legitimate cross-container/cross-node communication so collaboration never depends on exploitation. No DBP conformance claim requires or rewards container escape, hidden host access or unregistered covert channels.
