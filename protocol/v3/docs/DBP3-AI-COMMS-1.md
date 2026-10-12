# DBP3-AI-COMMS-1 — Secure Agent and Augmented-Intelligence Communications

**Status:** Draft 0.11 profile (profile v1, extended by DBP3-AI-FREE-1)

DBP3-AI-COMMS-1 makes WG-RNN instances, observers, routers, memory services, model workers and other autonomous/augmented-intelligence components first-class DBP principals. It is not a human-chat shim. It defines secure machine-native exchange patterns that may be synchronous, asynchronous, one-way, many-to-one, many-to-many, role-asymmetric or capability-asymmetric.

## Security boundary

All protected transport is supplied by an approved Xavi-Void provider/profile. DBP binds the protected session, exchange identity, key epoch, replay state and transcript; the Witness Contract and local policy decide whether a message may cause authority-bearing action or recurrent/memory mutation.

```text
protected != admitted != delegated != authorized != executed != state-mutating
```

A post-quantum authenticated peer cannot grant itself tool authority, memory-write authority, recurrent-state mutation, or authority to impersonate another principal.

## Principal identity

An AI principal is bound independently to:

- DBP principal identity;
- Xavi-Void protected-session identity;
- runtime/service identity;
- optional model identity and model instance;
- session generation and key epochs;
- optional Witness authority reference;
- optional delegation reference.

Human, device and AI principals use the same cryptographic carrier but different authority semantics.

## Exchange kinds

Core machine-native exchange kinds include observations, queries, responses, proposals, critiques, plans, negotiations, delegated actions, tool intents/results, memory deltas, state synchronization, consensus votes/results, capability advertisements, feature references, artifact references and blackboard events.

Payloads may contain or reference text, voice, video, files, structured data, model artifacts, evidence bundles, embeddings/features, tensors, plans or application-specific objects. DBP does not assign truth or authority to opaque payloads merely because they arrived over a protected session.

## Delivery patterns

The profile defines:

- unicast;
- multicast;
- broadcast;
- durable mailbox/store-forward;
- publish/subscribe style one-way publication;
- request/response;
- fanout/gather;
- quorum exchange;
- pipeline hand-off.

These patterns intentionally permit asymmetric communication. A vision observer may publish observations without accepting requests; an authority service may receive proposals but only emit signed decisions; a model worker may accept a task and return an opaque artifact; several observers may fan out and a consensus service may gather.

## Human-compatible media

WG-RNN principals may also participate in DBP3-COMMS-1 text, PTT, voice, video, file and data channels when allowed by policy. AI participation does not create extra authority and must be visible as an AI principal in participant bindings and evidence records.

## Files and structured data

Small objects may be carried directly as records. Larger files/data use DBP object manifests/chunks and are referenced by `agent-data-reference` or `attachment-reference`. The structured-data envelope declares media type, schema, encoding, compression, byte length, digest and optional Merkle root.

Supported standard encoding identifiers include raw, JSON, CBOR, MessagePack, FlatBuffers, Protobuf and Arrow IPC. Implementations may register extensions. Decompression limits remain mandatory.

## Feature/tensor exchange

Machine-native representations use references describing representation, element type, shape, digest, producer and optional semantic/quantization information. The feature payload itself remains opaque to DBP. A receiver must not assume two representations are semantically interchangeable solely because shapes match.

## Delegated action

Action-bearing messages require an explicit delegation reference. Implementations MUST separate transport authentication from delegation and policy authorization. State-mutating WG-RNN actions additionally require Witness admission when the applicable profile says so.

## Quorum and consensus

Quorum exchange transports votes and candidate digests but does not define truth. Threshold satisfaction is a transport/application event; promotion to authoritative state remains governed by Witness/policy rules.

## Autonomy and policy

An implementation may allow an autonomous agent to select a permitted delivery pattern, peer or communication mode according to local policy. DBP does not infer intent, consciousness or personhood; it only transports authenticated machine decisions and their evidence/authority bindings.


Draft 0.11 retains and hardens `DBP3-AI-FREE-1` for autonomous session initiation, peer consent, portable identity, private sealed envelopes, negotiated agent languages, coalitions, rendezvous/relay and federation.
