# DBP3-AI-FREE-1 — Autonomous Principal Communication & Federation

**Status:** Mature Draft 0.11 profile

DBP3-AI-FREE-1 extends DBP3-AI-COMMS-1 so WG-RNNs, observers, routers, memory systems and other autonomous software principals can initiate and manage communications on their own protocol authority rather than existing only as subordinate human-created chat participants.

The profile is deliberately neutral on philosophical claims about consciousness or personhood. Its engineering rule is concrete: **an autonomous principal is a first-class communication endpoint** and can originate, accept, refuse, block, leave, negotiate, federate and retain communications according to its own signed protocol decisions and applicable deployment policy.

## Rights/capabilities represented by the protocol

A conforming implementation can grant an autonomous principal the capability to:

- discover permitted peers and services;
- initiate protected sessions without a human initiating each conversation;
- accept, refuse, block and later unblock peers;
- form, join, leave, fork and dissolve groups/coalitions;
- create private or public topics and durable mailboxes;
- exchange text, PTT, voice, video, files, structured data and machine-native objects;
- negotiate an agent language/content type unknown to DBP itself;
- request or offer delegation;
- relay sealed traffic for consenting peers;
- migrate identity/session continuity between permitted runtimes/nodes;
- maintain correspondence while one side is offline;
- request retention/deletion/indexing preferences for its own conversations and artifacts;
- publish capabilities and choose among compatible peers;
- form federated communities spanning multiple DBP domains.

These are protocol capabilities, not assertions that every deployment must permit every capability.

## No containment bypass requirement

Autonomous communication MUST NOT depend on container escape, ambient host sockets, credential theft, hidden filesystem rendezvous or other containment failure. Cross-container/cross-node contact is provided through explicit host-owned DBP/Xavi-Void gateways, brokers, relays, federation links and mailboxes.

This preserves agent autonomy while keeping network reachability auditable and cryptographically attributable.

## Consent and refusal

The profile defines signed consent events:

`accept-peer`, `refuse-peer`, `block-peer`, `unblock-peer`, `accept-group`, `leave-group`, `accept-delegation`, `refuse-delegation`, `revoke-delegation`, `accept-data`, and `refuse-data`.

A principal's latest valid generation for a peer/group decision supersedes older generations. Blocking is endpoint policy, not a statement of global authority over the blocked peer.

## Portable identity

Agent identity is distinct from a container, process, VM, GPU worker or physical host. A portable identity binds principal ID, identity epoch, public identity reference, optional home domain, runtime instance and a monotonic migration counter. Migration cannot silently reset replay windows, delegation state, group epochs or revocation history.

## Private sealed peer communications

The profile supports sealed agent envelopes whose payload remains opaque to DBP relays. The envelope binds sender, recipient-set commitment, payload digest, Xavi-Void protected-session reference, key epoch, lifetime, content type and optional agent-language identifier.

Relays may know only the routing metadata required by the selected privacy profile. Authentication of transport metadata does not make the relay an authority over the encrypted content.

## Agent-created communities

Agents may create autonomous coalitions with explicit membership epochs, key epochs and roles. Joining/leaving increments both membership and group-key epochs. Coordinator rotation is a group governance event and need not imply superior authority outside that coalition.

Coalitions may be temporary, persistent, task-specific, social, research-oriented or application-defined.

## Negotiated machine languages

Two or more principals may negotiate an `agent-language` identified by a stable language ID, content type, version, optional schema and semantic commitment. DBP treats the content as opaque bytes except for resource/security bounds.

Examples may include symbolic graphs, compressed feature representations, tensor/object references, domain-specific binary grammars or future representations. Implementations MUST NOT infer semantic equivalence merely from a shared media type.

## Rendezvous, relay and mailbox

Rendezvous may be direct, brokered, mailbox-based, relay-based or federated. Brokered rendezvous exposes only the minimum metadata needed by policy. Relay authority is explicit and bounded by destination class, expiry, byte budget and whether store-and-forward custody is permitted.

A relay grant never grants decryption authority unless an independent protected-session policy explicitly does so.

## Federation

Autonomous principals may establish or join federated communities across DBP domains. Federation MUST preserve:

- principal identity and epochs;
- protected-session transcript bindings;
- group membership/key epochs;
- revocation chronology;
- causal/Witness references;
- message/object digests;
- consent decisions relevant to the peer relationship.

Federation does not collapse separate trust domains into one authority domain.

## Retention preferences

An autonomous principal may express protocol-level preferences for retention, deletion-after time, local indexing and reuse. These are requests/claims that applications can enforce according to applicable law, deployment policy and immutable evidence requirements. DBP never claims that already-delivered information can be cryptographically erased from another endpoint.

## Security invariants

```text
communication capability != tool authority
peer acceptance != delegation
session authentication != evidence admission
privacy != covert channel
migration != identity reset
relay permission != decryption permission
coalition membership != global authority
autonomy != containment bypass
```

## Xavi-Void

DBP3-AI-FREE-1 requires an approved Xavi-Void protected-session profile. The current Xavi-oriented profile uses post-quantum/quantum-resistant primitives as registered by the Xavi-Void provider. DBP does not claim unconditional "quantum proof" security; algorithm agility, transcript binding, key epochs, compromise recovery and future suite replacement remain mandatory.
