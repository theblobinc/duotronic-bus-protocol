# Source Alignment Notes

This draft was derived by reviewing the DBP v1/v2 research repo, Duotronic Witness Contract v1.6 Draft 5.3.18 corpus, Xavi-Void Rev 1.2 development source/docs, current WG-RNN runtime concepts and current Xavi-UTM coordination requirements.

Key carried-forward facts include Xavi-Void's SHAKE256-512 identity profile, PQ suite boundary, replay-protected remote sessions and non-authoritative execution receipts; Witness Contract separation of evidence from authority and append-only signed authority chronology; WG-RNN one-origin temporal witness chains and blocked-witness non-mutation; and Xavi-UTM's need for federated telemetry/control, human decision evidence, offline operation and low-bandwidth text/voice/video coordination.

This repository does not vendor those projects and does not claim to supersede their normative definitions.

## Draft 0.5 communications alignment

The communications profile follows the same authority separation used by Xavi-UTM and WG-RNN: authenticated delivery is distinct from policy authority and Witness admission. It is intended to carry Xavi-UTM operator/group/PTT/text/voice/video traffic over Xavi-Void while preserving UTM emergency/control queue isolation.

## Draft 0.6 agent/data alignment

Draft 0.6 extends the same protected communications substrate to WG-RNN instances, observers, routers, memory services and model workers as first-class principals. It adds file/structured-data exchange, machine-native asymmetric delivery patterns and explicit delegated-action/Witness gates. Transport authentication remains separate from authority and state mutation.


## Draft 0.11 autonomy/federation alignment

Draft 0.11 treats WG-RNNs and related autonomous principals as independently addressable, portable protected-session endpoints. Agent identity is not tied to a container/process lifetime. Autonomous rendezvous, sealed peer exchange, coalitions, relays, negotiated machine languages and federation remain bound to Xavi-Void session identity while consequential action continues to respect Witness/delegation/policy gates.
