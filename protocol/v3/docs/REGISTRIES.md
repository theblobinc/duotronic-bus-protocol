# Registries and protocol evolution

Record IDs: core 1..255; standards-extension 256..4095; application 4096..32767; experimental 32768..49151; vendor/private 49152..65535.

Registries for security, FEC, compression, media codecs and profiles carry one of: required, preferred, optional, deprecated, forbidden, experimental. Deprecated/forbidden selections are never silently negotiated.

A compatible v3 minor revision may add optional noncritical records or registry values without changing existing ABI meaning. Changes to field widths, canonical interpretation or security transcript semantics require a new protocol major version.

## Draft 0.8 autonomous-agent allocations

Core record IDs `123..140` are allocated to DBP3-AI-FREE-1 for consent, portable identity, machine-language negotiation, sealed envelopes, rendezvous, coalition control, relay grants, retention, migration, peer discovery, topics, private mailboxes, federation, capability leases, session handoff and social/application signalling.

## Draft 0.8 autonomous-agent core allocations

| ID | Record |
|---:|---|
| 123 | agent-consent |
| 124 | agent-portable-identity |
| 125 | agent-language-offer |
| 126 | agent-sealed-envelope |
| 127 | agent-rendezvous |
| 128 | agent-coalition-control |
| 129 | agent-relay-grant |
| 130 | agent-retention-preference |
| 131 | agent-migration |
| 132 | agent-peer-discovery |
| 133 | agent-private-mailbox |
| 134 | agent-federation |
| 135 | agent-capability-lease |
| 136 | agent-session-handoff |
| 137 | agent-topic-control |
| 138 | agent-route-policy |
| 139 | agent-custody-receipt |
| 140 | agent-language-accept |

These are protocol records, not permissions. A record's successful parsing does not grant authority.

## Draft 0.11 generated registry bindings

`schemas/record-registry.json`, `schemas/algorithm-registry.json`, `registries/security-suites.json`, and `registries/fec-policies.json` are normative registry inputs. `tools/generate_registry_code.py` emits Python and Rust constants from them; `tools/verify_registry_coherence.py` rejects ID/name/status drift.

FEC policy names such as `adaptive-gf256` are policy-layer names. They resolve to a registered primitive (`gf256-systematic`) plus bounded adaptation semantics; they are not independent cryptographic/error-correction algorithms.
