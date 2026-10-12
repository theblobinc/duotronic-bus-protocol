# Design Rationale and v1/v2 Disposition

V1/v2 demonstrated useful concepts such as deterministic framing, fixed-shape transport, multiplexing and adaptive use of payload space, but they also coupled semantic/numeric representation too tightly to the wire.

V3 intentionally breaks compatibility. It keeps deterministic fixed framing and bounded parsing while making the body byte-native. Security, evidence and authority are explicit planes with independent identities. Large evidence/signatures are content-addressed/referenceable rather than squeezed into float cells. Capability/profile negotiation replaces hardwired semantic bands.
