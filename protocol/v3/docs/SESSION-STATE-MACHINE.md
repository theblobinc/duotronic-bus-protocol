# Session, Capability and Rekey State Machine

Canonical states: `DISCOVER -> NEGOTIATE -> ESTABLISH -> ACTIVE`, with controlled transitions to `DEGRADED`, `REKEY`, `SUSPENDED`, `RESUME`, and terminal `CLOSED`.

Capability advertisements include protocol minor versions, protected suites, FEC profiles, codecs/media capabilities, object-transfer limits, replay-window support, Witness profile/version identifiers and extension namespaces. The chosen intersection is committed into the authenticated session transcript.

A peer MUST NOT accept an unauthenticated downgrade from a previously stronger protected profile. Rekey increments the key epoch. Resume increments session generation and creates a new replay domain while retaining an explicit relationship to the prior session.

Half-open sessions, expired negotiations, stale generations and invalid transitions fail closed. Applications should place bounded timers around every non-active transitional state.
