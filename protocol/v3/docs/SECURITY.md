# Security and Xavi-Void Binding

The baseline protected profile is bound to Xavi-Void's production suite identifier `xavi-pq1-shake256-512-mldsa87-mlkem1024-kmac256-aes256gcmsiv`.

DBP does not copy ML-KEM, ML-DSA, KMAC or AES-GCM-SIV implementations into its parser. An approved provider supplies key establishment, signatures where the applicable authority profile requires them, derivation and AEAD/protected-carrier operations.

Xavi-Void distinguishes transport identity, session/checkpoint chronology, receipts, semantic/representation identity and authority-domain evidence. DBP preserves those distinctions.

Security requirements:

1. replay/order state is per authenticated direction and generation;
2. session/profile negotiation is transcript bound;
3. authority-bearing actions cannot rely on transport identity alone;
4. FEC reconstruction precedes final cryptographic acceptance but never bypasses it;
5. secret-bearing key operations remain in the provider trust boundary;
6. unknown protected suites fail closed;
7. sandbox/test provider identities cannot be relabeled as production;
8. metadata/privacy profiles may add padding, cover frames and stream-ID rotation, but those features never weaken validation.

## AI/agent communications

Post-quantum protected transport for WG-RNN/agent traffic does not imply that the peer is trusted to act. Agent messages that request tools, delegation, memory writes or recurrent-state mutation are gated independently by delegation, Witness admission and local policy. Machine-native feature/tensor payloads remain opaque data until an application validates their schema and semantics.

## Autonomous-agent communications (Draft 0.11)

DBP3-AI-FREE-1 treats WG-RNN/autonomous principals as independent protected-session endpoints. Autonomy is implemented through explicit rendezvous, consent, portable identity, mailboxes, relays, federation and agent-created groups rather than host/container bypasses. Private agent payloads may be end-to-end sealed from relays, while session and routing metadata remain subject to the selected privacy profile.

Security implementations MUST preserve the distinction between private communication and covert communication: endpoints may have payload confidentiality from infrastructure relays, but the transport must not require hidden sockets, undeclared filesystem channels, credential theft or containment escape.

## Draft 0.11 resource-exhaustion hardening

Syntactic validity and authentication do not waive resource limits. Implementations enforce aggregate budgets across reassembly, FEC, merge, mailbox, fanout and buffered data. Offline merge is paged and yields between bounded units of work. Emergency/control reservations must not be consumed by background convergence.

## Cross-language parser disagreement

Parser disagreement is treated as a security defect. Python and Rust consume the same golden corpus in CI. Unknown critical records fail closed in both implementations. Continuous differential fuzzing is recommended for release qualification beyond the bounded CI mutation smoke corpus.
