# DBP3-COMMS-1 — Secure Communications Profile

`DBP3-COMMS-1` is the normative communications profile for DBP v3 Draft 0.5 and remains normative in Draft 0.11. It does not replace Xavi-Void cryptography. It defines communications state, identities, records, recovery and evidence semantics carried inside an authenticated DBP/Xavi-Void session.

## Four subplanes

### COMM-CONTROL
Call invite/ringing/accept/decline/cancel/hangup, hold/resume/transfer, conference membership, presence, capability negotiation, participant/device bindings, PTT floor arbitration and moderation authority.

### COMM-MESSAGE
Reliable text, edits, reactions, tombstones, delivery stages, attachments and store-and-forward envelopes. Message events are chainable by digest. A deletion/tombstone never claims to erase bytes already received; it records a deletion request/policy event and may be coupled to application key erasure.

### COMM-MEDIA
Opaque codec payloads for voice/video, media-layer negotiation, recovery hints, per-stream key epochs and degraded operation. Core DBP remains codec-independent. Profiles MAY register Opus/AV1/etc.; implementations MUST NOT infer codec parameters absent negotiation.

### COMM-EVIDENCE
Participant identity bindings, call/group chronology, recording commitments, media-to-Witness correlation and staged receipts. A protected recording is not automatically admitted as Witness evidence.

## Call state

`IDLE -> INVITED -> RINGING -> ACTIVE -> HELD -> ACTIVE -> ENDED`.

Direct acceptance from `INVITED -> ACTIVE` is permitted. Decline/cancel/hangup terminate the call. Illegal transitions are protocol errors.

## PTT floor

Channels use deterministic floor arbitration. A holder retains the floor until release/timeout/preemption. Higher-priority requests may preempt lower priority holders. An authenticated emergency request has the reserved emergency priority and may preempt ordinary traffic. Authentication alone does not grant policy authority to use emergency priority.

## Identity and handoff

Participants bind `principal_id + device_id + session_generation + group_epoch + optional witness authority reference`. Device handoff increments the communication generation so stale media/control from the prior device can be rejected.

## Key epochs

Text, voice, video, telemetry and control have independent logical key epochs. Xavi-Void performs cryptographic key derivation/ratcheting. DBP carries the epoch identity and transition semantics. Group membership changes require a new group key epoch. Sender-key group mode is permitted for scalable group media if the selected Xavi-Void security profile supports it.

## Store and forward

Message envelopes have destination, expiry, priority and custody chronology. Custody is not delivery. Delivery is not authentication. Authentication is not Witness admission.

## Adaptive media

Profiles may transition `video -> thumbnail -> audio-only -> text/PTT survival` as authenticated link metrics worsen. Media adaptation MUST NOT consume the queue reservation assigned to emergency, command or UTM deconfliction traffic.

## Federation

A conversation may span multiple Xavi servers. No single relay is implicitly authoritative. Federation state carries a conversation epoch and monotonically increasing local chronology; reconnect merge is deterministic and authority-changing events remain Witness/policy gated.

## Recording

A recording commitment identifies the conversation, media digest, time interval and optional Witness reference. It proves commitment to bytes/time metadata; it does not prove semantic truth or policy authorization.

## Emergency broadcast

Emergency broadcast is a compact one-to-many control record intended for F256/F512 survival operation. It receives maximum scheduler protection and configured redundancy. Authorization is still enforced independently of transport authentication.
