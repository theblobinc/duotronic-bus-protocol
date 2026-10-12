# Secure Communications Plane

DBP v3 Draft 0.11 defines secure communications through the normative **DBP3-COMMS-1** profile. See `DBP3-COMMS-1.md`.

The profile is divided into COMM-CONTROL, COMM-MESSAGE, COMM-MEDIA and COMM-EVIDENCE. It includes direct/group calls, presence, deterministic PTT floor control, reliable text, edits/tombstones/reactions, store-and-forward custody, attachments, opaque voice/video media, adaptive low-bandwidth fallback, per-stream key epochs, group rekey, sender-key group mode, device handoff, federation and recording commitments.

Xavi-Void supplies the protected transport and cryptographic session machinery. DBP defines the deterministic communications contract around it. Media or messages do not become authoritative Witness evidence simply because transport authentication succeeds.
