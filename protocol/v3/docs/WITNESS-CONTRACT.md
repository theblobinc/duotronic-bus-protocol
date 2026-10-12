# Witness Contract Binding

DBP v3 treats Witness objects as external canonical evidence, not inline magic authority bytes.

The current Witness model distinguishes claims, proof artifacts, compiler/proof witnesses, policy decisions, lifecycle events, authority snapshots, promotion gates and release signatures. No object self-certifies the object on which its authority depends. DBP mirrors that non-collapse rule.

An authority-bearing DBP transaction should bind at minimum:

- canonical Witness object type and ID;
- authority domain;
- authority snapshot ID;
- ledger high-water sequence / effective chronology;
- authorization witness ID;
- applicable policy/profile identity;
- supersession/revocation state when relevant.

DBP sender hints and an authenticated carrier are only routing/transport facts. The application must resolve and validate the canonical Witness graph before authority is granted.

Authority failures should be stable typed failures and should not mutate authoritative state.
