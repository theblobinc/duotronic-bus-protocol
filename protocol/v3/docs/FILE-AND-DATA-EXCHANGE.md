# File and Data Exchange

DBP v3 supports files and arbitrary structured data for both human and machine principals.

## Small data

Bounded payloads may travel directly in typed records where the negotiated frame/body limits permit it.

## Large data

Large files, map tiles, model artifacts, recordings, evidence bundles, datasets and structured objects use `object-manifest`, `object-chunk`, resumable custody and Merkle verification. Conversation or agent records carry references rather than duplicating the object bytes.

## Required metadata

A structured object reference identifies at least object ID, media type, content digest and byte length. Schema reference, encoding, compression, Merkle root and confidentiality label are optional but strongly recommended where applicable.

## Safety invariants

- receipt of bytes is not semantic acceptance;
- decompression is bounded by negotiated policy;
- schema identifiers are data, not executable code;
- unknown critical schemas are rejected or quarantined;
- executable/model/update objects require separate authority/policy gates;
- object reconstruction never bypasses Xavi-Void authentication or Witness admission.
