# Metadata/privacy profile

Encryption does not hide traffic timing, direction, volume or long-lived stream identifiers. DBP therefore defines an optional privacy profile with fixed-frame padding buckets, bounded batching delay, cover frames and stream-ID rotation. Deployments choose explicit bandwidth/privacy tradeoffs. Cover traffic MUST NOT starve emergency/control reservations.
