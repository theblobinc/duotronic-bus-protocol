# Resilience, Error Control and Interference

DBP v3 includes error-control metadata and a baseline systematic GF(256) erasure code. Protected bytes are generated first; parity is calculated over those protected bytes. A receiver may reconstruct missing shards, but reconstructed data is accepted only after the normal cryptographic and semantic pipeline succeeds.

The protocol also supports bounded interleaving generations, selective retransmit hints, deadlines, redundant critical records, multipath duplication and degraded-mode priorities.

This improves robustness against random loss, burst loss, congestion, intermittent links and some interference effects. It does not defeat a sufficiently strong jammer that removes all usable physical paths. RF anti-jam waveform/frequency-control mechanisms are intentionally outside this software wire specification.

## Draft 0.11 resource admission

The reference GF(256) implementation exposes a deterministic workspace estimator. A caller that supplies less than the required workspace receives `FECWorkspaceError`; DBP does not silently disable required FEC or protection. Production codecs may be more memory-efficient, but must advertise and enforce their own conservative admission floor.

For multicast, recovery budgets are per recipient/path. A fragment loss at one recipient must not trigger unbounded group-wide parity recomputation.
