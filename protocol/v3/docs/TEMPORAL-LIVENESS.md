# Temporal and work-unit liveness

DBP3 does not define link death as "the decoder has not finished yet". Runtime speed differs across Python, Rust, embedded systems, accelerators, and loaded hosts.

Every production implementation therefore combines two independent bounds:

1. **deterministic work units** — an operation is rejected before it starts if its estimated bounded work exceeds the admitted contract;
2. **local monotonic elapsed time** — an operation that fails to complete within the negotiated/local deadline is abandoned and contained.

A runtime that cannot satisfy both bounds under its admitted resource profile must reject profile/session activation. It must not silently stretch timeouts.

Only authenticated, structurally accepted peer activity refreshes peer liveness. CRC failures, malformed frames, unauthenticated traffic, FEC garbage, and quarantined-peer traffic do not refresh the timer.

This avoids two failure modes:

- a fast native peer declaring failure based on completed loop counts while a slower runtime is still doing unbounded work;
- a babbling peer remaining logically alive merely by flooding malformed bytes.

Physical watchdog deadlines are deployment policy and live outside the managed protocol process; see `FAIL-SILENT-SUPERVISION.md`.
