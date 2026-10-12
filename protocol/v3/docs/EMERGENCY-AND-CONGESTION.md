# Emergency, congestion and degraded service

Emergency payloads use a fixed 24-byte grammar (`EmergencyRecord`) and MUST NOT depend on compression, dynamic schemas or application codecs. Emergency/control schedulers reserve bounded capacity even when media/bulk traffic saturates queues.

Congestion feedback is useful only after authentication. Unauthenticated link reports may cause conservative shedding but MUST NOT cause rate increases, larger FEC allocations or greater memory commitments.

Recommended state progression is NORMAL -> CONSTRAINED -> DEGRADED -> SURVIVAL. Recovery uses hysteresis in deployment profiles; rapid unauthenticated oscillation must not trigger expensive reallocations.
