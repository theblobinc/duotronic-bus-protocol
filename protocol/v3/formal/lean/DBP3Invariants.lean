namespace DBP3
structure GateReceipt where admitted : Bool; stateMutated : Bool

def gateValid (g : GateReceipt) : Prop := g.admitted = false -> g.stateMutated = false

theorem blocked_witness_no_mutation (g : GateReceipt) (h : gateValid g) (hb : g.admitted = false) : g.stateMutated = false := h hb

structure SecurityState where authenticated : Bool; authorized : Bool

def authorityValid (s : SecurityState) : Prop := s.authorized = true -> s.authenticated = true

theorem authorization_requires_authentication (s : SecurityState) (h : authorityValid s) (ha : s.authorized = true) : s.authenticated = true := h ha



structure ReadmissionAttempt where
  challengeFresh : Bool
  proofVerified : Bool
  oldGeneration : Nat
  newGeneration : Nat
  accepted : Bool

def attemptValid (a : ReadmissionAttempt) : Prop :=
  a.accepted = true ->
    a.challengeFresh = true /\ a.proofVerified = true /\ a.newGeneration > a.oldGeneration

theorem accepted_readmission_requires_fresh_challenge (a : ReadmissionAttempt)
    (h : attemptValid a) (ha : a.accepted = true) : a.challengeFresh = true := (h ha).1

theorem accepted_readmission_requires_verified_proof (a : ReadmissionAttempt)
    (h : attemptValid a) (ha : a.accepted = true) : a.proofVerified = true := (h ha).2.1

theorem accepted_readmission_advances_generation (a : ReadmissionAttempt)
    (h : attemptValid a) (ha : a.accepted = true) : a.newGeneration > a.oldGeneration := (h ha).2.2

structure ReadmissionState where
  quarantined : Bool
  challengeFresh : Bool
  proofVerified : Bool
  oldGeneration : Nat
  newGeneration : Nat
  probation : Bool
  active : Bool

def readmissionValid (r : ReadmissionState) : Prop :=
  (r.probation = true -> r.proofVerified = true) /\
  (r.active = true -> r.proofVerified = true) /\
  (r.active = true -> r.newGeneration > r.oldGeneration)

theorem probation_requires_verified_proof (r : ReadmissionState)
    (h : readmissionValid r) (hp : r.probation = true) : r.proofVerified = true := h.1 hp

theorem active_readmission_requires_verified_proof (r : ReadmissionState)
    (h : readmissionValid r) (ha : r.active = true) : r.proofVerified = true := h.2.1 ha

theorem active_readmission_advances_generation (r : ReadmissionState)
    (h : readmissionValid r) (ha : r.active = true) : r.newGeneration > r.oldGeneration := h.2.2 ha

theorem quarantined_is_not_active_when_flagged (r : ReadmissionState)
    (hq : r.quarantined = true) (hn : r.active = false) : r.active = false := hn

end DBP3
