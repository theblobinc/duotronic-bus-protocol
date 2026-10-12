----------------------------- MODULE DBP3Session -----------------------------
EXTENDS Naturals, TLC
States == {"discover","negotiate","establish","active","degraded","rekey","suspended","resume","closed"}
VARIABLE state, generation, keyEpoch, authorized, executed
vars == <<state,generation,keyEpoch,authorized,executed>>
Init == /\ state = "discover" /\ generation = 1 /\ keyEpoch = 1 /\ authorized = FALSE /\ executed = FALSE
Next ==
  \/ /\ state="discover" /\ state'="negotiate" /\ UNCHANGED <<generation,keyEpoch,authorized,executed>>
  \/ /\ state="negotiate" /\ state'="establish" /\ UNCHANGED <<generation,keyEpoch,authorized,executed>>
  \/ /\ state="establish" /\ state'="active" /\ UNCHANGED <<generation,keyEpoch,authorized,executed>>
  \/ /\ state\in{"active","degraded"} /\ state'="rekey" /\ keyEpoch'=keyEpoch+1 /\ UNCHANGED <<generation,authorized,executed>>
  \/ /\ state="rekey" /\ state'="active" /\ UNCHANGED <<generation,keyEpoch,authorized,executed>>
  \/ /\ state\in{"active","degraded"} /\ state'="suspended" /\ UNCHANGED <<generation,keyEpoch,authorized,executed>>
  \/ /\ state="suspended" /\ state'="resume" /\ generation'=generation+1 /\ UNCHANGED <<keyEpoch,authorized,executed>>
  \/ /\ state="resume" /\ state'="active" /\ UNCHANGED <<generation,keyEpoch,authorized,executed>>
  \/ /\ ~authorized /\ authorized'=TRUE /\ UNCHANGED <<state,generation,keyEpoch,executed>>
  \/ /\ authorized /\ ~executed /\ executed'=TRUE /\ UNCHANGED <<state,generation,keyEpoch,authorized>>
  \/ /\ state # "closed" /\ state'="closed" /\ UNCHANGED <<generation,keyEpoch,authorized,executed>>
Safety == executed => authorized
Spec == Init /\ [][Next]_vars
=============================================================================
