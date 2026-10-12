---------------- MODULE DBP3BootstrapContention ----------------
EXTENDS Naturals
CONSTANT MaxAttempts
VARIABLES state, attempts, collisions, quarantined
vars == <<state, attempts, collisions, quarantined>>
Init == /\ state = "backoff"
        /\ attempts = 0
        /\ collisions = 0
        /\ quarantined = FALSE
Announce == /\ state = "backoff"
            /\ state' = "announcing"
            /\ UNCHANGED <<attempts,collisions,quarantined>>
Collision == /\ state = "announcing"
             /\ attempts < MaxAttempts
             /\ state' = "backoff"
             /\ attempts' = attempts + 1
             /\ collisions' = collisions + 1
             /\ quarantined' = quarantined
Negotiate == /\ state = "announcing"
             /\ state' = "negotiating"
             /\ UNCHANGED <<attempts,collisions,quarantined>>
Activate == /\ state = "negotiating"
            /\ state' = "active"
            /\ UNCHANGED <<attempts,collisions,quarantined>>
Next == Announce \/ Collision \/ Negotiate \/ Activate
CollisionNeverQuarantines == quarantined = FALSE
AttemptsBounded == attempts <= MaxAttempts
Types == /\ attempts \in Nat /\ collisions \in Nat
Spec == Init /\ [][Next]_vars
=============================================================================
