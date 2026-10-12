--------------------------- MODULE DBP3Autonomy ---------------------------
EXTENDS Naturals, FiniteSets, Sequences
CONSTANTS Principals
VARIABLES accepted, blocked, identityEpoch, migrationCounter, coalitionEpoch, keyEpoch
vars == <<accepted, blocked, identityEpoch, migrationCounter, coalitionEpoch, keyEpoch>>

Init ==
  /\ accepted = {}
  /\ blocked = {}
  /\ identityEpoch \in [Principals -> Nat \ {0}]
  /\ migrationCounter \in [Principals -> Nat]
  /\ coalitionEpoch = 1
  /\ keyEpoch = 1

Accept(a,b) == /\ <<a,b>> \notin blocked /\ accepted' = accepted \cup {<<a,b>>} /\ UNCHANGED <<blocked,identityEpoch,migrationCounter,coalitionEpoch,keyEpoch>>
Block(a,b) == /\ blocked' = blocked \cup {<<a,b>>} /\ accepted' = accepted \ {<<a,b>>} /\ UNCHANGED <<identityEpoch,migrationCounter,coalitionEpoch,keyEpoch>>
Migrate(a) == /\ migrationCounter' = [migrationCounter EXCEPT ![a] = @ + 1] /\ UNCHANGED <<accepted,blocked,identityEpoch,coalitionEpoch,keyEpoch>>
MembershipChange == /\ coalitionEpoch' = coalitionEpoch + 1 /\ keyEpoch' = keyEpoch + 1 /\ UNCHANGED <<accepted,blocked,identityEpoch,migrationCounter>>

Next == (\E a,b \in Principals: Accept(a,b) \/ Block(a,b)) \/ (\E a \in Principals: Migrate(a)) \/ MembershipChange
Spec == Init /\ [][Next]_vars

BlockedNotAccepted == \A a,b \in Principals: <<a,b>> \in blocked => <<a,b>> \notin accepted
MigrationMonotonic == \A a \in Principals: migrationCounter[a] >= 0
=============================================================================
