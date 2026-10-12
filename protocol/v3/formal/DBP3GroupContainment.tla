---------------- MODULE DBP3GroupContainment ----------------
EXTENDS Naturals, FiniteSets
CONSTANT Principals, MaxMembers, MaxFanout, MaxRecovery
VARIABLES members, keyEpoch, recoveryJobs
vars == <<members,keyEpoch,recoveryJobs>>
Init == /\ members = {} /\ keyEpoch = 1 /\ recoveryJobs = 0
Join(p) == /\ p \in Principals /\ p \notin members /\ Cardinality(members) < MaxMembers
           /\ members' = members \cup {p} /\ keyEpoch' = keyEpoch + 1 /\ UNCHANGED recoveryJobs
Leave(p) == /\ p \in members /\ members' = members \ {p} /\ keyEpoch' = keyEpoch + 1 /\ UNCHANGED recoveryJobs
StartRecovery == /\ Cardinality(members) <= MaxFanout /\ recoveryJobs < MaxRecovery
                 /\ recoveryJobs' = recoveryJobs + 1 /\ UNCHANGED <<members,keyEpoch>>
FinishRecovery == /\ recoveryJobs > 0 /\ recoveryJobs' = recoveryJobs - 1 /\ UNCHANGED <<members,keyEpoch>>
Next == (\E p \in Principals: Join(p) \/ Leave(p)) \/ StartRecovery \/ FinishRecovery
MembershipBound == Cardinality(members) <= MaxMembers
FanoutSafety == recoveryJobs > 0 => Cardinality(members) <= MaxFanout
RecoveryBound == recoveryJobs <= MaxRecovery
KeyEpochOneOrigin == keyEpoch >= 1
Spec == Init /\ [][Next]_vars
=============================================================================
