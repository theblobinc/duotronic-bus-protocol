------------------------------- MODULE DBP3Partition -------------------------------
EXTENDS Naturals, FiniteSets
CONSTANT Nodes, BadLimit, CorrelationLimit, RequiredThreshold
VARIABLES badCount, status, pathNoise, pathStatus, leftRevoked, rightRevoked, merged, threshold
vars == <<badCount,status,pathNoise,pathStatus,leftRevoked,rightRevoked,merged,threshold>>
Init == /\ badCount = [n \in Nodes |-> 0]
        /\ status = [n \in Nodes |-> "active"]
        /\ pathNoise = 0 /\ pathStatus = "active"
        /\ leftRevoked = {} /\ rightRevoked = {} /\ merged = {}
        /\ threshold = RequiredThreshold
PeerNoise(n) == /\ n \in Nodes /\ status[n] = "active"
                /\ badCount' = [badCount EXCEPT ![n] = @ + 1]
                /\ UNCHANGED <<status,pathNoise,pathStatus,leftRevoked,rightRevoked,merged,threshold>>
SharedPathNoise == /\ pathStatus = "active" /\ pathNoise' = pathNoise + 1
                   /\ UNCHANGED <<badCount,status,pathStatus,leftRevoked,rightRevoked,merged,threshold>>
DegradePath == /\ pathStatus = "active" /\ pathNoise >= CorrelationLimit
               /\ pathStatus' = "degraded"
               /\ UNCHANGED <<badCount,status,pathNoise,leftRevoked,rightRevoked,merged,threshold>>
Quarantine(n) == /\ n \in Nodes /\ status[n] = "active" /\ badCount[n] >= BadLimit
                 /\ status' = [status EXCEPT ![n] = "quarantined"]
                 /\ UNCHANGED <<badCount,pathNoise,pathStatus,leftRevoked,rightRevoked,merged,threshold>>
RevokeLeft(n) == /\ n \in Nodes /\ leftRevoked' = leftRevoked \cup {n} /\ UNCHANGED <<badCount,status,pathNoise,pathStatus,rightRevoked,merged,threshold>>
RevokeRight(n) == /\ n \in Nodes /\ rightRevoked' = rightRevoked \cup {n} /\ UNCHANGED <<badCount,status,pathNoise,pathStatus,leftRevoked,merged,threshold>>
Merge == /\ merged' = leftRevoked \cup rightRevoked /\ UNCHANGED <<badCount,status,pathNoise,pathStatus,leftRevoked,rightRevoked,threshold>>
Next == (\E n \in Nodes: PeerNoise(n) \/ Quarantine(n) \/ RevokeLeft(n) \/ RevokeRight(n)) \/ SharedPathNoise \/ DegradePath \/ Merge
NoResurrection == merged \subseteq (leftRevoked \cup rightRevoked)
QuarantineStateBound == \A n \in Nodes: status[n] \in {"active","quarantined"}
ThresholdNeverDrops == threshold = RequiredThreshold
Spec == Init /\ [][Next]_vars
=============================================================================
