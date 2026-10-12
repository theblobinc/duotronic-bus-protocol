--------------------------- MODULE DBP3Comms ---------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Participants
VARIABLES callState, floorHolder, groupEpoch, keyEpoch
vars == <<callState, floorHolder, groupEpoch, keyEpoch>>
CallStates == {"idle","invited","ringing","active","held","ended"}
Init == /\ callState = "idle" /\ floorHolder = "none" /\ groupEpoch = 1 /\ keyEpoch = 1
Invite == /\ callState = "idle" /\ callState' = "invited" /\ UNCHANGED <<floorHolder,groupEpoch,keyEpoch>>
Ring == /\ callState = "invited" /\ callState' = "ringing" /\ UNCHANGED <<floorHolder,groupEpoch,keyEpoch>>
Accept == /\ callState \in {"invited","ringing"} /\ callState' = "active" /\ UNCHANGED <<floorHolder,groupEpoch,keyEpoch>>
Hold == /\ callState = "active" /\ callState' = "held" /\ UNCHANGED <<floorHolder,groupEpoch,keyEpoch>>
Resume == /\ callState = "held" /\ callState' = "active" /\ UNCHANGED <<floorHolder,groupEpoch,keyEpoch>>
End == /\ callState \in {"invited","ringing","active","held"} /\ callState' = "ended" /\ UNCHANGED <<floorHolder,groupEpoch,keyEpoch>>
MembershipChange == /\ groupEpoch' = groupEpoch + 1 /\ keyEpoch' = keyEpoch + 1 /\ UNCHANGED <<callState,floorHolder>>
Next == Invite \/ Ring \/ Accept \/ Hold \/ Resume \/ End \/ MembershipChange
TypeOK == /\ callState \in CallStates /\ groupEpoch >= 1 /\ keyEpoch >= 1
RekeyOnMembership == keyEpoch >= groupEpoch
Spec == Init /\ [][Next]_vars
=============================================================================
