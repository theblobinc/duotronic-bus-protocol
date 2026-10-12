----------------------------- MODULE DBP3ReplayRekey -----------------------------
EXTENDS Naturals, FiniteSets
CONSTANT MaxSeq
VARIABLES epoch, accepted, compromised, state
Init == /\ epoch = 1 /\ accepted = {} /\ compromised = {} /\ state = "active"
Accept(s) == /\ state = "active" /\ s \in 1..MaxSeq /\ s \notin accepted /\ accepted' = accepted \cup {s} /\ UNCHANGED <<epoch,compromised,state>>
Rekey == /\ state = "active" /\ epoch' = epoch + 1 /\ accepted' = {} /\ UNCHANGED <<compromised,state>>
Compromise == /\ state = "active" /\ compromised' = compromised \cup {epoch} /\ state' = "quarantined" /\ UNCHANGED <<epoch,accepted>>
Next == (\E s \in 1..MaxSeq: Accept(s)) \/ Rekey \/ Compromise
NoDuplicate == accepted \subseteq 1..MaxSeq
NoResumeCompromised == state = "quarantined" => epoch \in compromised
=============================================================================
