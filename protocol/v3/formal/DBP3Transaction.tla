------------------------------ MODULE DBP3Transaction ------------------------------
EXTENDS Naturals, FiniteSets
CONSTANT Keys
VARIABLES delivered, executed
Init == /\ delivered = {} /\ executed = {}
Deliver(k) == /\ k \in Keys /\ delivered' = delivered \cup {k} /\ UNCHANGED executed
Execute(k) == /\ k \in delivered /\ k \notin executed /\ executed' = executed \cup {k} /\ UNCHANGED delivered
Next == (\E k \in Keys: Deliver(k)) \/ (\E k \in Keys: Execute(k))
AtMostOnce == executed \subseteq Keys
=============================================================================
