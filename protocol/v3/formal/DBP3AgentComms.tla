-------------------------- MODULE DBP3AgentComms --------------------------
EXTENDS Naturals, Sequences
CONSTANTS Agents
VARIABLES authenticated, delegated, witnessed, authorized, mutated
vars == <<authenticated, delegated, witnessed, authorized, mutated>>
Init == /\ authenticated = [a \in Agents |-> FALSE]
        /\ delegated = [a \in Agents |-> FALSE]
        /\ witnessed = [a \in Agents |-> FALSE]
        /\ authorized = [a \in Agents |-> FALSE]
        /\ mutated = [a \in Agents |-> FALSE]
Mutate(a) == /\ authenticated[a] /\ delegated[a] /\ witnessed[a] /\ authorized[a]
             /\ mutated' = [mutated EXCEPT ![a] = TRUE]
             /\ UNCHANGED <<authenticated, delegated, witnessed, authorized>>
NoUnauthorizedMutation == \A a \in Agents : mutated[a] => (authenticated[a] /\ delegated[a] /\ witnessed[a] /\ authorized[a])
=============================================================================
