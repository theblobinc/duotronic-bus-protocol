---------------- MODULE DBP3QuarantineReadmission ----------------
EXTENDS Naturals
CONSTANT RequiredValid
VARIABLES state, quarantineEpoch, generation, challengeFresh, proofVerified, probationValid
vars == <<state,quarantineEpoch,generation,challengeFresh,proofVerified,probationValid>>
Init == /\ state = "active"
        /\ quarantineEpoch = 0
        /\ generation = 0
        /\ challengeFresh = FALSE
        /\ proofVerified = FALSE
        /\ probationValid = 0
Quarantine == /\ state \in {"active","degraded"}
              /\ state' = "quarantined"
              /\ quarantineEpoch' = quarantineEpoch + 1
              /\ challengeFresh' = FALSE
              /\ proofVerified' = FALSE
              /\ probationValid' = 0
              /\ UNCHANGED generation
IssueChallenge == /\ state = "quarantined"
                  /\ challengeFresh' = TRUE
                  /\ UNCHANGED <<state,quarantineEpoch,generation,proofVerified,probationValid>>
VerifyProof == /\ state = "quarantined" /\ challengeFresh
               /\ proofVerified' = TRUE
               /\ UNCHANGED <<state,quarantineEpoch,generation,challengeFresh,probationValid>>
Readmit == /\ state = "quarantined" /\ challengeFresh /\ proofVerified
           /\ state' = "probation"
           /\ generation' = generation + 1
           /\ challengeFresh' = FALSE
           /\ probationValid' = 0
           /\ UNCHANGED <<quarantineEpoch,proofVerified>>
PassProbation == /\ state = "probation"
                 /\ probationValid' = probationValid + 1
                 /\ state' = IF probationValid + 1 >= RequiredValid THEN "active" ELSE "probation"
                 /\ UNCHANGED <<quarantineEpoch,generation,challengeFresh,proofVerified>>
Next == Quarantine \/ IssueChallenge \/ VerifyProof \/ Readmit \/ PassProbation
NoGhostReset == quarantineEpoch > 0 /\ state = "active" => generation > 0
ProbationNeedsProof == state = "probation" => proofVerified
EpochGenerationNatural == /\ quarantineEpoch \in Nat /\ generation \in Nat /\ probationValid \in Nat
Spec == Init /\ [][Next]_vars
=============================================================================
