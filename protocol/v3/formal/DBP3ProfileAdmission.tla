---------------- MODULE DBP3ProfileAdmission ----------------
EXTENDS Naturals
VARIABLES state, semanticValid, resourceAdmitted, registryFresh, suiteRegistered, fecRegistered, limitsInRange
vars == <<state,semanticValid,resourceAdmitted,registryFresh,suiteRegistered,fecRegistered,limitsInRange>>
Init == /\ state = "candidate"
        /\ semanticValid = FALSE /\ resourceAdmitted = FALSE
        /\ registryFresh = FALSE /\ suiteRegistered = FALSE /\ fecRegistered = FALSE /\ limitsInRange = FALSE
ValidateRegistry == /\ state = "candidate"
                    /\ registryFresh' = TRUE /\ suiteRegistered' = TRUE /\ fecRegistered' = TRUE /\ limitsInRange' = TRUE
                    /\ UNCHANGED <<state,semanticValid,resourceAdmitted>>
ValidateSemantics == /\ state = "candidate" /\ registryFresh /\ suiteRegistered /\ fecRegistered /\ limitsInRange
                     /\ semanticValid' = TRUE
                     /\ UNCHANGED <<state,resourceAdmitted,registryFresh,suiteRegistered,fecRegistered,limitsInRange>>
AdmitResources == /\ state = "candidate" /\ semanticValid /\ resourceAdmitted' = TRUE
                  /\ UNCHANGED <<state,semanticValid,registryFresh,suiteRegistered,fecRegistered,limitsInRange>>
Activate == /\ state = "candidate" /\ semanticValid /\ resourceAdmitted /\ registryFresh /\ suiteRegistered /\ fecRegistered /\ limitsInRange
            /\ state' = "active"
            /\ UNCHANGED <<semanticValid,resourceAdmitted,registryFresh,suiteRegistered,fecRegistered,limitsInRange>>
Reject == /\ state = "candidate" /\ state' = "rejected"
          /\ UNCHANGED <<semanticValid,resourceAdmitted,registryFresh,suiteRegistered,fecRegistered,limitsInRange>>
Next == ValidateRegistry \/ ValidateSemantics \/ AdmitResources \/ Activate \/ Reject
ActiveRequiresAll == state = "active" => semanticValid /\ resourceAdmitted /\ registryFresh /\ suiteRegistered /\ fecRegistered /\ limitsInRange
Spec == Init /\ [][Next]_vars
=============================================================================
