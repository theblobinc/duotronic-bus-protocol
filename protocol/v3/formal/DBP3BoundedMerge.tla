---------------- MODULE DBP3BoundedMerge ----------------
EXTENDS Naturals
CONSTANT TotalSegments, MaxItems, MaxBytes, SegmentBytes
VARIABLES cursor, pageItems, pageBytes, done
vars == <<cursor,pageItems,pageBytes,done>>
Init == /\ cursor = 0 /\ pageItems = 0 /\ pageBytes = 0 /\ done = (TotalSegments = 0)
CanEmit == /\ ~done /\ cursor < TotalSegments /\ pageItems < MaxItems /\ pageBytes + SegmentBytes <= MaxBytes
Emit == /\ CanEmit
        /\ cursor' = cursor + 1
        /\ pageItems' = pageItems + 1
        /\ pageBytes' = pageBytes + SegmentBytes
        /\ done' = (cursor + 1 = TotalSegments)
Yield == /\ ~done /\ ~CanEmit
         /\ pageItems' = 0 /\ pageBytes' = 0
         /\ UNCHANGED <<cursor,done>>
Next == Emit \/ Yield
PerPageBound == /\ pageItems <= MaxItems /\ pageBytes <= MaxBytes
CursorBound == cursor <= TotalSegments
Spec == Init /\ [][Next]_vars
=============================================================================
