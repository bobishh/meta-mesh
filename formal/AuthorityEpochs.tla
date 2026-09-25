--------------------------- MODULE AuthorityEpochs ---------------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Replicas, People, Epochs, GenesisOwner, Mutation

ASSUME /\ Replicas # {}
       /\ People # {}
       /\ GenesisOwner \in People
       /\ 0 \in Epochs
       /\ Mutation \in {"None", "GrantReset", "SnapshotReset"}

VARIABLES grantEpoch, revokedThrough, seenRevocations,
          ownerEpoch, ownerCandidates, seenOwners

vars == <<grantEpoch, revokedThrough, seenRevocations,
          ownerEpoch, ownerCandidates, seenOwners>>

HasAccess(r) == grantEpoch[r] > revokedThrough[r]

Init ==
  /\ grantEpoch = [r \in Replicas |-> 0]
  /\ revokedThrough = [r \in Replicas |-> 0]
  /\ seenRevocations = [r \in Replicas |-> {0}]
  /\ ownerEpoch = [r \in Replicas |-> 0]
  /\ ownerCandidates = [r \in Replicas |-> {GenesisOwner}]
  /\ seenOwners = [r \in Replicas |-> {<<0, GenesisOwner>>}]

ReceiveGrant(r, e) ==
  /\ e \in Epochs \ {0}
  /\ grantEpoch' = [grantEpoch EXCEPT ![r] = IF e > @ THEN e ELSE @]
  /\ IF Mutation = "GrantReset" /\ e <= revokedThrough[r]
        THEN revokedThrough' = [revokedThrough EXCEPT ![r] = 0]
        ELSE UNCHANGED revokedThrough
  /\ UNCHANGED <<seenRevocations, ownerEpoch, ownerCandidates, seenOwners>>

ReceiveRevocation(r, e) ==
  /\ e \in Epochs \ {0}
  /\ seenRevocations' = [seenRevocations EXCEPT ![r] = @ \cup {e}]
  /\ revokedThrough' = [revokedThrough EXCEPT ![r] = IF e > @ THEN e ELSE @]
  /\ UNCHANGED <<grantEpoch, ownerEpoch, ownerCandidates, seenOwners>>

ReceiveOwnerRecord(r, e, owner) ==
  /\ e \in Epochs
  /\ owner \in People
  /\ seenOwners' = [seenOwners EXCEPT ![r] = @ \cup {<<e, owner>>}]
  /\ ownerEpoch' = [ownerEpoch EXCEPT ![r] = IF e > @ THEN e ELSE @]
  /\ ownerCandidates' =
       [ownerCandidates EXCEPT ![r] =
          IF e > ownerEpoch[r] THEN {owner}
          ELSE IF e = ownerEpoch[r] THEN @ \cup {owner}
          ELSE @]
  /\ UNCHANGED <<grantEpoch, revokedThrough, seenRevocations>>

\* Models IndexedDB credential reconciliation with an older offline snapshot.
\* Correct code unions security records and keeps the highest authority epoch.
ReceiveGenesisSnapshot(r) ==
  /\ seenRevocations' = [seenRevocations EXCEPT ![r] = @ \cup {0}]
  /\ seenOwners' = [seenOwners EXCEPT ![r] = @ \cup {<<0, GenesisOwner>>}]
  /\ IF Mutation = "SnapshotReset"
        THEN /\ grantEpoch' = [grantEpoch EXCEPT ![r] = 0]
             /\ revokedThrough' = [revokedThrough EXCEPT ![r] = 0]
             /\ ownerEpoch' = [ownerEpoch EXCEPT ![r] = 0]
             /\ ownerCandidates' = [ownerCandidates EXCEPT ![r] = {GenesisOwner}]
        ELSE UNCHANGED <<grantEpoch, revokedThrough, ownerEpoch, ownerCandidates>>

Next ==
  \/ \E r \in Replicas, e \in Epochs : ReceiveGrant(r, e)
  \/ \E r \in Replicas, e \in Epochs : ReceiveRevocation(r, e)
  \/ \E r \in Replicas, e \in Epochs \ {0}, o \in People : ReceiveOwnerRecord(r, e, o)
  \/ \E r \in Replicas : ReceiveGenesisSnapshot(r)

TypeOK ==
  /\ grantEpoch \in [Replicas -> Epochs]
  /\ revokedThrough \in [Replicas -> Epochs]
  /\ seenRevocations \in [Replicas -> SUBSET Epochs]
  /\ ownerEpoch \in [Replicas -> Epochs]
  /\ ownerCandidates \in [Replicas -> SUBSET People]
  /\ seenOwners \in [Replicas -> SUBSET (Epochs \X People)]

RevocationNeverRollsBack ==
  \A r \in Replicas :
    /\ revokedThrough[r] \in seenRevocations[r]
    /\ \A e \in seenRevocations[r] : e <= revokedThrough[r]

AccessRespectsAllSeenRevocations ==
  \A r \in Replicas :
    HasAccess(r) => \A e \in seenRevocations[r] : e < grantEpoch[r]

OwnerHistoryNeverRollsBack ==
  \A r \in Replicas :
    /\ \E o \in People : <<ownerEpoch[r], o>> \in seenOwners[r]
    /\ \A record \in seenOwners[r] : record[1] <= ownerEpoch[r]

ConflictStateIsExplicit ==
  \A r \in Replicas :
    ownerCandidates[r] = {o \in People : <<ownerEpoch[r], o>> \in seenOwners[r]}

Safety == TypeOK /\ RevocationNeverRollsBack /\ AccessRespectsAllSeenRevocations
          /\ OwnerHistoryNeverRollsBack /\ ConflictStateIsExplicit

Spec == Init /\ [][Next]_vars

=============================================================================
