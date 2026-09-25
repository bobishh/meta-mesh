------------------------ MODULE AuthorityConformance -------------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS People, Epochs, GenesisOwner

ASSUME /\ Cardinality(People) = 3
       /\ GenesisOwner \in People
       /\ Epochs = {0, 1, 2}

VARIABLES grantEpoch, revokedThrough, seenRevocations, access,
          ownerEpoch, owner, ownerCandidates, conflicted,
          ownerHistory, replayedHistory

vars == <<grantEpoch, revokedThrough, seenRevocations, access,
          ownerEpoch, owner, ownerCandidates, conflicted,
          ownerHistory, replayedHistory>>

Init ==
  /\ grantEpoch = 0
  /\ revokedThrough = 0
  /\ seenRevocations = {0}
  /\ access = FALSE
  /\ ownerEpoch = 0
  /\ owner = GenesisOwner
  /\ ownerCandidates = {GenesisOwner}
  /\ conflicted = FALSE
  /\ ownerHistory = {}
  /\ replayedHistory = FALSE

Grant(epoch) ==
  /\ epoch \in Epochs \ {0}
  /\ grantEpoch' = IF epoch > grantEpoch THEN epoch ELSE grantEpoch
  /\ access' = ((IF epoch > grantEpoch THEN epoch ELSE grantEpoch) > revokedThrough)
  /\ UNCHANGED <<revokedThrough, seenRevocations, ownerEpoch, owner,
                  ownerCandidates, conflicted, ownerHistory, replayedHistory>>

Revoke(epoch) ==
  /\ epoch \in Epochs \ {0}
  /\ seenRevocations' = seenRevocations \cup {epoch}
  /\ revokedThrough' = IF epoch > revokedThrough THEN epoch ELSE revokedThrough
  /\ access' = (grantEpoch > (IF epoch > revokedThrough THEN epoch ELSE revokedThrough))
  /\ UNCHANGED <<grantEpoch, ownerEpoch, owner, ownerCandidates,
                  conflicted, ownerHistory, replayedHistory>>

\* A normal record is signed by the current owner and advances one epoch.
Transfer(nextOwner) ==
  /\ ~conflicted
  /\ ownerEpoch < 2
  /\ nextOwner \in People \ {owner}
  /\ ownerHistory' = ownerHistory \cup {<<ownerEpoch + 1, owner, nextOwner>>}
  /\ ownerEpoch' = ownerEpoch + 1
  /\ owner' = nextOwner
  /\ ownerCandidates' = {nextOwner}
  /\ replayedHistory' = FALSE
  /\ UNCHANGED <<grantEpoch, revokedThrough, seenRevocations, access, conflicted>>

\* A delayed, differently signed successor for the just-accepted epoch is an
\* explicit conflict. The already selected local owner is not rolled back.
Fork(alternateOwner) ==
  /\ ~conflicted
  /\ ownerEpoch > 0
  /\ \E record \in ownerHistory :
       /\ record[1] = ownerEpoch
       /\ record[3] = owner
       /\ alternateOwner \in People \ {record[2], owner}
       /\ ownerHistory' = ownerHistory \cup {<<ownerEpoch, record[2], alternateOwner>>}
  /\ ownerCandidates' = ownerCandidates \cup {alternateOwner}
  /\ conflicted' = TRUE
  /\ replayedHistory' = FALSE
  /\ UNCHANGED <<grantEpoch, revokedThrough, seenRevocations, access, ownerEpoch, owner>>

\* Replaying an already accepted signed transfer through a stale snapshot may
\* add merge work, but cannot roll current authority backward.
ReplayOwnershipHistory ==
  /\ ownerHistory # {}
  /\ ~replayedHistory
  /\ replayedHistory' = TRUE
  /\ UNCHANGED <<grantEpoch, revokedThrough, seenRevocations, access, ownerEpoch,
                  owner, ownerCandidates, conflicted, ownerHistory>>

Next ==
  \/ \E epoch \in Epochs : Grant(epoch)
  \/ \E epoch \in Epochs : Revoke(epoch)
  \/ \E nextOwner \in People : Transfer(nextOwner)
  \/ \E alternateOwner \in People : Fork(alternateOwner)
  \/ ReplayOwnershipHistory

TypeOK ==
  /\ grantEpoch \in Epochs
  /\ revokedThrough \in Epochs
  /\ seenRevocations \subseteq Epochs
  /\ access \in BOOLEAN
  /\ ownerEpoch \in Epochs
  /\ owner \in People
  /\ ownerCandidates \subseteq People
  /\ conflicted \in BOOLEAN
  /\ ownerHistory \subseteq (Epochs \X People \X People)
  /\ replayedHistory \in BOOLEAN

Safety ==
  /\ TypeOK
  /\ revokedThrough \in seenRevocations
  /\ \A epoch \in seenRevocations : epoch <= revokedThrough
  /\ access = (grantEpoch > revokedThrough)
  /\ owner \in ownerCandidates
  /\ conflicted = (Cardinality(ownerCandidates) > 1)
  /\ \A record \in ownerHistory :
       /\ record[1] > 0
       /\ record[1] <= ownerEpoch
       /\ record[2] # record[3]

Spec == Init /\ [][Next]_vars

=============================================================================
