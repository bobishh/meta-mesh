--------------------------- MODULE GrantProvenanceTransfer ---------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS SourceVariants, PageOne, PageTwo,
          ConfiguredManifestMode, ConfiguredRequestMode,
          DropProvenanceVariant, AllowEarlyCompletion,
          AllowMissingVariantCompletion

Stages == {"new", "manifest", "transferring", "complete", "rejected"}
Modes == {"none", "legacy", "upgraded"}
Outcomes == {"pending", "accepted", "mode-mismatch", "identity-conflict", "ambiguous-provenance"}
Cursors == {0, 1, 2}

VARIABLES stage, manifestMode, requestMode, cursor,
          manifestVariants, requestVariants, wireVariants,
          receiverVariants, outcome

vars == <<stage, manifestMode, requestMode, cursor,
          manifestVariants, requestVariants, wireVariants,
          receiverVariants, outcome>>

Signature(variant) ==
  IF variant = "legacy-only" THEN "legacy-proof" ELSE "proof-a"

SignedIdentity(variant) ==
  IF variant = "identity-conflict" THEN "change-b"
  ELSE IF variant = "legacy-only" THEN "legacy-change" ELSE "change-a"

GrantProvenance(variant) ==
  CASE variant = "absent" -> "absent"
    [] variant = "grant-a" -> "grant-a"
    [] variant = "grant-b" -> "grant-b"
    [] variant = "identity-conflict" -> "grant-a"
    [] OTHER -> "legacy"

IdentityConflict ==
  \E left, right \in SourceVariants :
    left # right /\ Signature(left) = Signature(right)
      /\ SignedIdentity(left) # SignedIdentity(right)

AmbiguousProvenance ==
  \E left, right \in SourceVariants :
    left # right /\ Signature(left) = Signature(right)
      /\ SignedIdentity(left) = SignedIdentity(right)
      /\ GrantProvenance(left) # GrantProvenance(right)

Delivered(page) ==
  IF DropProvenanceVariant
  THEN {variant \in page : GrantProvenance(variant) = "grant-a"}
  ELSE page

RequestOutcome ==
  IF manifestMode # ConfiguredRequestMode THEN "mode-mismatch"
  ELSE IF IdentityConflict THEN "identity-conflict"
  ELSE IF ConfiguredRequestMode = "legacy" /\ AmbiguousProvenance
       THEN "ambiguous-provenance"
       ELSE "accepted"

Init ==
  /\ stage = "new"
  /\ manifestMode = "none"
  /\ requestMode = "none"
  /\ cursor = 0
  /\ manifestVariants = {}
  /\ requestVariants = {}
  /\ wireVariants = {}
  /\ receiverVariants = {}
  /\ outcome = "pending"

PrepareManifest ==
  /\ stage = "new"
  /\ stage' = "manifest"
  /\ manifestMode' = ConfiguredManifestMode
  /\ manifestVariants' = SourceVariants
  /\ UNCHANGED <<requestMode, cursor, requestVariants, wireVariants, receiverVariants, outcome>>

AcceptRequest ==
  /\ stage = "manifest"
  /\ requestMode' = ConfiguredRequestMode
  /\ requestVariants' = manifestVariants
  /\ IF RequestOutcome = "accepted"
        THEN /\ stage' = "transferring"
             /\ outcome' = "accepted"
        ELSE /\ stage' = "rejected"
             /\ outcome' = RequestOutcome
  /\ UNCHANGED <<manifestMode, cursor, manifestVariants, wireVariants, receiverVariants>>

DeliverFirstPage ==
  /\ stage = "transferring"
  /\ cursor = 0
  /\ wireVariants' = wireVariants \cup Delivered(PageOne \cap requestVariants)
  /\ receiverVariants' = receiverVariants \cup Delivered(PageOne \cap requestVariants)
  /\ cursor' = 1
  /\ UNCHANGED <<stage, manifestMode, requestMode, manifestVariants, requestVariants, outcome>>

DeliverSecondPage ==
  /\ stage = "transferring"
  /\ cursor = 1
  /\ wireVariants' = wireVariants \cup Delivered(PageTwo \cap requestVariants)
  /\ receiverVariants' = receiverVariants \cup Delivered(PageTwo \cap requestVariants)
  /\ cursor' = 2
  /\ UNCHANGED <<stage, manifestMode, requestMode, manifestVariants, requestVariants, outcome>>

ReplayFirstPage ==
  /\ stage = "transferring"
  /\ cursor \in {1, 2}
  /\ wireVariants' = wireVariants \cup Delivered(PageOne \cap requestVariants)
  /\ receiverVariants' = receiverVariants \cup Delivered(PageOne \cap requestVariants)
  /\ UNCHANGED <<stage, manifestMode, requestMode, cursor, manifestVariants, requestVariants, outcome>>

CompleteTransfer ==
  /\ stage = "transferring"
  /\ IF AllowEarlyCompletion
        THEN cursor >= 1
        ELSE /\ cursor = 2
             /\ (AllowMissingVariantCompletion \/ receiverVariants = requestVariants)
  /\ stage' = "complete"
  /\ outcome' = "accepted"
  /\ UNCHANGED <<manifestMode, requestMode, cursor, manifestVariants, requestVariants, wireVariants, receiverVariants>>

TerminalStutter ==
  /\ stage \in {"complete", "rejected"}
  /\ UNCHANGED vars

Next ==
  PrepareManifest \/ AcceptRequest \/ DeliverFirstPage \/ DeliverSecondPage
    \/ ReplayFirstPage \/ CompleteTransfer \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ stage \in Stages
  /\ manifestMode \in Modes
  /\ requestMode \in Modes
  /\ cursor \in Cursors
  /\ manifestVariants \subseteq SourceVariants
  /\ requestVariants \subseteq SourceVariants
  /\ wireVariants \subseteq SourceVariants
  /\ receiverVariants \subseteq SourceVariants
  /\ outcome \in Outcomes

RejectedBeforeTransfer ==
  stage = "rejected" =>
    /\ outcome \in {"mode-mismatch", "identity-conflict", "ambiguous-provenance"}
    /\ wireVariants = {}
    /\ receiverVariants = {}

NoTransferOnConflict ==
  (IdentityConflict \/ manifestMode # requestMode) => stage # "transferring" /\ stage # "complete"

LegacyAmbiguityRejected ==
  (requestMode = "legacy" /\ AmbiguousProvenance) => stage # "transferring" /\ stage # "complete"

PagesPartitionManifest ==
  PageOne \cup PageTwo = SourceVariants
    /\ PageOne \cap PageTwo = {}

CompletedTransferPreservesVariants ==
  stage = "complete" =>
    /\ outcome = "accepted"
    /\ manifestMode = requestMode
    /\ manifestVariants = SourceVariants
    /\ requestVariants = SourceVariants
    /\ cursor = 2
    /\ wireVariants = SourceVariants
    /\ receiverVariants = SourceVariants

Safety ==
  /\ TypeOK
  /\ RejectedBeforeTransfer
  /\ NoTransferOnConflict
  /\ LegacyAmbiguityRejected
  /\ PagesPartitionManifest
  /\ CompletedTransferPreservesVariants

=======================================================================================
