-------------------------- MODULE CausalAdmission --------------------------
EXTENDS FiniteSets, Integers, TLC

CONSTANTS Replicas, R1, R2, Mutant

ASSUME /\ Replicas = {R1, R2}
       /\ Mutant \in {"None", "KnownHashBypass", "TimestampPriority",
                      "MissingDependencyAcceptance", "ForgettingQuarantine"}

Changes == {"root", "inside", "outside", "regrant-edit", "depends-on-outside"}
Proofs == {"revocation", "regrant"}
Times == {-10000, 0, 10000}
Frontier == {"root", "inside"}
RevocationTime == 0

GrantEpoch(c) ==
  CASE c = "root"               -> 0
    [] c = "inside"             -> 1
    [] c = "outside"            -> 1
    [] c = "regrant-edit"       -> 2
    [] c = "depends-on-outside" -> 2

Deps(c) ==
  CASE c = "root"               -> {}
    [] c = "inside"             -> {"root"}
    [] c = "outside"            -> {"root"}
    [] c = "regrant-edit"       -> {"root"}
    [] c = "depends-on-outside" -> {"outside"}

SignedTime(c) == IF c = "outside" THEN 10000 ELSE -10000

VARIABLES raw, seen, proofs, view, dirty,
          forgottenOutside, acceptedOutside, clock
vars == <<raw, seen, proofs, view, dirty,
          forgottenOutside, acceptedOutside, clock>>

RECURSIVE CorrectStatus(_, _)
CorrectStatus(c, r) ==
  IF c \notin raw
    THEN "Absent"
    ELSE IF ~Deps(c) \subseteq raw
      THEN "Pending"
      ELSE IF ~\A d \in Deps(c) : CorrectStatus(d, r) = "Admitted"
        THEN "Pending"
        ELSE IF GrantEpoch(c) = 0
                  \/ (GrantEpoch(c) = 1
                      /\ ("revocation" \notin proofs \/ c \in Frontier))
                  \/ (GrantEpoch(c) = 2 /\ "regrant" \in proofs)
          THEN "Admitted"
          ELSE "Quarantined"

RECURSIVE BrokenStatus(_, _)
BrokenStatus(c, r) ==
  IF c \notin raw
    THEN "Absent"
    ELSE IF Mutant = "MissingDependencyAcceptance"
              /\ ~(Deps(c) \subseteq raw)
      THEN "Admitted"
      ELSE IF ~Deps(c) \subseteq raw
        THEN "Pending"
        ELSE IF ~\A d \in Deps(c) : BrokenStatus(d, r) = "Admitted"
          THEN "Pending"
          ELSE IF GrantEpoch(c) = 0
                    \/ (GrantEpoch(c) = 1
                        /\ ("revocation" \notin proofs \/ c \in Frontier
                            \/ (Mutant = "TimestampPriority"
                                /\ SignedTime(c) > clock)))
                    \/ (GrantEpoch(c) = 2 /\ "regrant" \in proofs)
            THEN "Admitted"
            ELSE "Quarantined"

ExpectedProjection(r) ==
  {c \in raw : CorrectStatus(c, r) = "Admitted"}

Classify(r) ==
  <<{c \in raw : CorrectStatus(c, r) = "Admitted"},
    {c \in raw : CorrectStatus(c, r) = "Quarantined"},
    {c \in raw : CorrectStatus(c, r) = "Pending"}>>

BrokenProjection(r) ==
  {c \in raw :
    \/ BrokenStatus(c, r) = "Admitted"
    \/ (Mutant = "KnownHashBypass" /\ c = "outside" /\ acceptedOutside)}

BrokenClassification(r) ==
  <<BrokenProjection(r),
    {c \in raw : CorrectStatus(c, r) = "Quarantined"},
    {c \in raw : CorrectStatus(c, r) = "Pending"}>>

Init ==
  /\ raw = {"root"}
  /\ seen = {"root"}
  /\ proofs = {}
  /\ view = [r \in Replicas |-> <<{"root"}, {}, {}>>]
  /\ dirty = [r \in Replicas |-> FALSE]
  /\ forgottenOutside = FALSE
  /\ acceptedOutside = FALSE
  /\ clock = -10000

ClockInit ==
  /\ raw = {"root"}
  /\ seen = {"root"}
  /\ proofs = {}
  /\ view = [r \in Replicas |-> <<{"root"}, {}, {}>>]
  /\ dirty = [r \in Replicas |-> FALSE]
  /\ forgottenOutside = FALSE
  /\ acceptedOutside = FALSE
  /\ clock \in Times

ReceiveChange(c) ==
  /\ c \in Changes
  /\ c \notin raw
  /\ raw' = raw \cup {c}
  /\ seen' = seen \cup {c}
  /\ dirty' = [r \in Replicas |-> TRUE]
  /\ UNCHANGED <<proofs, view, forgottenOutside, acceptedOutside, clock>>

ReceiveRevocation ==
  /\ "inside" \in raw
  /\ "revocation" \notin proofs
  /\ proofs' = proofs \cup {"revocation"}
  /\ dirty' = [r \in Replicas |-> TRUE]
  /\ UNCHANGED <<raw, seen, view, forgottenOutside, acceptedOutside, clock>>

ReceiveRegrant ==
  /\ "regrant" \notin proofs
  /\ proofs' = proofs \cup {"regrant"}
  /\ dirty' = [r \in Replicas |-> TRUE]
  /\ UNCHANGED <<raw, seen, view, forgottenOutside, acceptedOutside, clock>>

Reclassify(r) ==
  /\ r \in Replicas
  /\ view' = [view EXCEPT ![r] = BrokenClassification(r)]
  /\ dirty' = [dirty EXCEPT ![r] = FALSE]
  /\ acceptedOutside' =
       (acceptedOutside \/ (CorrectStatus("outside", r) = "Admitted"))
  /\ UNCHANGED <<raw, seen, proofs, clock, forgottenOutside>>

ClockSample(t) ==
  /\ t \in Times
  /\ clock' = t
  /\ UNCHANGED <<raw, seen, proofs, view, dirty,
                  forgottenOutside, acceptedOutside>>

ForgetQuarantined(r, c) ==
  /\ Mutant = "ForgettingQuarantine"
  /\ r \in Replicas
  /\ c = "outside"
  /\ c \in raw
  /\ \E rr \in Replicas : CorrectStatus(c, rr) = "Quarantined"
  /\ ~forgottenOutside
  /\ forgottenOutside' = TRUE
  /\ UNCHANGED <<raw, seen, proofs, view, dirty, acceptedOutside, clock>>

Next ==
  \/ \E c \in Changes : ReceiveChange(c)
  \/ ReceiveRevocation
  \/ ReceiveRegrant
  \/ \E r \in Replicas : Reclassify(r)
  \/ (Mutant # "None" /\ \E t \in Times : ClockSample(t))
  \/ \E r \in Replicas : \E c \in Changes : ForgetQuarantined(r, c)

Spec == Init /\ [][Next]_vars
ClockNext == \E t \in Times : ClockSample(t)
ClockSpec == ClockInit /\ [][ClockNext]_vars
FairReclassification == WF_vars(Reclassify(R1)) /\ WF_vars(Reclassify(R2))
FairSpec == Spec /\ FairReclassification

RawEvidenceImmutable == seen \subseteq raw

AppliedViewMatchesPolicy ==
  \A r \in Replicas : ~dirty[r] =>
    view[r] = Classify(r)

ClockDoesNotSelectAuthorization ==
  \A r \in Replicas : view[r][1] = ExpectedProjection(r)

QuarantinedHashesExcluded ==
  \A r \in Replicas :
    ~dirty[r] => \A c \in raw :
      CorrectStatus(c, r) = "Quarantined" => c \notin view[r][1]

QuarantineEvidenceRetained ==
  \A r \in Replicas :
    ~dirty[r] => \A c \in raw :
      CorrectStatus(c, r) = "Quarantined"
        => (c # "outside" \/ ~forgottenOutside)

ProjectionDependencyClosed ==
  \A r \in Replicas : ~dirty[r] =>
    \A c \in view[r][1] : Deps(c) \subseteq view[r][1]

MissingDependenciesNeverAdmitted ==
  \A r \in Replicas : ~dirty[r] =>
    \A c \in view[r][1] : Deps(c) \subseteq raw

Complete(r) == raw = Changes /\ proofs = Proofs
CompleteEvidenceConverges ==
  []((Complete(R1) /\ Complete(R2)) => <>(view[R1] = view[R2]))

KnownHashBypass == QuarantinedHashesExcluded
TimestampPriority == AppliedViewMatchesPolicy
MissingDependencyAcceptance == MissingDependenciesNeverAdmitted
ForgettingQuarantine == QuarantineEvidenceRetained

=============================================================================
