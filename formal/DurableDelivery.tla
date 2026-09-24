--------------------------- MODULE DurableDelivery ---------------------------
EXTENDS FiniteSets, TLC

CONSTANTS Hashes, Mutation

ASSUME /\ Hashes # {}
       /\ IsFiniteSet(Hashes)
       /\ Mutation \in {"None", "PartialAck", "EmptyAck"}

VARIABLES persisted, pending, acknowledgements, complete

vars == <<persisted, pending, acknowledgements, complete>>

Init ==
  /\ persisted = {}
  /\ pending = Hashes
  /\ acknowledgements = {}
  /\ complete = FALSE

Persist(hash) ==
  /\ hash \in Hashes \ persisted
  /\ persisted' = persisted \cup {hash}
  /\ UNCHANGED <<pending, acknowledgements, complete>>

\* The receiver can only sign hashes already durable. The sender accepts the
\* ACK as batch success only when its distinct hash set exactly equals Hashes.
ReceiveAck(confirmed) ==
  /\ confirmed \subseteq persisted
  /\ acknowledgements' = acknowledgements \cup {confirmed}
  /\ IF (IF Mutation = "PartialAck" THEN confirmed # {}
          ELSE IF Mutation = "EmptyAck" THEN confirmed = {}
          ELSE confirmed = Hashes)
        THEN /\ complete' = TRUE
             /\ pending' = {}
        ELSE /\ UNCHANGED <<complete, pending>>
  /\ UNCHANGED persisted

Retry ==
  /\ ~complete
  /\ UNCHANGED vars

Next ==
  \/ \E hash \in Hashes : Persist(hash)
  \/ \E confirmed \in SUBSET Hashes : ReceiveAck(confirmed)
  \/ Retry

TypeOK ==
  /\ persisted \subseteq Hashes
  /\ pending \subseteq Hashes
  /\ acknowledgements \subseteq SUBSET Hashes
  /\ complete \in BOOLEAN

SuccessRequiresAllHashesPersistedAndAcknowledged ==
  complete => persisted = Hashes /\ Hashes \in acknowledgements

UnconfirmedBatchRemainsPending ==
  ~complete => pending = Hashes

CompletedBatchHasNoPendingHashes ==
  complete => pending = {}

Safety == TypeOK /\ SuccessRequiresAllHashesPersistedAndAcknowledged
          /\ UnconfirmedBatchRemainsPending /\ CompletedBatchHasNoPendingHashes

\* Fairness is used only for this liveness statement. WF(Persist(hash)) says
\* every continuously missing hash is eventually persisted. Once all hashes
\* are durable, WF(ReceiveAck(Hashes)) says a complete ACK is eventually seen.
Fairness == /\ \A hash \in Hashes : WF_vars(Persist(hash))
            /\ WF_vars(ReceiveAck(Hashes))

EventuallyDelivered == <>complete

Spec == Init /\ [][Next]_vars /\ Fairness

=============================================================================
