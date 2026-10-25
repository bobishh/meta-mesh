--------------------------- MODULE IdentitySignIn ---------------------------
EXTENDS Integers, TLC

\* Two enrolled managers of one Identity. The source has already approved the
\* Rusty link. A cold phone may have an older signed profile with no locator.
\* Cryptographic verification, board authority and durable storage are assumed;
\* this model checks orchestration, not cryptography or data replication.
CONSTANTS PhoneInitiallyLinked, PeerAvailable, CatalogAvailable, HasCatalog,
          TimeoutEnabled, Mutation

ASSUME /\ PhoneInitiallyLinked \in BOOLEAN
       /\ PeerAvailable \in BOOLEAN
       /\ CatalogAvailable \in BOOLEAN
       /\ HasCatalog \in BOOLEAN
       /\ TimeoutEnabled \in BOOLEAN
       /\ Mutation \in {"None", "SkipSync", "TimeoutAsEmpty", "ReturnBeforeLoad", "NoReconnect"}

VARIABLES phoneLinked, sync, phase, status, approvedPin, catalogRead,
          boardLoaded, ticks, attempt, sourceReady

vars == <<phoneLinked, sync, phase, status, approvedPin, catalogRead,
          boardLoaded, ticks, attempt, sourceReady>>

Init ==
  /\ sourceReady = FALSE
  /\ phoneLinked = PhoneInitiallyLinked
  /\ sync = "idle"
  /\ phase = "idle"
  /\ status = "none"
  /\ approvedPin = FALSE
  /\ catalogRead = FALSE
  /\ boardLoaded = FALSE
  /\ ticks = 0
  /\ attempt = 0

BeginAttempt ==
  /\ phase \in {"idle", "retry"}
  /\ attempt < 2
  /\ attempt' = attempt + 1
  /\ phase' = "waiting"
  /\ sync' = IF phoneLinked THEN "notRequired" ELSE "pending"
  /\ status' = "none"
  /\ approvedPin' = FALSE
  /\ catalogRead' = FALSE
  /\ boardLoaded' = FALSE
  /\ ticks' = 0
  /\ UNCHANGED <<phoneLinked, sourceReady>>

ReconnectSource ==
  /\ phase = "waiting"
  /\ sync = "pending"
  /\ PeerAvailable
  /\ ~sourceReady
  /\ Mutation # "NoReconnect"
  /\ sourceReady' = TRUE
  /\ UNCHANGED <<phoneLinked, sync, phase, status, approvedPin, catalogRead,
                  boardLoaded, ticks, attempt>>

ReceiveIdentityProfile ==
  /\ phase = "waiting"
  /\ sync = "pending"
  /\ PeerAvailable
  /\ sourceReady
  /\ phoneLinked' = TRUE
  /\ sync' = "complete"
  /\ UNCHANGED <<phase, status, approvedPin, catalogRead, boardLoaded,
                  ticks, attempt, sourceReady>>

SnapshotForApproval ==
  /\ phase = "waiting"
  /\ (sync \in {"complete", "notRequired"} \/ Mutation = "SkipSync")
  /\ phase' = "lookup"
  /\ approvedPin' = phoneLinked
  /\ UNCHANGED <<phoneLinked, sync, status, catalogRead, boardLoaded,
                  ticks, attempt, sourceReady>>

LookupCatalog ==
  /\ phase = "lookup"
  /\ catalogRead' = (approvedPin /\ CatalogAvailable)
  /\ status' = IF ~approvedPin THEN "empty"
                ELSE IF ~CatalogAvailable THEN "unavailable"
                ELSE IF HasCatalog THEN "ready" ELSE "empty"
  /\ phase' = "response"
  /\ UNCHANGED <<phoneLinked, sync, approvedPin, boardLoaded, ticks, attempt, sourceReady>>

Tick ==
  /\ TimeoutEnabled
  /\ phase = "waiting"
  /\ sync = "pending"
  /\ ticks < 2
  /\ ticks' = ticks + 1
  /\ UNCHANGED <<phoneLinked, sync, phase, status, approvedPin, catalogRead,
                  boardLoaded, attempt, sourceReady>>

SyncTimeout ==
  /\ phase = "waiting"
  /\ sync = "pending"
  /\ ticks = 2
  /\ sync' = "failed"
  /\ status' = IF Mutation = "TimeoutAsEmpty" THEN "empty" ELSE "unavailable"
  /\ phase' = "response"
  /\ UNCHANGED <<phoneLinked, approvedPin, catalogRead, boardLoaded, ticks, attempt, sourceReady>>

ReturnToApplication ==
  /\ phase = "response"
  /\ phase' = IF status = "unavailable" THEN "retry"
               ELSE IF status = "ready" /\ Mutation # "ReturnBeforeLoad"
                 THEN "loading" ELSE "done"
  /\ UNCHANGED <<phoneLinked, sync, status, approvedPin, catalogRead,
                  boardLoaded, ticks, attempt, sourceReady>>

LoadAuthorizedBoard ==
  /\ phase = "loading"
  /\ status = "ready"
  /\ boardLoaded' = TRUE
  /\ phase' = "done"
  /\ UNCHANGED <<phoneLinked, sync, status, approvedPin, catalogRead, ticks, attempt, sourceReady>>

Next == BeginAttempt \/ ReconnectSource \/ ReceiveIdentityProfile \/ SnapshotForApproval
        \/ LookupCatalog \/ Tick \/ SyncTimeout \/ ReturnToApplication
        \/ LoadAuthorizedBoard

TypeOK ==
  /\ sourceReady \in BOOLEAN
  /\ phoneLinked \in BOOLEAN
  /\ sync \in {"idle", "pending", "notRequired", "complete", "failed"}
  /\ phase \in {"idle", "waiting", "lookup", "response", "loading", "done", "retry"}
  /\ status \in {"none", "empty", "ready", "unavailable"}
  /\ approvedPin \in BOOLEAN
  /\ catalogRead \in BOOLEAN
  /\ boardLoaded \in BOOLEAN
  /\ ticks \in 0..2
  /\ attempt \in 0..2

EmptyRequiresCompletedLookup == status = "empty" => catalogRead
ReadyRequiresVerifiedLocator == status = "ready" => (approvedPin /\ catalogRead)
SuccessWaitsForBoard == (phase = "done" /\ status = "ready") => boardLoaded
UnavailableIsRetryable == (phase \in {"done", "retry"} /\ status = "unavailable") => phase = "retry"
Safety == TypeOK /\ EmptyRequiresCompletedLookup /\ ReadyRequiresVerifiedLocator
          /\ SuccessWaitsForBoard /\ UnavailableIsRetryable

Fairness == WF_vars(BeginAttempt) /\ WF_vars(ReconnectSource)
            /\ WF_vars(ReceiveIdentityProfile)
            /\ WF_vars(SnapshotForApproval) /\ WF_vars(LookupCatalog)
            /\ WF_vars(Tick) /\ WF_vars(SyncTimeout)
            /\ WF_vars(ReturnToApplication) /\ WF_vars(LoadAuthorizedBoard)

AttemptSettles == []((phase \in {"waiting", "lookup", "response", "loading"})
                    ~> (phase \in {"done", "retry"}))
BoardEventuallyLoads == <>boardLoaded
Spec == Init /\ [][Next]_vars /\ Fairness
=============================================================================
