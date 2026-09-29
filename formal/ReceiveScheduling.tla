---------------------- MODULE ReceiveScheduling ----------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS MaxHandlers, DeadlineSteps, Mutation

ASSUME /\ MaxHandlers = 2
       /\ DeadlineSteps = 2
       /\ Mutation \in {"None", "HeartbeatBehindPersistence", "AckBeforePersistence"}

Frames == {"document", "wrongHeartbeat", "heartbeat"}

VARIABLES now, deadline, accepted, documentPersisting, persistenceBlocked,
          persisted, heartbeatAcked, durableAcked, timedOut

vars == <<now, deadline, accepted, documentPersisting, persistenceBlocked,
           persisted, heartbeatAcked, durableAcked, timedOut>>

Init ==
  /\ now = 0
  /\ deadline = -1
  /\ accepted = {}
  /\ documentPersisting = FALSE
  /\ persistenceBlocked = TRUE
  /\ persisted = FALSE
  /\ heartbeatAcked = FALSE
  /\ durableAcked = FALSE
  /\ timedOut = FALSE

Accept(frame) ==
  /\ frame \in Frames
  /\ frame \notin accepted
  /\ Cardinality(accepted) < MaxHandlers
  /\ accepted' = accepted \cup {frame}
  /\ IF frame = "heartbeat"
        THEN deadline' = now + DeadlineSteps
        ELSE UNCHANGED deadline
  /\ UNCHANGED <<now, documentPersisting, persistenceBlocked, persisted,
                heartbeatAcked, durableAcked, timedOut>>

BeginPersistence ==
  /\ "document" \in accepted
  /\ ~documentPersisting
  /\ documentPersisting' = TRUE
  /\ UNCHANGED <<now, deadline, accepted, persistenceBlocked, persisted,
                heartbeatAcked, durableAcked, timedOut>>

RecoverStorage ==
  /\ persistenceBlocked
  /\ persistenceBlocked' = FALSE
  /\ UNCHANGED <<now, deadline, accepted, documentPersisting, persisted,
                heartbeatAcked, durableAcked, timedOut>>

PersistDocument ==
  /\ documentPersisting
  /\ ~persistenceBlocked
  /\ persisted' = TRUE
  /\ documentPersisting' = FALSE
  /\ accepted' = accepted \ {"document"}
  /\ UNCHANGED <<now, deadline, persistenceBlocked, heartbeatAcked,
                durableAcked, timedOut>>

HeartbeatAck ==
  /\ "heartbeat" \in accepted
  /\ ~heartbeatAcked
  /\ IF Mutation = "HeartbeatBehindPersistence" THEN persisted ELSE TRUE
  /\ heartbeatAcked' = TRUE
  /\ accepted' = accepted \ {"heartbeat"}
  /\ UNCHANGED <<now, deadline, documentPersisting, persistenceBlocked,
                persisted, durableAcked, timedOut>>

RejectWrongHeartbeat ==
  /\ "wrongHeartbeat" \in accepted
  /\ accepted' = accepted \ {"wrongHeartbeat"}
  /\ UNCHANGED <<now, deadline, documentPersisting, persistenceBlocked,
                persisted, heartbeatAcked, durableAcked, timedOut>>

DurableAck ==
  /\ "document" \in accepted
  /\ IF Mutation = "AckBeforePersistence" THEN TRUE ELSE persisted
  /\ durableAcked' = TRUE
  /\ accepted' = accepted \ {"document"}
  /\ UNCHANGED <<now, deadline, documentPersisting, persistenceBlocked,
                persisted, heartbeatAcked, timedOut>>

Tick ==
  /\ now < DeadlineSteps
  /\ now' = now + 1
  /\ UNCHANGED <<deadline, accepted, documentPersisting, persistenceBlocked,
                persisted, heartbeatAcked, durableAcked, timedOut>>

ExpireHeartbeat ==
  /\ "heartbeat" \in accepted
  /\ ~heartbeatAcked
  /\ deadline # -1
  /\ now = deadline
  /\ ~ENABLED HeartbeatAck
  /\ timedOut' = TRUE
  /\ UNCHANGED <<now, deadline, accepted, documentPersisting,
                persistenceBlocked, persisted, heartbeatAcked, durableAcked>>

Next ==
  \/ \E frame \in Frames : Accept(frame)
  \/ BeginPersistence
  \/ RecoverStorage
  \/ PersistDocument
  \/ HeartbeatAck
  \/ RejectWrongHeartbeat
  \/ DurableAck
  \/ Tick
  \/ ExpireHeartbeat

TypeOK ==
  /\ now \in 0..DeadlineSteps
  /\ deadline \in {-1} \cup DeadlineSteps..(2 * DeadlineSteps)
  /\ accepted \subseteq Frames
  /\ Cardinality(accepted) <= MaxHandlers
  /\ documentPersisting \in BOOLEAN
  /\ persistenceBlocked \in BOOLEAN
  /\ persisted \in BOOLEAN
  /\ heartbeatAcked \in BOOLEAN
  /\ durableAcked \in BOOLEAN
  /\ timedOut \in BOOLEAN

DurableAckRequiresPersistence == durableAcked => persisted

HeartbeatHandlerDoesNotWaitForStorage ==
  ("heartbeat" \in accepted /\ ~heartbeatAcked) => ENABLED HeartbeatAck

NoLivenessTimeoutWhileHandlerIsServiceable ==
  timedOut => ~("heartbeat" \in accepted /\ ~heartbeatAcked)

Safety == TypeOK /\ DurableAckRequiresPersistence
          /\ HeartbeatHandlerDoesNotWaitForStorage
          /\ NoLivenessTimeoutWhileHandlerIsServiceable

Fairness == WF_vars(HeartbeatAck)

HeartbeatEventuallyAcknowledged ==
  [](("heartbeat" \in accepted /\ ~heartbeatAcked) ~> heartbeatAcked)

Spec == Init /\ [][Next]_vars /\ Fairness

=======================================================================
