---------------------- MODULE SessionImplementationStates -------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Keys, Generations

ASSUME /\ Keys # {}
       /\ Generations # {}
       /\ 0 \notin Generations

VARIABLES current, requestedCurrent, registered, open, stable,
          failureReported, recoveryPublished, lastGeneration, parity

vars == <<current, requestedCurrent, registered, open, stable,
          failureReported, recoveryPublished, lastGeneration, parity>>

Init ==
  /\ current = [k \in Keys |-> 0]
  /\ requestedCurrent = [k \in Keys |-> 0]
  /\ registered = {}
  /\ open = {}
  /\ stable = {}
  /\ failureReported = {}
  /\ recoveryPublished = {}
  /\ lastGeneration = 0
  /\ parity = 0

\* Toggle a model-only bit so every callback, including a repeated no-op,
\* appears as a labeled edge in TLC's exported graph.
Touch == parity' = 1 - parity

Register(k, generation) ==
  /\ generation \in Generations
  /\ generation = lastGeneration + 1
  /\ current' = [current EXCEPT ![k] = generation]
  /\ requestedCurrent' = [requestedCurrent EXCEPT ![k] = generation]
  /\ registered' = registered \cup {<<k, generation>>}
  /\ open' = open \cup {<<k, generation>>}
  /\ lastGeneration' = generation
  /\ UNCHANGED <<stable, failureReported, recoveryPublished>>
  /\ Touch

CleanupOlder(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ generation < current[k]
  /\ open' = open \ {<<k, generation>>}
  /\ UNCHANGED current
  /\ UNCHANGED <<requestedCurrent, registered, stable,
                  failureReported, recoveryPublished, lastGeneration>>
  /\ Touch

Recovery(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ IF /\ current[k] = generation
         /\ <<k, generation>> \in open
        THEN recoveryPublished' = recoveryPublished \cup {<<k, generation>>}
        ELSE UNCHANGED recoveryPublished
  /\ UNCHANGED <<current, requestedCurrent, registered, open, stable,
                  failureReported, lastGeneration>>
  /\ Touch

StableEarly(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ UNCHANGED <<current, requestedCurrent, registered, open, stable,
                  failureReported, recoveryPublished, lastGeneration>>
  /\ Touch

StableDue(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ IF /\ current[k] = generation
         /\ <<k, generation>> \in open
        THEN stable' = stable \cup {<<k, generation>>}
        ELSE UNCHANGED stable
  /\ UNCHANGED <<current, requestedCurrent, registered, open,
                  failureReported, recoveryPublished, lastGeneration>>
  /\ Touch

HeartbeatFailed(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ IF /\ current[k] = generation
         /\ <<k, generation>> \in open
         /\ <<k, generation>> \notin failureReported
        THEN /\ current' = [current EXCEPT ![k] = 0]
             /\ open' = open \ {<<k, generation>>}
             /\ failureReported' = failureReported \cup {<<k, generation>>}
        ELSE /\ UNCHANGED current
             /\ UNCHANGED open
             /\ UNCHANGED failureReported
  /\ UNCHANGED <<requestedCurrent, registered, stable,
                  recoveryPublished, lastGeneration>>
  /\ Touch

ReceiveSucceeded(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ IF <<k, generation>> \in open
        THEN /\ open' = open \ {<<k, generation>>}
             /\ current' = IF current[k] = generation
                              THEN [current EXCEPT ![k] = 0]
                              ELSE current
        ELSE /\ UNCHANGED open
             /\ UNCHANGED current
  /\ UNCHANGED <<requestedCurrent, registered, stable,
                  failureReported, recoveryPublished, lastGeneration>>
  /\ Touch

ReceiveFailed(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ IF <<k, generation>> \in open
        THEN /\ open' = open \ {<<k, generation>>}
             /\ current' = IF current[k] = generation
                              THEN [current EXCEPT ![k] = 0]
                              ELSE current
             /\ failureReported' = IF current[k] = generation
                                      THEN failureReported \cup {<<k, generation>>}
                                      ELSE failureReported
        ELSE /\ UNCHANGED open
             /\ UNCHANGED current
             /\ UNCHANGED failureReported
  /\ UNCHANGED <<requestedCurrent, registered, stable,
                  recoveryPublished, lastGeneration>>
  /\ Touch

Next ==
  \/ \E k \in Keys, generation \in Generations : Register(k, generation)
  \/ \E k \in Keys, generation \in Generations : CleanupOlder(k, generation)
  \/ \E k \in Keys, generation \in Generations : Recovery(k, generation)
  \/ \E k \in Keys, generation \in Generations : StableEarly(k, generation)
  \/ \E k \in Keys, generation \in Generations : StableDue(k, generation)
  \/ \E k \in Keys, generation \in Generations : HeartbeatFailed(k, generation)
  \/ \E k \in Keys, generation \in Generations : ReceiveSucceeded(k, generation)
  \/ \E k \in Keys, generation \in Generations : ReceiveFailed(k, generation)

TypeOK ==
  /\ current \in [Keys -> Generations \cup {0}]
  /\ requestedCurrent \in [Keys -> Generations \cup {0}]
  /\ registered \subseteq (Keys \X Generations)
  /\ open \subseteq registered
  /\ stable \subseteq registered
  /\ failureReported \subseteq registered
  /\ recoveryPublished \subseteq registered
  /\ lastGeneration \in Generations \cup {0}
  /\ parity \in {0, 1}

CurrentIsNewestRegistered ==
  \A k \in Keys :
    /\ (requestedCurrent[k] = 0) =
         (~\E generation \in Generations : <<k, generation>> \in registered)
    /\ \A generation \in Generations :
         <<k, generation>> \in registered => generation <= requestedCurrent[k]

CurrentTransportIsOpen ==
  \A k \in Keys : current[k] # 0 => <<k, current[k]>> \in open

IndependentTabsRetainTheirRequestedSessions ==
  \A k \in Keys :
    requestedCurrent[k] # 0 =>
      /\ current[k] \in {0, requestedCurrent[k]}
      /\ (current[k] = requestedCurrent[k]) =
           (<<k, requestedCurrent[k]>> \in open)

Safety == TypeOK /\ CurrentIsNewestRegistered /\ CurrentTransportIsOpen
          /\ IndependentTabsRetainTheirRequestedSessions

Spec == Init /\ [][Next]_vars

=============================================================================
