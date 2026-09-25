------------------------- MODULE SessionGenerations --------------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Keys, Generations, CanonicalKey, Mutation

ASSUME /\ Keys # {}
       /\ Generations # {}
       /\ 0 \notin Generations
       /\ CanonicalKey \in Keys
       /\ Mutation \in {"None", "StaleCleanup", "CollapseTabs"}

VARIABLES current, requestedCurrent, registered, open, lastGeneration

vars == <<current, requestedCurrent, registered, open, lastGeneration>>

Init ==
  /\ current = [k \in Keys |-> 0]
  /\ requestedCurrent = [k \in Keys |-> 0]
  /\ registered = {}
  /\ open = {}
  /\ lastGeneration = 0

Register(k, generation) ==
  /\ generation \in Generations
  /\ generation > lastGeneration
  /\ LET storedKey == IF Mutation = "CollapseTabs" THEN CanonicalKey ELSE k
     IN current' = [current EXCEPT ![storedKey] = generation]
  /\ requestedCurrent' = [requestedCurrent EXCEPT ![k] = generation]
  /\ registered' = registered \cup {<<k, generation>>}
  /\ open' = open \cup {<<k, generation>>}
  /\ lastGeneration' = generation

\* Only cleanup callbacks for replaced generations are modeled here. The
\* callback may close that old transport, but may not remove the newer one.
CleanupOlder(k, generation) ==
  /\ <<k, generation>> \in registered
  /\ generation < current[k]
  /\ IF Mutation = "StaleCleanup"
        THEN /\ open' = open \ {<<k, generation>>, <<k, current[k]>>}
             /\ current' = [current EXCEPT ![k] = 0]
        ELSE /\ open' = open \ {<<k, generation>>}
             /\ UNCHANGED current
  /\ UNCHANGED <<requestedCurrent, registered, lastGeneration>>

Next ==
  \/ \E k \in Keys, generation \in Generations : Register(k, generation)
  \/ \E k \in Keys, generation \in Generations : CleanupOlder(k, generation)

TypeOK ==
  /\ current \in [Keys -> Generations \cup {0}]
  /\ requestedCurrent \in [Keys -> Generations \cup {0}]
  /\ registered \subseteq (Keys \X Generations)
  /\ open \subseteq registered
  /\ lastGeneration \in Generations \cup {0}

CurrentIsNewestRegistered ==
  \A k \in Keys :
    /\ (requestedCurrent[k] = 0) = (~\E generation \in Generations : <<k, generation>> \in registered)
    /\ \A generation \in Generations :
         <<k, generation>> \in registered => generation <= requestedCurrent[k]

CurrentTransportIsOpen ==
  \A k \in Keys : current[k] # 0 => <<k, current[k]>> \in open

\* Because each browser instance is a distinct key, installing or cleaning up
\* one tab cannot alias another tab's current generation.
IndependentTabsRetainTheirRequestedSessions ==
  \A k \in Keys :
    requestedCurrent[k] # 0 =>
      /\ current[k] = requestedCurrent[k]
      /\ <<k, requestedCurrent[k]>> \in open

Safety == TypeOK /\ CurrentIsNewestRegistered /\ CurrentTransportIsOpen
          /\ IndependentTabsRetainTheirRequestedSessions

Spec == Init /\ [][Next]_vars

=============================================================================
