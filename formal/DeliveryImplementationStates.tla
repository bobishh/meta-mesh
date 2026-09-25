---------------------- MODULE DeliveryImplementationStates -----------------
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS Routes, RoundArguments, RouteArguments, RetryLimit

ASSUME /\ Routes = 0..1
       /\ RoundArguments = 0..2
       /\ RouteArguments = 0..2
       /\ RetryLimit = 1

VARIABLES state, retryIndex, round, nextRoute, pending, fallbackArmed,
          attempted, failures, lastActions, parity

vars == <<state, retryIndex, round, nextRoute, pending, fallbackArmed,
          attempted, failures, lastActions, parity>>

Init ==
  /\ state = "Ready"
  /\ retryIndex = 0
  /\ round = 0
  /\ nextRoute = 0
  /\ pending = {}
  /\ fallbackArmed = FALSE
  /\ attempted = <<>>
  /\ failures = <<>>
  /\ lastActions = <<>>
  /\ parity = 0

Touch == parity' = 1 - parity

Start ==
  /\ state = "Ready"
  /\ state' = "Running"
  /\ nextRoute' = 1
  /\ pending' = {0}
  /\ fallbackArmed' = TRUE
  /\ attempted' = <<0>>
  /\ lastActions' = <<<<"Launch", 0, 0>>, <<"ArmFallback", 0>>>>
  /\ UNCHANGED <<retryIndex, round, failures>>
  /\ Touch

FallbackElapsed(argument) ==
  /\ argument \in RoundArguments
  /\ IF /\ state = "Running"
         /\ argument = round
         /\ fallbackArmed
        THEN /\ fallbackArmed' = FALSE
             /\ IF nextRoute < Cardinality(Routes)
                   THEN /\ pending' = pending \cup {nextRoute}
                        /\ attempted' = Append(attempted, nextRoute)
                        /\ nextRoute' = nextRoute + 1
                        /\ lastActions' = <<<<"Launch", round, nextRoute>>>>
                   ELSE /\ UNCHANGED <<pending, attempted, nextRoute>>
                        /\ lastActions' = <<>>
        ELSE /\ UNCHANGED <<fallbackArmed, pending, attempted, nextRoute>>
             /\ lastActions' = <<>>
  /\ UNCHANGED <<state, retryIndex, round, failures>>
  /\ Touch

RouteAccepted(argumentRound, routeIndex) ==
  /\ argumentRound \in RoundArguments
  /\ routeIndex \in RouteArguments
  /\ IF /\ state = "Running"
         /\ argumentRound = round
         /\ routeIndex \in pending
        THEN /\ state' = "Complete"
             /\ pending' = pending \ {routeIndex}
             /\ lastActions' =
                  <<<<"CancelOther", round, routeIndex>>,
                    <<"Completed", round, routeIndex, attempted>>>>
        ELSE /\ UNCHANGED <<state, pending>>
             /\ lastActions' = <<>>
  /\ UNCHANGED <<retryIndex, round, nextRoute, fallbackArmed,
                  attempted, failures>>
  /\ Touch

RouteRejected(argumentRound, routeIndex) ==
  /\ argumentRound \in RoundArguments
  /\ routeIndex \in RouteArguments
  /\ IF /\ state = "Running"
         /\ argumentRound = round
         /\ routeIndex \in pending
        THEN LET remaining == pending \ {routeIndex}
                 failed == Append(failures, routeIndex)
             IN /\ failures' = failed
                /\ IF nextRoute < Cardinality(Routes)
                      THEN /\ pending' = remaining \cup {nextRoute}
                           /\ attempted' = Append(attempted, nextRoute)
                           /\ nextRoute' = nextRoute + 1
                           /\ lastActions' = <<<<"Launch", round, nextRoute>>>>
                           /\ UNCHANGED <<state, retryIndex>>
                      ELSE /\ UNCHANGED <<attempted, nextRoute>>
                           /\ IF remaining # {}
                                 THEN /\ pending' = remaining
                                      /\ lastActions' = <<>>
                                      /\ UNCHANGED <<state, retryIndex>>
                                 ELSE IF retryIndex < RetryLimit
                                   THEN /\ pending' = {}
                                        /\ retryIndex' = retryIndex + 1
                                        /\ state' = "WaitingRetry"
                                        /\ lastActions' = <<<<"ArmRetry", round>>>>
                                   ELSE /\ pending' = {}
                                        /\ state' = "Failed"
                                        /\ lastActions' =
                                             <<<<"Exhausted", attempted, failed>>>>
                                        /\ UNCHANGED retryIndex
        ELSE /\ UNCHANGED <<state, retryIndex, nextRoute, pending,
                            attempted, failures>>
             /\ lastActions' = <<>>
  /\ UNCHANGED <<round, fallbackArmed>>
  /\ Touch

RetryElapsed(argument) ==
  /\ argument \in RoundArguments
  /\ IF /\ state = "WaitingRetry"
         /\ argument = round
        THEN /\ state' = "Running"
             /\ round' = round + 1
             /\ nextRoute' = 1
             /\ pending' = {0}
             /\ fallbackArmed' = TRUE
             /\ attempted' = Append(attempted, 0)
             /\ lastActions' =
                  <<<<"Launch", round + 1, 0>>, <<"ArmFallback", round + 1>>>>
        ELSE /\ UNCHANGED <<state, round, nextRoute, pending,
                            fallbackArmed, attempted>>
             /\ lastActions' = <<>>
  /\ UNCHANGED <<retryIndex, failures>>
  /\ Touch

Abort ==
  /\ IF state \in {"Complete", "Failed", "Aborted"}
        THEN /\ UNCHANGED state
             /\ lastActions' = <<>>
        ELSE /\ state' = "Aborted"
             /\ lastActions' = <<<<"CancelAll", round>>, <<"Aborted">>>>
  /\ UNCHANGED <<retryIndex, round, nextRoute, pending, fallbackArmed,
                  attempted, failures>>
  /\ Touch

Next ==
  \/ Start
  \/ \E argument \in RoundArguments : FallbackElapsed(argument)
  \/ \E argument \in RoundArguments : RetryElapsed(argument)
  \/ \E argumentRound \in RoundArguments, routeIndex \in RouteArguments :
       RouteAccepted(argumentRound, routeIndex)
  \/ \E argumentRound \in RoundArguments, routeIndex \in RouteArguments :
       RouteRejected(argumentRound, routeIndex)
  \/ Abort

TypeOK ==
  /\ state \in {"Ready", "Running", "WaitingRetry", "Complete", "Failed", "Aborted"}
  /\ retryIndex \in 0..RetryLimit
  /\ round \in 0..RetryLimit
  /\ nextRoute \in 0..Cardinality(Routes)
  /\ pending \subseteq Routes
  /\ fallbackArmed \in BOOLEAN
  /\ \A item \in DOMAIN attempted : attempted[item] \in Routes
  /\ \A item \in DOMAIN failures : failures[item] \in Routes
  /\ parity \in {0, 1}

TerminalStatesDoNotRestart ==
  state = "Failed" => nextRoute = Cardinality(Routes)

Safety == TypeOK /\ TerminalStatesDoNotRestart

Spec == Init /\ [][Next]_vars

\* A bounded recovery scenario starts after the first round failed and its only
\* retry is armed. Once recovery begins, route failures and abort are excluded;
\* weak fairness requires the host to service the current retry timer and then
\* a pending successful result. This says nothing about arbitrary outage length
\* or recovery after the finite retry budget has already been exhausted.
RecoveryInit ==
  /\ state = "WaitingRetry"
  /\ retryIndex = RetryLimit
  /\ round = 0
  /\ nextRoute = Cardinality(Routes)
  /\ pending = {}
  /\ fallbackArmed = TRUE
  /\ attempted = <<0, 1>>
  /\ failures = <<0, 1>>
  /\ lastActions = <<<<"ArmRetry", 0>>>>
  /\ parity = 0

CurrentRetry == RetryElapsed(round)
CurrentFallback == FallbackElapsed(round)
CurrentSuccess == \E routeIndex \in Routes : RouteAccepted(round, routeIndex)

RecoveryNext == CurrentRetry \/ CurrentFallback \/ CurrentSuccess

RecoverySpec ==
  /\ RecoveryInit
  /\ [][RecoveryNext]_vars
  /\ WF_vars(CurrentRetry)
  /\ WF_vars(CurrentFallback)
  /\ WF_vars(CurrentSuccess)

EventuallyComplete == <> (state = "Complete")

=============================================================================
