// -*- mode: Bluespec; -*-
// Formal specification of Durable Replica Delivery with Route Racing & Retries
// Subsystem: packages/mesh-replication/src/protocol.ts (deliverBatchToDevice)

module durable_delivery {
  // Routes available for the target durable replica
  const ROUTES: Set[str]
  // Change hashes in the batch to deliver
  const BATCH_HASHES: Set[str]
  // Maximum retry rounds allowed
  const MAX_RETRIES: int

  // Delivery phase
  var phase: str // "RUNNING" | "DELIVERED" | "FAILED"
  // Current retry round (0 .. MAX_RETRIES)
  var currentRound: int
  // Set of routes attempted across all rounds
  var attemptedRoutes: Set[str]
  // Routes launched in the current round
  var roundAttemptedRoutes: Set[str]
  // Currently in-flight routes in the current round
  var activeRoutes: Set[str]
  // Committed hashes in durable storage at the target device
  var targetStore: Set[str]
  // Number of times target storage admitted this batch (testing idempotence)
  var targetAdmissions: int
  // Instance ID of the route that returned the winning valid ACK
  var winningRoute: str
  // Accepted hashes reported in the winning ACK
  var lastAckAcceptedHashes: Set[str]

  action init = all {
    phase' = "RUNNING",
    currentRound' = 0,
    attemptedRoutes' = Set(),
    roundAttemptedRoutes' = Set(),
    activeRoutes' = Set(),
    targetStore' = Set(),
    targetAdmissions' = 0,
    winningRoute' = "none",
    lastAckAcceptedHashes' = Set(),
  }

  // Launch the next candidate route (happy-eyeballs / fallback / retry)
  action launchRoute(r: str): bool = all {
    phase == "RUNNING",
    ROUTES.contains(r),
    not(roundAttemptedRoutes.contains(r)),
    phase' = phase,
    currentRound' = currentRound,
    attemptedRoutes' = attemptedRoutes.union(Set(r)),
    roundAttemptedRoutes' = roundAttemptedRoutes.union(Set(r)),
    activeRoutes' = activeRoutes.union(Set(r)),
    targetStore' = targetStore,
    targetAdmissions' = targetAdmissions,
    winningRoute' = winningRoute,
    lastAckAcceptedHashes' = lastAckAcceptedHashes,
  }

  // Route commits batch at target device and successfully returns valid ACK
  action routeCommitAndAck(r: str): bool = all {
    phase == "RUNNING",
    activeRoutes.contains(r),
    phase' = "DELIVERED",
    currentRound' = currentRound,
    attemptedRoutes' = attemptedRoutes,
    roundAttemptedRoutes' = roundAttemptedRoutes,
    activeRoutes' = Set(), // Sibling in-flight routes are aborted upon delivery
    targetStore' = targetStore.union(BATCH_HASHES),
    targetAdmissions' = targetAdmissions + 1,
    winningRoute' = r,
    lastAckAcceptedHashes' = BATCH_HASHES,
  }

  // Route commits at target device, but network fails before ACK reaches client
  action routeCommitAndLoseAck(r: str): bool = all {
    phase == "RUNNING",
    activeRoutes.contains(r),
    phase' = phase,
    currentRound' = currentRound,
    attemptedRoutes' = attemptedRoutes,
    roundAttemptedRoutes' = roundAttemptedRoutes,
    activeRoutes' = activeRoutes.exclude(Set(r)),
    targetStore' = targetStore.union(BATCH_HASHES),
    targetAdmissions' = targetAdmissions + 1,
    winningRoute' = winningRoute,
    lastAckAcceptedHashes' = lastAckAcceptedHashes,
  }

  // Route fails before committing at target device (e.g. connection error)
  action routeFailBeforeCommit(r: str): bool = all {
    phase == "RUNNING",
    activeRoutes.contains(r),
    phase' = phase,
    currentRound' = currentRound,
    attemptedRoutes' = attemptedRoutes,
    roundAttemptedRoutes' = roundAttemptedRoutes,
    activeRoutes' = activeRoutes.exclude(Set(r)),
    targetStore' = targetStore,
    targetAdmissions' = targetAdmissions,
    winningRoute' = winningRoute,
    lastAckAcceptedHashes' = lastAckAcceptedHashes,
  }

  // If all routes in current round failed and retries remain, start next round
  action retryRound: bool = all {
    phase == "RUNNING",
    roundAttemptedRoutes == ROUTES,
    activeRoutes == Set(),
    currentRound < MAX_RETRIES,
    phase' = phase,
    currentRound' = currentRound + 1,
    attemptedRoutes' = attemptedRoutes,
    roundAttemptedRoutes' = Set(),
    activeRoutes' = Set(),
    targetStore' = targetStore,
    targetAdmissions' = targetAdmissions,
    winningRoute' = winningRoute,
    lastAckAcceptedHashes' = lastAckAcceptedHashes,
  }

  // If all routes in round failed and no retries remain, delivery fails
  action exhaustRetries: bool = all {
    phase == "RUNNING",
    roundAttemptedRoutes == ROUTES,
    activeRoutes == Set(),
    currentRound >= MAX_RETRIES,
    phase' = "FAILED",
    currentRound' = currentRound,
    attemptedRoutes' = attemptedRoutes,
    roundAttemptedRoutes' = roundAttemptedRoutes,
    activeRoutes' = Set(),
    targetStore' = targetStore,
    targetAdmissions' = targetAdmissions,
    winningRoute' = winningRoute,
    lastAckAcceptedHashes' = lastAckAcceptedHashes,
  }

  action step = any {
    nondet r = ROUTES.oneOf()
    launchRoute(r),
    nondet r = activeRoutes.oneOf()
    routeCommitAndAck(r),
    nondet r = activeRoutes.oneOf()
    routeCommitAndLoseAck(r),
    nondet r = activeRoutes.oneOf()
    routeFailBeforeCommit(r),
    retryRound,
    exhaustRetries,
    // Stutter when settled
    all {
      phase != "RUNNING",
      phase' = phase,
      currentRound' = currentRound,
      attemptedRoutes' = attemptedRoutes,
      roundAttemptedRoutes' = roundAttemptedRoutes,
      activeRoutes' = activeRoutes,
      targetStore' = targetStore,
      targetAdmissions' = targetAdmissions,
      winningRoute' = winningRoute,
      lastAckAcceptedHashes' = lastAckAcceptedHashes,
    },
  }

  // --- Invariants ---

  // 1. A delivery marked DELIVERED must have received a valid ACK with batch hashes
  val invDeliveryRequiresAck =
    (phase == "DELIVERED") implies (winningRoute != "none" and lastAckAcceptedHashes == BATCH_HASHES)

  // 2. An accepted ACK guarantees the target replica committed all batch changes
  val invAckRequiresTargetCommit =
    (phase == "DELIVERED") implies BATCH_HASHES.subseteq(targetStore)

  // 3. Once settled (DELIVERED or FAILED), no in-flight route attempts remain
  val invSettledHasNoActiveRoutes =
    (phase != "RUNNING") implies activeRoutes == Set()

  // 4. The winning route must have been launched and attempted
  val invWinningRouteAttempted =
    (winningRoute != "none") implies attemptedRoutes.contains(winningRoute)

  // 5. Retry bounds are strictly respected
  val invRetryBounds =
    currentRound <= MAX_RETRIES

  // Combined invariant
  val invAll =
    invDeliveryRequiresAck and
    invAckRequiresTargetCommit and
    invSettledHasNoActiveRoutes and
    invWinningRouteAttempted and
    invRetryBounds
}

module durable_delivery_instance {
  import durable_delivery(
    ROUTES = Set("route-a", "route-b", "route-c"),
    BATCH_HASHES = Set("change-1", "change-2"),
    MAX_RETRIES = 2
  ).*

  run happyPathTest = {
    init
      .then(launchRoute("route-a"))
      .then(routeCommitAndAck("route-a"))
      .then(all {
        assert(phase == "DELIVERED"),
        assert(winningRoute == "route-a"),
        assert(targetStore == Set("change-1", "change-2")),
        phase' = phase,
        currentRound' = currentRound,
        attemptedRoutes' = attemptedRoutes,
        roundAttemptedRoutes' = roundAttemptedRoutes,
        activeRoutes' = activeRoutes,
        targetStore' = targetStore,
        targetAdmissions' = targetAdmissions,
        winningRoute' = winningRoute,
        lastAckAcceptedHashes' = lastAckAcceptedHashes,
      })
  }

  run routeSwitchTest = {
    init
      .then(launchRoute("route-a"))
      .then(routeFailBeforeCommit("route-a"))
      .then(launchRoute("route-b"))
      .then(routeCommitAndAck("route-b"))
      .then(all {
        assert(phase == "DELIVERED"),
        assert(winningRoute == "route-b"),
        assert(attemptedRoutes == Set("route-a", "route-b")),
        phase' = phase,
        currentRound' = currentRound,
        attemptedRoutes' = attemptedRoutes,
        roundAttemptedRoutes' = roundAttemptedRoutes,
        activeRoutes' = activeRoutes,
        targetStore' = targetStore,
        targetAdmissions' = targetAdmissions,
        winningRoute' = winningRoute,
        lastAckAcceptedHashes' = lastAckAcceptedHashes,
      })
  }

  run retryAfterLostAckTest = {
    init
      .then(launchRoute("route-a"))
      .then(routeCommitAndLoseAck("route-a"))
      .then(launchRoute("route-b"))
      .then(routeFailBeforeCommit("route-b"))
      .then(launchRoute("route-c"))
      .then(routeFailBeforeCommit("route-c"))
      .then(retryRound)
      .then(launchRoute("route-a"))
      .then(routeCommitAndAck("route-a"))
      .then(all {
        assert(phase == "DELIVERED"),
        assert(currentRound == 1),
        assert(targetAdmissions == 2),
        assert(targetStore == Set("change-1", "change-2")),
        phase' = phase,
        currentRound' = currentRound,
        attemptedRoutes' = attemptedRoutes,
        roundAttemptedRoutes' = roundAttemptedRoutes,
        activeRoutes' = activeRoutes,
        targetStore' = targetStore,
        targetAdmissions' = targetAdmissions,
        winningRoute' = winningRoute,
        lastAckAcceptedHashes' = lastAckAcceptedHashes,
      })
  }
}
