// -*- mode: Bluespec; -*-
// Formal specification of Sparse Scoped Gossip & Rumor Convergence
// Subsystem: packages/mesh-replication/src/gossip.ts (SparseGossip)

module sparse_gossip {
  // Set of participant peer device IDs
  const DEVICES: Set[str]
  // Document ID for gossip scope
  const DOC_ID: str
  // Universe of valid changes that can be published
  const AVAILABLE_CHANGES: Set[str]

  // Frame representation
  type Frame = { fromDevice: str, toDevice: str, hash: str }

  // Durable store of admitted changes per device
  var store: str -> Set[str]
  // LRU / seen cache preventing duplicate admission and amplification
  var seen: str -> Set[str]
  // Currently failing / backed-off devices
  var failed: Set[str]
  // In-flight gossip protocol frames (offer, want, changes)
  var inFlightOffers: Set[Frame]
  var inFlightWants: Set[Frame]
  var inFlightChanges: Set[Frame]

  // Active neighbors for a device (excluding self and failed candidates)
  def activeNeighbors(d: str): Set[str] =
    DEVICES.exclude(Set(d)).exclude(failed)

  action init = all {
    // Device "d1" starts with initial change, others empty
    store' = DEVICES.mapBy(d => if (d == "d1") AVAILABLE_CHANGES else Set()),
    seen' = DEVICES.mapBy(d => if (d == "d1") AVAILABLE_CHANGES else Set()),
    failed' = Set(),
    inFlightOffers' = Set(),
    inFlightWants' = Set(),
    inFlightChanges' = Set(),
  }

  // A device with changes publishes offers to its active neighbors
  action publishOffer(fromDevice: str, hash: str): bool = all {
    not(failed.contains(fromDevice)),
    store.get(fromDevice).contains(hash),
    val targets = activeNeighbors(fromDevice)
    val newOffers = targets.map(toDevice => { fromDevice: fromDevice, toDevice: toDevice, hash: hash })
    all {
      inFlightOffers' = inFlightOffers.union(newOffers),
      store' = store,
      seen' = seen,
      failed' = failed,
      inFlightWants' = inFlightWants,
      inFlightChanges' = inFlightChanges,
    }
  }

  // Receiver processes offer: if hash is missing from store, replies with want
  action handleOffer(msg: Frame): bool = all {
    inFlightOffers.contains(msg),
    inFlightOffers' = inFlightOffers.exclude(Set(msg)),
    if (not(failed.contains(msg.toDevice)) and not(store.get(msg.toDevice).contains(msg.hash))) {
      inFlightWants' = inFlightWants.union(Set({
        fromDevice: msg.toDevice,
        toDevice: msg.fromDevice,
        hash: msg.hash,
      }))
    } else {
      inFlightWants' = inFlightWants
    },
    store' = store,
    seen' = seen,
    failed' = failed,
    inFlightChanges' = inFlightChanges,
  }

  // Receiver processes want: loads change and replies with changes frame
  action handleWant(msg: Frame): bool = all {
    inFlightWants.contains(msg),
    inFlightWants' = inFlightWants.exclude(Set(msg)),
    if (not(failed.contains(msg.toDevice)) and store.get(msg.toDevice).contains(msg.hash)) {
      inFlightChanges' = inFlightChanges.union(Set({
        fromDevice: msg.toDevice,
        toDevice: msg.fromDevice,
        hash: msg.hash,
      }))
    } else {
      inFlightChanges' = inFlightChanges
    },
    store' = store,
    seen' = seen,
    failed' = failed,
    inFlightOffers' = inFlightOffers,
  }

  // Receiver processes changes:
  // - If already in seen cache, ignores (deduplication & loop prevention)
  // - If fresh, admits to store, updates seen, and re-announces offer to other neighbors
  action handleChanges(msg: Frame): bool = all {
    inFlightChanges.contains(msg),
    inFlightChanges' = inFlightChanges.exclude(Set(msg)),
    if (not(failed.contains(msg.toDevice)) and not(seen.get(msg.toDevice).contains(msg.hash))) {
      val freshStore = store.get(msg.toDevice).union(Set(msg.hash))
      val freshSeen = seen.get(msg.toDevice).union(Set(msg.hash))
      val forwardTargets = activeNeighbors(msg.toDevice).exclude(Set(msg.fromDevice))
      val forwardOffers = forwardTargets.map(target => { fromDevice: msg.toDevice, toDevice: target, hash: msg.hash })
      all {
        store' = store.setBy(msg.toDevice, _ => freshStore),
        seen' = seen.setBy(msg.toDevice, _ => freshSeen),
        inFlightOffers' = inFlightOffers.union(forwardOffers),
      }
    } else {
      // Ignored: already seen or receiver failed
      all {
        store' = store,
        seen' = seen,
        inFlightOffers' = inFlightOffers,
      }
    },
    failed' = failed,
    inFlightWants' = inFlightWants,
  }

  // Mark a device failed (simulates backoff / disconnect)
  action markFailed(d: str): bool = all {
    DEVICES.contains(d),
    not(failed.contains(d)),
    failed' = failed.union(Set(d)),
    store' = store,
    seen' = seen,
    inFlightOffers' = inFlightOffers,
    inFlightWants' = inFlightWants,
    inFlightChanges' = inFlightChanges,
  }

  // Recover a device (simulates backoff expiration)
  action recoverDevice(d: str): bool = all {
    failed.contains(d),
    failed' = failed.exclude(Set(d)),
    store' = store,
    seen' = seen,
    inFlightOffers' = inFlightOffers,
    inFlightWants' = inFlightWants,
    inFlightChanges' = inFlightChanges,
  }

  action step = any {
    nondet d = DEVICES.oneOf()
    nondet h = AVAILABLE_CHANGES.oneOf()
    publishOffer(d, h),

    nondet msg = inFlightOffers.oneOf()
    handleOffer(msg),

    nondet msg = inFlightWants.oneOf()
    handleWant(msg),

    nondet msg = inFlightChanges.oneOf()
    handleChanges(msg),

    nondet d = DEVICES.oneOf()
    markFailed(d),

    nondet d = failed.oneOf()
    recoverDevice(d),

    // Stutter when quiescent
    all {
      inFlightOffers == Set(),
      inFlightWants == Set(),
      inFlightChanges == Set(),
      store' = store,
      seen' = seen,
      failed' = failed,
      inFlightOffers' = inFlightOffers,
      inFlightWants' = inFlightWants,
      inFlightChanges' = inFlightChanges,
    },
  }

  // --- Invariants ---

  // 1. Storage safety: Any change held by any device must be in the valid universe
  val invStoreSafety =
    DEVICES.forall(d => store.get(d).subseteq(AVAILABLE_CHANGES))

  // 2. Storage consistency: Admitted changes must be reflected in the seen cache
  val invStoreInSeen =
    DEVICES.forall(d => store.get(d).subseteq(seen.get(d)))

  // 3. Seen cache monotonicity: seen cache contains all local store items
  val invNoSeenReAdmission =
    DEVICES.forall(d => store.get(d).subseteq(seen.get(d)))

  // Combined invariant
  val invAll =
    invStoreSafety and
    invStoreInSeen and
    invNoSeenReAdmission
}

module sparse_gossip_instance {
  import sparse_gossip(
    DEVICES = Set("d1", "d2", "d3"),
    DOC_ID = "doc-1",
    AVAILABLE_CHANGES = Set("c1")
  ).*

  run propagationTest = {
    init
      .then(publishOffer("d1", "c1"))
      .then(handleOffer({ fromDevice: "d1", toDevice: "d2", hash: "c1" }))
      .then(handleWant({ fromDevice: "d2", toDevice: "d1", hash: "c1" }))
      .then(handleChanges({ fromDevice: "d1", toDevice: "d2", hash: "c1" }))
      .then(all {
        assert(store.get("d2").contains("c1")),
        assert(seen.get("d2").contains("c1")),
        store' = store,
        seen' = seen,
        failed' = failed,
        inFlightOffers' = inFlightOffers,
        inFlightWants' = inFlightWants,
        inFlightChanges' = inFlightChanges,
      })
  }

  run seenDeduplicationTest = {
    init
      .then(publishOffer("d1", "c1"))
      .then(handleOffer({ fromDevice: "d1", toDevice: "d2", hash: "c1" }))
      .then(handleWant({ fromDevice: "d2", toDevice: "d1", hash: "c1" }))
      .then(handleChanges({ fromDevice: "d1", toDevice: "d2", hash: "c1" }))
      // Re-delivery of the same changes frame to d2 must be ignored
      .then(all {
        inFlightChanges' = inFlightChanges.union(Set({ fromDevice: "d1", toDevice: "d2", hash: "c1" })),
        store' = store,
        seen' = seen,
        failed' = failed,
        inFlightOffers' = inFlightOffers,
        inFlightWants' = inFlightWants,
      })
      .then(handleChanges({ fromDevice: "d1", toDevice: "d2", hash: "c1" }))
      .then(all {
        assert(store.get("d2") == Set("c1")),
        store' = store,
        seen' = seen,
        failed' = failed,
        inFlightOffers' = inFlightOffers,
        inFlightWants' = inFlightWants,
        inFlightChanges' = inFlightChanges,
      })
  }

  run failureHealingTest = {
    init
      .then(markFailed("d2"))
      .then(publishOffer("d1", "c1"))
      .then(handleOffer({ fromDevice: "d1", toDevice: "d3", hash: "c1" }))
      .then(handleWant({ fromDevice: "d3", toDevice: "d1", hash: "c1" }))
      .then(handleChanges({ fromDevice: "d1", toDevice: "d3", hash: "c1" }))
      .then(recoverDevice("d2"))
      .then(publishOffer("d3", "c1"))
      .then(handleOffer({ fromDevice: "d3", toDevice: "d2", hash: "c1" }))
      .then(handleWant({ fromDevice: "d2", toDevice: "d3", hash: "c1" }))
      .then(handleChanges({ fromDevice: "d3", toDevice: "d2", hash: "c1" }))
      .then(all {
        assert(store.get("d2") == Set("c1")),
        assert(store.get("d3") == Set("c1")),
        store' = store,
        seen' = seen,
        failed' = failed,
        inFlightOffers' = inFlightOffers,
        inFlightWants' = inFlightWants,
        inFlightChanges' = inFlightChanges,
      })
  }
}
