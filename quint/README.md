# Quint Formal Verification & Model-Based Testing (MBT)

Formal specifications and model-based test drivers for `meta-mesh` concurrent and distributed replication subsystems using [Quint](https://quint-lang.org/) (`@informalsystems/quint`).

## Modeled Subsystems

1. **Durable Replica Delivery with Route Racing & Retries** (`quint/durable_delivery.qnt`)
   - **Production Subsystem**: [`packages/mesh-replication/src/protocol.ts`](../packages/mesh-replication/src/protocol.ts) (`deliverBatchToDevice`, `deliverBatchRound`, `ackMatches`).
   - **Scope**: Happy-eyeballs concurrent route racing across browser instances, fallback delays, losing route aborts (`AbortController`), retry rounds with backoff, idempotent durable storage, and cryptographic commit acknowledgement verification.
   - **Invariants**:
     - `invDeliveryRequiresAck`: Delivery settles as `DELIVERED` if and only if a valid ACK containing all batch change hashes is received.
     - `invAckRequiresTargetCommit`: Accepted ACK guarantees the durable target replica committed all batch changes.
     - `invSettledHasNoActiveRoutes`: Once settled (`DELIVERED` or `FAILED`), all in-flight sibling route attempts are cancelled.
     - `invWinningRouteAttempted`: Winning route was legitimately dialed and attempted.
     - `invRetryBounds`: Retry count strictly adheres to configured retry limits.

2. **Sparse Scoped Gossip & Convergence** (`quint/sparse_gossip.qnt`)
   - **Production Subsystem**: [`packages/mesh-replication/src/gossip.ts`](../packages/mesh-replication/src/gossip.ts) (`SparseGossip`, `selectScopedNeighbors`).
   - **Scope**: Ring-based neighbor selection, 3-step gossip exchange (`offer` -> `want` -> `changes`), bounded eager fanout, LRU seen cache deduplication, and failure backoff repair.
   - **Invariants**:
     - `invStoreSafety`: Any change held by any device is a subset of valid published changes.
     - `invStoreInSeen`: Admitted changes are recorded in the seen cache, preventing echo loops.
     - `invNoSeenReAdmission`: Hashes in the seen cache are never re-admitted or forwarded.

---

## Fast Checks (PR / Local)

Fast checks run in seconds without requiring Java:

```bash
# 1. Typecheck Quint specifications
npm run quint:check

# 2. Run Quint unit tests
npm run quint:test

# 3. Fast randomized simulation & invariant checking (1,000 samples, 20 steps)
npm run quint:run

# 4. Model-based tests (replay traces through production TypeScript)
npm run quint:mbt

# Or run everything together with the standard test suite:
npm test
```

---

## Deep Verification (State-Space Exploration)

Deep verification uses the [Apalache](https://apalache-mc.org/) symbolic model checker via Quint to exhaustively explore the state space. Requires Java (JDK 21):

```bash
# Apalache symbolic model checking for Durable Delivery
npx quint verify quint/durable_delivery.qnt --main=durable_delivery_instance --invariants=invAll --max-steps=15

# Apalache symbolic model checking for Sparse Gossip
npx quint verify quint/sparse_gossip.qnt --main=sparse_gossip_instance --invariants=invAll --max-steps=15

# Deep randomized simulation fuzzing (10,000 samples each)
npx quint run quint/durable_delivery.qnt --main=durable_delivery_instance --invariants=invAll --max-samples=10000 --max-steps=50
npx quint run quint/sparse_gossip.qnt --main=sparse_gossip_instance --invariants=invAll --max-samples=10000 --max-steps=50
```

GitHub Actions automatically runs fast checks and MBT on PRs and pushes to `main` and `codex/quint-mbt` in `.github/workflows/ci.yml`, and deep verification on pushes to `main` and `codex/quint-mbt`, weekly schedule, and `workflow_dispatch` in `.github/workflows/quint-deep-verify.yml`.

---

## Discrepancies Discovered & Fixed

During model-to-implementation comparison, two discrepancies between production TypeScript and intended formal semantics were discovered and fixed:

1. **Gossip Publish Seen Cache Omission**:
   - **File**: [`packages/mesh-replication/src/gossip.ts`](../packages/mesh-replication/src/gossip.ts)
   - **Issue**: `SparseGossip.publish` did not record published hashes in `this.seen`. When a peer echoed a change back, `receive("changes")` treated it as fresh, re-invoking `admitChanges` and re-broadcasting to other neighbors in an amplified loop.
   - **Counterexample**: [`quint/counterexamples/sparse_gossip_publish_seen_counterexample.json`](counterexamples/sparse_gossip_publish_seen_counterexample.json)
   - **Fix**: Added `for (const hash of bounded) this.remember(...)` in `publish`.

2. **Durable Delivery Incomplete ACK Acceptance**:
   - **File**: [`packages/mesh-replication/src/protocol.ts`](../packages/mesh-replication/src/protocol.ts)
   - **Issue**: `ackMatches` checked `ack.acceptedHashes.length <= expected.size`. An ACK with empty `acceptedHashes: []` or duplicates like `["c1", "c1"]` (missing `"c2"`) was accepted as a complete batch delivery.
   - **Counterexample**: [`quint/counterexamples/durable_delivery_empty_ack_counterexample.json`](counterexamples/durable_delivery_empty_ack_counterexample.json)
   - **Fix**: Enforced that `ack.acceptedHashes` must uniquely and completely match `expected.size`.

---

## Trace Fixtures

ITF (Informal Trace Format) traces are located in [`quint/traces/`](traces/):
- `durable_delivery_happy.itf.json`
- `durable_delivery_route_switch.itf.json`
- `durable_delivery_retry_after_lost_ack.itf.json`
- `durable_delivery_mbt.itf.json`
- `sparse_gossip_propagate.itf.json`
- `sparse_gossip_dedup.itf.json`
- `sparse_gossip_failure_healing.itf.json`
EOF
