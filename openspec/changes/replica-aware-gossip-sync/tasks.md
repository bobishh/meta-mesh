## 1. Baseline and protocol fixtures

- [x] 1.1 Record clean `test` and `check` baselines for canonical meta-mesh, Match, and Twang; inventory current multi-tab, reconnect, incremental-sync, storage-failure, and partition coverage.
- [x] 1.2 Add deterministic in-memory fixtures for people, device replicas, multiple instance routes, authorized documents, Iroh-like route failures, durable stores, and controllable clocks/randomness.
- [x] 1.3 Add failing Given/When/Then core scenarios for one delivery across several routes, durable-ack loss, route replacement, bounded neighbors, missed gossip, and partition healing before implementation.

## 2. Shared device route catalog

- [x] 2.1 Add transport-neutral versioned signed device-route types, canonical validation, `ReplicaId = DeviceId` semantics, monotonic per-instance sequence, expiry, and structural limits.
- [x] 2.2 Refactor `mesh-peer-store` to expose device replicas with route collections keyed by instance; remove wall-clock authority from route dominance while retaining backward-compatible record reads.
- [x] 2.3 Add legacy route adapters that preserve valid workspace advertisements and Twang contact cards as synthetic instances without changing identities, devices, grants, or endpoints.
- [x] 2.4 Verify two tabs coexist, one instance refresh cannot erase siblings, stale sequences cannot dominate, expired routes do not revoke membership, and malformed signatures publish nothing.

## 3. Durable browser replica storage and local fan-out

- [x] 3.1 Extend `mesh-browser-store` with immutable document changes keyed by document/change hash, verified metadata, explicit-head snapshots, and atomic idempotent batch admission.
- [x] 3.2 Add short IndexedDB outbox claims scoped by document, target device, and batch; ensure claim expiry permits takeover without a long-lived tab leader.
- [x] 3.3 Add a browser replica invalidation adapter using `BroadcastChannel` plus focus/head reconciliation; notification payloads remain non-authoritative.
- [x] 3.4 Verify concurrent tabs retain both Automerge branches, commit-before-ack ordering, crash before/after commit, duplicate admission, lost local notification, and safe snapshot reopen.

## 4. Device-scoped delivery and acknowledgement

- [x] 4.1 Add shared device delivery interfaces that group candidate routes, rank transient health, race/fallback without shared endpoint identity, and complete on the first valid durable acknowledgement.
- [x] 4.2 Add bounded device-signed batch acknowledgements binding scope, document, batch, receiver device, and accepted heads or hashes.
- [x] 4.3 Add retry/backoff and cancellation semantics where losing route attempts may complete safely and route failure never mutates durable membership.
- [x] 4.4 Verify preferred-route failure, concurrent successful routes, lost acknowledgement, unauthorized admission, all-routes-offline recovery, and distinct-device replication evidence.

## 5. Incremental Automerge anti-entropy

- [x] 5.1 Add a document adapter contract for authorization, current heads, candidate validation, durable change admission, snapshots, and publication callbacks.
- [x] 5.2 Implement per-document/per-remote-device native Automerge sync sessions with bounded framing, restartable state, route switching, proof exchange hooks, and backpressure.
- [x] 5.3 Trigger synchronization after local commit, accepted remote change, connection establishment, scope discovery, and scheduled repair; stop rounds when neither side produces another sync message.
- [x] 5.4 Verify initial bootstrap, one-change incremental bytes, disposable sync-state restart, duplicated/delayed frames, missing dependencies, oversize rejection, and equal heads after concurrent partitions.

## 6. Sparse scoped gossip

- [x] 6.1 Implement deterministic and injectable neighbor selection by device replica with configurable low/target/high bounds, health-aware replacement, rotation, and backoff.
- [x] 6.2 Implement bounded eager change offers, wants, forwarding, seen-cache deduplication, and per-scope authorization over a multiplexed authenticated connection pool.
- [x] 6.3 Connect gossip scheduling to short local outbox claims so sibling tabs remain independently reachable while duplicate outbound work stays bounded.
- [x] 6.4 Add deterministic simulations for 3, 10, and 100 devices covering convergence rounds, connection degree, duplicate rate, partitions, bridge recovery, sleeping devices, and several routes per device; select measured defaults.
- [x] 6.5 Verify malformed, unauthorized, oversized, repeated, and amplification-prone gossip cannot advance trusted heads or exceed configured queues.

## 7. Match integration

- [x] 7.1 Add outer real-route Playwright scenarios first: multiple tabs of one device appear as one member/device, one route can receive a workspace update, and a failed/pending durable write never appears delivered.
- [x] 7.2 Adapt Match signed advertisements and peer storage to the shared route catalog while preserving workspace grants, ownership transfers, succession, and existing IndexedDB data.
- [x] 7.3 Replace per-instance replication sessions and application reconnect/topology policy with shared device delivery, Automerge anti-entropy, and scoped gossip.
- [x] 7.4 Remove superseded Match-specific lifecycle and replication code; derive connection/delivery UI from shared aggregate state and retain route-level diagnostics.
- [x] 7.5 Verify live card movement, reconnect after closing arbitrary tabs, offline edit partition healing, owner/editor/visitor admission, storage failure, and mobile status on real routes.

## 8. Twang integration

- [x] 8.1 Add outer real-route Playwright scenarios first: two tabs retain separate endpoints under one contact device, either tab can receive one message delivery, sibling UI refreshes locally, and failure remains pending.
- [x] 8.2 Introduce Twang contact-route v2 with instance, sequence, and expiry; migrate legacy contact cards and preserve several routes per contact device.
- [x] 8.3 Replace complete room-byte overwrites with immutable Automerge change storage, explicit snapshots, and shared local invalidation.
- [x] 8.4 Replace four-second full-room/all-endpoint polling with shared device delivery, bounded gossip, and Automerge anti-entropy; keep contact grants, message proofs, call signaling, and blob authorization intact.
- [x] 8.5 Adapt blob provider selection to device routes and durable availability evidence without downloading each blob into every tab.
- [x] 8.6 Verify direct and group messages, duplicate contact migration, reconnect, calls, attachments, concurrent offline messages, partition healing, and one-hundred-member bounded topology.

## 9. Canonical distribution, documentation, and release evidence

- [x] 9.1 Add deterministic vendor sync and equality checks so Match and Twang consume one reviewed canonical meta-mesh package tree and CI rejects drift.
- [x] 9.2 Update meta-mesh README and architecture documentation with identity/device/instance/endpoint boundaries, delivery state machine, gossip topology, anti-entropy flow, browser lifecycle, security limits, and operational traces.
- [x] 9.3 Update Match and Twang operator/user documentation to distinguish connection, presence, durable delivery, convergence, offline limitations, and route diagnostics.
- [x] 9.4 Run strict OpenSpec validation; canonical meta-mesh tests/check; complete Match and Twang unit, type, build, and required real-route Playwright suites on alternate ports.
- [x] 9.5 Record measured connection degree, initial and one-change bytes, convergence under partition, duplicate rate with several tabs, reconnect latency, and remaining E2EE/store-and-forward limitations.
- [x] 9.6 Review diffs for unrelated changes and secrets, commit canonical meta-mesh before vendor updates, prepare consumer commits, and report exact deployment readiness without deploying automatically.
