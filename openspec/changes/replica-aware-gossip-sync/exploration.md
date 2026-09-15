# Replica-aware gossip exploration

## Question

How should one protocol support many tabs, many devices, intermittent browser runtimes, incremental Automerge replication, and groups with hundreds of members without making a tab a device or dialing every endpoint continuously?

## Current facts

### Meta-mesh

- `mesh-instance` gives concurrent tabs different `instanceId` values and derives distinct transport seeds. This prevents simultaneous Iroh nodes from claiming one transport key.
- `mesh-workspace` already signs `deviceId`, optional `instanceId`, endpoint, route sequence, issue time, and expiry in peer advertisements.
- `mesh-peer-store` persists peers by `[workspaceId, deviceId]` and retains a nested list of transport instances.
- `mesh-replication` currently reconciles timestamped record arrays. It does not provide gossip, durable acknowledgement, document sync sessions, or Automerge anti-entropy.
- `mesh-transport` provides Iroh connections, streams, heartbeat, direct/relay racing, and trace buffering. It does not understand people, devices, rooms, documents, or replication.

### Match

- Each browser runtime owns a distinct leased instance and Iroh endpoint.
- Peer sessions are keyed by workspace, device, and instance.
- Dialing iterates every stored remote instance, so several tabs on each side multiply persistent sessions.
- Workspace replication already has incremental concepts, but topology and lifecycle remain application-owned.
- Workspace IndexedDB and `BroadcastChannel` already support cross-tab reconciliation at the application layer.

### Twang

- Each tab derives a distinct Iroh endpoint from its instance seed.
- Contact cards omit `instanceId`; the route cache key is only `personId:deviceId`.
- Directory contact updates replace the previous endpoint for the same device. Concurrent tabs therefore overwrite one another's routes.
- Every four seconds each runtime pings contacts, sends every complete room document to every participant endpoint, and probes missing blobs.
- A received room is written as complete bytes. Separate in-memory documents in concurrent tabs can become stale even though IndexedDB is shared.

## Identity hierarchy

```text
Person identity
  -> Device identity and certificate
       -> Shared durable browser store
            -> Browser instance A -> Iroh endpoint A
            -> Browser instance B -> Iroh endpoint B
            -> Browser instance C -> Iroh endpoint C
```

Current browser invariant: one persisted device key belongs to one same-origin storage profile. Tabs sharing that profile share both `deviceId` and IndexedDB. Restoring an identity into another profile creates another device key. Therefore `deviceId` is sufficient as the replica identifier for protocol version 1.

Do not introduce a separate `replicaId` until one authorized device key can intentionally front multiple independent durable stores. That use case does not exist today. The generic term *replica* means the durable store identified by `deviceId` in this version.

`instanceId` is a route namespace, not membership and not a replication target. `endpointId` is Iroh transport identity, not application authority.

## Invariants

1. Every live browser instance may own an independent Iroh node and endpoint.
2. No tab owns mesh-wide authority. No endpoint ID is shared by simultaneous Iroh nodes.
3. Membership and roles attach to people/devices, never tabs or endpoints.
4. All valid instance routes for one device may coexist.
5. One device is one durable delivery target. Sending identical data to every tab is unnecessary.
6. Durable acknowledgement occurs only after an idempotent IndexedDB transaction commits.
7. Sibling tabs learn about committed changes through local invalidation and read the durable store. `BroadcastChannel` notification is not durable state.
8. Lost notifications heal on focus, reconnect, or periodic local head comparison.
9. Route failure changes transient health. It never deletes identity, device membership, grants, or stored history.
10. Repeated network delivery is safe. Change hashes and message IDs provide deduplication.
11. CRDT convergence does not imply availability. At least one holder must remain reachable eventually.

## Layering

```text
Application policy and authorization
                  |
Automerge document anti-entropy
                  |
Sparse gossip and durable replication targets
                  |
Device delivery across alternative instance routes
                  |
Authenticated session and route health
                  |
Iroh connection, relay/direct path, and streams
```

### Device route catalog

The catalog stores signed route records keyed by `(scopeId, deviceId, instanceId)`. A record binds its Iroh endpoint to the certified device key and carries a monotonic sequence. A newer record for one instance supersedes only that instance. It cannot erase sibling instances.

Expired routes remain historical knowledge but are not preferred for dialing. Successful authenticated traffic refreshes transient health; it does not manufacture a new signed route. Applications may exchange current signed routes through authorized document sessions.

### One delivery per device

The sender groups candidate endpoints by device. It selects a preferred healthy route, starts alternatives after a delay or immediate failure, and completes the device delivery on the first durable acknowledgement. An acknowledgement binds scope, document, receiver device, accepted change heads or hashes, and protocol session.

All routes may receive duplicate bytes during a race. Receiver storage must use immutable change hashes or equivalent idempotent keys. No correctness property depends on cancellation reaching losing routes.

### Local cross-instance fan-out

The receiving instance commits changes, replies with durable acknowledgement, then publishes a small local invalidation containing document ID and heads. Other tabs reread missing durable chunks. They do not accept the invalidation payload as authoritative data.

Whole-document last-writer-wins storage is unsafe across tabs. Durable storage should append immutable Automerge changes by hash and maintain replaceable snapshots whose included heads are explicit.

### Sparse gossip

Gossip selects device replicas, not instance endpoints. Route selection happens below gossip. Each runtime may participate independently; protocol version 1 accepts duplicate gossip from sibling tabs and relies on content-addressed deduplication. No long-lived tab leader is required.

A peer maintains a bounded neighbor set rather than sessions to every member. Membership supplies authorized candidates; route exchange supplies reachability. Fresh local changes are pushed to a small fanout. Anti-entropy repairs omissions and partitions. Forwarded payloads retain original signatures and authorship.

Neighbor selection must avoid counting several routes of one device as several neighbors. Replication acknowledgements should prefer distinct devices and, when measuring failure independence, distinct people.

### Automerge anti-entropy

Each `(documentId, remoteDeviceId)` relationship owns Automerge sync state. Any instance route of that remote device may carry the next sync message. Route replacement or stream loss must not reset application history. Sync state may be persisted as an optimization; resetting it must remain correct.

The session exchanges native Automerge sync messages until both sides generate no further message. New local or merged changes schedule another round. Full saved documents are reserved for initial snapshot transfer or explicit compaction, not periodic publication.

## Alternatives

### One tab leader and one shared Iroh endpoint

Rejected. Simultaneous nodes cannot safely claim one endpoint identity, leadership couples reachability to one tab, and handoff creates avoidable connection churn. SharedWorker could host one process where supported, but Safari/browser lifecycle differences make it unsuitable as the required correctness path.

### Every tab as an independent device

Rejected. Tabs share keys and durable storage. Counting them as replicas invents durability, duplicates membership, and makes access control depend on UI processes.

### Independent tab endpoints grouped by device

Selected. Preserves inbound reachability without shared transport identity. Alternative routes converge on one durable store and one device acknowledgement.

### Broadcast complete state to every endpoint

Rejected as steady state. Across `N` runtimes it creates quadratic requests, retransmits growing history, and repeatedly dials dead routes. Keep only as bounded migration/bootstrap fallback.

### Sparse gossip without anti-entropy

Rejected. Rumor forwarding has finite caches and may miss partitions. Periodic incremental comparison is required for convergence.

### Anti-entropy without live push

Rejected. Correct but produces avoidable message latency. Fresh changes need immediate bounded fanout.

## Consumer migration

### Meta-mesh first

1. Add versioned route records and group them by device.
2. Add route-aware device delivery and durable acknowledgement interfaces.
3. Add browser change storage and local invalidation contracts.
4. Add native Automerge sync sessions.
5. Add bounded gossip scheduling and neighbor selection.
6. Add protocol traces and deterministic fault tests.

### Match

1. Adapt existing signed instance advertisements and nested peer instances to the shared catalog.
2. Replace per-instance replication ownership with device delivery across instance routes.
3. Move incremental session and topology policy into meta-mesh.
4. Preserve workspace authorization, ownership, succession, and UI outside transport packages.

### Twang

1. Accept legacy contact card v1 as one legacy instance route.
2. Introduce a versioned contact route carrying instance, sequence, and expiry.
3. Preserve multiple routes per contact device.
4. Replace four-second full-room broadcast with shared gossip and Automerge anti-entropy.
5. Replace complete room overwrite with append-by-change-hash storage and local invalidation.
6. Preserve message signatures, room grants, and blob descriptors.

## Failure scenarios required before rollout

- Two tabs of one device receive the same change through different routes; one durable copy and one device acknowledgement result.
- Receiving tab closes before commit; no acknowledgement is emitted and another route succeeds.
- Receiving tab closes after commit but before acknowledgement; retry deduplicates and acknowledges existing data.
- `BroadcastChannel` notification is lost; sibling tab heals from IndexedDB on focus.
- Two tabs create concurrent Automerge changes; reopening unions both immutable changes.
- One route expires while another instance of the device remains live; delivery continues without membership churn.
- Mesh partitions into two writable components; one later bridge converges both histories.
- Gossip push misses one member; anti-entropy later supplies missing changes.
- Malformed, oversized, unauthorized, or incorrectly signed changes never receive durable acknowledgement.
- One hundred logical members do not create one hundred persistent sessions per runtime.

## Open decisions

1. Neighbor selection scope: global device overlay multiplexing authorized documents, or a separate overlay per workspace/conversation. Global overlay minimizes connections; per-scope overlay simplifies authorization and information leakage.
2. Default mesh degree and gossip fanout. Values require deterministic simulation and browser measurements, not copied libp2p defaults.
3. Durable acknowledgement granularity: individual change hashes, Automerge heads, or bounded batches.
4. Snapshot bootstrap threshold and compaction ownership.
5. Whether sibling tabs all schedule gossip or use short task leases only to reduce duplicate outbound work. Correctness must not depend on a long-lived leader.
6. Route retention and dial scoring. Expiry must stop preference without deleting identity or history.
7. Replication target semantics for chats versus workspaces. Every member is an eventual destination, while additional availability copies may use a smaller configurable factor.
8. Encryption boundary. Store-and-forward nodes remain trusted-only until message bodies and blobs use E2EE envelopes.
