## Context

Meta-mesh supplies reusable browser identity, route, transport, storage, workspace, messaging, and replication primitives to Match and Twang. Iroh provides transport endpoint identity, connection establishment, relay/direct paths, and streams. Application identity and authorization remain separate.

Match already signs per-instance routes and stores several instances under one device, but it maintains per-instance peer sessions and owns most lifecycle and replication policy. Twang derives a distinct Iroh endpoint per tab but contact records retain only one endpoint per device; every four seconds it sends complete Automerge room bytes to every known participant endpoint. Both applications therefore implement different semantics over the same packages.

All same-origin tabs in one browser profile share the persisted device key and IndexedDB. That durable storage boundary, not a tab, is the logical replica. Another browser profile or recovered installation obtains another device key and durable store.

## Goals / Non-Goals

**Goals:**

- Define one device-replica and multi-instance-route model reusable by Match and Twang.
- Preserve independent Iroh endpoints for every live browser instance without a mesh-wide tab leader.
- Deliver and acknowledge data once per durable device store.
- Reconcile sibling tabs through shared durable changes and local invalidation.
- Bound active mesh degree and eager propagation independently of member count.
- Use Automerge native incremental synchronization to heal missed gossip and partitions.
- Make authorization, route validity, transient health, presence, and delivery independently observable.
- Migrate current records without changing identity, grants, workspace IDs, room IDs, or Automerge history.

**Non-Goals:**

- Store-and-forward availability while all authorized holders are offline.
- End-to-end message or blob encryption.
- Public permissionless peer discovery, DHT operation, Sybil resistance, or full Gossipsub compatibility.
- Consensus ordering for ordinary document changes.
- Treating tabs as devices, members, or independent durability copies.
- Making BroadcastChannel, wall-clock timestamps, or transport connectivity authoritative.

## Decisions

### Device ID is replica ID in protocol version 1

`ReplicaId` is a semantic alias for `DeviceId`. One browser storage profile persists one device key and one document/change store; its tabs share both. Another installation receives another device ID. A separate replica identifier would add an unsigned or separately governed identity without a current use case.

Alternative: add an independent `replicaId`. Rejected until one certified device intentionally operates multiple independent stores. A future protocol version can add that cardinality.

### Every browser instance owns a distinct transport identity

Each tab obtains an `instanceId`, derives a separate Iroh node seed, and advertises the resulting endpoint under its certified device. No simultaneous Iroh nodes share an endpoint key. No tab controls the device's inbound reachability.

Alternative: one leader tab owns a shared endpoint. Rejected because leader handoff closes healthy transport, introduces a correctness dependency on one tab, and recreates the observed route churn. SharedWorker remains a future optimization, not a required execution model.

### Signed routes form a collection below a device

Introduce a transport-neutral `DeviceRoute` envelope. Key routes by `(scopeId, deviceId, instanceId)`. Each instance owns a monotonic sequence; sequence dominates issue time. Canonical envelope bytes break an impossible equal-sequence tie deterministically. Expiry controls selection, not authority or deletion.

Legacy records lacking instance identity map to `legacy:<hash(endpoint)>`. Their signed endpoint remains the authority. New writers emit the new route version; readers accept both during migration.

### Delivery is device-scoped and route-raced

`ReplicaDelivery` receives a target device and its candidate routes. It starts the healthiest route, starts alternatives after configurable delay or immediate failure, and succeeds on the first valid durable acknowledgement. Losing requests may still arrive, so the receiver admits batches idempotently.

Acknowledgements are device-signed bounded records containing scope ID, document ID, batch ID, accepted heads or change hashes, receiver device ID, and commit time. Batch acknowledgement avoids one signature per Automerge change while retaining portable evidence.

### Short outbox claims replace tab leadership

Every instance remains reachable. A shared IndexedDB outbox gives one instance a bounded claim for `(documentId, targetDeviceId, batchId)`. Claim expiry permits takeover after a crash. The claim reduces duplicate outbound work but never controls the Iroh node, membership, inbound traffic, or local writes.

Without Web Locks or during races, duplicate delivery remains correct because batch and change hashes are idempotent. Correctness never depends on claim exclusivity.

### Durable changes are append-only; snapshots are caches

Browser storage writes immutable Automerge changes by document ID and change hash in one transaction with verified proof metadata. Whole documents are snapshots labeled with included heads. Local invalidations contain only document ID and heads; sibling tabs load authoritative bytes from IndexedDB.

Snapshot policy stays adapter-configurable. Compaction may remove physical chunks only when the snapshot demonstrably includes them; logical Automerge history and application tombstones follow their own retention policy.

### Connection pool is global; gossip eligibility is scoped

One authenticated device connection can multiplex several authorized documents. Neighbor candidates and change exchange are evaluated separately for each workspace, room, or private-root scope, preventing one shared connection from disclosing unrelated document identifiers.

The overlay exposes configurable `low`, `target`, `high`, eager fanout, rotation, and backoff. Defaults will be selected through deterministic simulation and browser measurements. Specs require bounds, not copied public-Gossipsub constants.

Alternative: one connection overlay per document. Rejected because shared contacts and workspaces would multiply transport connections. Alternative: global unscoped gossip. Rejected because it leaks scope membership and document identifiers.

### Gossip provides latency; Automerge anti-entropy provides convergence

Fresh durable changes enter a bounded eager queue. Neighbors advertise bounded change availability and request unknown data. Seen caches suppress repeated forwarding. Periodic or event-triggered Automerge sync sessions compare actual document histories and repair omissions.

Sync state is keyed by `(documentId, remoteDeviceId)`, not endpoint. Any authorized route can carry the exchange. Sync state may be discarded and regenerated safely. Transport loss restarts a round without changing application history.

### Application adapters retain authorization policy

Meta-mesh authenticates route and device envelopes, frames traffic, schedules gossip, and manages sync state. A document adapter owns scope membership, proof verification, candidate validation, durable change application, current heads, and snapshots. Match keeps workspace roles/ownership/succession; Twang keeps conversation grants and message validation.

### Every member is an eventual destination; availability fanout is smaller

For a shared room or workspace, every authorized member device eventually receives permitted document history. Fresh changes first target a configurable subset for low latency and redundancy. Gossip plus anti-entropy completes propagation. Replication UI distinguishes current eager acknowledgements from eventual destination convergence.

### Observability follows protocol boundaries

Structured trace events use `operationId`, `batchId`, `scopeId`, `documentId`, local and remote device IDs, local and remote instance IDs, route ID, attempt number, and stage. Sensitive payloads are excluded. Consumer UI aggregates routes under devices and never counts tabs as members or durable replicas.

## Risks / Trade-offs

- [All tabs can generate duplicate gossip] → Shared short outbox claims reduce work; content hashes and acknowledgements preserve correctness when claims race.
- [Browser suspension expires every route] → Preserve durable device membership and retry historical signed routes with lower priority when no fresh route exists.
- [Device-signed batch acknowledgements cost CPU] → Acknowledge bounded batches/frontiers rather than individual chunks; measure before weakening evidence.
- [Automerge sync state races across local tabs] → Treat sync state as disposable optimization and serialize durable document admission by change hash.
- [Sparse overlay temporarily disconnects] → Rotate neighbors and run anti-entropy whenever a bridge appears; deterministic partition tests cover healing.
- [Malicious authorized member amplifies wants or invalid changes] → Bound frames, queues, wants, retries, validation work, and peer contribution scores before forwarding.
- [Legacy routes lack instance sequence] → Isolate each legacy endpoint under a synthetic instance and never let it dominate a valid newer-version route by timestamp alone.
- [Canonical and vendored packages drift] → Change canonical meta-mesh first, add a deterministic vendor sync/check command, then update both consumers from one commit.
- [Unencrypted room bytes reach future mailbox nodes] → Keep untrusted store-and-forward outside this change; add E2EE before mailbox integration.

## Migration Plan

1. Add protocol types and state-machine tests in canonical meta-mesh without changing consumer defaults.
2. Add device route collections alongside legacy endpoint fields; read both and write the new version.
3. Add append-only browser change storage, local invalidation, device delivery, acknowledgement, and Automerge sync adapters.
4. Add bounded gossip behind an explicit consumer feature switch.
5. Integrate Match first because its signed instance catalog and incremental workspace services already exist. Compare connection count, update bytes, convergence, and UI state against current behavior.
6. Integrate Twang, migrate contact routes, then remove four-second full-room broadcast only after live push and partition-healing tests pass.
7. Copy the canonical package commit into consumer vendor trees with a deterministic equality check.
8. Deploy one consumer at a time. Old readers continue accepting legacy routes; new readers retain both formats during the compatibility window.

Rollback disables the new gossip scheduler and restores consumer orchestration while leaving additive route and change records intact. Never roll persisted documents, identities, grants, or histories backward.

## Open Questions

- Exact initial neighbor and eager-fanout defaults require simulation and browser measurements.
- Automerge compressed-document bootstrap threshold requires fixture measurements.
- Long-term route retention and health-score decay require observed mobile/browser lifecycle data.
- E2EE group epochs and untrusted mailbox replication require a separate security change before store-and-forward deployment.
