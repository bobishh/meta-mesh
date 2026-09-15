## Why

Current consumers conflate trusted devices, browser transport instances, and Iroh endpoints. Match maintains connections to every known instance, while Twang replaces one device route with another and periodically sends complete room documents to every participant endpoint. Multiple tabs therefore multiply traffic or invalidate each other's routes, and document synchronization scales with both participant count and complete history size.

Meta-mesh needs one shared replication contract: a trusted device is one durable browser replica backed by shared IndexedDB; each tab is an independently reachable transport instance of that replica. Data is durably delivered once per device, propagated through a bounded gossip overlay, and reconciled incrementally with Automerge anti-entropy.

## What Changes

- Represent every trusted device as one durable replica with zero or more signed instance routes.
- Keep one independent Iroh endpoint per live browser instance; do not share endpoint identities or appoint a mesh-wide tab leader.
- Deliver a change once per target device by racing or falling back across that device's routes and accepting acknowledgement only after durable storage.
- Notify sibling tabs through a local invalidation bus so they reload durable changes without network redelivery.
- Replace all-peer full-document flooding with bounded gossip between device replicas.
- Use native Automerge sync messages and per-peer/per-document sync state for incremental anti-entropy and partition healing.
- Separate durable membership, signed route validity, transient route health, connection presence, and replication acknowledgement.
- Preserve legacy single-route advertisements during migration; new advertisements carry instance identity, monotonic route sequence, and expiry.
- Define observable delivery states and structured traces without presenting transport connectivity as durable delivery.
- Update Match and Twang to consume the shared protocol after meta-mesh behavior is verified.

## Capabilities

### New Capabilities

- `device-route-catalog`: Signed multi-instance routes grouped under one trusted device replica, with deterministic merge and route health independent from membership.
- `durable-replica-delivery`: One durable delivery per target device across alternative routes, idempotent acknowledgement, and local cross-instance invalidation.
- `sparse-gossip`: Bounded neighbor selection, change advertisement, forwarding, deduplication, and eventual propagation across a temporally connected mesh.
- `automerge-anti-entropy`: Incremental per-document synchronization using native Automerge sync state, safe restart, and partition convergence.
- `replication-observability`: Stable trace vocabulary and delivery state derived from durable evidence rather than a momentary transport channel.

### Modified Capabilities

None. Meta-mesh has no checked-in baseline OpenSpec capabilities yet.

## Impact

- Canonical packages: `mesh-directory`, `mesh-workspace`, `mesh-peer-store`, `mesh-instance`, `mesh-transport`, `mesh-replication`, and `mesh-browser-store`.
- Match: durable mesh dialing, session topology, workspace publication, connection status, and vendored package update.
- Twang: contact route model, full-room polling, room persistence, cross-tab refresh, connection status, and vendored package update.
- Persisted records gain backward-compatible route collections and incremental sync metadata. Existing identities, device IDs, grants, messages, workspaces, and Automerge histories remain unchanged.
- Offline mailbox storage and message encryption remain follow-up work. Untrusted store-and-forward cannot ship until message bodies and blobs are end-to-end encrypted.
