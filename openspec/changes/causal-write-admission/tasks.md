## 1. Contract

- [x] 1.1 User approved retained quarantine and authorized-view implementation.
- [x] 1.2 Trace editor-to-viewer transition through grant revocation, signed frontier, storage and projection; define already-accepted-change treatment.
- [x] 1.3 Specify dependency closure, explicit review/rebase and newer-grant semantics.

## 2. Model and conformance

- [x] 2.1 Add bounded two-replica DAG/role/clock TLA+ model and exact negative controls.
- [x] 2.2 Compare clean fresh-graph replica snapshots with production Rust admission and rebuilt projection; test host raw/view persistence separately, including already-known hashes. Exported edges are not action-replayed.
- [x] 2.3 Check conditional agreement within the shared-evidence model bounds; compare actual signed decisions and deterministic projection under arrival-order and receiver-clock variation.

## 3. Consumer integration

- [x] 3.1 Implement reviewed admission/projection policy and durable quarantine without changing raw signed history.
- [x] 3.2 Outer BDD: replay late signed revocation, show quarantined draft and pending descendant, retain evidence after reload, retry failed storage, and create a new signed review command. Check real offline/reconnect and access removal separately.
- [x] 3.3 Test far-future metadata, skewed receiver clock, dependency replay and authorized regrant; document legacy timestamp limits.

## Scope limits

- Host sync consumes serialized Automerge documents. The core API separately
  checks detached `pendingChangeBytes`, but the host has no tested orphan-byte
  transport/persistence path. Pending descendants already present in raw history
  appear in the UI; do not claim orphan-byte UI support.
- Policy/transport WASM separation remains future packaging work.
- No deployment or CI changes.
