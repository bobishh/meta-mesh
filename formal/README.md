# MetaMesh protocol models

These finite TLA+ models cover three protocol seams where asynchronous history
must not be mistaken for current authority or durable success. Run all positive
models and their required negative controls with:

```sh
./formal/check.sh
```

The script pins the official TLA+ tools 1.8.0 release, verifies its SHA-256
before execution, and fails if Java/TLC is unavailable. It uses `JAVA_HOME` or
`java` on `PATH`; on Homebrew macOS it also discovers `openjdk@21` and `openjdk`.
TLC metadata and counterexample traces are created under temporary directories.

## Bounds and checked results

The checked configurations are exhaustive only within these finite bounds.
Results below are from TLC 1.8.0 on 2026-09-25.

| Model | Bound | Result |
| --- | --- | --- |
| `AuthorityEpochs` | two replicas, two people, epochs 0 through 2 | 663,553 generated / 36,864 distinct states, depth 17; passed |
| `SessionGenerations` | two browser instances on one device, generations 1 through 3 | 71 generated / 45 distinct states, depth 6; passed |
| `DurableDelivery` | one two-hash batch, every persistence and ACK subset | 113 generated / 26 distinct states, depth 7; safety and liveness passed |

Every negative control must fail `Safety`; an unexpected pass fails the script:

| Mutation | Representative reachable trace | Search at violation |
| --- | --- | --- |
| an old grant clears a known revocation | revoke epoch 1, then replay grant epoch 1 | 301 generated / 199 distinct states |
| a genesis snapshot replaces newer authority history | accept owner `bob` at epoch 1, then merge the epoch-0 genesis snapshot | 746 generated / 451 distinct states |
| cleanup of an older generation closes the current session | register tab A generations 1 and 2, then clean up generation 1 | 41 generated / 41 distinct states |
| same-device tabs collapse to one stored session key | register tab B generation 1 while storage aliases it to tab A | 15 generated / 10 distinct states |
| a nonempty partial ACK completes a batch | persist `h1`, then ACK only `{h1}` | 25 generated / 14 distinct states |
| an empty ACK completes a batch | ACK `{}` in the initial state | 9 generated / 8 distinct states |

Counts may vary slightly with TLC worker scheduling and fingerprint seed. A
complete queue and the invariant/liveness result are authoritative.

## Authority and revocation mapping

`AuthorityEpochs.tla` models local verified authority knowledge at each replica.
`ReceiveGrant` maps to `plan_member_grant` in
`crates/meta-mesh-core/src/member_grant.rs` and the higher-`accessEpoch` choice in
`mergeCredentialSecurity` in `packages/mesh-peer-store/src/index.ts`.
`ReceiveRevocation` maps to the canonical union and epoch comparison in
`plan_authority_merge` (`authority_merge.rs`) and the same comparison in
`decide_workspace_access` (`access.rs`). `ReceiveOwnerRecord` maps to
`plan_ownership_merge` and `next_verified_ownership_transition`. The genesis
snapshot action represents a stale IndexedDB/network credential reaching a
replica after newer local authority records.

The model checks monotonic local owner/revocation history and makes two owners
at the same locally maximal epoch an explicit conflict set. It does not assert
globally unique ownership during a partition. A replica that has not received a
revocation may still grant access from its stale offline knowledge. Once that
replica accepts the revocation, only a strictly newer access epoch can restore
access; replaying an old grant or snapshot cannot do so.

Actions abstract records that have already passed issuer, certificate-chain,
signature, timestamp, and payload verification. TLC does not verify the
cryptography or the Rust parser. In particular, `VerifiedWorkspaceMember` in
`member.rs` and `VerifiedOwnershipTransition` in `authority.rs` have public
fields and derive `Deserialize`, so their type names alone do not establish
that verification ran. Current inspected consumers obtain them through the
verification functions; keeping these result types construction-sealed would
make that boundary stronger.

## Session mapping

`SessionGenerations.tla` maps each key to Rust `SessionKey { workspace_id,
device_id, instance_id }`. `Register` combines `MeshRuntimeState::admit_session`
in `runtime.rs` with `MeshSessionLifecycleState::register` in
`session_lifecycle.rs`. `CleanupOlder` maps to callback planning, lifecycle
eviction, and the generation-checked `MeshRuntimeState::remove_session` call
used by `packages/mesh-runtime/src/browserSessions.ts`.

The independent requested-session history is separate from the storage map, so
the model detects both a stale callback clearing a newer generation and an
implementation that accidentally keys two tabs only by durable device. The
model does not cover transport internals, heartbeat timing, or JavaScript task
scheduling beyond arbitrary action interleavings. These are safety properties;
no fairness is assumed and a session is not promised eventual establishment.

## Durable delivery mapping and fairness

`Persist(hash)` represents an honest receiver completing durable storage before
ACK construction. The native implementation's `FileScopeStore::write_validated`
in `crates/meta-mesh-native/src/scope_store.rs` writes a temporary file, calls
`sync_all`, renames it, and calls `sync_all` on the parent directory. The scope
service returns completion only after that method succeeds. Browser hosts have
the same protocol ordering obligation through the injected persistence adapter.

`ReceiveAck` maps to `durable_ack_matches` in `replication.rs`, which requires
set equality with every batch hash and rejects duplicate hash entries, followed
by signature verification in `deliverBatchToDevice` in `protocol.ts`. A failed
or incomplete ACK leaves the logical batch pending and lets route/retry work
continue.

The model's safety statement assumes the receiver is honest and its persistence
primitive honors the fsync contract. A device signature authenticates the ACK;
it cannot prove that a dishonest receiver wrote to disk. The liveness property
adds two explicit weak-fairness assumptions: every continuously missing hash is
eventually persisted, and once all hashes are durable the complete ACK is
eventually processed. Safety does not depend on those assumptions. Offline
forever, a permanently failed disk, or a permanently lost ACK is allowed to
remain pending.

## Limits

Model checking proves the TLA+ transition systems within the listed bounds. It
is not a proof that Rust, TypeScript, IndexedDB, the filesystem, WASM bindings,
or callers refine those systems. The action-to-function mapping above is the
review surface for keeping implementation and model coupled. No runtime
discrepancy was found in this inspection, so no runtime source or WASM artifact
was changed.
