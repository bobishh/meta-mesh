# MetaMesh protocol models

These finite TLA+ models cover three protocol seams where asynchronous history
must not be mistaken for current authority or durable success. The runner also
exports fresh TLC state graphs and replays every exported edge against the real
Rust implementation; model checks alone are not the acceptance gate. Run all positive
models and their required negative controls with:

```sh
./formal/check.sh
```

The script pins the official TLA+ tools 1.8.0 release, verifies its SHA-256
before execution, and fails if Java/TLC is unavailable. It uses `JAVA_HOME` or
`java` on `PATH`; on Homebrew macOS it also discovers `openjdk@21` and `openjdk`.
TLC metadata and counterexample traces are created under temporary directories.

## Executable implementation conformance

`check.sh` exports TLC DOT graphs with action labels, converts their values to
JSON without implementing protocol decisions, and runs Rust conformance tests.
The compact delivery and session-generation checks replay every model edge
after a shortest initial-to-source trace. Authority, delivery-flow, and session
callbacks also have bounded worklist explorers that start from real Rust initial
state, execute every enabled event from every distinct reachable concrete state,
and match each effect to a labeled model transition. Implementation
state is built by API calls, never by injecting the model's expected state.
Failures include the action trace and model edge.

- `tlc_sessions.rs` calls `MeshRuntimeState::admit_session/remove_session` and
  `MeshSessionLifecycleState::register/evict/publish_plan`, and checks transport
  close effects as well as current sessions. Model generation numbers are mapped
  to Rust's allocated generation numbers without changing expected connections.
- The session unit-test explorer calls those APIs plus `callback_plan` for
  recovery, early and due stability timers, heartbeat failure, receive success,
  and receive failure. It covers two instance IDs on one device and three global
  generations, including replacement and delayed or repeated callbacks for old
  generations. Its structural state key includes all runtime fields, lifecycle
  generation/current maps, and every entry's `stable_at_ms`, `stable`,
  `failure_reported`, `recovery_published`, and `evicted` fields. Test-only
  equality and hashing derive from the Rust structures; debug output and model
  projections are not state keys. Hash collisions are resolved by structural
  equality. When a concrete state is reached again, its complete abstract state
  must agree with the previous mapping, except for TLC's instrumentation parity
  bit; otherwise the explorer fails before merging the paths.
- `tlc_delivery.rs` signs and verifies ACK fixtures, calls `durable_ack_matches`
  and `MeshBatchDeliveryFlow::route_result/retry_elapsed`, and compares batch
  completion. Retry scheduling is an internal stuttering step. `Persist` is an
  external input assumption here: this test does **not** exercise filesystem
  writes, crash durability, or the TS adapter that wires ACK checks to the flow.
- `tlc_authority.rs` uses `AuthorityConformance`, a concrete signed-history model
  rather than the broader `AuthorityEpochs` abstraction. It calls
  `plan_member_grant`, `plan_authority_merge`, `plan_ownership_merge`, and
  `decide_workspace_access` with signed grant/revocation/transfer fixtures. It
  compares access, epochs, retained history, selected owner, and conflicts.
  Three possible owners, one separate member, and two transfer/access epochs
  bound the graph. A worklist retains distinct concrete credential, grant,
  revocation, ownership-history, and host-applied plan states even when their
  authority projection is equal. Model epoch 0 is Rust genesis epoch 1; nonzero model epochs
  are translated by +1. Returned ownership steps drive harness state; intended
  successor inputs do not stand in for Rust's returned decisions.

The Rust tests are explicitly ignored in ordinary `cargo test` because they
require fresh TLC graphs. `check.sh` supplies them and runs `--ignored`; missing
inputs fail rather than silently skip. The CI job runs that exact command.

`check_rust_mutations.py` copies the actual crates into a temporary workspace and
mutates production Rust (not the model). Each mutated implementation must fail a
conformance assertion; a compilation error or successful test is a failed check.
The probes cover incomplete ACK acceptance, stale route results completing a
new delivery round, stale cleanup in runtime and lifecycle, tab-key aliasing,
revoked-epoch access, and ignored ownership conflict.
Each mutated build uses its own Cargo target directory so neither the production
build cache nor another mutant can satisfy it. The working tree is never mutated.
The substitutions are exact and fail if their source targets change, so obsolete
mutation probes cannot quietly disappear.

This is bounded model-based conformance testing, **not** an unbounded refinement
proof. The callback explorer retains concrete states even when their session
projection is equal, but only within its explicit keys, generations, events, and
clock samples. The compact edge-replay checks still use one representative
shortest prefix; the concrete worklists supplement them. Cryptography and host
scheduling remain review boundaries; adapter and persistence tests below cover
specific failure scenarios rather than all external behavior.

## Bounds and checked results

The checked configurations are exhaustive only within these finite bounds.
Results below use the pinned v1.8.0 release asset (TLC build
2026.09.25.020137) on 2026-09-25. The checksum matches the official
GitHub release asset digest; a changed upstream asset fails closed.

| Model | Bound | Result |
| --- | --- | --- |
| `AuthorityEpochs` | two replicas, two people, epochs 0 through 2 | 663,553 generated / 36,864 distinct states, depth 17; passed |
| `AuthorityConformance` | three owners, one member, epochs 0 through 2 | 300 model states; 3,774 concrete Rust states / 21,250 enabled edges through signed Rust APIs |
| `SessionGenerations` | two browser instances on one device, generations 1 through 3 | 71 generated / 45 distinct states, depth 6; passed |
| `SessionImplementationStates` | two instances on one device, three global generations, callback clocks before and at stability | 525,891 generated / 28,849 distinct model states, depth 14; 14,425 concrete Rust states / 262,946 enabled edges explored |
| `DeliveryImplementationStates` | two routes, one retry, old/current/future callbacks and invalid route index | 234 model states; 62 concrete Rust states / 1,551 enabled edges |
| `DeliveryImplementationStates` recovery configuration | start after failed first round; one retry available; eventually handled successful routes | 23 states; eventual completion passed under weak fairness |
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

`SessionImplementationStates.tla` adds callback bookkeeping and a model-only
parity bit so TLC exports labeled edges even for repeated callbacks whose protocol
effect is a stutter. The Rust explorer samples stability immediately before and
at each generation's deadline. It reports how many concrete states and enabled
edges were checked, and asserts that equal session projections retain multiple
private Rust states; the current bound reaches 512 concrete states for one
projection. Every callback effect must map to an outgoing labeled model edge.

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

## Delivery flow and reconnect recovery

The concrete delivery explorer exercises `MeshBatchDeliveryFlow` with late,
duplicate, and out-of-range callbacks, route rejection, retry/fallback timers,
and abort. Its structural key includes all private flow fields, failure and
attempt ordering, and exact floating-point configuration bits. It compares both
returned host actions and state against `DeliveryImplementationStates`.

The recovery configuration starts in a reachable waiting-for-retry state.
Failures stop, a retry remains available, and timer/success handling is weakly
fair. TLC checks eventual completion under those conditions. This is not a
promise to recover after the flow has exhausted its finite retry budget; an
outer supervisor must start new work then.

`packages/mesh-runtime/src/browserLifecycle.test.ts` exercises the production
browser supervisor and WASM lifecycle state with controlled host failures and
actual timer scheduling under a fake clock. Cases include rejected startup
notification, failed node runs, failed cleanup, stale async starts crossing
stop/start, pending instance acquisition, concurrent stops, and explicit stop. The failure matrix uses 1/2/4 failed runs,
0/2 failed cleanups, and 0/1 failed notifications before recovery. It checks
that cleanup finishes before another run, eventual progress after those finite
failures, and no resurrection after stop. These are executable bounded tests,
not a proof of every JavaScript schedule.

Match's `e2e/durable-mesh.spec.ts` additionally pairs real Chromium contexts,
goes offline, verifies that the Iroh session closes, persists edits in IndexedDB,
returns online, and verifies a new session and bidirectional convergence without
reload or re-pairing. Identity and roles must remain unchanged. This scenario
keeps the transport node alive; unexpected whole-node restart is covered by the
adapter tests, not that browser test. Match regenerates sync frames from its
persisted Automerge state; this is not evidence of a separate browser outbox.

Native persistence tests inject failure after temporary-file `sync_all` and
before rename, reopen the store, verify the previous committed bytes remain,
and retry successfully. A peer receive test verifies no saved receipt is emitted
on failed host persistence and replay succeeds after recovery. These tests do
not simulate power loss, dishonesty, or a filesystem violating `fsync` semantics.

Connection liveness requires that the peer and network eventually become
reachable, authorization remains valid, the host schedules timers, and transport
operations eventually complete or fail. An indefinitely suspended tab, a hung
transport operation, or permanent network loss does not satisfy those premises.

## Limits

Model checking checks the TLA+ transition systems within the listed bounds.
The executable conformance tests couple the selected Rust APIs to freshly
generated model transitions. They are not an unbounded refinement proof, and
do not establish unbounded correctness of TypeScript, IndexedDB, transport,
filesystem crash behavior, or WASM bindings. Separate executable tests exercise
the particular adapter and persistence cases described above.
