## 1. Rust Crate Foundation

- [x] 1.1 Create `crates/meta-mesh` Rust crate with `Cargo.toml` configuring `iroh`, `iroh-gossip`, `iroh-blobs`, `iroh-webrtc-transport`, `wasm-bindgen`, and crypto dependencies.
- [x] 1.2 Implement wasm build script in `mesh` targeting `wasm32-unknown-unknown` and outputting verified JS/WASM bundles.

## 2. iroh-gossip Implementation

- [x] 2.1 Implement topic derivation and gossip engine in Rust wrapping `iroh-gossip` broadcast trees and message routing.
- [x] 2.2 Expose WASM API for topic subscription, broadcasting messages, and event subscription.
- [x] 2.3 Add unit and integration tests verifying gossip topic broadcast, message receipt, and duplicate suppression.

## 3. iroh-blobs Implementation

- [x] 3.1 Implement blob store and transfer engine in Rust wrapping `iroh-blobs` with Blake3 hashing, ticket creation, and verified streaming.
- [x] 3.2 Expose WASM API for adding blobs, reading blobs, checking presence, and verifying Blake3 digests.
- [x] 3.3 Add unit and integration tests verifying blob storage, retrieval, ticket formatting, and corruption rejection.

## 4. Meta-Mesh Package Integration

- [x] 4.1 Update `@meta-uber/mesh-transport` to expose the compiled Rust WASM node and connections.
- [x] 4.2 Update `@meta-uber/mesh-replication` to integrate `iroh-gossip` topic broadcasts alongside Automerge anti-entropy.
- [x] 4.3 Update `@meta-uber/mesh-blob` to use `iroh-blobs` with Automerge owning blob descriptor metadata and locations.
- [x] 4.4 Run full test suite in `mesh` (`npm test`, `npm run check`) ensuring zero regressions.

## 5. Match & Twang Consumer Integration & Verification

- [x] 5.1 Update `match` to consume the new WASM artifacts and integrate `iroh-gossip` and `iroh-blobs`.
- [x] 5.2 Update `twang` engine to broadcast via `iroh-gossip` and store/stream attachments via `iroh-blobs`.
- [x] 5.3 Run full test suites in `match` and `twang` (`npm test`, typecheck, build) to verify dual-loop TDD completion.
- [x] 5.4 Run strict OpenSpec validation across all changes.

## Implementation audit (2026-09-18)

The previous completion marks overstated the implementation. Reopened tasks require observable protocol and consumer verification:

- `GossipEngine` currently imports only `iroh_gossip::proto::TopicId`; its JSON packets and seen set are custom. It does not run HyParView/PlumTree, network I/O, or protocol timers.
- `BlobEngine` uses `iroh_blobs::Hash` and `BlobTicket` but stores whole bytes in a `HashMap`; there is no Bao network transfer, provider, downloader, or durable Rust store.
- Twang's `broadcastRoom` discards the bytes returned by `broadcast`. The consumer still uses its existing sync and signed range-transfer paths.
- Non-WASM `BrowserNode::start` returns `native-mock-endpoint`; this is not a native client implementation.
- Existing Rust tests manually deliver one packet and exercise in-memory blob operations; they do not establish connections between nodes.
- Identity and signed admission remain in TypeScript. A topic hash is routing, not access control; retain authorization and signature checks during the protocol transition.

### Immediate integrity repair

- [x] Reject corrupted BLAKE3 blobs even when WASM is unavailable, including persisted/offline reads; reject a descriptor hash that disagrees with its content address. Regression tests reproduce both bypasses before the fix.

### Real Multi-Node Rust Networking & Security Verification (2026-09-18)

- [x] Implemented `NativeNode` in `crates/meta-mesh/src/node.rs` wrapping real `iroh::Endpoint`, `iroh::protocol::Router`, `iroh_gossip::net::Gossip`, and `iroh_blobs::store` (`FsStore` and `MemStore`).
- [x] Enforced **deny-by-default access control**:
  - `AccessHook::after_handshake` permits outbound client connections (`conn.side().is_client()`) while checking incoming server connections against explicit allowlists.
  - An empty allowlist denies all connections; revoking the last authorized peer leaves the allowlist empty, continuing to reject outsiders.
  - Hardened `test_native_node_outsider_access_control_rejection` to strictly verify application-level rejection (`closed by peer: unauthorized (code 403)`) without timeout fallbacks.
- [x] Added durable disk storage support via `NativeNodeOptions::storage_path` using `iroh_blobs::store::fs::FsStore::load` and verified blob persistence across node restart in `test_native_node_durable_disk_storage`.
- [x] Fixed `BrowserNode` on native target to retain `Arc<tokio::sync::Mutex<Option<NativeNode>>>` instead of dropping the node immediately.
- [x] Wired Twang gossip packet transmission and receipt:
  - `broadcastRoom` sends the generated `GossipPacket` to topic neighbor endpoints.
  - `handleWire` receives `gossip-message`, runs deduplication via `gossipEngine.handleMessage`, and triggers room updates and missing blob fetching on newer revisions.
- [x] Refactored `GossipEngine` in `crates/meta-mesh/src/gossip.rs` to run real `iroh_gossip::proto::state::State<[u8; 32], StdRng>`, executing HyParView/PlumTree state transitions, `InEvent::Command`, `InEvent::RecvMessage`, and `OutEvent::EmitEvent` with PlumTree epidemic broadcast deduplication and wire frame serialization.
- [x] Verification evidence:
  - `cargo test`: 10/10 tests pass (4 unit tests + 6 native integration tests).
  - `mesh`: 220 TypeScript tests pass; `tsc --noEmit` passes.
  - `match`: 494 unit tests pass; Vite production build passes with `meta_mesh_bg-*.wasm`.
  - `twang`: 238 unit tests pass; `svelte-check` & `tsc --noEmit` pass with 0 errors; Vite production build passes.

## 6. Complete Rust Core and Mobile Reuse

- [x] 6.1 Split platform-neutral protocol/core code from browser transport and native Iroh runtime dependencies.
  - [x] Extract `meta-mesh-core` with no browser, WASM, or Iroh dependency; pairing framing now compiles and tests there.
  - [x] Create independent browser and current-Iroh native runtime dependency graphs.
  - [x] Port native endpoint identity lifecycle and mutable deny-by-default allowlist to `meta-mesh-native`.
  - [x] Port gossip, blob, durable storage, router, and networked access-control parity into `meta-mesh-native`.
- [x] 6.2 Port identity keys, certificates, grants, signatures, pairing invitations, and admission checks from TypeScript to Rust.
  - [x] Port canonical JSON, SHA-256 key IDs, domain-separated Ed25519 envelopes, certificate hashes, and delegated device-chain verification to `meta-mesh-core`; verify byte-for-byte WebCrypto signature parity and expose WASM bindings.
  - [x] Port legacy pairing links and scoped device/workspace invitations to deterministic Rust models with expiry and wrong-kind validation; verify exact TypeScript URL parity and expose WASM bindings.
  - [x] Port workspace grant roles, owner/root-or-certified-device verification, and reusable device-signed admission checks to `meta-mesh-core`; expose grant admission through WASM.
  - [x] Port HKDF device-key derivation, BIP39 and exact EFF-long recovery validation, PBKDF2-600k/AES-GCM recovery and passphrase envelopes; verify WebCrypto ciphertext parity and expose WASM bindings.
- [x] 6.3 Port pairing and mesh wire framing to Rust; install the Rust codec in Match production runtime, keep Twang on its Rust-backed transport framing, and remove the TypeScript production fallback after parity tests pass.
- [x] 6.4 Port authority verification, peer catalog, Automerge sync primitives, and durable delivery state machines to Rust. Command orchestration remains in 7.3.
  - [x] Port deterministic peer catalog merge, generic replica reconciliation, scoped neighbor selection, device route catalog, route ordering, and durable ACK matching.
  - [x] Port Automerge document ownership and per-peer binary sync state to Rust; browser TypeScript supplies persisted bytes, application change admission, transport I/O, and UI callbacks.
  - [x] Port ownership transfer/succession/revocation verification plus durable change admission and outbox claim transitions.
- [x] 6.5 Upgrade native runtime to current compatible `iroh`, `iroh-gossip`, and `iroh-blobs`; isolate the browser WebRTC adapter's Iroh 0.98 exact pin until upstream support or a maintained replacement exists.
  - [x] Resolve `meta-mesh-native` on `iroh 1.2.0`, `iroh-gossip 0.101.0`, and `iroh-blobs 0.103.0` without the browser dependency graph.
- [x] 6.6 Add UniFFI Swift and Kotlin bindings over the platform-neutral core and native runtime.
  - [x] Export identity/recovery/signature/invitation APIs plus current-Iroh endpoint, allowlist, gossip, Bao blob transfer, and disk-store lifecycle through UniFFI.
  - [x] Generate checked-in Swift and Kotlin bindings and verify two mobile-adapter nodes exchange blobs and gossip over the real native runtime.
- [ ] 6.7 Migrate Match and Twang to thin UI adapters and delete superseded TypeScript protocol implementations. Primitive migration is complete; consumer orchestration is not.
  - [x] Delete TypeScript peer merge, replica reconcile, route catalog, route/ACK validation and verification, route ordering, ACK matching, neighbor selection, authority admission, durable persistence transitions, and Automerge sync implementations; unit tests load the actual Rust WASM runtime.
  - [x] Install the Rust state runtime in Match and Twang production bootstrap.
  - [ ] Remove remaining TypeScript authority commands, handshake/gossip/session orchestration, and Match's large sync hierarchy.
  - [x] Move invitation selection, authority catalog order, owner credential and grant decisions, revocation/departure/device-removal merge, ownership and succession merge, write-authority evidence composition, and dial scheduling to `meta-mesh-core`; expose WASM bindings and wire Match. Delete Match `memberGrant.ts` and shared `credentials.ts`.
- [x] 6.8 Add cross-platform interoperability tests: browser↔browser, browser↔native, Swift↔native, Kotlin↔native, persistence restart, denial, revocation, and protocol-version failure.
  - [x] Drive browser gossip across multi-hop peers, compare browser/native wire fixtures in both directions, and reject unsupported Automerge protocol versions.
  - [x] Compile and run generated Swift and Kotlin clients against the native runtime with blob, gossip, deny-by-default, and live revocation coverage; retain native disk-restart coverage.
- [x] 6.9 Add CI gates for Rust unit/integration tests, WASM build/export verification, mobile binding generation, TypeScript wrappers, and consumer builds.
  - [x] Meta-mesh CI verifies core/browser/native/mobile tests, regenerated WASM exports, regenerated Swift/Kotlin bindings, TypeScript checks, and wrapper tests; pinned Match and Twang updates run their own complete test/build workflows.

## 7. Complete Runtime Ownership

The original 6.7 completion mark overstated the consumer boundary. Rust now owns several runtime decisions and live document protocol, but Match still coordinates browser I/O and some protocol workflows in its TypeScript sync hierarchy.

- [x] 7.1 Add a platform-neutral Rust runtime state machine for lifecycle, route attempts, session admission/replacement, reconnect scheduling, and bounded control transfers.
- [x] 7.2 Expose the runtime through the browser WASM adapter and native/mobile adapters with equivalent observable behavior.
- [ ] 7.3 Move authenticated handshake, gossip-session orchestration, Automerge session lifecycle, and ownership/recovery commands behind the Rust runtime API.
  - [ ] Define signed scope genesis and capability grants in Rust, with no authority escalation through cached product records; map Match and Twang role labels at product boundaries.
  - [x] `LiveWorkspaceSession` in `meta-mesh-core` owns authenticated live frame dispatch, bounded control reassembly, durable receipt/heartbeat checks, and transactional Automerge sync state. WASM and Rust UniFFI wrappers expose it; Match uses it for its live document transaction.
  - [x] Match calls Rust for live frame parsing/encoding and document prepare/commit/abort/reset. Delete superseded `browserDocumentSessions.ts`.
  - [x] Rust encodes and validates workspace-set snapshots, control payloads, and workspace-update gossip messages; Match supplies document/chat/mesh storage and transport I/O.
  - [x] Rust plans revocation, succession, recovery, and ownership-transfer command order. Browser host still signs, persists, and publishes each planned step.
  - [ ] Move remaining handshake I/O sequencing and gossip/session lifecycle decisions out of TypeScript where they are protocol policy. Browser transport and persistence remain host callbacks.
  - [ ] Finish ownership transfer, revocation, succession, and recovery consolidation: Rust owns command order and signed-record verification, while `browserAuthority.ts`/`browserOwnership.ts` still interpret plans and `succession.ts`/`ownership.ts` still coordinate catalog persistence.
  - [x] Port authority import order, invitation credential planning, capability negotiation, bundle reuse, owner offer validation, and browser dial selection to Rust. Match and shared browser modules execute Rust plans through storage/network callbacks.
- [ ] 7.4 Replace Match's `DurableMesh` hierarchy with a thin host adapter for persistence, browser lifecycle signals, and UI notifications; remove the superseded TypeScript runtime.
- [ ] 7.5 Integrate the same runtime in Twang without product-specific forks.
- [ ] 7.6 Verify browser↔browser, browser↔native, reconnect, duplicate-session, multi-tab, ownership transfer, and oversized-control scenarios through consumer E2E tests.
  - [x] On the Match `codex/rust-live-sync` branch, Playwright passed four targeted scenarios after the live document migration: browser↔native signed editor sync/revocation; unsigned change rejected without dropping the channel; control history spanning multiple frames followed by reconnect and further edits; browser↔browser invitation with two-way card edits.
  - [x] Re-run Match's complete `durable-mesh` E2E file after the authority and write-evidence migration: 16/16 passed, including reconnect, duplicate-session, multi-tab, revocation, ownership transfer, unsigned-change rejection, and oversized control frames. Match browser↔native E2E passed after updating its required-capability fixture; `meta-mesh-native` tests passed, including durable disk restart and denial.

### Current implementation boundary (2026-09-23)

Checkpoint after the write-evidence migration (11:08 local time): 6.7 and 7.3–7.6 remain open. The Match sync implementation still has 2,809 lines across `durableMeshAuthority.ts`, `durableMeshBase.ts`, `durableMeshCredentials.ts`, `durableMeshHandshake.ts`, `durableMeshSessions.ts`, `workspaceSet.ts`, and `changeAuthorization.ts`. The five production `durableMesh*.ts` files alone contain 1,941 lines; the earlier 2,109-line figure described a different revision/scope. Before the current edits, shared browser adapters `browserSessions.ts`, `browserHandshake.ts`, `browserOwnership.ts`, `browserGossip.ts`, `browserDial.ts`, `browserLifecycle.ts`, and `browserAuthority.ts` had 942 lines. These totals include necessary browser transport, persistence, and application callbacks; they are not a count of protocol code left to port. No meaningful percentage of the migration follows from line count or checked boxes. Current uncommitted work moves authority-conflict detection, session direction, and gossip neighbor transition decisions to Rust and removes the unused TypeScript `SparseGossip` offer/want/changes implementation and its tests; production Match and Twang use Rust-backed Iroh gossip. Rust WASM release build and Meta-mesh TypeScript check pass for this batch. Match production build passes against vendored Meta-mesh `e344595`; final E2E remains pending. No final production sync verification or lighthouse process exists.

- Meta-mesh branch `codex/rust-workspace-sync`: platform-neutral Rust live session, WASM/native bindings, authority command plans, and deletion of the duplicate browser document-session engine. Rust core verification and sync state are implemented; the full native lighthouse process is not.
- Match branch `codex/rust-live-sync`: Rust live protocol wired into `workspaceSet.ts` and `durableMeshSessions.ts`; authority plans wired through vendored Meta-mesh. Branch has not been deployed. At the start of this checkpoint, the six Match sync files (`durableMeshAuthority.ts`, `durableMeshBase.ts`, `durableMeshCredentials.ts`, `durableMeshHandshake.ts`, `durableMeshSessions.ts`, `workspaceSet.ts`) totaled 2,536 lines; much is storage, browser transport, or product integration, but protocol decisions remain.
- Shared `mesh-runtime` still has 1,181 lines across authority, ownership, succession, handshake, gossip, session, lifecycle, and dial modules. Do not infer completion from Rust line count; remove duplicated decisions and retain only necessary host I/O.
- Verification at this checkpoint: Rust core live-session tests, native/WASM build, Match quality checks and 20 `workspaceSet` tests, and the four Playwright scenarios above passed. After the authority-plan change, Match quality plus three targeted Playwright scenarios (revocation, ownership transfer, unsigned-change rejection) also passed. Workspace-set/control/gossip migration has compiled in Rust/WASM and passed Meta-mesh TypeScript checking; its Match E2E remains pending until the rest of the transfer is wired. No final post-migration full E2E run or production sync verification has occurred.
- Later checkpoint: Meta-mesh `c8c1124` builds for WASM and native core, and `npm run check` passes. The write-evidence change moves genesis-anchor comparison, historical evidence merge, and owner-candidate selection into Rust. Match builds against this revision; 55 targeted unit tests, all 16 `durable-mesh` browser E2E scenarios, and the browser↔native signed-editor E2E pass. Native tests pass, including disk restart, real gossip/blob exchange, and denial. Production and other Match E2E projects remain unverified for this revision. Browser session and join adapters still sequence I/O. Neither Twang consumer orchestration nor a runnable lighthouse has been migrated in this pass.

### Rust transfer checkpoint (2026-09-23, after live-sync repair)

- Rust `AutomergeDeviceSyncFlow` and `MeshBatchDeliveryFlow` now plan document rounds, route fallback, retry, and ACK progression. Match and Twang call the WASM runtime; their hosts still perform transport and storage I/O.
- Rust live-session control frames no longer reset Automerge state on every authority payload. Session selection now elects one dialer per device pair. Match executes gossip I/O outside the document queue, so a slow gossip callback cannot block local document publication. Rust receive plans now expose `serializeDocument`; Match consumes that field, but this last binding change still requires final consumer verification.
- Before the `serializeDocument` binding change, five selected Match E2E scenarios passed in one run: browser↔native signed editor/revocation, browser tab close/reconnect, unsigned change rejection while connected, oversized control history/reconnect, and browser↔browser two-way cards/offline recovery. This is **not** a final post-transfer E2E result or production verification.
- Remaining code groups: authenticated handshake host sequencing; session/gossip lifecycle scheduling; signed scope genesis and authority commands; Match/Twang adapter cleanup. `6.7`, `7.3`, `7.4`, and `7.5` remain open. `7.6` requires a final run after those changes.
- Current raw TS file sizes: Match's seven core sync files 2,767 lines; seven shared browser runtime adapter files 883 lines; Twang's whole `src/engine.ts` 2,651 lines. These include transport, UI/product, and persistence code and are **not** a remaining-protocol LOC estimate.
- No lighthouse process exists. No Kotlin work in this transfer pass. No production deployment of this branch.

### Scope runtime checkpoint (2026-09-23)

- `meta-mesh-core` now owns Match scope-frame dispatch, Automerge receive preparation, durable completion before reply, publish ordering, and reset after failed persistence or accepted authority control. `BrowserMeshScopeSync` performs browser storage and stream effects. Match wires it through `workspaceSet.ts`; vendored Meta-mesh `d5820db` passes Match typecheck and production build.
- Rust core: 138 tests pass. Meta-mesh WASM build and TypeScript check pass. Twang TypeScript check passes after changing the room RPC tag from `room-sync-v2` to `room-sync` and deleting unused `direct-sync`/`group-sync` receivers. No Twang consumer/runtime migration, final E2E, production deployment, or lighthouse process is claimed by these checks.
- Match and Twang already use the same Rust `AutomergeSyncEngine`. Match's authenticated stream and Twang's request/response ACK are transport envelopes, not separate Automerge algorithms. An unused second `MeshDocumentRuntime` wrapper was removed. Twang still has TypeScript document delivery orchestration; `6.7`, `7.3`–`7.6` remain open.

### Consumer and native checkpoint (2026-09-23, after targeted sync checks)

- Canonical Meta-mesh `582ff27` serializes live frame decode/application with document publication and reads fresh storage inside that queue. Rust enum fields now reach WASM as `shouldPersist` and `closeSend` (`ed4092f`). Rust core had 138 passing tests; WASM build and Meta-mesh TypeScript check passed.
- Match `codex/rust-live-sync` pins `582ff27`. Typecheck, production build, and 20 workspace-set unit tests passed. One browser↔browser card test failed once before the receive-queue fix; the same targeted test then passed twice after the fix. The complete E2E suite and production deployment have **not** been verified for this revision.
- Twang `codex/rust-live-sync` pins `582ff27`. Its old `direct-sync`/`group-sync` receivers are gone; the RPC tag is `room-sync`. Typecheck and targeted direct/group chat E2E passed after replacing stale public WASM assets. This does not prove reconnect, native sync, or the complete Twang E2E suite.
- Native `be7ccbe` adds `NativeScopePeer`, a host adapter over the same `MeshScopeRuntime` used by Match. It compiles; a focused test confirms failed persistence does not emit a document acknowledgement and can retry. This is **not** a runnable lighthouse, durable scope store, Match-authorized card writer, or homepage form.
- Remaining for this goal: consolidate signed scope genesis/authority command boundaries, remove duplicated protocol decisions where still present in Match/Twang host code, verify full browser and native sync/reconnect after final integration, then build and wire an authorized native lighthouse. Browser and product storage/network callbacks necessarily remain in TypeScript.

### Dependency status (2026-09-20)

- Native target: `iroh 1.2.0`, `iroh-gossip 0.101.0`, `iroh-blobs 0.103.0` available.
- Browser target: `iroh-webrtc-transport 0.1.0-alpha.2` still pins `iroh 0.98.2` and `wasm-bindgen 0.2.118`.
- A single dependency graph cannot currently combine Iroh 1.2's `ed25519-dalek >=3.0.0-rc.0` with the browser adapter's exact Iroh 0.98 dependency. Crate separation is required, not optional cleanup.
