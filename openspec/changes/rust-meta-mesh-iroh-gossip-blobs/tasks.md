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
- [ ] 6.2 Port identity keys, certificates, grants, signatures, pairing invitations, and admission checks from TypeScript to Rust.
  - [x] Port canonical JSON, SHA-256 key IDs, domain-separated Ed25519 envelopes, certificate hashes, and delegated device-chain verification to `meta-mesh-core`; verify byte-for-byte WebCrypto signature parity and expose WASM bindings.
  - [x] Port legacy pairing links and scoped device/workspace invitations to deterministic Rust models with expiry and wrong-kind validation; verify exact TypeScript URL parity and expose WASM bindings.
- [ ] 6.3 Port pairing and mesh wire framing to Rust; install the Rust codec in Match and Twang production runtimes; remove the TypeScript fallback after parity tests pass.
- [ ] 6.4 Port workspace authority, peer catalog, Automerge orchestration, and durable delivery state machines to Rust.
- [x] 6.5 Upgrade native runtime to current compatible `iroh`, `iroh-gossip`, and `iroh-blobs`; isolate the browser WebRTC adapter's Iroh 0.98 exact pin until upstream support or a maintained replacement exists.
  - [x] Resolve `meta-mesh-native` on `iroh 1.2.0`, `iroh-gossip 0.101.0`, and `iroh-blobs 0.103.0` without the browser dependency graph.
- [ ] 6.6 Add UniFFI Swift and Kotlin bindings over the platform-neutral core and native runtime.
- [ ] 6.7 Migrate Match and Twang to thin UI adapters and delete superseded TypeScript protocol implementations.
- [ ] 6.8 Add cross-platform interoperability tests: browser↔browser, browser↔native, Swift↔native, Kotlin↔native, persistence restart, denial, revocation, and protocol-version failure.
- [ ] 6.9 Add CI gates for Rust unit/integration tests, WASM build/export verification, mobile binding generation, TypeScript wrappers, and consumer builds.

### Dependency status (2026-09-20)

- Native target: `iroh 1.2.0`, `iroh-gossip 0.101.0`, `iroh-blobs 0.103.0` available.
- Browser target: `iroh-webrtc-transport 0.1.0-alpha.2` still pins `iroh 0.98.2` and `wasm-bindgen 0.2.118`.
- A single dependency graph cannot currently combine Iroh 1.2's `ed25519-dalek >=3.0.0-rc.0` with the browser adapter's exact Iroh 0.98 dependency. Crate separation is required, not optional cleanup.
