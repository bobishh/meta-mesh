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
