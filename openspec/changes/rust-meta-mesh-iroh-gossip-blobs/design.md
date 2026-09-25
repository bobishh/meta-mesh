## Context

`meta-mesh` provides identity, signed routes, durable delivery, sparse gossip, Automerge anti-entropy, calling, and blob transfer across Match and Twang. Currently, gossip and blob chunking are hand-rolled TypeScript modules (`SparseGossip` and `MeshBlobStore`). Meanwhile, Iroh already provides industry-standard, production-tested implementations for both gossip (`iroh-gossip`, implementing HyParView and PlumTree broadcast trees) and content-addressed binary transfer (`iroh-blobs`, implementing Blake3 verified streaming with Bao outboards and tickets).

Rewriting `meta-mesh` in Rust brings native performance, eliminates duplicate protocol implementations, and creates one core shared by browsers and future iOS/Android clients.

## Goals / Non-Goals

**Goals:**
- Implement a platform-neutral Rust core in `mesh`, with separate browser WASM and native runtime adapters.
- Reuse the same core in future iOS and Android clients through generated Swift/Kotlin bindings.
- Replace custom TypeScript gossip with `iroh-gossip` topic broadcast trees for message, change, and sync coordination.
- Replace custom TypeScript chunked blob handling with `iroh-blobs` content-addressed storage and streaming.
- Ensure Automerge CRDT documents own all metadata, filenames, MIME types, and blob locations (tickets/hashes), while `iroh-blobs` handles raw binary transfer and caching.
- Restrict TypeScript wrappers to UI-facing adapters; protocol and authorization logic lives in Rust.
- Ensure all test suites across `mesh`, `match`, and `twang` pass with dual-loop TDD verification.

**Non-Goals:**
- Replacing Automerge CRDT with any alternate data structure.
- Changing consumer UI layouts or unrelated application logic.
- Adding central coordination servers or corporate relays beyond standard Iroh relays.

## Decisions

### 1. Shared Rust Core with Thin Platform Adapters
- **Choice**: Split canonical `mesh/crates/meta-mesh` into a platform-neutral protocol core, a native Iroh runtime, a browser adapter compiled with `wasm-bindgen`, and UniFFI bindings for Swift/Kotlin.
- **Constraint**: `iroh-webrtc-transport 0.1.0-alpha.2` pins Iroh 0.98 and `wasm-bindgen 0.2.118`. Keep that dependency isolated in the browser adapter. Native/mobile runtime advances independently to current Iroh.
- **Alternatives Considered**:
  - Keeping TypeScript for identity/envelopes and only using Rust for transport: Rejected because running gossip and blobs directly in Rust eliminates JS-WASM boundary crossing overhead for network traffic.
  - One mixed native/browser crate: Rejected because the browser transport's old exact pins prevent current native Iroh dependencies from resolving together.

### 2. Topic-Based Gossip Overlay with `iroh-gossip`
- **Choice**: Derive 32-byte `TopicId`s from scope identifiers (workspace ID or conversation ID) using Blake3 hashing. Use `iroh-gossip` to join topics, manage peer views, and broadcast Automerge change hashes, control envelopes, and sync signals across broadcast trees.
- **Alternatives Considered**:
  - Retaining TypeScript `SparseGossip`: Rejected per user mandate to replace our implementation with `iroh-gossip`.

### 3. Automerge Metadata Ownership with `iroh-blobs` Transfer
- **Choice**: When a file is uploaded or attached, `iroh-blobs` computes its Blake3 hash, stores the blob bytes, and generates a `BlobTicket` containing the hash and node address. The Automerge document records the blob metadata `{ type: "blob", hash, ticket, byteLength, mimeType, fileName }`. Peers discovering the attachment via Automerge sync use the ticket to stream the content via `iroh-blobs`.
- **Alternatives Considered**:
  - Embedding base64 or raw bytes in Automerge: Rejected because binary data inflates CRDT document history and memory usage.
  - Storing blobs in custom 256 KiB chunks in IndexedDB: Replaced by native `iroh-blobs` verification and streaming.

### 4. Clean TypeScript Surface for Match & Twang
- **Choice**: Update `@meta-uber/mesh-transport`, `@meta-uber/mesh-replication`, and `@meta-uber/mesh-blob` to wrap the WASM module and present standard async APIs to `match` and `twang`.
- **Alternatives Considered**:
  - Rewriting all of `match` and `twang` in Rust: Out of scope; both are Vue/Svelte web applications with substantial UI code.

### 5. Scope authority shared by workspaces, conversations, and future channels
- **Choice**: Rust owns a scope authority state machine keyed by an immutable scope ID and genesis creator. The signed genesis controller, and only the controller selected by an explicit signed transfer chain, has the full base capability set (read, write, invite, manage members, grant, control). Signed grants carry capabilities rather than product role names; signed revocations and explicit control transfers advance an authority epoch. A grant issuer cannot delegate capabilities it does not hold, and loss of a local credential never creates a new controller.
- **Product boundary**: Match maps owner/editor/visitor to capabilities and stores board documents. Twang maps creator/admin/member to capabilities and stores conversation documents. A future broadcast channel can grant read to subscribers, publish to editors, and member management to admins without adding a channel-specific authority protocol. Product commands still enforce content rules after mesh authorization.
- **Recovery**: Missing or incompatible authority evidence leaves the old scope read-only. Content may be copied into a new scope with a new ID and signed genesis, then members are invited again. Chat profile records, cached grants, device names, and UI roles cannot imply ownership of an old scope.
- **Compatibility**: Existing workspace and conversation envelopes remain explicitly versioned adapters while the common verifier is introduced. Do not silently reinterpret one product's grants as another product's authority, or auto-migrate old break-glass records.

## Risks / Trade-offs

- [WASM compilation requirements on macOS] → Mitigation: Use Homebrew LLVM/LLD tools (`$llvm_prefix/bin/clang` and `ld.lld`) with automated build scripts verified in both local and CI environments.
- [Browser memory limits for large blobs] → Mitigation: Stream blobs with Bao chunk verification; expose verified Blob URLs with clean revocation lifecycles.
- [Topic isolation between workspaces/conversations] → Mitigation: Blake3-derived topic IDs enforce cryptographic topic segregation; messages outside an authorized topic are ignored by peers not joined to that topic.
