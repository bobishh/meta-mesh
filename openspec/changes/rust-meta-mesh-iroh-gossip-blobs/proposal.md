## Why

Meta-mesh currently implements an in-house sparse gossip overlay and custom chunked blob transfer protocol in TypeScript. These subsystems add maintenance overhead, are limited in scaling for high participant counts and large media attachments, and replicate functionality that Iroh already provides natively with production-grade performance. Rewriting meta-mesh in Rust using `iroh-gossip` and `iroh-blobs` provides robust, high-performance P2P gossip and content-addressed blob delivery across Match and Twang, with Automerge retaining pure ownership of document state, metadata, and blob locations.

## What Changes

- Migrate custom TypeScript `SparseGossip` overlay to Rust-backed `iroh-gossip` topic broadcast trees (HyParView/PlumTree).
- Migrate custom TypeScript chunked `mesh-blob` transfer to native `iroh-blobs` content-addressed storage, Blake3 hashing, Bao verified streaming, and blob tickets.
- Implement a platform-neutral Rust core plus WebAssembly, iOS, Android, and native runtime adapters. Browser applications retain TypeScript only for UI integration.
- Migrate identity, pairing, admission, workspace authority, peer state, durable delivery, and protocol framing from TypeScript into the shared Rust core.
- Establish an Automerge-centric blob architecture: Automerge CRDT documents own attachment metadata (blob ticket, Blake3 hash, file name, mime type, byte size), while Iroh handles peer-to-peer storage, streaming, and caching.
- Package Rust WASM bindings within `meta-mesh` packages (`@meta-uber/mesh-*`) and native bindings for future mobile clients so every client consumes one protocol implementation.
- Update `match` and `twang` engines, types, and attachment pipelines to integrate with the new `iroh-gossip` and `iroh-blobs` model.

## Capabilities

### New Capabilities
- `iroh-gossip-transport`: Distributed topic-based gossip broadcast overlay utilizing `iroh-gossip` with broadcast trees (HyParView + PlumTree), replacing custom gossip state machines and message forwarding.
- `iroh-blobs-storage`: Content-addressed P2P blob storage and streaming utilizing `iroh-blobs` with Blake3 hashes, Bao streaming verification, and tickets, with Automerge owning blob metadata and references.
- `rust-mesh-core`: Platform-neutral Rust core providing protocol framing, identity, authorization, workspace state, durable delivery, gossip coordination, and blob semantics.
- `rust-mesh-platform-adapters`: WASM bindings for browsers and native Swift/Kotlin bindings for mobile clients.

### Modified Capabilities
None. Meta-mesh has no checked-in baseline OpenSpec capabilities yet.

## Impact

- Canonical `meta-mesh` repository: Added Rust crate (`crates/meta-mesh` / `Cargo.toml`), compiled WASM artifacts, and updated TypeScript packages (`mesh-transport`, `mesh-replication`, `mesh-blob`, `mesh-identity`).
- Match: Updated sync engine and attachment handling to use the Rust WASM runtime with `iroh-gossip` topic communication and `iroh-blobs` transfer.
- Twang: Updated messaging engine to broadcast messages/sync via `iroh-gossip` and manage attachments through `iroh-blobs` with Automerge metadata ownership.
- Dependencies: Introduced Rust dependencies on `iroh`, `iroh-gossip`, `iroh-blobs`, `iroh-webrtc-transport`, `wasm-bindgen`. Removed obsolete custom chunking protocols.
