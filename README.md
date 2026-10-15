# Mesh

Reusable browser P2P primitives for identity, signed routes, durable delivery, sparse gossip, native Automerge anti-entropy, calling, blobs, and contact bootstrap.

Rust layout:

- `crates/meta-mesh-core`: platform-neutral protocol code. No browser, WASM, or Iroh dependency; owns pairing frames, identity/recovery crypto, Ed25519 envelopes, grants, invitations, certificate admission, workspace ownership/succession/revocation, peer/replica merge policy, durable admission/outbox transitions, route/ACK policy, and Automerge sync state for web, iOS, Android, and native clients.
- `crates/meta-mesh-native`: native/mobile runtime on current Iroh, iroh-gossip, and iroh-blobs. Owns endpoint identity, admission, gossip, Bao blob transfer, and memory/disk stores.
- `crates/meta-mesh-mobile`: UniFFI adapter over the same core and native runtime. `scripts/generate-mobile-bindings.sh` emits checked-in Swift and Kotlin APIs for iOS and Android clients.
- `crates/meta-mesh`: browser-only WASM adapter on the WebRTC transport's pinned Iroh version. No native runtime fallback.

The npm workspace is marked `private` so root-package publishing cannot happen accidentally. Packages are consumed from a pinned Git submodule until their API stabilizes. Repository visibility is a separate GitHub setting.

See [replication protocol](docs/replication.md) for identity boundaries, route lifecycle, delivery guarantees, browser-instance behavior, security checks, and operational traces.
See [verification measurements](docs/measurements.md) for current topology, byte, duplicate, reconnect, and limitation evidence.
See [protocol models](formal/README.md) for bounded TLA+ checks of authority epochs, session generations, and durable batch acknowledgements.
See [co-owned scope governance](docs/coownership.md) for opt-in v2 quorum, conflict resolution, independent forks, and consumer integration limits.
See [causal write admission](docs/causal-admission.md) for retained raw history, revocation reclassification, authorized projections, and grant-bound transaction provenance.

Identity recovery uses a random 256-bit Ed25519 root. A 4, 12, or 24-word recovery phrase derives an AES-256-GCM wrapping key with PBKDF2-HMAC-SHA-256 and 600,000 iterations; it never derives the identity itself. Rewrapping with newly generated words changes recovery strength without changing the person ID. Applications own storage and replication of the encrypted version-3 recovery envelope.

Workspace authority is durable application state, separate from live transport. `mesh-peer-store` keeps owner history, grants, revocations, transfer records, and succession records in its `authority` store. Route cleanup and leaving an active mesh remove peers and transport credentials while preserving that signed authority. Full local-data reset may remove both.

`BrowserIdentityStore.refreshPresentation()` verifies durable metadata against
the current identity, certificate and private keys. Unchanged labels retain the
active profile object, preserving in-flight signing guards. Overlapping requests
for the same cached profile and exact expected bytes share one validated read;
different expected snapshots never share success. Real identity/key/certificate
replacement and stale captured bytes still reject without overwriting storage.

No direct-derived identity compatibility or migration path exists. Applications discard pre-envelope sessions. Application-specific passphrases can encrypt a separate envelope around the same random-root model; they never derive identity keys.

## Native history capture

`history_preparation::prepare_workspace_history` derives causal admission and
verifies the current Owner device. `history_capture::capture_workspace_history`
consumes its private token, validates separately retained original JSON against
that evidence and keeps the original bytes. It rejects duplicate/unknown keys
and changed signed payloads; only unsigned container defaults may be absent.
`VerifiedHistoryArchiveCapture::write_catalogue` emits content-addressed original
records, source document/control, proofs and pending originals through a sink.
Objects carry the same page/part binding as the browser archive codec; records and
pages are at most 64 KiB, parts 256 KiB, and index fanout at most 64. A failed sink
leaves the source unchanged. Native admission observations carry the explicit
`mesh-causal-admission@2` policy ID; semantic policy changes require a new ID.
Version 2 preserves valid historical Owner device removals and rejects historical
Owner person removals beyond their outgoing ownership frontier. The preparation
revision includes this exact policy ID. Older `@1` observations remain original
versioned evidence and are not relabeled by a new verifier.
`WasmStateCore.causalAdmissionPolicyId()` reports the compiled rule ID. The shared
Native/WASM control vectors check the actual packaged policy, not a source label;
the two historical-control defects first reproduced in that WASM artifact too.

The catalogue is content, not Owner baseline authorization. Its source-derived
classifications do not make an unsigned serialized catalogue trusted by a receiver.
WASM capture handles, normal host scheduling, per-entity history indexes, network
Owner-transition admission, activation, bounded active history and restore remain open.
The preparation and change/proof maps still scale with source history even though
the index writer buffers bounded pages.

`VerifiedHistoryPreparation::rebase` copies only admitted current state into one
deterministic, explicitly marked Automerge basis change. A typed binary state
digest preserves scalar types, Unicode text, tables and current counter values
without JSON-number coercion. Real signed histories of 1k, 10k and 100k edits to
the same state produce one basis change under 2 KiB. Preparation still reads full
history; this does not establish bounded ordinary writes or active-tail admission.
Conflicting current values, marked/block text and future scalar types currently
reject without replacing the source, rather than flattening unsupported content.
Their lossless support remains required by the complete baseline contract.

Reproduce the shared public test vector from this directory:

```sh
cargo run -p meta-mesh-core --example history_capture_fixture > packages/mesh-replication/fixtures/history-capture-v1.json
```

`historyCaptureInterop.test.ts` checks lazy original reads, retained signatures,
actual WASM reclassification and exact encrypted-journal resume. The example and
fixture contain generated test identities, not user data.

`history-archive-locators` provides a portable encrypted directory from complete
archive binding hashes to opaque ciphertext IDs. Its bounded encrypted pages carry
both plaintext and ciphertext child hashes, so a cold reader starts from one root
without the sender's journal or a flat locator list. `history-archive-locator-preparation`
freezes this directory in a separate durable journal after data coverage, validates
the same source/authority/private/storage bindings and resumes exact ciphertext
after lost replies. Directory and data require separate complete coverage proofs.
SDK, native HTTP and Workerd tests cover cold reads, multi-page retry and tampering.

Native `VerifiedHistoryArchiveCapture::verify_storage_directory` regenerates every
captured object, resolves its binding through authenticated locator pages, opens
the addressed ciphertext and compares exact bytes. Its private, non-deserializable
storage-evidence token retains the Native catalogue, locator root, scope/key digest
and exact sorted data/directory ciphertext sets. This is content correspondence,
not a storage receipt, signed Owner transition or activation authority. Verification
scales with captured history and runs only during preparation. Ordinary WASM/host
producer integration and the full baseline lifecycle remain open.

`VerifiedHistoryArchiveStorage::verify_coverage` derives exact data and directory
coverage trees from those private expected sets. It verifies both strict bounded
aggregate receipts under `RUSTY/2`, pinned service/scope/policy, key epoch and
distinct preparation IDs. A signed subset containing the catalogue root still
fails. The resulting private coverage token retains roots, Native revisions,
key digest and both receipts; it does not establish current Owner authority or
activate history. JavaScript and Native share deterministic signed vectors for
1/64/65/512/513/4101 objects; Native also exercises a lazy 100,000-object set.

`VerifiedHistoryArchiveCapture::bind_rebase` joins private rebase and coverage
evidence against exact source/authority/capture revisions, history epoch, data
preparation ID and preparing Owner/device/full signer chain. It borrows immutable
tokens and retains the full verified control evidence and source frontier. Equal
current content from another source or preparing device cannot substitute for
that preparation. The joined token is not a signed Owner transition, cold-receiver
control proof or activation authority; those integrations remain open.

`VerifiedHistoryBasisArchive::propose_baseline` prepares the exact bounded
`workspace-history-baseline@1` Owner payload under `MESH-HISTORY/1`. It binds
admission policy, raw/admitted frontiers, complete signer chain, state/basis hashes,
archive/locator roots and both signed storage receipts. An initial epoch must be
one; successors require a private verified parent, consecutive epoch, admitted
parent basis and preservation of known signed control evidence. `confirm` rejects
source drift, changed payloads, wrong domains/keys and lossy JSON normalization,
then retains the exact signed envelope and basis in a private attestation token.
This is local preparation/signature verification. It does not implement a cold
receiver's control/frontier proof, active-pointer transaction, capability rollout
or ordinary browser/Worker producer.

Build `cargo build -p meta-mesh-core --example history_archive_verify` for the
application's opt-in Native HTTP acceptance. This stdin adapter has a 32-MiB input
limit, runs real preparation/rebase/capture/storage/coverage and joins the basis
to the original archive before printing a small result. An explicit initial-proposal
request optionally returns the payload and verifies an externally signed envelope;
the adapter never accepts a signing key. The app test supplies ciphertext and both real signed receipts from
a restarted Rusty, signs the Owner payload through the JavaScript identity SDK,
verifies it in Native and checks wrong-domain/substituted coverage rejection. The adapter is test
infrastructure; it is not a live WASM handle, production producer or authority
token transport. Its JSON output cannot authorize baseline activation.

## Browser WASM packaging

`@meta-uber/mesh-transport/wasm` exports policy, identity, pairing, Automerge and
runtime state machines from `meta-mesh-policy`. Initialize it before local policy
reads. This crate has no transitive Iroh/WebRTC dependency.

`@meta-uber/mesh-transport/transport-wasm` exports `BrowserNode`, gossip and blobs
from the transport adapter. Import and initialize it when starting network work.
`scripts/build-wasm.sh` generates both artifacts. The previous relative
`wasm/meta_mesh.js` files remain for existing direct-path consumers; package
imports use the new boundaries.

## Bounded browser blob storage

`@meta-uber/mesh-blob` exposes `MeshBlobStore.putStream(descriptor, source)` and
`getStream(descriptor)`; both load their storage implementation lazily. The
`@meta-uber/mesh-blob/stream` entry exports incremental hash/source helpers and
`preloadBlobStreamStorage()` to warm that implementation before going offline.
Sources and yielded parts use an async byte iterable; canonical persisted chunks are at most 256 KiB.
The stream verifier checks the exact descriptor size and SHA-256/BLAKE3 digest.
Writes stage a new immutable chunk set and publish the pointer only after full
verification using the store's atomic compare-and-swap. Previous byte records
and chunk sets stay untouched. A committed stream pointer takes precedence over
old byte records, including a preserved corrupt record after a successful repair.
Readers verify the final digest only when the
consumer drains the iterable; legacy whole-byte records still require one bounded
whole-record read. This API bounds local blob persistence, not an application's
network encryption/transfer path: callers that collect bytes still allocate the
complete file within the existing maximum.

### Bounded peer reads and stream reset

`MeshStream.read(maximumBytes?)` accepts an optional u32 byte limit; omission
preserves the original zero-argument read for existing callers. The transport
wrapper rejects invalid limits, and current browser WASM reads bounded responses
incrementally. `mesh-blob` requests at most
`ceil(256 KiB / 3) * 4 + 4096` bytes per 256-KiB attachment chunk, then verifies
the returned frame length. The native reader uses an inline `[u8; 16 KiB]`
scratch buffer and checks `remaining + 1` before appending; excess data resets and
retires only that stream before waiting for EOF. `MeshStream.reset()` cancels both directions
without closing the connection. Older cached adapters may ignore the optional
read bound, so the memory guarantee requires compatible adapters.

From this repository, run focused wrapper/blob tests and the native loopback
stream-state harness:

```sh
npm test -- packages/mesh-transport/src/streamReadLimit.test.ts packages/mesh-blob/src/index.test.ts packages/mesh-transport/src/streamReset.test.ts
cargo test -p meta-mesh-transport-tests --lib stream_state::tests
```

## Apple package

Build the iOS device and Apple Silicon simulator binaries, then package them with the generated Swift bindings:

```sh
./scripts/build-apple-xcframework.sh
./scripts/verify-apple-xcframework.sh
```

The generated Swift package lives at `crates/meta-mesh-mobile/generated`. The XCFramework is a local build artifact and is not committed.

Run generated Swift and Kotlin clients against the native runtime, including deny-by-default and revocation checks:

```sh
./scripts/test-mobile-language-interop.sh
```

## Browser release artifacts

`scripts/build-wasm.sh` omits the WebAssembly debugging `name` section from
the shipped browser artifact. This keeps Rust symbol names out of the download;
exports and executable sections are preserved. For symbolized local debugging,
run `wasm-bindgen` on `target/wasm32-unknown-unknown/release/meta_mesh.wasm`
without `--remove-name-section` into a separate local output directory.
