# Mesh

Reusable browser P2P primitives for identity, signed routes, durable delivery, sparse gossip, native Automerge anti-entropy, calling, blobs, and contact bootstrap.

Rust layout:

- `crates/meta-mesh-core`: platform-neutral protocol code. No application or Iroh dependency; monotonic deadlines use the portable `web-time` clock. Owns pairing frames, identity/recovery crypto, Ed25519 envelopes, grants, invitations, certificate admission, workspace ownership/succession/revocation, peer/replica merge policy, durable admission/outbox transitions, route/ACK policy, and Automerge sync state for web, iOS, Android, and native clients.
- `crates/meta-mesh-native`: native/mobile runtime on current Iroh, iroh-gossip, and iroh-blobs. Owns endpoint identity, admission, gossip, Bao blob transfer, and memory/disk stores.
- `crates/meta-mesh-mobile`: UniFFI adapter over the same core and native runtime. `scripts/generate-mobile-bindings.sh` emits checked-in Swift and Kotlin APIs for iOS and Android clients.
- `crates/meta-mesh`: browser-only WASM adapter on the WebRTC transport's pinned Iroh version. No native runtime fallback.

The npm workspace is marked `private` so root-package publishing cannot happen accidentally. Packages are consumed from a pinned Git submodule until their API stabilizes. Repository visibility is a separate GitHub setting.

Shared Identity sign-in, service sessions and resource ownership contracts are described in [Identity and resource access](docs/identity-and-resource-access.md).

An approved Identity manager can publish its verified authority view to a new
Rusty service using its own device key. `createIdentityManagerAuthorityView`
checks the manager certificate chain and revocations without requiring recovery
material. Ordinary app certificates do not have this management role. The
separate `createLocalRootIdentityAuthorityView` helper retains its local-root
requirement for application genesis.

## Independent Rusty replica clients

`@meta-uber/mesh-replication/rusty-replica` exports the shared Rusty origin,
bounded HTTP, opaque encryption/AAD, object hash and pinned storage-receipt
contracts. `uploadRustyObject` verifies the signed receipt against the exact
scope, epoch, object, request and policy before returning. A storage receipt
establishes durable ciphertext storage; it does not authorize product changes.
The existing `replica-engine` and `history-archive*` exports remain the engine and
archive contracts. They do not depend on a consuming application's source tree.

`@meta-uber/mesh-replication/rusty-principal-grant` registers one current workspace
member's Rusty access. The host supplies membership intent, the accepted workspace
authority and local signing capability; the SDK owns authority freshness checks,
token hashing, wire normalization, signature verification and registration HTTP.
The host must reject revoked membership in its `ensureCurrent` guard. Registration
retries use the same membership grant; an accepted controller or policy change
requires fresh authoritative state instead of rewriting the signed grant.

Hosts own credentials, durable CAS, lifetime guards and product admission. Save
the exact pending ciphertext and request ID before sending; after an uncertain
reply, restart and retry those bytes rather than encrypting a replacement. Hosts
must recheck current authority and commit accepted progress before acknowledging
or publishing saved state. The independent-consumer CI job exercises public
exports with the policy WASM built from the same source revision.

See [replication protocol](docs/replication.md) for identity boundaries, route lifecycle, delivery guarantees, browser-instance behavior, security checks, and operational traces.
See [verification measurements](docs/measurements.md) for current topology, byte, duplicate, reconnect, and limitation evidence.
See [protocol models](formal/README.md) for bounded TLA+ checks of authority epochs, session generations, and durable batch acknowledgements.

Browser ingress shares one 32-MiB read budget across connections to the same
authenticated endpoint. Up to 32 bounded header reads may wait independently;
their 4-KiB reservations count toward that same byte budget. The native reader
validates the frame kind before requesting its payload reservation, with at most
two payload reads active. A response that has not arrived therefore cannot
occupy a full payload slot and block another board's heartbeat. Older transport
adapters retain the conservative full-frame reservation and bounded queue.
See [co-owned scope governance](docs/coownership.md) for opt-in v2 quorum, conflict resolution, independent forks, and consumer integration limits.
See [causal write admission](docs/causal-admission.md) for retained raw history, revocation reclassification, authorized projections, and grant-bound transaction provenance.

Identity recovery uses a random 256-bit Ed25519 root. A 4, 12, or 24-word recovery phrase derives an AES-256-GCM wrapping key with PBKDF2-HMAC-SHA-256 and 600,000 iterations; it never derives the identity itself. Rewrapping with newly generated words changes recovery strength without changing the person ID. Applications own storage and replication of the encrypted version-3 recovery envelope.

`signEnvelope` captures a detached plain JSON payload before asynchronous signing.
Undefined object members are omitted as on the JSON wire; arrays require defined,
dense entries. Unsupported object types, accessors, cycles and non-finite numbers
reject before signing. Binary data needs an explicit application encoding. The
returned payload is the exact captured data covered by the signature.
JavaScript recovery phrase helpers are exported from `@meta-uber/mesh-identity/recovery`.

`@meta-uber/mesh-workspace` exports `createAutomationWorkspaceGrant` for explicit
automation scopes. The host selects board, columns, fields and expiry and supplies
its live signing guard; the SDK owns exact wire validation and signing. Persist
the approval intent and its `grantId` before delivery to retry the same grant.
`parseAutomationGrantScope` validates detached evidence without expanding scope.

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
`mesh-causal-admission@3` policy ID; semantic policy changes require a new ID.
Version 2 preserves valid historical Owner device removals and rejects historical
Owner person removals beyond their outgoing ownership frontier. Current version 3
also admits exact application-source v2 records with immutable original message
and ATS references. The preparation revision includes this exact policy ID.
Older `@1` and `@2` observations remain original versioned evidence and are not
relabeled by a new verifier.
`WasmStateCore.causalAdmissionPolicyId()` reports the compiled rule ID. The shared
Native/WASM control vectors check the actual packaged policy, not a source label;
the two historical-control defects first reproduced in that WASM artifact too.

The catalogue is content, not Owner baseline authorization. Its source-derived
classifications do not make an unsigned serialized catalogue trusted by a receiver.
The WASM adapter exposes opaque preparation, capture, rebase, storage, coverage
and received-baseline handles. Native catalogue indexes support change-hash lookup
and paged chronological entity history, including imported changes without command
metadata. Lookup metadata is not author authorization. Preparation and its
change/proof maps still scale with the captured source history; index pages and
parts are bounded.

`VerifiedHistoryPreparation::rebase` copies only admitted current state into one
deterministic, explicitly marked Automerge basis change. A typed binary state
digest preserves scalar types, Unicode text, tables and current counter values
without JSON-number coercion. Real signed histories of 1k, 10k and 100k edits to
the same state produce one basis change under 2 KiB. Preparation still reads full
history. A verified received baseline separately admits the active tail against
its exact compact root and current signed control evidence.
Conflicting current values, marked/block text and future scalar types currently
reject without replacing the source, rather than flattening unsupported content.
Their lossless support remains required by the complete baseline contract.

Generate a current-policy test vector from this directory into a separate file:

```sh
cargo run --locked -p meta-mesh-core --example history_capture_fixture > /tmp/history-capture-current.json
```

Keep the committed historical fixture unchanged: its original policy ID and bytes
exercise old archive readability.

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
scales with captured history and runs only during preparation. WASM capture
handles expose the same verification to the application producer.

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
control proof or activation authority. Those require the separate Owner
attestation, receiver verification and application activation transaction.

`VerifiedHistoryBasisArchive::propose_baseline` prepares the exact bounded
`workspace-history-baseline@1` Owner payload under `MESH-HISTORY/1`. It binds
admission policy, raw/admitted frontiers, complete signer chain, state/basis hashes,
archive/locator roots and both signed storage receipts. An initial epoch must be
one; successors require a private verified parent, consecutive epoch, admitted
parent basis and preservation of known signed control evidence. `confirm` rejects
source drift, changed payloads, wrong domains/keys and lossy JSON normalization,
then retains the exact signed envelope and basis in a private attestation token.
This legacy version-1 proposal remains available for original historical evidence.
Confirmation alone does not activate a baseline.

The current `propose_owner_attested_baseline` format is version 2 with
`workspace-history-baseline@2` capabilities. Its bounded signed envelope binds the
current Owner attestation, signed scope ledger, current control, compact document
digest and original archive roots. The compact document has its own 256-MiB
content bound, separate from the 256-KiB attestation bound. A cold receiver checks
an independently admitted signed scope genesis, the Owner/device chain and control
continuity. `VerifiedReceivedHistoryBaseline::admit_tail` accepts only descendants
of that exact compact root and applies normal Native authorization to tail changes.

Tincanban connects these WASM handles to durable encrypted preparation, Rusty
coverage, Worker freeze/drain/activation and a compare-and-swap workspace journal.
Original changes, proofs, pending/quarantined observations and prior baselines stay
archived while the active document uses the compact basis and new tail. Earlier
entity versions are loaded explicitly through bounded index paths. Native verifies
the selected original evidence; restoring a version creates a fresh command under
the current author's permissions and retains the original classification/provenance.

Authorized direct peers can relay bounded plaintext archive objects over their
authenticated encrypted device channel without transferring Rusty tokens or keys.
The same Native Owner/control verifier checks the signed baseline and
content-addressed proof paths. This establishes baseline authority, not ciphertext
correspondence to Rusty storage. Saved proof bytes are reverified after restart.

The consumer's Chromium and WebKit acceptance covers an archived Owner baseline,
a credential-free Editor's lazy original-version read, complete private export,
honest incomplete coverage after both sources close, fresh identity/workspace
recovery, and an offline historical restore as a new signed command. Native HTTP
acceptance also exercises the live WASM capture sink and exact original bytes.
These are local acceptance results. Production activation is established separately
by the coordinated CI cohort's exact frontend, Worker, Rusty and SDK artifacts.

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
Its default initializer shares one in-flight initialization across callers and
allows retry after failure. Synchronous initialization rejects while asynchronous
initialization is pending. Use this public entrypoint rather than generated glue.
`scripts/build-wasm.sh` generates both artifacts with Rust 1.98.0 so optimized
browser artifacts stay within the measured startup budget across local and CI
builds. The previous relative
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

The shared core ingress profile sets a 4-KiB maximum pairing header (including
the newline), a 16-MiB maximum complete ordinary pairing frame (header and
payload), and a finite 16-MiB default for raw stream reads when callers omit a
limit. A caller limit can only tighten that default. Existing stricter per-kind
limits remain in force: control, owner-offer-page, gossip, and Automerge
payloads stay at 256 KiB; Automerge's serialized JSON/base64 envelope is capped
at 512 KiB so its inner 256-KiB message fits with metadata. Proof frames retain
their existing 256-KiB complete-wire limit. Pairing readers inspect the bounded header before retaining
payload bytes; raw readers use a separate API and do not require pairing framing.
`mesh-blob` requests at most
`ceil(256 KiB / 3) * 4 + 4096` bytes per 256-KiB attachment chunk, then verifies
the returned frame length. The core 32-MiB header/payload reservation applies
to readers that explicitly reserve it, including the pairing path; native Iroh
does not use it as an aggregate cap. Native readers use bounded scratch buffers, reset
only the affected stream on oversize or timeout, and preserve the connection.
The native registry tracks separate per-peer inbound and outbound budgets across
connections and ALPNs. Each direction allows two concurrent budgeted frame
reads or exchanges. Inbound streams may wait behind those reads in a queue
capped at 32 per peer. Queued
streams do not read payload bytes, overflow resets only that stream, and queue
waits share the 600-second transfer deadline and cancel when their connection
closes. `NativeNode.request` rejects a third concurrent outbound request;
`NativeBrowserConnection.exchange` waits within its caller-supplied deadline,
including stream open. The native directional budgets allow up to four
concurrent budgeted frame reads or exchanges and at most 64 MiB of active
budgeted frame payloads at the 16-MiB per-frame ceiling. This is a transport
budget, not a bound on total process
memory or application-owned payloads after a read completes. The native
registry tracks at most 1,024 live endpoint entries and removes idle entries as
new peers connect. One pending
logical control or owner-offer reassembly is capped separately at 24 MiB, 256
pages, and 600 seconds; owner offers above one frame use the authenticated
`owner-workspace-paging-v1` capability and bounded pages. A peer
without that capability is rejected before an oversized offer is sent. The
browser transport requires the matching WASM profile and bounded pairing-read
API; a stale adapter fails closed instead of ignoring a requested bound.

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
exports and executable sections are preserved. Its browser-only Cargo invocations
use size optimization, thin LTO and one code generation unit to deduplicate
protocol code. Native consumers retain their own release profiles. For symbolized local debugging,
run `wasm-bindgen` on `target/wasm32-unknown-unknown/release/meta_mesh.wasm`
without `--remove-name-section` into a separate local output directory.

Resource connections and explicit service capabilities: [`@meta-uber/mesh-resource`](packages/mesh-resource/README.md). Its shared native/WASM validator is `meta_mesh_core::resource_access`; application approval UI and durable authority storage are host-owned.
