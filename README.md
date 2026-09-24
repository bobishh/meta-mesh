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

Identity recovery uses a random 256-bit Ed25519 root. A 4, 12, or 24-word recovery phrase derives an AES-256-GCM wrapping key with PBKDF2-HMAC-SHA-256 and 600,000 iterations; it never derives the identity itself. Rewrapping with newly generated words changes recovery strength without changing the person ID. Applications own storage and replication of the encrypted version-3 recovery envelope.

Workspace authority is durable application state, separate from live transport. `mesh-peer-store` keeps owner history, grants, revocations, transfer records, and succession records in its `authority` store. Route cleanup and leaving an active mesh remove peers and transport credentials while preserving that signed authority. Full local-data reset may remove both.

No direct-derived identity compatibility or migration path exists. Applications discard pre-envelope sessions. Application-specific passphrases can encrypt a separate envelope around the same random-root model; they never derive identity keys.

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
