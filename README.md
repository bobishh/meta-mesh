# Mesh

Reusable browser P2P primitives for identity, signed routes, durable delivery, sparse gossip, native Automerge anti-entropy, calling, blobs, and contact bootstrap.

Rust layout:

- `crates/meta-mesh-core`: platform-neutral protocol code. No browser, WASM, or Iroh dependency; intended shared core for web, iOS, Android, and native clients.
- `crates/meta-mesh`: current browser WASM adapter and native Iroh runtime. These adapters will split as the native runtime advances beyond the browser WebRTC transport's pinned Iroh version.

The npm workspace is marked `private` so root-package publishing cannot happen accidentally. Packages are consumed from a pinned Git submodule until their API stabilizes. Repository visibility is a separate GitHub setting.

See [replication protocol](docs/replication.md) for identity boundaries, route lifecycle, delivery guarantees, browser-instance behavior, security checks, and operational traces.
See [verification measurements](docs/measurements.md) for current topology, byte, duplicate, reconnect, and limitation evidence.

Identity recovery uses a random 256-bit Ed25519 root. A 4, 12, or 24-word recovery phrase derives an AES-256-GCM wrapping key with PBKDF2-HMAC-SHA-256 and 600,000 iterations; it never derives the identity itself. Rewrapping with newly generated words changes recovery strength without changing the person ID. Applications own storage and replication of the encrypted version-3 recovery envelope.

No direct-derived identity compatibility or migration path exists. Applications discard pre-envelope sessions. Application-specific passphrases can encrypt a separate envelope around the same random-root model; they never derive identity keys.
