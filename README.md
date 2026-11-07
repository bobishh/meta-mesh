# MetaMesh

MetaMesh is a reusable peer-to-peer SDK for application identity, signed
authorization, durable delivery, gossip, Automerge synchronization, and encrypted
blob transfer. It supplies shared infrastructure to products such as tincanban;
applications keep their own data model, user interface, and business rules.

## Components

| Component | Role |
| --- | --- |
| `meta-mesh-core` | Platform-neutral protocol, identity, authority, delivery, and Automerge policy |
| `meta-mesh-native` | Native runtime using Iroh, gossip, and blob transfer |
| `meta-mesh-mobile` | UniFFI interface for Swift and Kotlin clients over the shared native runtime |
| `meta-mesh` | Browser WebAssembly adapter for the pinned WebRTC transport |
| `packages/*` | TypeScript identity, transport, replication, runtime, storage, and workspace APIs |

The Rust core does not depend on browser, WASM, or Iroh APIs. Browser and native
adapters use the shared protocol code while providing platform-specific transport
and storage.

## Use from an application

Tincanban consumes these packages from a pinned Git submodule. The npm workspace
is private and the packages are not published to npm while their APIs stabilize.
See the [tincanban ecosystem map](https://github.com/bobishh/tincanban/blob/main/README.md) for the
application-to-SDK boundary.

## Check the TypeScript workspace

Requirements: Node.js 22.12 or newer on the supported Node 22, 24, or 26+ lines.

```sh
npm ci
npm run check
npm test
```

## Build platform artifacts

For browser development, `scripts/build-wasm.sh` generates the policy WASM package
and the transport WASM package. `@meta-uber/mesh-transport/wasm` contains policy
and runtime state machines; `@meta-uber/mesh-transport/transport-wasm` contains
`BrowserNode`, gossip, and blobs. Initialize policy WASM before local policy
reads, and initialize transport WASM before network work.

For Apple platforms, `scripts/build-apple-xcframework.sh` builds device and Apple
Silicon simulator artifacts; `scripts/verify-apple-xcframework.sh` checks the
package. Generated Swift and Kotlin clients can be exercised with
`scripts/test-mobile-language-interop.sh`. The generated XCFramework is a local
build artifact.

## Protocol and evidence

- [Replication protocol](docs/replication.md): identity boundaries, route
  lifecycle, delivery guarantees, browser instances, and security checks.
- [Verification measurements](docs/measurements.md): measured topology, bytes,
  duplicates, reconnect behavior, and limits.
- [Causal write admission](docs/causal-admission.md): retained history,
  revocation reclassification, and grant-bound writes.
- [Co-owned scopes](docs/coownership.md): quorum rules, conflict resolution,
  independent forks, and consumer integration limits.
- [Formal models](formal/README.md): bounded checks for authority epochs,
  sessions, delivery, and acknowledgements.

Identity uses a random root key. Recovery words wrap that key; they do not derive
identity. Workspace authority is durable application state, separate from live
transport routes. There is no compatibility path for the former direct-derived
identity scheme. See the protocol docs for exact formats, migration boundaries,
and verification scope.
