## ADDED Requirements

### Requirement: Unified Rust WebAssembly mesh runtime
The system SHALL compile the core `meta-mesh` Rust crate to WebAssembly (`wasm32-unknown-unknown`), exposing node lifecycle management, Iroh WebRTC and relay connections, gossip operations, and blob storage to browser environments.

#### Scenario: Node initialization and endpoint derivation
- **WHEN** the browser node is started with an optional 32-byte secret seed
- **THEN** the Rust WebAssembly runtime spawns an active node and provides a stable hexadecimal endpoint identifier

#### Scenario: Browser-to-browser stream communication
- **WHEN** a node dials a remote peer endpoint over WebRTC or relay
- **THEN** bidirectional streams are established for protocol framing, sync, and control message exchange

### Requirement: Unified cryptographic identity and envelope operations
The system SHALL support Ed25519 identity generation, PBKDF2/BIP-39 mnemonic recovery wrapping, device certificate chains, and signed envelope creation and verification within the mesh library.

#### Scenario: Envelope signing and chain verification
- **WHEN** a local profile signs an envelope with its device key
- **THEN** any peer holding the corresponding public certificate chain verifies the envelope signature and signer validity

### Requirement: Rust-owned mesh runtime orchestration
The system SHALL own connection lifecycle, route attempts, authenticated session admission, duplicate-session replacement, reconnect scheduling, gossip participation, incremental document sessions, and bounded control transfers in the shared Rust runtime. Consumer TypeScript SHALL only provide platform persistence, browser lifecycle signals, application document admission, and UI notifications.

#### Scenario: Competing routes establish the same session
- **WHEN** incoming and outgoing connections for the same workspace, device, and runtime instance complete concurrently
- **THEN** the Rust runtime deterministically retains one connection and closes the loser without reporting the reachable peer as offline

#### Scenario: Consumer uses the browser runtime
- **WHEN** Match starts workspace synchronization
- **THEN** it constructs the WASM runtime with host callbacks and does not implement handshake, dialing, reconnect, session ownership, or gossip topology itself

### Requirement: Signed scope authority
The platform-neutral Rust core SHALL verify an immutable scope genesis, capability grants, revocations, and explicit control transfers before accepting an operation. A grant SHALL be bound to one scope and authority epoch. A delegate SHALL NOT grant capabilities beyond its own delegable authority. Product role labels SHALL be projections of verified capabilities.

The verified controller from signed genesis or an explicit signed control-transfer chain SHALL have the complete base capability set. This base set SHALL NOT be reconstructed from product documents, cached roles, or participant records.

#### Scenario: Channel-style delegation
- **GIVEN** a scope creator grants publish and invite capabilities to one administrator
- **WHEN** that administrator grants publish to an editor
- **THEN** Rust accepts the editor grant but rejects a control-transfer grant from that administrator unless transfer was explicitly delegated

#### Scenario: Missing authority history
- **GIVEN** a local board or conversation has content but lacks a verifiable authority chain
- **WHEN** the user opens or syncs that scope
- **THEN** Rust does not infer creator or owner rights from cached profiles, local grants, or UI state; the product may create a new scope with a new signed genesis and copied content
