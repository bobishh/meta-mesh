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
