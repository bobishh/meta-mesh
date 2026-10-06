//! Browser policy WASM. This crate deliberately has no Iroh or WebRTC dependency.

#[cfg(target_family = "wasm")]
#[path = "../../meta-mesh/src/automerge.rs"]
pub mod automerge;
#[cfg(target_family = "wasm")]
#[path = "../../meta-mesh/src/identity.rs"]
pub mod identity;
#[cfg(target_family = "wasm")]
#[path = "../../meta-mesh/src/invitation.rs"]
pub mod invitation;
#[cfg(target_family = "wasm")]
#[path = "../../meta-mesh/src/pairing.rs"]
pub mod pairing;
#[path = "../../meta-mesh/src/runtime.rs"]
pub mod runtime;
#[path = "../../meta-mesh/src/session_lifecycle.rs"]
pub mod session_lifecycle;
#[cfg(target_family = "wasm")]
#[path = "../../meta-mesh/src/state.rs"]
pub mod state;

#[cfg(target_family = "wasm")]
pub use automerge::{WasmAutomergeDeviceSyncFlow, WasmAutomergeSyncEngine};
#[cfg(target_family = "wasm")]
pub use identity::WasmIdentityCrypto;
#[cfg(target_family = "wasm")]
pub use invitation::WasmInvitations;
#[cfg(target_family = "wasm")]
pub use pairing::{WasmPairingCodec, WasmWorkspaceJoinHandoff, WasmWorkspaceJoinHandshake};
pub use runtime::{
    WasmGossipLifecycleState, WasmLiveWorkspaceSession, WasmMeshBatchDeliveryFlow,
    WasmMeshHandshakeFlow, WasmMeshLifecycleState, WasmMeshRuntimeState, WasmMeshScopeRuntime,
};
pub use session_lifecycle::WasmMeshSessionLifecycle;
#[cfg(target_family = "wasm")]
pub use state::{WasmDeviceRouteCatalog, WasmMeshAuthenticatedSessions, WasmStateCore};

#[wasm_bindgen::prelude::wasm_bindgen]
pub fn mesh_version() -> String {
    "0.1.0".to_string()
}
