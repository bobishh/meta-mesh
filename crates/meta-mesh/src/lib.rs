#[cfg(target_family = "wasm")]
pub mod automerge;
pub mod blobs;
#[cfg(target_family = "wasm")]
mod browser_tracing;
pub mod gossip;
#[cfg(target_family = "wasm")]
pub mod identity;
#[cfg(target_family = "wasm")]
pub mod invitation;
pub mod node;
pub mod pairing;
pub mod runtime;
#[cfg(target_family = "wasm")]
pub mod state;

pub use blobs::{BlobDescriptor, BlobEngine, ParsedTicket, WasmBlobEngine};
pub use gossip::{GossipEngine, GossipPacket, WasmGossipEngine};
pub use meta_mesh_core::{PairingCodec, PairingFrameHeader};
pub use pairing::WasmPairingCodec;
pub use runtime::WasmMeshRuntimeState;

#[cfg(target_family = "wasm")]
pub use automerge::WasmAutomergeSyncEngine;
#[cfg(target_family = "wasm")]
pub use identity::WasmIdentityCrypto;
#[cfg(target_family = "wasm")]
pub use invitation::WasmInvitations;
#[cfg(target_family = "wasm")]
pub use node::{
    BrowserAcceptor, BrowserConnection, BrowserNode, BrowserStream, start_browser_node,
};
#[cfg(target_family = "wasm")]
pub use state::{WasmDeviceRouteCatalog, WasmStateCore};

use wasm_bindgen::prelude::*;

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_name = setBrowserTransportDebugLogging)]
pub fn set_browser_transport_debug_logging(enabled: bool) {
    browser_tracing::set_verbose_transport_logging(enabled);
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_name = browserTransportDebugLoggingEnabled)]
pub fn browser_transport_debug_logging_enabled() -> bool {
    browser_tracing::verbose_transport_logging_enabled()
}

#[wasm_bindgen]
pub fn mesh_version() -> String {
    "0.1.0".to_string()
}
