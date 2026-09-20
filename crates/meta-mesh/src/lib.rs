pub mod blobs;
pub mod gossip;
#[cfg(target_family = "wasm")]
pub mod identity;
pub mod node;
pub mod pairing;

pub use blobs::{BlobDescriptor, BlobEngine, ParsedTicket, WasmBlobEngine};
pub use gossip::{GossipEngine, GossipPacket, WasmGossipEngine};
pub use meta_mesh_core::{PairingCodec, PairingFrameHeader};
pub use pairing::WasmPairingCodec;

#[cfg(target_family = "wasm")]
pub use identity::WasmIdentityCrypto;
#[cfg(target_family = "wasm")]
pub use node::{
    BrowserAcceptor, BrowserConnection, BrowserNode, BrowserStream, start_browser_node,
};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn mesh_version() -> String {
    "0.1.0".to_string()
}
