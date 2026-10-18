pub mod node;
pub mod scope;
pub mod scope_admission;
pub mod scope_rpc;
pub mod scope_service;
pub mod scope_store;

pub use meta_mesh_core::{
    CONTROL_CHUNK_BYTES, ControlChunk, ControlFrameReceiver, DEFAULT_STREAM_READ_BYTES,
    GossipLifecycleState, MAX_CONCURRENT_FRAMES_PER_CONNECTION, MAX_CONTROL_FRAME_BYTES,
    MAX_CONTROL_SNAPSHOT_BYTES, MAX_IN_FLIGHT_BYTES_PER_CONNECTION, MAX_LOGICAL_TRANSFER_BYTES,
    MAX_PAIRING_HEADER_BYTES, MAX_RPC_FRAME_BYTES, MAX_TRANSFER_DEADLINE_MS, MAX_TRANSFER_PAGES,
    MeshLifecycleState, MeshRuntimeState, MeshSessionLifecycleState, PAIRING_VERSION, PairingCodec,
    PairingFrameHeader, ReconnectState, RouteAttempt, RuntimeSession, SessionAdmission,
    SessionCandidate, SessionDirection, SessionKey, control_frames, effective_read_limit,
    pairing_frame_budget, pairing_payload_limit,
};
pub use node::{
    GossipReceivedMessage, GossipTopicReceiver, GossipTopicSender, NativeBrowserConnection,
    NativeBrowserRequest, NativeNode, NativeNodeOptions, NativeRpcInbox, NativeRpcRequest,
};
pub use scope::{NativeOwnerOfferSnapshot, NativeScopeHost, NativeScopePeer, NativeScopeSnapshot};
pub use scope_admission::NativeScopeAdmission;
pub use scope_rpc::{
    ScopePublishError, ScopePublishFailureKind, publish_scope_to, serve_scope_connection,
    serve_scope_request,
};
pub use scope_service::{NativeScopeCredential, NativeScopeService, NativeScopeServiceHost};
pub use scope_store::FileScopeStore;

pub const IROH_VERSION: &str = "1.2.0";
pub const IROH_GOSSIP_VERSION: &str = "0.101.0";
pub const IROH_BLOBS_VERSION: &str = "0.103.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_runtime_uses_shared_protocol_core() {
        let frame = PairingCodec::encode("sync-request", "secret", &[1]).unwrap();
        assert_eq!(
            PairingCodec::decode(&frame, "sync-request", "secret").unwrap(),
            vec![1]
        );
    }
}
