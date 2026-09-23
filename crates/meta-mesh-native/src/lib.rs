pub mod node;

pub use meta_mesh_core::{
    CONTROL_CHUNK_BYTES, ControlChunk, ControlFrameReceiver, MAX_CONTROL_FRAME_BYTES,
    MAX_CONTROL_SNAPSHOT_BYTES, GossipLifecycleState, MeshLifecycleState,
    MeshRuntimeState, MeshSessionLifecycleState, PAIRING_VERSION, PairingCodec,
    PairingFrameHeader, ReconnectState, RouteAttempt, RuntimeSession, SessionAdmission,
    SessionCandidate, SessionDirection, SessionKey, control_frames,
};
pub use node::{
    GossipReceivedMessage, GossipTopicReceiver, GossipTopicSender, NativeNode, NativeNodeOptions,
    NativeRpcInbox, NativeRpcRequest,
};

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
