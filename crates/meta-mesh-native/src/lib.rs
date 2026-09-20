pub use meta_mesh_core::{PAIRING_VERSION, PairingCodec, PairingFrameHeader};

pub const IROH_VERSION: &str = "1.2.0";
pub const IROH_GOSSIP_VERSION: &str = "0.101.0";
pub const IROH_BLOBS_VERSION: &str = "0.103.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_runtime_uses_shared_protocol_core() {
        let frame = PairingCodec::encode("sync-request", "secret", &[1]).unwrap();
        assert_eq!(PairingCodec::decode(&frame, "sync-request", "secret").unwrap(), vec![1]);
    }
}
