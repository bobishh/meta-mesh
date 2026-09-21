use serde::{Deserialize, Serialize};

pub const PAIRING_VERSION: &str = "0.0.1";

const PAIRING_FRAME_TYPES: &[&str] = &[
    "sync-request",
    "sync-response",
    "sync-ack",
    "sync-update",
    "sync-heartbeat",
    "sync-heartbeat-ack",
    "enroll-request",
    "enroll-approved",
    "enroll-ack",
    "enroll-complete",
    "workspace-join-request",
    "workspace-join-response",
    "mesh-handshake-request",
    "mesh-handshake-response",
    "mesh-handoff-request",
    "mesh-handoff-ready",
    "mesh-handoff-confirmed",
    "mesh-automerge-sync",
    "mesh-control-sync",
    "mesh-gossip",
    "mesh-iroh-gossip",
    "mesh-durable-batch",
    "mesh-durable-ack",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingFrameHeader {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub version: String,
    pub secret: String,
}

pub struct PairingCodec;

impl PairingCodec {
    pub fn encode(frame_type: &str, secret: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        if !is_pairing_frame_type(frame_type) || secret.is_empty() {
            return Err("Pairing frame invalid".to_string());
        }
        let header = PairingFrameHeader {
            frame_type: frame_type.to_string(),
            version: PAIRING_VERSION.to_string(),
            secret: secret.to_string(),
        };
        let mut frame =
            serde_json::to_vec(&header).map_err(|_| "Pairing frame invalid".to_string())?;
        frame.push(b'\n');
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    pub fn inspect(frame: &[u8]) -> Result<PairingFrameHeader, String> {
        let separator = frame
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| "Pairing frame missing".to_string())?;
        let header: PairingFrameHeader = serde_json::from_slice(&frame[..separator])
            .map_err(|_| "Pairing frame invalid".to_string())?;
        if header.version != PAIRING_VERSION
            || header.secret.is_empty()
            || !is_pairing_frame_type(&header.frame_type)
        {
            return Err("Pairing frame invalid".to_string());
        }
        Ok(header)
    }

    pub fn decode(
        frame: &[u8],
        expected_type: &str,
        expected_secret: &str,
    ) -> Result<Vec<u8>, String> {
        let separator = frame
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| "Pairing frame missing".to_string())?;
        let header: PairingFrameHeader = serde_json::from_slice(&frame[..separator])
            .map_err(|_| "Pairing frame invalid".to_string())?;
        if header.frame_type != expected_type
            || header.version != PAIRING_VERSION
            || header.secret != expected_secret
        {
            return Err("Pairing authorization failed".to_string());
        }
        Ok(frame[separator + 1..].to_vec())
    }
}

fn is_pairing_frame_type(frame_type: &str) -> bool {
    PAIRING_FRAME_TYPES.contains(&frame_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_frame_round_trips_binary_payload() {
        let frame =
            PairingCodec::encode("mesh-control-sync", "workspace-secret", &[0, 1, 255]).unwrap();
        assert_eq!(
            PairingCodec::inspect(&frame).unwrap(),
            PairingFrameHeader {
                frame_type: "mesh-control-sync".to_string(),
                version: PAIRING_VERSION.to_string(),
                secret: "workspace-secret".to_string(),
            }
        );
        assert_eq!(
            PairingCodec::decode(&frame, "mesh-control-sync", "workspace-secret").unwrap(),
            vec![0, 1, 255]
        );
    }

    #[test]
    fn pairing_frame_rejects_wrong_secret() {
        let frame = PairingCodec::encode("sync-request", "wrong-secret", &[1]).unwrap();
        assert_eq!(
            PairingCodec::decode(&frame, "sync-request", "expected-secret").unwrap_err(),
            "Pairing authorization failed"
        );
    }

    #[test]
    fn iroh_gossip_frame_round_trips_binary_packet() {
        let packet = [0, 1, 2, 255];
        let frame = PairingCodec::encode("mesh-iroh-gossip", "workspace-secret", &packet).unwrap();
        assert_eq!(
            PairingCodec::decode(&frame, "mesh-iroh-gossip", "workspace-secret").unwrap(),
            packet
        );
    }

    #[test]
    fn pairing_frame_rejects_unknown_type() {
        assert_eq!(
            PairingCodec::encode("unknown", "secret", &[]).unwrap_err(),
            "Pairing frame invalid"
        );
    }
}
