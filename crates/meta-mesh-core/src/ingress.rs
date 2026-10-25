//! Shared hard limits for authenticated mesh ingress.

use crate::MAX_CONTROL_FRAME_BYTES;
use crate::proof_transfer::MAX_PROOF_FRAME_BYTES;
use crate::{PAIRING_VERSION, PairingFrameHeader};

/// Maximum encoded pairing header, including its newline delimiter.
pub const MAX_PAIRING_HEADER_BYTES: usize = 4 * 1024;
/// Maximum complete frame for ordinary RPC kinds, including header and payload.
pub const MAX_RPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Small fixed completion receipt used after an Identity device enrollment ack.
pub const MAX_ENROLLMENT_COMPLETION_PAYLOAD_BYTES: usize = 256;
/// Finite default for stream reads that do not supply a tighter limit.
pub const DEFAULT_STREAM_READ_BYTES: usize = MAX_RPC_FRAME_BYTES;
/// Existing logical allowance for chunked control snapshots and owner offers.
pub const MAX_LOGICAL_TRANSFER_BYTES: usize = 24 * 1024 * 1024;
/// Existing complete gossip payload ceiling.
pub const MAX_GOSSIP_PAYLOAD_BYTES: usize = 256 * 1024;
/// JSON/base64 envelope allowance for a 256-KiB Automerge message and metadata.
pub const MAX_AUTOMERGE_WIRE_PAYLOAD_BYTES: usize = 512 * 1024;
/// Maximum bytes reserved by concurrent frame reads on one authenticated peer.
pub const MAX_IN_FLIGHT_BYTES_PER_CONNECTION: usize = 32 * 1024 * 1024;
/// Maximum concurrent payload frame reads on one authenticated peer.
pub const MAX_CONCURRENT_FRAMES_PER_CONNECTION: usize = 2;
/// Maximum simultaneous bounded header waits on one authenticated peer.
/// Header reservations share the byte budget with payloads; idle responses cannot occupy payload slots.
/// Native ingress reuses this count for queued, unread streams across peer connections and ALPNs.
pub const MAX_CONCURRENT_HEADERS_PER_CONNECTION: usize = 32;
/// Upper bound on pages in one logical transfer.
pub const MAX_TRANSFER_PAGES: usize = 256;
/// Maximum time allowed for one bounded logical transfer.
pub const MAX_TRANSFER_DEADLINE_MS: u32 = 600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingFrameBudget {
    /// Complete wire bytes including JSON header and delimiter.
    pub max_wire_bytes: usize,
    /// Payload bytes after the delimiter.
    pub max_payload_bytes: usize,
}

/// Returns the hard budget for every supported pairing frame kind.
///
/// Special-purpose frames retain their existing stricter payload or total-wire
/// units. Other frame kinds share the complete 16 MiB RPC ceiling.
pub fn pairing_frame_budget(frame_type: &str) -> Option<PairingFrameBudget> {
    let (max_wire_bytes, max_payload_bytes) = match frame_type {
        "sync-heartbeat"
        | "sync-heartbeat-ack"
        | "mesh-handoff-request"
        | "mesh-handoff-ready"
        | "mesh-handoff-confirmed" => (MAX_RPC_FRAME_BYTES, 0),
        "enroll-complete" => (MAX_RPC_FRAME_BYTES, MAX_ENROLLMENT_COMPLETION_PAYLOAD_BYTES),
        "mesh-control-sync" => (MAX_RPC_FRAME_BYTES, MAX_CONTROL_FRAME_BYTES),
        "mesh-owner-workspace-offer-page-v1" => (MAX_RPC_FRAME_BYTES, MAX_CONTROL_FRAME_BYTES),
        "mesh-iroh-gossip" => (MAX_RPC_FRAME_BYTES, MAX_GOSSIP_PAYLOAD_BYTES),
        "mesh-automerge-sync" => (MAX_RPC_FRAME_BYTES, MAX_AUTOMERGE_WIRE_PAYLOAD_BYTES),
        "mesh-proof-request-v1" | "mesh-proof-page-v1" => {
            (MAX_PROOF_FRAME_BYTES, MAX_PROOF_FRAME_BYTES - 1)
        }
        "sync-request"
        | "sync-response"
        | "sync-ack"
        | "sync-update"
        | "enroll-request"
        | "enroll-approved"
        | "enroll-rejected"
        | "enroll-rejected-ack"
        | "enroll-ack"
        | "workspace-join-request"
        | "workspace-join-response"
        | "workspace-join-rejected-ack"
        | "mesh-handshake-request"
        | "mesh-handshake-response"
        | "mesh-owner-workspace-offer"
        | "mesh-durable-batch"
        | "mesh-durable-ack"
        | "mesh-blob-request-v1"
        | "mesh-blob-response-v1"
        | "mesh-blob-error-v1" => (MAX_RPC_FRAME_BYTES, MAX_RPC_FRAME_BYTES - 1),
        _ => return None,
    };
    Some(PairingFrameBudget {
        max_wire_bytes,
        max_payload_bytes,
    })
}

/// Calculates the exact payload allowance after accounting for this secret's
/// serialized header, before a caller copies payload bytes across an FFI.
pub fn pairing_payload_limit(frame_type: &str, secret: &str) -> Result<usize, String> {
    let budget =
        pairing_frame_budget(frame_type).ok_or_else(|| "Pairing frame invalid".to_string())?;
    let header = PairingFrameHeader {
        frame_type: frame_type.to_string(),
        version: PAIRING_VERSION.to_string(),
        secret: secret.to_string(),
    };
    let header_bytes = serde_json::to_vec(&header)
        .map_err(|_| "Pairing frame invalid".to_string())?
        .len()
        .saturating_add(1);
    if header_bytes > MAX_PAIRING_HEADER_BYTES || header_bytes > budget.max_wire_bytes {
        return Err(format!(
            "Pairing header exceeds ingress limit: kind={frame_type} bytes={header_bytes} max={MAX_PAIRING_HEADER_BYTES}"
        ));
    }
    Ok(budget
        .max_payload_bytes
        .min(budget.max_wire_bytes - header_bytes))
}

/// Applies an optional caller limit without allowing it to loosen the profile.
pub fn effective_read_limit(caller_limit: Option<usize>, hard_limit: usize) -> usize {
    caller_limit.map_or(hard_limit, |limit| limit.min(hard_limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_exposes_finite_rpc_and_stricter_kind_limits() {
        assert_eq!(MAX_PAIRING_HEADER_BYTES, 4_096);
        assert_eq!(MAX_RPC_FRAME_BYTES, 16_777_216);
        assert_eq!(
            pairing_frame_budget("mesh-control-sync")
                .unwrap()
                .max_payload_bytes,
            MAX_CONTROL_FRAME_BYTES
        );
        assert_eq!(
            pairing_frame_budget("mesh-proof-page-v1")
                .unwrap()
                .max_wire_bytes,
            MAX_PROOF_FRAME_BYTES
        );
        assert_eq!(pairing_frame_budget("mesh-unknown"), None);
    }

    #[test]
    fn concurrent_header_reservations_fit_beside_a_full_payload() {
        assert!(MAX_CONCURRENT_HEADERS_PER_CONNECTION > MAX_CONCURRENT_FRAMES_PER_CONNECTION);
        assert!(
            MAX_CONCURRENT_HEADERS_PER_CONNECTION * MAX_PAIRING_HEADER_BYTES + MAX_RPC_FRAME_BYTES
                <= MAX_IN_FLIGHT_BYTES_PER_CONNECTION
        );
        let heartbeat = PairingFrameHeader {
            frame_type: "sync-heartbeat-ack".to_owned(),
            version: PAIRING_VERSION.to_owned(),
            secret: "scope".to_owned(),
        };
        let header_bytes = serde_json::to_vec(&heartbeat).unwrap().len() + 1;
        assert!(
            header_bytes
                + pairing_frame_budget(&heartbeat.frame_type)
                    .unwrap()
                    .max_payload_bytes
                <= MAX_PAIRING_HEADER_BYTES
        );
    }

    #[test]
    fn omitted_read_limits_are_finite_and_explicit_limits_only_tighten() {
        assert_eq!(
            effective_read_limit(None, MAX_RPC_FRAME_BYTES),
            MAX_RPC_FRAME_BYTES
        );
        assert_eq!(effective_read_limit(Some(1), MAX_RPC_FRAME_BYTES), 1);
        assert_eq!(
            effective_read_limit(Some(usize::MAX), MAX_RPC_FRAME_BYTES),
            MAX_RPC_FRAME_BYTES
        );
    }
}
