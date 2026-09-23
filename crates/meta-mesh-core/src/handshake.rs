use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{validate_mesh_capabilities, PairingCodec, PairingFrameHeader};

const MAX_HANDSHAKE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PEERS: usize = 512;
const MAX_AUTHORITY_RECORDS: usize = 32;
const MESH_HANDSHAKE_REQUEST: &str = "mesh-handshake-request";
const MESH_HANDSHAKE_RESPONSE: &str = "mesh-handshake-response";

/// The authenticated portion of a mesh handshake, before the caller resolves
/// workspace authority and verifies the advertised member bundle. Transport
/// adapters supply streams; this type owns the bounded protocol shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshHandshake {
    pub workspace_id: String,
    pub peer: Value,
    #[serde(default)]
    pub revocations: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_revocations: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub departures: Vec<Value>,
    #[serde(default)]
    pub ownership_transfers: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succession_policy: Option<Value>,
    #[serde(default)]
    pub succession_votes: Vec<Value>,
    #[serde(default)]
    pub succession_claims: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_workspace_ids: Option<Vec<String>>,
    pub capabilities: Vec<String>,
}

/// Candidate records supplied by a host's peer store. The host reads storage;
/// the core decides which local advertisement represents this instance.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshHandshakeBundleCandidate {
    pub device_id: String,
    #[serde(default)]
    pub instance_id: Option<String>,
}

pub fn validate_mesh_handshake(
    mut raw: Value,
    expected_workspace_id: Option<&str>,
) -> Result<MeshHandshake, String> {
    if let Some(claims) = raw.get("breakGlassClaims") {
        if !matches!(claims, Value::Array(items) if items.is_empty()) {
            return Err("Break-glass authority is no longer supported".to_string());
        }
        raw.as_object_mut()
            .expect("field belongs to an object")
            .remove("breakGlassClaims");
    }
    let encoded = serde_json::to_vec(&raw).map_err(|_| "Invalid mesh handshake".to_string())?;
    if encoded.len() > MAX_HANDSHAKE_BYTES {
        return Err("Mesh handshake exceeds size limit".to_string());
    }
    let handshake: MeshHandshake =
        serde_json::from_value(raw).map_err(|_| "Invalid mesh handshake".to_string())?;
    if handshake.workspace_id.is_empty()
        || expected_workspace_id.is_some_and(|workspace_id| workspace_id != handshake.workspace_id)
        || !handshake.peer.is_object()
        || handshake.revocations.len() > MAX_PEERS
        || handshake.device_revocations.len() > MAX_PEERS
        || handshake.departures.len() > MAX_PEERS
        || handshake.ownership_transfers.len() > MAX_AUTHORITY_RECORDS
        || handshake.succession_votes.len() > MAX_AUTHORITY_RECORDS
        || handshake.succession_claims.len() > MAX_AUTHORITY_RECORDS
        || handshake
            .owner_workspace_ids
            .as_ref()
            .is_some_and(|ids| ids.len() > MAX_PEERS || ids.iter().any(|id| id.is_empty()))
    {
        return Err("Invalid mesh handshake".to_string());
    }
    validate_mesh_capabilities(&handshake.capabilities)?;
    Ok(handshake)
}

/// Encode a validated mesh handshake with the shared pairing frame codec.
/// Pairing framing remains generic; this boundary restricts it to the two
/// mesh-handshake message types and keeps payload JSON in the Rust core.
pub fn encode_mesh_handshake(
    frame_type: &str,
    secret: &str,
    raw: Value,
) -> Result<Vec<u8>, String> {
    require_mesh_handshake_frame_type(frame_type)?;
    let handshake = validate_mesh_handshake(raw, None)?;
    let payload =
        serde_json::to_vec(&handshake).map_err(|_| "Invalid mesh handshake".to_string())?;
    PairingCodec::encode(frame_type, secret, &payload)
}

/// Inspect only mesh handshake frames. Hosts may use the secret to select
/// credentials, while type validation remains shared protocol policy.
pub fn inspect_mesh_handshake(frame: &[u8]) -> Result<PairingFrameHeader, String> {
    let header = PairingCodec::inspect(frame)?;
    require_mesh_handshake_frame_type(&header.frame_type)?;
    Ok(header)
}

/// Decode, authenticate, and validate one mesh handshake frame through the
/// shared pairing codec. No platform host parses handshake JSON itself.
pub fn decode_mesh_handshake(
    frame: &[u8],
    expected_type: &str,
    secret: &str,
    workspace_id: &str,
) -> Result<MeshHandshake, String> {
    require_mesh_handshake_frame_type(expected_type)?;
    let payload = PairingCodec::decode(frame, expected_type, secret)?;
    let raw = serde_json::from_slice(&payload).map_err(|_| "Invalid mesh handshake".to_string())?;
    validate_mesh_handshake(raw, Some(workspace_id))
}

fn require_mesh_handshake_frame_type(frame_type: &str) -> Result<(), String> {
    if matches!(frame_type, MESH_HANDSHAKE_REQUEST | MESH_HANDSHAKE_RESPONSE) {
        Ok(())
    } else {
        Err("Unsupported mesh handshake".to_string())
    }
}

/// Prefer the exact local device instance, then its legacy instance-less
/// advertisement. Preserve host candidate order for deterministic fallback.
pub fn select_mesh_handshake_bundle(
    candidates: &[MeshHandshakeBundleCandidate],
    local_device_id: &str,
    local_instance_id: &str,
) -> Option<usize> {
    candidates
        .iter()
        .position(|candidate| {
            candidate.device_id == local_device_id
                && candidate.instance_id.as_deref() == Some(local_instance_id)
        })
        .or_else(|| {
            candidates.iter().position(|candidate| {
                candidate.device_id == local_device_id
                    && candidate
                        .instance_id
                        .as_deref()
                        .is_none_or(str::is_empty)
            })
        })
}

/// Authority merge order for authenticated mesh handshakes. Each host action
/// is I/O; Rust decides the protocol order and required transfer refresh.
pub fn plan_mesh_handshake_authority_import(
) -> Result<Vec<crate::AuthorityImportAction>, String> {
    crate::plan_authority_import("handshake", false, true)
}

/// Owner-workspace identifiers are only useful to another device owned by the
/// same owner identity. Keep this disclosure decision platform-neutral.
pub fn should_advertise_owner_workspace_ids(
    credential_owner_person_id: &str,
    local_person_id: &str,
    remote_person_id: &str,
) -> bool {
    credential_owner_person_id == local_person_id && local_person_id == remote_person_id
}

/// The peer which answered an outbound handshake must be the device selected
/// by the dial plan. Keep this identity comparison in the protocol core so
/// every host rejects a substituted response the same way.
pub fn matches_expected_mesh_peer(expected_device_id: &str, verified_device_id: &str) -> bool {
    expected_device_id == verified_device_id
}

/// A session admission must describe the same verified peer. Admission also
/// binds the signed endpoint to the transport endpoint; hosts must not invent
/// a separate identity policy after Rust has admitted the peer.
pub fn matches_admitted_mesh_peer(
    verified_device_id: &str,
    verified_person_id: &str,
    verified_endpoint: &str,
    admitted_device_id: &str,
    admitted_person_id: &str,
    admitted_endpoint: &str,
) -> bool {
    verified_device_id == admitted_device_id
        && verified_person_id == admitted_person_id
        && verified_endpoint == admitted_endpoint
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        decode_mesh_handshake, encode_mesh_handshake, inspect_mesh_handshake,
        matches_admitted_mesh_peer, matches_expected_mesh_peer,
        plan_mesh_handshake_authority_import, select_mesh_handshake_bundle,
        should_advertise_owner_workspace_ids, validate_mesh_handshake,
        MeshHandshakeBundleCandidate,
    };

    #[test]
    fn validates_bounded_handshake_for_expected_workspace() {
        let handshake = json!({
            "workspaceId": "workspace",
            "peer": { "advertisement": {} },
            "capabilities": ["iroh-gossip-v1", "automerge-sync-v1", "device-revocation-v1"],
        });
        let validated = validate_mesh_handshake(handshake, Some("workspace")).unwrap();
        assert_eq!(validated.workspace_id, "workspace");
        let round_trip = serde_json::to_value(validated).unwrap();
        assert!(round_trip.get("successionPolicy").is_none());
        assert!(round_trip.get("ownerWorkspaceIds").is_none());
    }

    #[test]
    fn ignores_an_empty_obsolete_claim_list_but_rejects_authority_evidence() {
        let base = json!({ "workspaceId": "workspace", "peer": {}, "capabilities": ["iroh-gossip-v1", "automerge-sync-v1", "device-revocation-v1"] });
        let mut empty = base.clone();
        empty["breakGlassClaims"] = json!([]);
        assert!(validate_mesh_handshake(empty, Some("workspace")).is_ok());
        let mut occupied = base;
        occupied["breakGlassClaims"] = json!([{}]);
        assert!(validate_mesh_handshake(occupied, Some("workspace")).is_err());
    }

    #[test]
    fn rejects_wrong_workspace_or_missing_required_capability() {
        let handshake = json!({ "workspaceId": "other", "peer": {}, "capabilities": [] });
        assert!(validate_mesh_handshake(handshake, Some("workspace")).is_err());
        let missing_sync =
            json!({ "workspaceId": "workspace", "peer": {}, "capabilities": ["iroh-gossip-v1"] });
        assert_eq!(
            validate_mesh_handshake(missing_sync, Some("workspace")).unwrap_err(),
            "Peer does not support required Automerge sync"
        );
    }
    #[test]
    fn rejects_removed_break_glass_evidence() {
        assert!(validate_mesh_handshake(json!({ "workspaceId": "workspace", "peer": {}, "capabilities": ["iroh-gossip-v1", "automerge-sync-v1"], "breakGlassClaims": [{}] }), Some("workspace")).is_err());
    }

    #[test]
    fn matches_only_the_expected_verified_device() {
        assert!(matches_expected_mesh_peer("device-a", "device-a"));
        assert!(!matches_expected_mesh_peer("device-a", "device-b"));
    }

    #[test]
    fn matches_only_an_admission_bound_to_the_verified_peer() {
        assert!(matches_admitted_mesh_peer(
            "device", "person", "endpoint", "device", "person", "endpoint",
        ));
        assert!(!matches_admitted_mesh_peer(
            "device", "person", "endpoint", "other", "person", "endpoint",
        ));
        assert!(!matches_admitted_mesh_peer(
            "device",
            "person",
            "endpoint",
            "device",
            "person",
            "other-endpoint",
        ));
    }

    #[test]
    fn frames_validated_handshakes_through_the_shared_pairing_codec() {
        let raw = json!({
            "workspaceId": "workspace",
            "peer": {},
            "capabilities": ["iroh-gossip-v1", "automerge-sync-v1", "device-revocation-v1"],
        });
        let frame = encode_mesh_handshake("mesh-handshake-request", "secret", raw).unwrap();
        assert_eq!(
            inspect_mesh_handshake(&frame).unwrap().frame_type,
            "mesh-handshake-request"
        );
        assert_eq!(
            decode_mesh_handshake(&frame, "mesh-handshake-request", "secret", "workspace")
                .unwrap()
                .workspace_id,
            "workspace",
        );
        assert!(
            decode_mesh_handshake(&frame, "mesh-handshake-response", "secret", "workspace")
                .is_err()
        );
        assert!(encode_mesh_handshake("sync-request", "secret", json!({})).is_err());
        let sync_frame = crate::PairingCodec::encode("sync-request", "secret", &[]).unwrap();
        assert!(inspect_mesh_handshake(&sync_frame).is_err());
    }

    #[test]
    fn plans_host_handshake_decisions_without_store_or_network_access() {
        let candidates = vec![
            MeshHandshakeBundleCandidate { device_id: "device".into(), instance_id: None },
            MeshHandshakeBundleCandidate { device_id: "device".into(), instance_id: Some("tab-a".into()) },
        ];
        assert_eq!(select_mesh_handshake_bundle(&candidates, "device", "tab-a"), Some(1));
        assert_eq!(select_mesh_handshake_bundle(&candidates, "device", "tab-b"), Some(0));
        assert!(should_advertise_owner_workspace_ids("owner", "owner", "owner"));
        assert!(!should_advertise_owner_workspace_ids("owner", "owner", "remote"));
        let actions = plan_mesh_handshake_authority_import().unwrap();
        assert!(actions.contains(&crate::AuthorityImportAction::ValidateCapabilities));
        assert!(actions.contains(&crate::AuthorityImportAction::OwnershipTransfers));
    }
}
