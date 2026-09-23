use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::validate_mesh_capabilities;

const MAX_HANDSHAKE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PEERS: usize = 512;
const MAX_AUTHORITY_RECORDS: usize = 32;

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

pub fn validate_mesh_handshake(mut raw: Value, expected_workspace_id: Option<&str>) -> Result<MeshHandshake, String> {
    if let Some(claims) = raw.get("breakGlassClaims") {
        if !matches!(claims, Value::Array(items) if items.is_empty()) {
            return Err("Break-glass authority is no longer supported".to_string());
        }
        raw.as_object_mut().expect("field belongs to an object").remove("breakGlassClaims");
    }
    let encoded = serde_json::to_vec(&raw).map_err(|_| "Invalid mesh handshake".to_string())?;
    if encoded.len() > MAX_HANDSHAKE_BYTES { return Err("Mesh handshake exceeds size limit".to_string()); }
    let handshake: MeshHandshake = serde_json::from_value(raw).map_err(|_| "Invalid mesh handshake".to_string())?;
    if handshake.workspace_id.is_empty()
        || expected_workspace_id.is_some_and(|workspace_id| workspace_id != handshake.workspace_id)
        || !handshake.peer.is_object()
        || handshake.revocations.len() > MAX_PEERS
        || handshake.device_revocations.len() > MAX_PEERS
        || handshake.departures.len() > MAX_PEERS
        || handshake.ownership_transfers.len() > MAX_AUTHORITY_RECORDS
        || handshake.succession_votes.len() > MAX_AUTHORITY_RECORDS
        || handshake.succession_claims.len() > MAX_AUTHORITY_RECORDS
        || handshake.owner_workspace_ids.as_ref().is_some_and(|ids| ids.len() > MAX_PEERS || ids.iter().any(|id| id.is_empty()))
    {
        return Err("Invalid mesh handshake".to_string());
    }
    validate_mesh_capabilities(&handshake.capabilities)?;
    Ok(handshake)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate_mesh_handshake;

    #[test]
    fn validates_bounded_handshake_for_expected_workspace() {
        let handshake = json!({
            "workspaceId": "workspace",
            "peer": { "advertisement": {} },
            "capabilities": ["iroh-gossip-v1", "automerge-sync-v1"],
        });
        let validated = validate_mesh_handshake(handshake, Some("workspace")).unwrap();
        assert_eq!(validated.workspace_id, "workspace");
        let round_trip = serde_json::to_value(validated).unwrap();
        assert!(round_trip.get("successionPolicy").is_none());
        assert!(round_trip.get("ownerWorkspaceIds").is_none());
    }

    #[test]
    fn ignores_an_empty_obsolete_claim_list_but_rejects_authority_evidence() {
        let base = json!({ "workspaceId": "workspace", "peer": {}, "capabilities": ["iroh-gossip-v1", "automerge-sync-v1"] });
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
        let missing_sync = json!({ "workspaceId": "workspace", "peer": {}, "capabilities": ["iroh-gossip-v1"] });
        assert_eq!(validate_mesh_handshake(missing_sync, Some("workspace")).unwrap_err(),
            "Peer does not support required Automerge sync");
    }
    #[test]
    fn rejects_removed_break_glass_evidence() {
        assert!(validate_mesh_handshake(json!({ "workspaceId": "workspace", "peer": {}, "capabilities": ["iroh-gossip-v1", "automerge-sync-v1"], "breakGlassClaims": [{}] }), Some("workspace")).is_err());
    }

}
