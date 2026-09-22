use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;
const MAX_PEERS: usize = 512;
const MAX_AUTHORITY_RECORDS: usize = 32;

/// Bounded, unsigned catalog carried after an authenticated mesh session.
/// Individual records are verified by their authority-specific Rust verifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshCatalog {
    pub version: u8,
    pub peers: Vec<Value>,
    pub revocations: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_revocations: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub departures: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_transfers: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succession_policy: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succession_votes: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succession_claims: Option<Vec<Value>>,
}

pub fn validate_mesh_catalog(raw: Value) -> Result<MeshCatalog, String> {
    if raw.get("breakGlassClaims").is_some() {
        return Err("Break-glass authority is no longer supported".to_string());
    }
    let encoded = serde_json::to_vec(&raw).map_err(|_| "Invalid mesh catalog".to_string())?;
    if encoded.len() > MAX_CATALOG_BYTES { return Err("Mesh catalog exceeds size limit".to_string()); }
    let catalog: MeshCatalog = serde_json::from_value(raw).map_err(|_| "Invalid mesh catalog".to_string())?;
    if catalog.version != 1
        || catalog.peers.len() > MAX_PEERS
        || catalog.revocations.len() > MAX_PEERS
        || catalog.device_revocations.len() > MAX_PEERS
        || catalog.departures.len() > MAX_PEERS
        || catalog.ownership_transfers.as_ref().is_some_and(|records| records.len() > MAX_AUTHORITY_RECORDS)
        || catalog.succession_votes.as_ref().is_some_and(|records| records.len() > MAX_AUTHORITY_RECORDS)
        || catalog.succession_claims.as_ref().is_some_and(|records| records.len() > MAX_AUTHORITY_RECORDS)
    {
        return Err("Invalid mesh catalog".to_string());
    }
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use super::validate_mesh_catalog;

    #[test]
    fn validates_the_catalog_boundary_and_omits_absent_optional_fields() {
        let catalog = validate_mesh_catalog(json!({ "version": 1, "peers": [], "revocations": [] })).unwrap();
        let encoded = serde_json::to_value(catalog).unwrap();
        assert!(encoded.get("ownershipTransfers").is_none());
    }

    #[test]
    fn rejects_an_unbounded_peer_catalog() {
        let catalog = json!({ "version": 1, "peers": vec![{}; 513], "revocations": [] });
        assert!(validate_mesh_catalog(catalog).is_err());
    }
    #[test]
    fn rejects_removed_break_glass_evidence() {
        assert!(validate_mesh_catalog(json!({ "version": 1, "peers": [], "revocations": [], "breakGlassClaims": [{}] })).is_err());
    }

}
