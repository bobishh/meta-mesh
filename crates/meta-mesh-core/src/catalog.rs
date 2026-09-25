use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    MESH_CAPABILITIES, MeshHandshake, WorkspaceWriteAuthorizationSnapshot, admit_mesh_peer,
};

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

pub fn validate_mesh_catalog(mut raw: Value) -> Result<MeshCatalog, String> {
    if let Some(claims) = raw.get("breakGlassClaims") {
        if !matches!(claims, Value::Array(items) if items.is_empty()) {
            return Err("Break-glass authority is no longer supported".to_string());
        }
        raw.as_object_mut()
            .expect("field belongs to an object")
            .remove("breakGlassClaims");
    }
    let encoded = serde_json::to_vec(&raw).map_err(|_| "Invalid mesh catalog".to_string())?;
    if encoded.len() > MAX_CATALOG_BYTES {
        return Err("Mesh catalog exceeds size limit".to_string());
    }
    let catalog: MeshCatalog =
        serde_json::from_value(raw).map_err(|_| "Invalid mesh catalog".to_string())?;
    if catalog.version != 1
        || catalog.peers.len() > MAX_PEERS
        || catalog.revocations.len() > MAX_PEERS
        || catalog.device_revocations.len() > MAX_PEERS
        || catalog.departures.len() > MAX_PEERS
        || catalog
            .ownership_transfers
            .as_ref()
            .is_some_and(|records| records.len() > MAX_AUTHORITY_RECORDS)
        || catalog
            .succession_votes
            .as_ref()
            .is_some_and(|records| records.len() > MAX_AUTHORITY_RECORDS)
        || catalog
            .succession_claims
            .as_ref()
            .is_some_and(|records| records.len() > MAX_AUTHORITY_RECORDS)
    {
        return Err("Invalid mesh catalog".to_string());
    }
    Ok(catalog)
}

/// Keep only signed, currently admitted member routes. Catalogs are gossip:
/// one invalid bundle must not reject valid peers from the same session.
/// Route sequence wins over wall-clock time; equal routes converge by bytes.
pub fn merge_verified_peer_catalog(
    existing: &[Value],
    incoming: &[Value],
    authority: &WorkspaceWriteAuthorizationSnapshot,
    now_ms: i128,
) -> Result<Vec<Value>, String> {
    if existing.len() > MAX_PEERS || incoming.len() > MAX_PEERS {
        return Err("Mesh peer catalog exceeds size limit".into());
    }
    let mut selected = BTreeMap::<(String, String), (u64, i128, String, Value)>::new();
    for bundle in existing.iter().chain(incoming) {
        let Some(payload) = bundle.pointer("/advertisement/payload") else {
            continue;
        };
        let Some(endpoint) = payload.get("endpoint").and_then(Value::as_str) else {
            continue;
        };
        let handshake = MeshHandshake {
            workspace_id: authority.workspace_id.clone(),
            peer: bundle.clone(),
            revocations: Vec::new(),
            device_revocations: Vec::new(),
            departures: Vec::new(),
            ownership_transfers: Vec::new(),
            succession_policy: None,
            succession_votes: Vec::new(),
            succession_claims: Vec::new(),
            owner_workspace_ids: None,
            capabilities: MESH_CAPABILITIES
                .iter()
                .map(|value| (*value).into())
                .collect(),
        };
        let Ok(peer) = admit_mesh_peer(
            serde_json::to_value(handshake).map_err(|error| error.to_string())?,
            authority,
            endpoint,
            now_ms,
        ) else {
            continue;
        };
        let instance = peer.instance_id.unwrap_or_else(|| endpoint.to_string());
        let sequence = payload
            .get("routeSequence")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let issued = payload
            .get("issuedAt")
            .and_then(Value::as_str)
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .map(|value| value.unix_timestamp_nanos() / 1_000_000)
            .unwrap_or_default();
        let bytes = serde_json::to_string(bundle).map_err(|error| error.to_string())?;
        let key = (peer.device_id, instance);
        let candidate = (sequence, issued, bytes, bundle.clone());
        match selected.get(&key) {
            Some(current)
                if candidate.0 < current.0
                    || (candidate.0 == current.0
                        && (candidate.1, &candidate.2) <= (current.1, &current.2)) =>
            {
                ()
            }
            _ => {
                selected.insert(key, candidate);
            }
        }
    }
    if selected.len() > MAX_PEERS {
        return Err("Mesh peer catalog exceeds size limit".into());
    }
    Ok(selected
        .into_values()
        .map(|(_, _, _, bundle)| bundle)
        .collect())
}

#[cfg(test)]
mod tests {
    use automerge::AutoCommit;
    use serde_json::json;

    use super::{merge_verified_peer_catalog, validate_mesh_catalog};
    use crate::{
        DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, WorkspaceAuthority,
        WorkspaceWriteAuthorizationSnapshot, public_key_from_seed, public_key_id,
        sign_device_certificate, sign_json_envelope,
    };

    #[test]
    fn validates_the_catalog_boundary_and_omits_absent_optional_fields() {
        let catalog =
            validate_mesh_catalog(json!({ "version": 1, "peers": [], "revocations": [] })).unwrap();
        let encoded = serde_json::to_value(catalog).unwrap();
        assert!(encoded.get("ownershipTransfers").is_none());
    }

    #[test]
    fn ignores_an_empty_obsolete_claim_list_but_rejects_authority_evidence() {
        let base = json!({ "version": 1, "peers": [], "revocations": [] });
        let mut empty = base.clone();
        empty["breakGlassClaims"] = json!([]);
        assert!(validate_mesh_catalog(empty).is_ok());
        let mut occupied = base;
        occupied["breakGlassClaims"] = json!([{}]);
        assert!(validate_mesh_catalog(occupied).is_err());
    }

    #[test]
    fn rejects_an_unbounded_peer_catalog() {
        let catalog = json!({ "version": 1, "peers": vec![{}; 513], "revocations": [] });
        assert!(validate_mesh_catalog(catalog).is_err());
    }
    #[test]
    fn rejects_removed_break_glass_evidence() {
        assert!(
            validate_mesh_catalog(
                json!({ "version": 1, "peers": [], "revocations": [], "breakGlassClaims": [{}] })
            )
            .is_err()
        );
    }

    #[test]
    fn signed_peer_catalog_keeps_newest_route_and_drops_unverified_peer() {
        let person_key = public_key_from_seed(&[1; 32]).unwrap();
        let person_id = public_key_id(&person_key).unwrap();
        let device_key = public_key_from_seed(&[2; 32]).unwrap();
        let device_id = public_key_id(&device_key).unwrap();
        let certificate = sign_device_certificate(
            &[1; 32],
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key: device_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let owner = WorkspaceAuthority {
            person_id: person_id.clone(),
            public_key: person_key.clone(),
            certificates: vec![certificate.clone()],
        };
        let authority = WorkspaceWriteAuthorizationSnapshot {
            workspace_id: "workspace".into(),
            genesis_owner: owner.clone(),
            genesis_epoch: 1,
            expected_current_owner: owner,
            document: AutoCommit::new().save(),
            ownership_transfers: vec![],
            succession_claims: vec![],
            revocations: vec![],
            device_revocations: vec![],
            departures: vec![],
        };
        let bundle = |sequence: u64| {
            let payload = json!({
                "kind": "peer-advertisement", "version": 1,
                "workspaceId": "workspace", "personId": person_id,
                "deviceId": device_id, "instanceId": "slot-1",
                "endpoint": "remote-endpoint", "issuedAt": "1970-01-01T00:00:00Z",
                "routeSequence": sequence,
            });
            json!({
                "advertisement": sign_json_envelope(&[2; 32], payload, &device_id, DEFAULT_SIGNATURE_DOMAIN).unwrap(),
                "publicKey": person_key, "certificates": [certificate],
            })
        };
        let older = bundle(1);
        let newer = bundle(2);
        let merged = merge_verified_peer_catalog(
            &[older],
            &[
                json!({"advertisement":{"payload":{"endpoint":"fake"}}}),
                newer.clone(),
            ],
            &authority,
            0,
        )
        .unwrap();
        assert_eq!(merged, vec![newer]);
    }
}
