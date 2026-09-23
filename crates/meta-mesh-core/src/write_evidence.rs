use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::has_conflicting_ownership_transfers;

pub fn has_authority_conflict(credential: &Value) -> bool {
    let epoch = credential.get("epoch").and_then(Value::as_u64);
    let catalog = credential.get("catalog");
    let claims = catalog
        .map(|value| array(value, "successionClaims"))
        .unwrap_or_default();
    let candidates = claims
        .iter()
        .filter(|claim| claim.pointer("/payload/epoch").and_then(Value::as_u64) == epoch)
        .filter_map(|claim| claim.pointer("/payload/toOwnerPersonId").and_then(Value::as_str))
        .collect::<std::collections::HashSet<_>>();
    let transfers = catalog
        .map(|value| array(value, "ownershipTransfers"))
        .unwrap_or_default();
    candidates.len() > 1 || has_conflicting_ownership_transfers(&transfers)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteEvidenceInput {
    pub incoming: Value,
    pub known: Option<Value>,
    pub records: Vec<Value>,
    pub genesis_person_id: String,
    pub remote_owner_person_id: String,
}

pub fn prepare_write_evidence(input: WriteEvidenceInput) -> Result<Value, String> {
    if input.genesis_person_id.is_empty()
        || input.remote_owner_person_id != input.genesis_person_id
        || text(&input.incoming, "/genesisOwner/personId") != Some(input.genesis_person_id.as_str())
    {
        return Err("Untrusted workspace owner".into());
    }
    if let Some(known) = &input.known {
        if text(known, "/genesisOwner/personId") != text(&input.incoming, "/genesisOwner/personId")
            || text(known, "/genesisOwner/publicKey")
                != text(&input.incoming, "/genesisOwner/publicKey")
        {
            return Err(
                "Workspace authority conflicts with this device's trusted genesis anchor".into(),
            );
        }
    }
    let mut authority = input.incoming;
    if let Some(known) = input.known {
        let known_transitions =
            array(&known, "ownershipTransfers").len() + array(&known, "successionClaims").len();
        let incoming_transitions = array(&authority, "ownershipTransfers").len()
            + array(&authority, "successionClaims").len();
        let retain_owner = known_transitions > incoming_transitions
            || (known_transitions == incoming_transitions
                && number(&known, "currentEpoch") > number(&authority, "currentEpoch"));
        let genesis = authority
            .get_mut("genesisOwner")
            .and_then(Value::as_object_mut)
            .ok_or("Invalid workspace authority evidence")?;
        genesis.insert(
            "certificates".into(),
            json!(merge_certificates(
                genesis.get("certificates").and_then(Value::as_array),
                known
                    .pointer("/genesisOwner/certificates")
                    .and_then(Value::as_array),
            )),
        );
        for field in [
            "ownershipTransfers",
            "successionClaims",
            "revocations",
            "deviceRevocations",
            "departures",
        ] {
            let merged = merge_records(array(&authority, field), array(&known, field));
            authority
                .as_object_mut()
                .ok_or("Invalid workspace authority evidence")?
                .insert(field.into(), json!(merged));
        }
        if retain_owner {
            let owner = known
                .get("currentOwner")
                .cloned()
                .ok_or("Invalid workspace authority evidence")?;
            let epoch = known
                .get("currentEpoch")
                .cloned()
                .ok_or("Invalid workspace authority evidence")?;
            let value = authority
                .as_object_mut()
                .ok_or("Invalid workspace authority evidence")?;
            value.insert("currentOwner".into(), owner);
            value.insert("currentEpoch".into(), epoch);
        }
    }
    let mut transitions = array(&authority, "ownershipTransfers");
    transitions.extend(array(&authority, "successionClaims"));
    transitions.sort_by_key(|record| {
        record
            .pointer("/payload/epoch")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    });
    if let Some(last) = transitions.last() {
        let payload = last
            .get("payload")
            .ok_or("Invalid workspace ownership transition")?;
        let owner = json!({
            "personId": payload.get("toOwnerPersonId").ok_or("Invalid workspace ownership transition")?,
            "publicKey": payload.get("toOwnerPublicKey").ok_or("Invalid workspace ownership transition")?,
            "certificates": payload.get("toOwnerCertificates").ok_or("Invalid workspace ownership transition")?,
        });
        let epoch = payload
            .get("epoch")
            .and_then(Value::as_u64)
            .ok_or("Invalid workspace ownership transition")?;
        let current_epoch = number(&authority, "currentEpoch");
        let value = authority
            .as_object_mut()
            .ok_or("Invalid workspace authority evidence")?;
        value.insert("currentOwner".into(), owner);
        value.insert("currentEpoch".into(), json!(current_epoch.max(epoch)));
    }
    for record in input.records {
        let Some(certificates) = record.get("ownerCertificates").and_then(Value::as_array) else {
            continue;
        };
        if certificates.len() > 32 {
            continue;
        }
        let Some(public_key) = record.get("ownerPublicKey").and_then(Value::as_str) else {
            continue;
        };
        for field in ["genesisOwner", "currentOwner"] {
            let Some(owner) = authority.get_mut(field).and_then(Value::as_object_mut) else {
                continue;
            };
            if owner.get("publicKey").and_then(Value::as_str) != Some(public_key) {
                continue;
            }
            owner.insert(
                "certificates".into(),
                json!(merge_certificates(
                    owner.get("certificates").and_then(Value::as_array),
                    Some(certificates),
                )),
            );
        }
    }
    Ok(authority)
}

fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn array(value: &Value, field: &str) -> Vec<Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn number(value: &Value, field: &str) -> u64 {
    value.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn merge_records(left: Vec<Value>, right: Vec<Value>) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    left.into_iter()
        .chain(right)
        .filter(|value| seen.insert(value.to_string()))
        .collect()
}

fn merge_certificates(left: Option<&Vec<Value>>, right: Option<&Vec<Value>>) -> Vec<Value> {
    let mut result = BTreeMap::<String, Value>::new();
    for certificate in left
        .into_iter()
        .flatten()
        .chain(right.into_iter().flatten())
    {
        let Some(signature) = certificate.get("signature").and_then(Value::as_str) else {
            continue;
        };
        match result.get(signature) {
            Some(current) if current.to_string() <= certificate.to_string() => {}
            _ => {
                result.insert(signature.to_string(), certificate.clone());
            }
        }
    }
    result.into_values().collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{WriteEvidenceInput, prepare_write_evidence};

    #[test]
    fn keeps_known_signed_transitions_and_updates_owner_candidate() {
        let incoming = json!({
            "genesisOwner": { "personId": "genesis", "publicKey": "key-a", "certificates": [{ "signature": "a" }] },
            "currentOwner": { "personId": "genesis", "publicKey": "key-a", "certificates": [] },
            "currentEpoch": 1, "ownershipTransfers": [], "successionClaims": [],
            "revocations": [], "deviceRevocations": [], "departures": []
        });
        let known = json!({
            "genesisOwner": { "personId": "genesis", "publicKey": "key-a", "certificates": [{ "signature": "b" }] },
            "currentOwner": { "personId": "editor", "publicKey": "key-b", "certificates": [] },
            "currentEpoch": 2,
            "ownershipTransfers": [{ "payload": { "epoch": 2, "toOwnerPersonId": "editor", "toOwnerPublicKey": "key-b", "toOwnerCertificates": [] } }],
            "successionClaims": [], "revocations": [], "deviceRevocations": [], "departures": []
        });
        let result = prepare_write_evidence(WriteEvidenceInput { incoming, known: Some(known), records: vec![],
            genesis_person_id: "genesis".into(), remote_owner_person_id: "genesis".into() }).unwrap();
        assert_eq!(result["currentOwner"]["personId"], "editor");
        assert_eq!(result["currentEpoch"], 2);
        assert_eq!(result["genesisOwner"]["certificates"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_conflicting_genesis_anchor_before_merging_evidence() {
        let incoming = json!({ "genesisOwner": { "personId": "genesis", "publicKey": "untrusted" } });
        let known = json!({ "genesisOwner": { "personId": "genesis", "publicKey": "trusted" } });
        assert!(prepare_write_evidence(WriteEvidenceInput { incoming, known: Some(known), records: vec![],
            genesis_person_id: "genesis".into(), remote_owner_person_id: "genesis".into() })
            .unwrap_err().contains("trusted genesis anchor"));
    }
}
