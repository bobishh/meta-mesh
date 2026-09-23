use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description};

use crate::{
    WorkspaceAuthority, WorkspaceOwnershipTransfer, WorkspacePeerRecord, WorkspaceRole,
    WorkspaceSuccessionClaim,
};

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum OwnershipAdoptionRecord {
    Transfer {
        record: WorkspaceOwnershipTransfer,
        accepted: Vec<WorkspaceOwnershipTransfer>,
    },
    Succession {
        record: WorkspaceSuccessionClaim,
        claims: Vec<WorkspaceSuccessionClaim>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipAdoptionInput {
    pub credential: Value,
    pub peers: Vec<WorkspacePeerRecord>,
    pub local_person_id: String,
    pub verified_current_owner_epoch: u64,
    pub transition: OwnershipAdoptionRecord,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipAdoptionPlan {
    pub previous_owner_person_id: String,
    pub credential: Value,
    pub peers: Vec<WorkspacePeerRecord>,
}

pub fn plan_ownership_adoption(
    mut input: OwnershipAdoptionInput,
) -> Result<OwnershipAdoptionPlan, String> {
    let credential = input
        .credential
        .as_object_mut()
        .ok_or("Invalid workspace credential")?;
    let previous_owner = string_field(credential, "ownerPersonId")?.to_string();
    let previous_authority = WorkspaceAuthority {
        person_id: previous_owner.clone(),
        public_key: string_field(credential, "ownerPublicKey")?.to_string(),
        certificates: serde_json::from_value(
            credential
                .get("ownerCertificates")
                .cloned()
                .ok_or("Invalid workspace credential")?,
        )
        .map_err(|_| "Invalid workspace credential")?,
    };
    let current_epoch = credential
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or("Invalid workspace credential")?;
    let (
        to_person,
        to_public_key,
        to_certificates,
        former_grant,
        new_owner_grant,
        epoch,
        changed_at,
        is_transfer,
    ) = match input.transition {
        OwnershipAdoptionRecord::Transfer {
            record,
            mut accepted,
        } => {
            let p = record.payload;
            if p.from_owner_person_id != previous_owner
                || p.epoch <= input.verified_current_owner_epoch
            {
                return Err("Invalid ownership transition".into());
            }
            accepted.sort_by(|a, b| {
                a.payload
                    .epoch
                    .cmp(&b.payload.epoch)
                    .then_with(|| a.signature.cmp(&b.signature))
            });
            let catalog = catalog(credential);
            catalog.insert("ownershipTransfers".into(), json!(accepted));
                catalog.remove("successionPolicy");
            catalog.insert("successionVotes".into(), json!([]));
            (
                p.to_owner_person_id,
                p.to_owner_public_key,
                p.to_owner_certificates,
                json!(p.former_owner_grant),
                Some(json!(p.to_owner_grant)),
                current_epoch.max(p.epoch),
                p.transferred_at,
                true,
            )
        }
        OwnershipAdoptionRecord::Succession { record, mut claims } => {
            let p = record.payload;
            if p.from_owner_person_id != previous_owner
                || p.epoch <= input.verified_current_owner_epoch
            {
                return Err("Invalid ownership transition".into());
            }
            claims.sort_by(|a, b| {
                a.payload
                    .epoch
                    .cmp(&b.payload.epoch)
                    .then_with(|| a.signature.cmp(&b.signature))
            });
            let catalog = catalog(credential);
                catalog.remove("successionPolicy");
            catalog.insert("successionVotes".into(), json!([]));
            catalog.insert("successionClaims".into(), json!(claims));
            (
                p.to_owner_person_id,
                p.to_owner_public_key,
                p.to_owner_certificates,
                json!(p.former_owner_grant),
                None,
                p.epoch,
                p.claimed_at,
                false,
            )
        }
    };
    let history = credential
        .entry("ownerHistory")
        .or_insert_with(|| json!([]));
    let history = history
        .as_array_mut()
        .ok_or("Invalid workspace credential")?;
    if !history
        .iter()
        .any(|owner| owner.get("personId").and_then(Value::as_str) == Some(&previous_owner))
    {
        history.push(json!(previous_authority));
    }
    if input.local_person_id == to_person {
        if let Some(grant) = &new_owner_grant {
            credential.insert("localGrant".into(), grant.clone());
        } else {
            credential.remove("localGrant");
        }
    } else if input.local_person_id == previous_owner {
        credential.insert("localGrant".into(), former_grant.clone());
    }
    credential.insert("ownerPersonId".into(), json!(to_person));
    credential.insert("ownerPublicKey".into(), json!(to_public_key));
    credential.insert("ownerCertificates".into(), json!(to_certificates));
    credential.insert("epoch".into(), json!(epoch));
    credential.insert("updatedAt".into(), json!(changed_at));

    let mut updated_peers = Vec::new();
    for mut peer in input.peers {
        if peer.person_id != previous_owner && peer.person_id != to_person {
            continue;
        }
        peer.role = if peer.person_id == to_person {
            WorkspaceRole::Owner
        } else {
            WorkspaceRole::Editor
        };
        peer.last_seen = later_than_both(&peer.last_seen, &changed_at)?;
        if let Some(advertisement) = peer.advertisement.as_mut().and_then(Value::as_object_mut) {
            if is_transfer || peer.person_id == previous_owner {
                advertisement.insert(
                    "grant".into(),
                    if peer.person_id == previous_owner {
                        former_grant.clone()
                    } else {
                        new_owner_grant.clone().expect("transfer has owner grant")
                    },
                );
            }
            advertisement.insert("ownerPublicKey".into(), json!(to_public_key));
            advertisement.insert("ownerCertificates".into(), json!(to_certificates));
        }
        updated_peers.push(peer);
    }
    Ok(OwnershipAdoptionPlan {
        previous_owner_person_id: previous_owner,
        credential: input.credential,
        peers: updated_peers,
    })
}

fn string_field<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| "Invalid workspace credential".into())
}

fn catalog(credential: &mut Map<String, Value>) -> &mut Map<String, Value> {
    let value = credential.entry("catalog").or_insert_with(|| json!({}));
    if !value.is_object() {
        *value = json!({});
    }
    value
        .as_object_mut()
        .expect("catalog initialized as object")
}

fn later_than_both(current: &str, transition: &str) -> Result<String, String> {
    let current = OffsetDateTime::parse(current, &Rfc3339).map_err(|_| "Invalid peer timestamp")?;
    let transition =
        OffsetDateTime::parse(transition, &Rfc3339).map_err(|_| "Invalid transition timestamp")?;
    let next = OffsetDateTime::from_unix_timestamp_nanos(
        current
            .unix_timestamp_nanos()
            .max(transition.unix_timestamp_nanos())
            + 1_000_000,
    )
    .map_err(|_| "Invalid transition timestamp")?;
    next.format(&format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    ))
    .map_err(|_| "Invalid transition timestamp".into())
}
