use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::authority::{
    WorkspaceDeparture, WorkspaceDeviceRevocation, verify_workspace_departure,
    verify_workspace_device_revocation,
};
use crate::{
    WorkspaceAuthority, WorkspacePeerRecord, WorkspaceRevocation, canonical_revocations,
    verify_workspace_revocation,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedDeparture {
    pub record: WorkspaceDeparture,
    pub authority: WorkspaceAuthority,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedDeviceRevocation {
    pub record: WorkspaceDeviceRevocation,
    pub authority: WorkspaceAuthority,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AuthorityMergeRecords {
    Revocations {
        records: Vec<WorkspaceRevocation>,
    },
    Departures {
        records: Vec<SignedDeparture>,
    },
    DeviceRevocations {
        records: Vec<SignedDeviceRevocation>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityMergeInput {
    pub credential: Value,
    pub peers: Vec<WorkspacePeerRecord>,
    pub local_person_id: String,
    pub local_device_id: String,
    pub now_ms: u64,
    pub records: AuthorityMergeRecords,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityMergePlan {
    pub credential: Value,
    pub peers: Vec<WorkspacePeerRecord>,
    pub evict_device_ids: Vec<String>,
    pub evict_person_ids: Vec<String>,
    pub local_access_revoked: bool,
}

pub fn plan_authority_merge(mut input: AuthorityMergeInput) -> Result<AuthorityMergePlan, String> {
    let credential = input
        .credential
        .as_object_mut()
        .ok_or("Invalid workspace credential")?;
    let workspace_id = credential
        .get("workspaceId")
        .and_then(Value::as_str)
        .ok_or("Invalid workspace credential")?
        .to_string();
    let owner_person_id = credential
        .get("ownerPersonId")
        .and_then(Value::as_str)
        .ok_or("Invalid workspace credential")?
        .to_string();
    let owner = WorkspaceAuthority {
        person_id: owner_person_id.clone(),
        public_key: credential
            .get("ownerPublicKey")
            .and_then(Value::as_str)
            .ok_or("Invalid workspace credential")?
            .to_string(),
        certificates: serde_json::from_value(
            credential
                .get("ownerCertificates")
                .cloned()
                .ok_or("Invalid workspace credential")?,
        )
        .map_err(|_| "Invalid workspace credential")?,
    };
    let mut authorities = vec![owner];
    if let Some(history) = credential.get("ownerHistory") {
        authorities.extend(
            serde_json::from_value::<Vec<WorkspaceAuthority>>(history.clone())
                .map_err(|_| "Invalid workspace credential")?,
        );
    }
    let catalog = credential.entry("catalog").or_insert_with(|| json!({}));
    if !catalog.is_object() {
        *catalog = json!({});
    }
    let catalog = catalog.as_object_mut().ok_or("Invalid workspace catalog")?;
    let mut changed_peers = Vec::new();
    let mut evict_device_ids = HashSet::new();
    let mut evict_person_ids = HashSet::new();
    let mut local_access_revoked = false;
    match input.records {
        AuthorityMergeRecords::Revocations { records } => {
            let mut merged: Vec<Value> = catalog
                .get("revocations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for record in records {
                if record.payload.person_id == owner_person_id {
                    continue;
                }
                if !authorities.iter().any(|authority| {
                    verify_workspace_revocation(
                        &record,
                        &workspace_id,
                        authority,
                        i128::from(input.now_ms),
                    )
                    .is_ok()
                }) {
                    return Err("Invalid workspace revocation signature".into());
                }
                merged.push(json!(record));
            }
            let merged = canonical_revocations(&merged);
            catalog.insert("revocations".into(), json!(merged));
            for mut peer in input.peers {
                let epoch = grant_epoch(peer.advertisement.as_ref());
                let revoked = merged.iter().find(|record| {
                    record["payload"]["personId"] == peer.person_id
                        && record["payload"]["epoch"]
                            .as_u64()
                            .is_some_and(|value| value >= epoch)
                });
                if let Some(record) = revoked {
                    evict_device_ids.insert(peer.device_id.clone());
                    if peer.revoked_at.as_ref().is_none_or(Option::is_none) {
                        peer.last_seen = timestamp(input.now_ms)?;
                        peer.revoked_at = Some(Some(
                            record["payload"]["revokedAt"]
                                .as_str()
                                .ok_or("Invalid workspace revocation")?
                                .to_string(),
                        ));
                        changed_peers.push(peer);
                    }
                }
            }
            let local_epoch = credential
                .get("localGrant")
                .and_then(|grant| grant.get("payload"))
                .and_then(|payload| payload.get("accessEpoch"))
                .and_then(Value::as_u64)
                .unwrap_or(1);
            local_access_revoked = credential
                .get("localGrant")
                .and_then(|grant| grant.get("payload"))
                .and_then(|payload| payload.get("personId"))
                .and_then(Value::as_str)
                .is_some_and(|person| {
                    merged.iter().any(|record| {
                        record["payload"]["personId"] == person
                            && record["payload"]["epoch"]
                                .as_u64()
                                .is_some_and(|value| value >= local_epoch)
                    })
                });
        }
        AuthorityMergeRecords::Departures { records } => {
            let mut merged: Vec<SignedDeparture> = serde_json::from_value(
                catalog
                    .get("departures")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            )
            .map_err(|_| "Invalid workspace departures")?;
            for record in records {
                verify_workspace_departure(
                    &record.record,
                    &workspace_id,
                    &record.authority,
                    i128::from(input.now_ms),
                )?;
                if !merged.contains_key(&record)? {
                    merged.push(record);
                }
            }
            if merged.len() > 512 {
                return Err("Too many workspace departures".into());
            }
            merged.sort_by(|a, b| {
                a.record
                    .payload
                    .person_id
                    .cmp(&b.record.payload.person_id)
                    .then_with(|| {
                        a.record
                            .payload
                            .access_epoch
                            .cmp(&b.record.payload.access_epoch)
                    })
            });
            for mut peer in input.peers {
                if peer.person_id == owner_person_id {
                    continue;
                }
                let epoch = grant_epoch(peer.advertisement.as_ref());
                if let Some(record) = merged
                    .iter()
                    .filter(|record| {
                        record.record.payload.person_id == peer.person_id
                            && record.record.payload.access_epoch >= epoch
                    })
                    .max_by_key(|record| record.record.payload.access_epoch)
                {
                    peer.revoked_at = Some(Some(record.record.payload.left_at.clone()));
                    evict_person_ids.insert(peer.person_id.clone());
                    changed_peers.push(peer);
                }
            }
            catalog.insert("departures".into(), json!(merged));
        }
        AuthorityMergeRecords::DeviceRevocations { records } => {
            let mut merged: Vec<SignedDeviceRevocation> = serde_json::from_value(
                catalog
                    .get("deviceRevocations")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            )
            .map_err(|_| "Invalid workspace device revocations")?;
            for record in records {
                verify_workspace_device_revocation(
                    &record.record,
                    &workspace_id,
                    &owner_person_id,
                    &record.authority,
                    i128::from(input.now_ms),
                )?;
                if !merged.contains_key(&record)? {
                    merged.push(record);
                }
            }
            if merged.len() > 512 {
                return Err("Too many device revocations".into());
            }
            merged.sort_by(|a, b| a.record.payload.device_id.cmp(&b.record.payload.device_id));
            for mut peer in input.peers {
                if let Some(record) = merged.iter().find(|record| {
                    record.record.payload.person_id == peer.person_id
                        && record.record.payload.device_id == peer.device_id
                }) {
                    peer.revoked_at = Some(Some(record.record.payload.revoked_at.clone()));
                    evict_device_ids.insert(peer.device_id.clone());
                    changed_peers.push(peer);
                }
            }
            local_access_revoked = merged.iter().any(|record| {
                record.record.payload.person_id == input.local_person_id
                    && record.record.payload.device_id == input.local_device_id
            });
            catalog.insert("deviceRevocations".into(), json!(merged));
        }
    }
    credential.insert("updatedAt".into(), json!(timestamp(input.now_ms)?));
    let mut evict_device_ids = evict_device_ids.into_iter().collect::<Vec<_>>();
    let mut evict_person_ids = evict_person_ids.into_iter().collect::<Vec<_>>();
    evict_device_ids.sort();
    evict_person_ids.sort();
    Ok(AuthorityMergePlan {
        credential: input.credential,
        peers: changed_peers,
        evict_device_ids,
        evict_person_ids,
        local_access_revoked,
    })
}

fn grant_epoch(advertisement: Option<&Value>) -> u64 {
    advertisement
        .and_then(|value| value.get("grant"))
        .and_then(|value| value.get("payload"))
        .and_then(|value| value.get("accessEpoch"))
        .and_then(Value::as_u64)
        .unwrap_or(1)
}

fn timestamp(now_ms: u64) -> Result<String, String> {
    let nanos = i128::from(now_ms)
        .checked_mul(1_000_000)
        .ok_or("Invalid authority timestamp")?;
    let at = time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| "Invalid authority timestamp")?;
    at.format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| "Invalid authority timestamp".into())
}

trait ContainsJson<T> {
    fn contains_key(&self, value: &T) -> Result<bool, String>;
}
impl<T: Serialize> ContainsJson<T> for Vec<T> {
    fn contains_key(&self, value: &T) -> Result<bool, String> {
        let key = serde_json::to_string(value).map_err(|_| "Invalid authority record")?;
        Ok(self
            .iter()
            .any(|item| serde_json::to_string(item).ok().as_deref() == Some(&key)))
    }
}
