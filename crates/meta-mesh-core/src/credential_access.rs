use crate::{PublicIdentity, WorkspaceAuthority, WorkspaceGrant, verify_workspace_grant};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub fn has_left_workspace(credential: &Value, person_id: &str, grant: Option<&Value>) -> bool {
    if credential.get("ownerPersonId").and_then(Value::as_str) == Some(person_id) {
        return false;
    }
    let access_epoch = grant
        .and_then(|grant| grant.pointer("/payload/accessEpoch"))
        .and_then(Value::as_u64)
        .unwrap_or(1);
    catalog_records(credential, "departures").any(|record| {
        record
            .pointer("/record/payload/personId")
            .and_then(Value::as_str)
            == Some(person_id)
            && record
                .pointer("/record/payload/accessEpoch")
                .and_then(Value::as_u64)
                .is_some_and(|epoch| epoch >= access_epoch)
    })
}

pub fn is_grant_revoked(credential: &Value, person_id: &str, grant: Option<&Value>) -> bool {
    if has_left_workspace(credential, person_id, grant) {
        return true;
    }
    let access_epoch = grant
        .and_then(|grant| grant.pointer("/payload/accessEpoch"))
        .and_then(Value::as_u64)
        .unwrap_or(1);
    catalog_records(credential, "revocations").any(|record| {
        record.pointer("/payload/personId").and_then(Value::as_str) == Some(person_id)
            && record
                .pointer("/payload/epoch")
                .and_then(Value::as_u64)
                .is_some_and(|epoch| epoch >= access_epoch)
    })
}

pub fn is_device_revoked(credential: &Value, person_id: &str, device_id: &str) -> bool {
    catalog_records(credential, "deviceRevocations").any(|record| {
        record
            .pointer("/record/payload/personId")
            .and_then(Value::as_str)
            == Some(person_id)
            && record
                .pointer("/record/payload/deviceId")
                .and_then(Value::as_str)
                == Some(device_id)
    })
}

fn catalog_records<'a>(credential: &'a Value, field: &str) -> impl Iterator<Item = &'a Value> {
    credential
        .get("catalog")
        .and_then(|catalog| catalog.get(field))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

pub fn next_access_epoch(
    credential: Option<&Value>,
    issued_grants: &[Value],
) -> Result<u64, String> {
    let mut epoch = credential
        .and_then(|value| value.get("epoch"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    for grant in issued_grants {
        epoch = epoch.max(
            grant
                .pointer("/payload/accessEpoch")
                .and_then(Value::as_u64)
                .unwrap_or(1),
        );
    }
    if let Some(credential) = credential {
        for record in catalog_records(credential, "departures") {
            epoch = epoch.max(
                record
                    .pointer("/record/payload/accessEpoch")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
        }
        for record in catalog_records(credential, "revocations") {
            epoch = epoch.max(
                record
                    .pointer("/payload/epoch")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
        }
    }
    epoch
        .checked_add(1)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| "Workspace access epoch exhausted".into())
}

pub fn credential_belongs_to_profile(
    credential: &Value,
    person_id: &str,
    public_key: &str,
) -> Result<bool, String> {
    let owner_id = credential
        .get("ownerPersonId")
        .and_then(Value::as_str)
        .ok_or("Invalid workspace credential")?;
    let owner_key = credential
        .get("ownerPublicKey")
        .and_then(Value::as_str)
        .ok_or("Invalid workspace credential")?;
    if owner_id == person_id {
        return Ok(owner_key == public_key);
    }
    let Some(grant) = credential.get("localGrant") else {
        return Ok(false);
    };
    let grant: WorkspaceGrant =
        serde_json::from_value(grant.clone()).map_err(|_| "Invalid workspace grant")?;
    if grant.payload.person_id != person_id {
        return Ok(false);
    }
    let workspace_id = credential
        .get("workspaceId")
        .and_then(Value::as_str)
        .ok_or("Invalid workspace credential")?;
    let mut authorities = vec![WorkspaceAuthority {
        person_id: owner_id.to_string(),
        public_key: owner_key.to_string(),
        certificates: serde_json::from_value(
            credential
                .get("ownerCertificates")
                .cloned()
                .ok_or("Invalid workspace credential")?,
        )
        .map_err(|_| "Invalid workspace credential")?,
    }];
    if let Some(history) = credential.get("ownerHistory") {
        authorities.extend(
            serde_json::from_value::<Vec<WorkspaceAuthority>>(history.clone())
                .map_err(|_| "Invalid workspace credential")?,
        );
    }
    Ok(authorities.iter().any(|authority| {
        verify_workspace_grant(
            &grant,
            workspace_id,
            person_id,
            &PublicIdentity {
                person_id: authority.person_id.clone(),
                public_key: authority.public_key.clone(),
                display_name: String::new(),
            },
            &authority.certificates,
        )
        .is_ok()
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPartitionInput {
    pub credentials: Vec<Value>,
    pub person_id: String,
    pub public_key: String,
    pub device_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPartition {
    pub active_indices: Vec<usize>,
    pub mismatched_indices: Vec<usize>,
}

pub fn partition_credentials(
    input: CredentialPartitionInput,
) -> Result<CredentialPartition, String> {
    let mut active_indices = Vec::new();
    let mut mismatched_indices = Vec::new();
    for (index, credential) in input.credentials.iter().enumerate() {
        if has_left_workspace(credential, &input.person_id, credential.get("localGrant"))
            || is_device_revoked(credential, &input.person_id, &input.device_id)
        {
            continue;
        }
        if credential_belongs_to_profile(credential, &input.person_id, &input.public_key)? {
            active_indices.push(index);
        } else {
            mismatched_indices.push(index);
        }
    }
    Ok(CredentialPartition {
        active_indices,
        mismatched_indices,
    })
}

pub fn owned_workspace_ids(
    credentials: &[Value],
    person_id: &str,
    public_key: &str,
) -> Vec<String> {
    let mut ids = credentials
        .iter()
        .filter(|credential| {
            credential.get("ownerPersonId").and_then(Value::as_str) == Some(person_id)
                && credential.get("ownerPublicKey").and_then(Value::as_str) == Some(public_key)
        })
        .filter_map(|credential| {
            credential
                .get("workspaceId")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

pub fn can_remove_workspace_device(
    credential: &Value,
    local_person_id: &str,
    local_public_key: &str,
    local_device_id: &str,
    target_person_id: &str,
    target_device_id: &str,
    peer_person_id: Option<&str>,
) -> Result<bool, String> {
    if has_left_workspace(credential, local_person_id, credential.get("localGrant"))
        || is_device_revoked(credential, local_person_id, local_device_id)
        || !credential_belongs_to_profile(credential, local_person_id, local_public_key)?
    {
        return Ok(false);
    }
    let owner = credential.get("ownerPersonId").and_then(Value::as_str) == Some(local_person_id);
    let editor = credential
        .pointer("/localGrant/payload/role")
        .and_then(Value::as_str)
        == Some("editor");
    Ok((owner || (local_person_id == target_person_id && editor))
        && peer_person_id == Some(target_person_id)
        && !is_device_revoked(credential, target_person_id, target_device_id))
}

pub fn is_workspace_envelope(value: &Value) -> Result<bool, String> {
    let Some(value) = value.as_object() else {
        return Ok(false);
    };
    if let Some(legacy) = value.get("breakGlassClaims") {
        if !legacy.as_array().is_some_and(Vec::is_empty) {
            return Err("Unsupported legacy break-glass authority evidence".into());
        }
    }
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|item| !item.is_empty())
    };
    let bounded = |key: &str, max: usize| {
        value
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() <= max)
    };
    let optional = |key: &str, max: usize| !value.contains_key(key) || bounded(key, max);
    let workspace_id = value.get("workspaceId").and_then(Value::as_str);
    let owner_person_id = value.get("ownerPersonId").and_then(Value::as_str);
    let owner_public_key = value.get("ownerPublicKey").and_then(Value::as_str);
    let epoch = value.get("epoch").and_then(Value::as_u64);
    let scope_authority_valid = match value.get("scopeAuthoritySnapshot") {
        None => true,
        Some(snapshot) => serde_json::from_value::<crate::ScopeAuthoritySnapshot>(snapshot.clone())
            .ok()
            .and_then(|snapshot| crate::validate_scope_authority(&snapshot).ok())
            .is_some_and(|authority| {
                Some(authority.scope_id.as_str()) == workspace_id
                    && Some(authority.controller.person_id.as_str()) == owner_person_id
                    && Some(authority.controller.public_key.as_str()) == owner_public_key
                    && Some(authority.control_epoch) == epoch
            }),
    };
    Ok(value.get("version").and_then(Value::as_u64) == Some(1)
        && text("workspaceId")
        && text("ownerPersonId")
        && text("ownerPublicKey")
        && text("transportSecret")
        && value
            .get("epoch")
            .and_then(Value::as_u64)
            .is_some_and(|epoch| (1..=9_007_199_254_740_991).contains(&epoch))
        && bounded("ownerCertificates", 32)
        && bounded("peers", 512)
        && scope_authority_valid
        && optional("ownerHistory", usize::MAX)
        && optional("ownershipTransfers", usize::MAX)
        && optional("successionVotes", 32)
        && optional("successionClaims", 32))
}
