use std::collections::HashSet;

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, WorkspaceGrant,
    WorkspacePeerRecord, is_device_revoked, is_grant_revoked, verify_device_certificate_chain,
    verify_workspace_grant,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationPlanInput {
    pub raw: Value,
    pub workspace_ids: Vec<String>,
    pub grant_workspace_ids: Vec<String>,
    pub existing_owner_person_ids: Vec<Option<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationPlanEntry {
    pub workspace_id: String,
    pub envelope_index: usize,
    pub grant_index: Option<usize>,
}

pub fn plan_invitation(input: InvitationPlanInput) -> Result<Vec<InvitationPlanEntry>, String> {
    let envelopes = input.raw.as_array().ok_or("Invalid mesh invitation")?;
    if envelopes.len() != input.workspace_ids.len()
        || input.existing_owner_person_ids.len() != input.workspace_ids.len()
        || input.workspace_ids.iter().any(String::is_empty)
        || input.workspace_ids.iter().collect::<HashSet<_>>().len() != input.workspace_ids.len()
        || serde_json::to_vec(&input.raw)
            .map_err(|_| "Invalid mesh invitation")?
            .len()
            > 8 * 1024 * 1024
    {
        return Err("Invalid mesh invitation".into());
    }
    let mut entries = Vec::with_capacity(input.workspace_ids.len());
    for (position, workspace_id) in input.workspace_ids.into_iter().enumerate() {
        let envelope_index = envelopes
            .iter()
            .position(|envelope| {
                envelope.get("workspaceId").and_then(Value::as_str) == Some(&workspace_id)
            })
            .ok_or("Invalid mesh invitation")?;
        let owner = envelopes[envelope_index]
            .get("ownerPersonId")
            .and_then(Value::as_str)
            .ok_or("Invalid mesh invitation")?;
        if input.existing_owner_person_ids[position]
            .as_deref()
            .is_some_and(|existing| existing != owner)
        {
            return Err("Workspace ownership proof is missing".into());
        }
        let grant_index = input
            .grant_workspace_ids
            .iter()
            .position(|id| id == &workspace_id);
        entries.push(InvitationPlanEntry {
            workspace_id,
            envelope_index,
            grant_index,
        });
    }
    Ok(entries)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationCredentialInput {
    pub workspace_id: String,
    pub envelope: Value,
    pub previous_credential: Option<Value>,
    pub previous_authority: Option<Value>,
    pub local_person_id: String,
    pub local_grant: Option<WorkspaceGrant>,
    pub updated_at: String,
}

pub fn plan_invitation_credential(input: InvitationCredentialInput) -> Result<Value, String> {
    let envelope = input
        .envelope
        .as_object()
        .ok_or("Invalid mesh invitation")?;
    let owner_person_id = field(envelope, "ownerPersonId")?;
    let owner_public_key = field(envelope, "ownerPublicKey")?;
    for previous in [&input.previous_credential, &input.previous_authority]
        .into_iter()
        .flatten()
    {
        if previous.get("ownerPersonId").and_then(Value::as_str) != Some(owner_person_id)
            || previous.get("ownerPublicKey").and_then(Value::as_str) != Some(owner_public_key)
        {
            return Err("Workspace authority conflict: this device and the invitation name different owners. Existing permissions were preserved.".into());
        }
    }
    let owner_certificates: Vec<DeviceCertificate> = serde_json::from_value(
        envelope
            .get("ownerCertificates")
            .cloned()
            .ok_or("Invalid mesh invitation")?,
    )
    .map_err(|_| "Invalid mesh invitation")?;
    let owner_device_id = owner_certificates
        .first()
        .map(|certificate| certificate.payload.device_id.as_str())
        .ok_or("Invalid mesh invitation")?;
    if owner_device_id.is_empty() {
        return Err("Invalid mesh invitation".into());
    }
    if owner_person_id != input.local_person_id
        && input
            .local_grant
            .as_ref()
            .is_none_or(|grant| grant.payload.person_id != input.local_person_id)
    {
        return Err("Missing local workspace grant".into());
    }
    let identity = PublicIdentity {
        person_id: owner_person_id.to_string(),
        public_key: owner_public_key.to_string(),
        display_name: String::new(),
    };
    verify_device_certificate_chain(
        &identity,
        owner_device_id,
        &owner_certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    let history: Vec<crate::WorkspaceAuthority> = serde_json::from_value(
        envelope
            .get("ownerHistory")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
    .map_err(|_| "Invalid mesh invitation")?;
    for authority in &history {
        let device_id = authority
            .certificates
            .first()
            .map(|certificate| certificate.payload.device_id.as_str())
            .ok_or("Invalid mesh invitation")?;
        verify_device_certificate_chain(
            &PublicIdentity {
                person_id: authority.person_id.clone(),
                public_key: authority.public_key.clone(),
                display_name: String::new(),
            },
            device_id,
            &authority.certificates,
            DEFAULT_SIGNATURE_DOMAIN,
        )?;
    }
    if let Some(grant) = &input.local_grant {
        verify_workspace_grant(
            grant,
            &input.workspace_id,
            &input.local_person_id,
            &identity,
            &owner_certificates,
        )?;
    }
    let retained = input
        .previous_credential
        .as_ref()
        .or(input.previous_authority.as_ref());
    let mut catalog = retained
        .and_then(|value| value.get("catalog"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    catalog.insert(
        "revocations".into(),
        retained
            .and_then(|value| value.pointer("/catalog/revocations"))
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    catalog.insert(
        "ownershipTransfers".into(),
        envelope
            .get("ownershipTransfers")
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    catalog.remove("successionPolicy");
    catalog.insert("successionVotes".into(), json!([]));
    catalog.insert("successionClaims".into(), json!([]));
    let epoch = envelope
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or("Invalid mesh invitation")?
        .max(
            retained
                .and_then(|value| value.get("epoch"))
                .and_then(Value::as_u64)
                .unwrap_or(1),
        );
    let mut credential = Map::new();
    credential.insert("version".into(), json!(1));
    credential.insert("workspaceId".into(), json!(input.workspace_id));
    credential.insert("ownerPersonId".into(), json!(owner_person_id));
    credential.insert("ownerPublicKey".into(), json!(owner_public_key));
    credential.insert("ownerCertificates".into(), json!(owner_certificates));
    if envelope.contains_key("ownerHistory") {
        credential.insert("ownerHistory".into(), json!(history));
    }
    credential.insert(
        "transportSecret".into(),
        envelope
            .get("transportSecret")
            .cloned()
            .ok_or("Invalid mesh invitation")?,
    );
    credential.insert("epoch".into(), json!(epoch));
    credential.insert("updatedAt".into(), json!(input.updated_at));
    if let Some(grant) = input.local_grant {
        credential.insert("localGrant".into(), json!(grant));
    }
    credential.insert("catalog".into(), Value::Object(catalog));
    Ok(Value::Object(credential))
}

fn field<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| "Invalid mesh invitation".into())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestAdvertisementInput {
    pub raw: Value,
    pub workspace_ids: Vec<String>,
    pub grant_workspace_ids: Vec<String>,
    pub credential_present: Vec<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestAdvertisementEntry {
    pub workspace_id: String,
    pub bundle_index: usize,
    pub grant_index: usize,
}

pub fn plan_guest_advertisements(
    input: GuestAdvertisementInput,
) -> Result<Vec<GuestAdvertisementEntry>, String> {
    let bundles = input.raw.as_array().ok_or("Invalid peer advertisements")?;
    if bundles.len() != input.workspace_ids.len()
        || input.credential_present.len() != input.workspace_ids.len()
    {
        return Err("Invalid peer advertisements".into());
    }
    let mut entries = Vec::with_capacity(input.workspace_ids.len());
    for (position, workspace_id) in input.workspace_ids.into_iter().enumerate() {
        let bundle_index = bundles.iter().position(|bundle| {
            bundle
                .pointer("/advertisement/payload/workspaceId")
                .and_then(Value::as_str)
                == Some(&workspace_id)
        });
        let grant_index = input
            .grant_workspace_ids
            .iter()
            .position(|id| id == &workspace_id);
        if !input.credential_present[position] || bundle_index.is_none() || grant_index.is_none() {
            return Err("Missing workspace mesh authority".into());
        }
        entries.push(GuestAdvertisementEntry {
            workspace_id,
            bundle_index: bundle_index.unwrap(),
            grant_index: grant_index.unwrap(),
        });
    }
    Ok(entries)
}

pub fn validate_owner_workspace_offer(
    value: &Value,
    remote_person_id: &str,
    local_person_id: &str,
) -> Result<String, String> {
    let workspace_id = value
        .get("workspaceId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or("Invalid owner workspace offer")?;
    if remote_person_id != local_person_id
        || value.get("version").and_then(Value::as_u64) != Some(1)
        || value
            .pointer("/envelope/ownerPersonId")
            .and_then(Value::as_str)
            != Some(local_person_id)
        || value
            .pointer("/envelope/workspaceId")
            .and_then(Value::as_str)
            != Some(workspace_id)
        || value.pointer("/workspace/id").and_then(Value::as_str) != Some(workspace_id)
    {
        return Err("Invalid owner workspace offer".into());
    }
    Ok(workspace_id.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerWorkspaceInput {
    pub credential: Option<Value>,
    pub issuer: Option<WorkspacePeerRecord>,
}

pub fn knows_workspace_issuer(
    workspaces: &[IssuerWorkspaceInput],
    issuer_person_id: &str,
    local_person_id: &str,
    local_device_id: &str,
) -> bool {
    !workspaces.is_empty()
        && workspaces.iter().all(|workspace| {
            let Some(credential) = workspace.credential.as_ref() else {
                return false;
            };
            let Some(issuer) = workspace.issuer.as_ref() else {
                return false;
            };
            let grant = credential.get("localGrant");
            credential.get("ownerPersonId").and_then(Value::as_str) == Some(issuer_person_id)
                && issuer.advertisement.is_some()
                && issuer.person_id == issuer_person_id
                && issuer.revoked_at.as_ref().is_none_or(Option::is_none)
                && !is_grant_revoked(credential, local_person_id, grant)
                && !is_device_revoked(credential, local_person_id, local_device_id)
                && (local_person_id == issuer_person_id
                    || grant
                        .and_then(|value| value.pointer("/payload/personId"))
                        .and_then(Value::as_str)
                        == Some(local_person_id))
        })
}

pub fn missing_owner_workspaces(owned: &[String], remote: &Value) -> Vec<String> {
    let known = remote
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    owned
        .iter()
        .filter(|id| !known.contains(id.as_str()))
        .cloned()
        .collect()
}
