use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, PublicIdentity, WorkspaceAuthority, WorkspaceGrant, WorkspaceRole,
    WorkspaceWriteAuthorizationSnapshot, authority::WorkspaceDeparture,
    authorization::ValidatedWorkspaceWriteAuthorizationContext, public_key_id,
    verify_device_certificate_chain, verify_workspace_grant,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDepartureEvidence {
    pub record: WorkspaceDeparture,
    pub authority: WorkspaceAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAccessDecisionInput {
    pub snapshot: WorkspaceWriteAuthorizationSnapshot,
    pub identity: WorkspaceAuthority,
    pub device_id: String,
    #[serde(default)]
    pub grant: Option<WorkspaceGrant>,
    #[serde(default)]
    pub departures: Vec<WorkspaceDepartureEvidence>,
    #[serde(default)]
    pub legacy_authority_evidence: Vec<Value>,
}

/// Resolve local workspace access from signed authority records. Invalid authority
/// evidence is an error; an absent or stale membership grant resolves to visitor.
pub fn decide_workspace_access(
    input: &WorkspaceAccessDecisionInput,
    now_ms: i128,
) -> Result<WorkspaceRole, String> {
    if input.identity.person_id.is_empty()
        || input.device_id.is_empty()
        || input.departures.len() > 512
        || input.legacy_authority_evidence.len() > 512
        || public_key_id(&input.identity.public_key)? != input.identity.person_id
    {
        return Err("Invalid workspace access decision input".into());
    }
    if !input.legacy_authority_evidence.is_empty() {
        return Err("Legacy workspace authority is unsupported".into());
    }
    verify_device_certificate_chain(
        &PublicIdentity {
            person_id: input.identity.person_id.clone(),
            public_key: input.identity.public_key.clone(),
            display_name: String::new(),
        },
        &input.device_id,
        &input.identity.certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    let context =
        ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(&input.snapshot, now_ms)?;
    if context.device_was_revoked(&input.identity.person_id, &input.device_id) {
        return Ok(WorkspaceRole::Visitor);
    }
    if input.identity.person_id == context.current_owner.person_id
        && input.identity.public_key == context.current_owner.public_key
    {
        return Ok(WorkspaceRole::Owner);
    }

    let grant = input.grant.as_ref();
    let grant_epoch = grant
        .map(|value| value.payload.effective_access_epoch())
        .unwrap_or(1);
    for evidence in &input.departures {
        if evidence.record.payload.person_id != input.identity.person_id {
            continue;
        }
        crate::authority::verify_workspace_departure(
            &evidence.record,
            &context.workspace_id,
            &evidence.authority,
            now_ms,
        )?;
        if evidence.record.payload.access_epoch >= grant_epoch {
            return Ok(WorkspaceRole::Visitor);
        }
    }

    for revocation in &input.snapshot.revocations {
        if revocation.payload.person_id == input.identity.person_id
            && revocation.payload.epoch >= grant_epoch
        {
            return Ok(WorkspaceRole::Visitor);
        }
    }

    let authorities =
        std::iter::once(&context.current_owner).chain(context.historical_owners.iter());
    for authority in authorities {
        let identity = PublicIdentity {
            person_id: authority.person_id.clone(),
            public_key: authority.public_key.clone(),
            display_name: String::new(),
        };
        if let Some(role) = grant.and_then(|grant| {
            verify_workspace_grant(
                grant,
                &context.workspace_id,
                &input.identity.person_id,
                &identity,
                &authority.certificates,
            )
            .ok()
        }) {
            return Ok(match role {
                WorkspaceRole::Owner => WorkspaceRole::Visitor,
                other => other,
            });
        }
    }
    Ok(WorkspaceRole::Visitor)
}
