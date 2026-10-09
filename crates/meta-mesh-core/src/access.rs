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
                WorkspaceRole::Automation
                    if grant
                        .and_then(|grant| grant.payload.automation.as_ref())
                        .is_none_or(|scope| i128::from(scope.expires_at) <= now_ms) =>
                {
                    WorkspaceRole::Visitor
                }
                other => other,
            });
        }
    }
    Ok(WorkspaceRole::Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AutomationGrantColumns, AutomationGrantScope, DeviceCertificatePayload,
        WorkspaceGrantPayload, public_key_from_seed, sign_device_certificate, sign_json_envelope,
    };

    #[test]
    fn expired_automation_grant_loses_current_access() {
        let owner_public = public_key_from_seed(&[111; 32]).unwrap();
        let owner_person = public_key_id(&owner_public).unwrap();
        let automation_public = public_key_from_seed(&[112; 32]).unwrap();
        let automation_person = public_key_id(&automation_public).unwrap();
        let device_public = public_key_from_seed(&[113; 32]).unwrap();
        let device_id = public_key_id(&device_public).unwrap();
        let certificate = sign_device_certificate(
            &[112; 32],
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: automation_person.clone(),
                device_id: device_id.clone(),
                device_public_key: device_public,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &automation_person,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let owner = WorkspaceAuthority {
            person_id: owner_person.clone(),
            public_key: owner_public,
            certificates: vec![],
        };
        let scope = AutomationGrantScope {
            version: 1,
            board_id: "board".into(),
            columns: AutomationGrantColumns {
                lead: "lead".into(),
                interview: "interview".into(),
                rejected: "rejected".into(),
            },
            field_ids: vec![],
            expires_at: 101,
        };
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(),
            version: 1,
            grant_id: "automation".into(),
            workspace_id: "workspace".into(),
            person_id: automation_person.clone(),
            role: WorkspaceRole::Automation,
            access_epoch: Some(1),
            automation: Some(scope),
        };
        let signed = sign_json_envelope(
            &[111; 32],
            serde_json::to_value(&payload).unwrap(),
            &owner_person,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let input = WorkspaceAccessDecisionInput {
            snapshot: WorkspaceWriteAuthorizationSnapshot {
                workspace_id: "workspace".into(),
                genesis_owner: owner.clone(),
                genesis_epoch: 1,
                expected_current_owner: owner,
                document: automerge::AutoCommit::new().save(),
                ownership_transfers: vec![],
                succession_claims: vec![],
                revocations: vec![],
                device_revocations: vec![],
                departures: vec![],
            },
            identity: WorkspaceAuthority {
                person_id: automation_person,
                public_key: automation_public,
                certificates: vec![certificate],
            },
            device_id,
            grant: Some(WorkspaceGrant {
                payload,
                signer_key_id: signed.signer_key_id,
                signature: signed.signature,
            }),
            departures: vec![],
            legacy_authority_evidence: vec![],
        };
        assert_eq!(
            decide_workspace_access(&input, 100).unwrap(),
            WorkspaceRole::Automation
        );
        assert_eq!(
            decide_workspace_access(&input, 101).unwrap(),
            WorkspaceRole::Visitor
        );
    }
}
