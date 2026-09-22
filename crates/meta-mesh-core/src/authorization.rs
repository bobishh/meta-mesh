use serde::{Deserialize, Serialize};

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope, public_key_id,
    verify_device_certificate_chain, verify_signed_envelope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceRole {
    Owner,
    Editor,
    Visitor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceGrantPayload {
    pub kind: String,
    pub version: u8,
    pub grant_id: String,
    pub workspace_id: String,
    pub person_id: String,
    pub role: WorkspaceRole,
    // Absence is part of the signed legacy JSON. Do not materialize its
    // effective value before signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_epoch: Option<u64>,
}

impl WorkspaceGrantPayload {
    pub fn effective_access_epoch(&self) -> u64 { self.access_epoch.unwrap_or(1) }
}

pub type WorkspaceGrant = SignedEnvelope<WorkspaceGrantPayload>;

pub fn verify_device_signed_envelope<T: Serialize>(
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &[DeviceCertificate],
    envelope: &SignedEnvelope<T>,
    domain: &str,
) -> Result<(), String> {
    if envelope.signer_key_id != device_id {
        return Err("Signed envelope device mismatch".to_string());
    }
    let device_public_key = verify_device_certificate_chain(
        identity,
        device_id,
        certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    if !verify_signed_envelope(envelope, &device_public_key, domain)? {
        return Err("Invalid signed envelope signature".to_string());
    }
    Ok(())
}

pub fn verify_workspace_grant(
    grant: &WorkspaceGrant,
    workspace_id: &str,
    member_person_id: &str,
    owner: &PublicIdentity,
    owner_certificates: &[DeviceCertificate],
) -> Result<WorkspaceRole, String> {
    let payload = &grant.payload;
    if payload.kind != "workspace-grant"
        || payload.version != 1
        || payload.workspace_id != workspace_id
        || payload.person_id != member_person_id
        || payload.grant_id.is_empty()
        || payload.effective_access_epoch() == 0
    {
        return Err("Invalid workspace grant".to_string());
    }
    if owner.person_id != public_key_id(&owner.public_key)? {
        return Err("Invalid workspace owner".to_string());
    }
    // Legacy invitations used the identity root key while labeling the envelope
    // with the active device id. Root verification stays first for wire parity.
    if verify_signed_envelope(grant, &owner.public_key, DEFAULT_SIGNATURE_DOMAIN)? {
        return Ok(payload.role);
    }
    let signer_key = verify_device_certificate_chain(
        owner,
        &grant.signer_key_id,
        owner_certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .map_err(|_| "Invalid workspace grant signature".to_string())?;
    if verify_signed_envelope(grant, &signer_key, DEFAULT_SIGNATURE_DOMAIN)? {
        Ok(payload.role)
    } else {
        Err("Invalid workspace grant signature".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCertificatePayload, certificate_hash, public_key_from_seed, sign_device_certificate,
        sign_json_envelope,
    };

    fn signed_grant(
        seed: &[u8; 32],
        signer_key_id: &str,
        payload: &WorkspaceGrantPayload,
    ) -> WorkspaceGrant {
        let signed = sign_json_envelope(
            seed,
            serde_json::to_value(payload).unwrap(),
            signer_key_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        WorkspaceGrant {
            payload: payload.clone(),
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        }
    }

    #[test]
    fn owner_root_and_certified_device_can_issue_scoped_grants() {
        let owner_seed = [41; 32];
        let owner_public_key = public_key_from_seed(&owner_seed).unwrap();
        let owner_person_id = public_key_id(&owner_public_key).unwrap();
        let owner = PublicIdentity {
            person_id: owner_person_id.clone(),
            public_key: owner_public_key,
            display_name: "Owner".to_string(),
        };
        let device_seed = [42; 32];
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &owner_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".to_string(),
                version: 1,
                person_id: owner_person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &owner_person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        assert!(!certificate_hash(&certificate).unwrap().is_empty());
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".to_string(),
            version: 1,
            grant_id: "grant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            person_id: "member-1".to_string(),
            role: WorkspaceRole::Editor,
            access_epoch: Some(1),
        };

        let root_grant = signed_grant(&owner_seed, &owner_person_id, &payload);
        assert_eq!(
            verify_workspace_grant(
                &root_grant,
                "workspace-1",
                "member-1",
                &owner,
                &[certificate.clone()]
            )
            .unwrap(),
            WorkspaceRole::Editor
        );

        let device_grant = signed_grant(&device_seed, &device_id, &payload);
        assert_eq!(
            verify_workspace_grant(
                &device_grant,
                "workspace-1",
                "member-1",
                &owner,
                &[certificate]
            )
            .unwrap(),
            WorkspaceRole::Editor
        );
        assert!(
            verify_workspace_grant(&device_grant, "workspace-other", "member-1", &owner, &[])
                .is_err()
        );
    }

    #[test]
    fn legacy_grant_without_access_epoch_keeps_its_signed_json_shape() {
        let seed = [51; 32];
        let public_key = public_key_from_seed(&seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(), version: 1, grant_id: "legacy".into(), workspace_id: "workspace".into(),
            person_id: "member".into(), role: WorkspaceRole::Editor, access_epoch: None,
        };
        let grant = signed_grant(&seed, &person_id, &payload);
        let raw = serde_json::to_value(&grant).unwrap();
        assert!(raw["payload"].get("accessEpoch").is_none());
        let decoded: WorkspaceGrant = serde_json::from_value(raw).unwrap();
        assert_eq!(decoded.payload.effective_access_epoch(), 1);
        assert_eq!(serde_json::to_value(&decoded).unwrap()["payload"].get("accessEpoch"), None);
        assert_eq!(verify_workspace_grant(&decoded, "workspace", "member", &PublicIdentity { person_id, public_key, display_name: "Owner".into() }, &[]).unwrap(), WorkspaceRole::Editor);
    }

    #[test]
    fn explicit_access_epoch_one_is_not_dropped_from_signed_json() {
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(), version: 1, grant_id: "explicit".into(), workspace_id: "workspace".into(),
            person_id: "member".into(), role: WorkspaceRole::Editor, access_epoch: Some(1),
        };
        let raw = serde_json::to_value(&payload).unwrap();
        assert_eq!(raw["accessEpoch"], 1);
        let decoded: WorkspaceGrantPayload = serde_json::from_value(raw).unwrap();
        assert_eq!(decoded.access_epoch, Some(1));
        assert_eq!(serde_json::to_value(decoded).unwrap()["accessEpoch"], 1);
    }

    #[test]
    fn null_access_epoch_is_not_accepted_as_a_valid_grant() {
        let raw = serde_json::json!({"kind":"workspace-grant","version":1,"grantId":"g","workspaceId":"w","personId":"p","role":"editor","accessEpoch":null});
        let payload: WorkspaceGrantPayload = serde_json::from_value(raw).unwrap();
        assert_eq!(payload.effective_access_epoch(), 1);
        // It serializes without the field, so a signature over the hostile null
        // shape cannot validate as a legacy grant.
        assert!(serde_json::to_value(payload).unwrap().get("accessEpoch").is_none());
    }
}
