use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    WorkspaceAccessDecisionInput, WorkspaceAuthority, WorkspaceRole,
    WorkspaceWriteAuthorizationSnapshot, access,
    authorization::ValidatedWorkspaceWriteAuthorizationContext, decide_workspace_access,
    member::VerifyWorkspaceMemberOptions, validate_mesh_handshake, verify_workspace_member_bundle,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshPeerAdmission {
    pub workspace_id: String,
    pub person_id: String,
    pub device_id: String,
    pub endpoint: String,
    pub instance_id: Option<String>,
    pub role: WorkspaceRole,
}

#[derive(Default)]
pub struct MeshAuthenticatedSessions {
    peers: BTreeMap<String, (Value, MeshPeerAdmission)>,
}

impl MeshAuthenticatedSessions {
    pub fn admit(
        &mut self,
        handshake: Value,
        snapshot: &WorkspaceWriteAuthorizationSnapshot,
        remote_endpoint: &str,
        now_ms: i128,
    ) -> Result<MeshPeerAdmission, String> {
        self.peers.remove(remote_endpoint);
        let peer = admit_mesh_peer(handshake.clone(), snapshot, remote_endpoint, now_ms)?;
        self.peers
            .insert(remote_endpoint.to_string(), (handshake, peer.clone()));
        Ok(peer)
    }

    pub fn peer(&self, remote_endpoint: &str) -> Option<&MeshPeerAdmission> {
        self.peers.get(remote_endpoint).map(|(_, peer)| peer)
    }

    /// Recompute every live admission against an updated signed authority
    /// snapshot before the host accepts another document or control frame.
    pub fn refresh(
        &mut self,
        snapshot: &WorkspaceWriteAuthorizationSnapshot,
        now_ms: i128,
    ) -> Result<Vec<String>, String> {
        ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(snapshot, now_ms)?;
        let mut evicted = Vec::new();
        for (endpoint, (handshake, peer)) in &mut self.peers {
            match admit_mesh_peer(handshake.clone(), snapshot, endpoint, now_ms) {
                Ok(admitted) => *peer = admitted,
                Err(_) => evicted.push(endpoint.clone()),
            }
        }
        for endpoint in &evicted {
            self.peers.remove(endpoint);
        }
        Ok(evicted)
    }

    pub fn remove(&mut self, remote_endpoint: &str) -> bool {
        self.peers.remove(remote_endpoint).is_some()
    }

    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

/// Admit a mesh peer only after its signed route, grant, ownership history,
/// revocations, and transport endpoint agree. The caller must decode the
/// credential-bound pairing frame before passing its JSON payload here.
pub fn admit_mesh_peer(
    handshake: Value,
    snapshot: &WorkspaceWriteAuthorizationSnapshot,
    remote_endpoint: &str,
    now_ms: i128,
) -> Result<MeshPeerAdmission, String> {
    if remote_endpoint.is_empty() {
        return Err("Missing mesh transport endpoint".into());
    }
    let context = ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(snapshot, now_ms)?;
    let handshake = validate_mesh_handshake(handshake, Some(&snapshot.workspace_id))?;
    let verified = verify_workspace_member_bundle(
        handshake.peer,
        VerifyWorkspaceMemberOptions {
            workspace_id: Some(snapshot.workspace_id.clone()),
            owner_person_id: Some(context.current_owner.person_id.clone()),
            owner_public_key: Some(context.current_owner.public_key.clone()),
            owner_certificates: context.current_owner.certificates.clone(),
            owner_history: context.historical_owners.clone(),
            ..Default::default()
        },
        now_ms,
    )?;
    if verified.payload.endpoint != remote_endpoint {
        return Err("Mesh peer endpoint does not match transport".into());
    }
    let identity = WorkspaceAuthority {
        person_id: verified.payload.person_id.clone(),
        public_key: verified.public_key,
        certificates: verified.certificates,
    };
    let access = decide_workspace_access(
        &WorkspaceAccessDecisionInput {
            snapshot: snapshot.clone(),
            identity,
            device_id: verified.payload.device_id.clone(),
            grant: verified.grant.clone(),
            departures: snapshot
                .departures
                .iter()
                .map(|evidence| access::WorkspaceDepartureEvidence {
                    record: evidence.record.clone(),
                    authority: evidence.authority.clone(),
                })
                .collect(),
            legacy_authority_evidence: vec![],
        },
        now_ms,
    )?;
    if access != verified.role
        || context.device_was_revoked(&verified.payload.person_id, &verified.payload.device_id)
    {
        return Err("Mesh peer access is revoked".into());
    }
    if verified.role == WorkspaceRole::Visitor {
        let epoch = verified
            .grant
            .as_ref()
            .ok_or("Missing visitor grant")?
            .payload
            .effective_access_epoch();
        if snapshot.revocations.iter().any(|record| {
            record.payload.person_id == verified.payload.person_id && record.payload.epoch >= epoch
        }) || snapshot.departures.iter().any(|evidence| {
            evidence.record.payload.person_id == verified.payload.person_id
                && evidence.record.payload.access_epoch >= epoch
        }) {
            return Err("Mesh peer access is revoked".into());
        }
    }
    Ok(MeshPeerAdmission {
        workspace_id: snapshot.workspace_id.clone(),
        person_id: verified.payload.person_id,
        device_id: verified.payload.device_id,
        endpoint: verified.payload.endpoint,
        instance_id: verified.payload.instance_id,
        role: verified.role,
    })
}

#[cfg(test)]
mod tests {
    use automerge::{AutoCommit, ROOT, transaction::Transactable};
    use serde_json::json;

    use super::*;
    use crate::{
        DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, PeerAdvertisement,
        PeerAdvertisementPayload, WorkspaceDeviceRevocation, WorkspaceDeviceRevocationEvidence,
        WorkspaceDeviceRevocationPayload, WorkspaceGrant, WorkspaceGrantPayload,
        public_key_from_seed, public_key_id, sign_device_certificate, sign_json_envelope,
    };

    fn identity(person_seed: &[u8; 32], device_seed: &[u8; 32]) -> (WorkspaceAuthority, String) {
        let public_key = public_key_from_seed(person_seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            person_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        (
            WorkspaceAuthority {
                person_id,
                public_key,
                certificates: vec![certificate],
            },
            device_id,
        )
    }

    fn signed_editor() -> (
        Value,
        WorkspaceWriteAuthorizationSnapshot,
        WorkspaceAuthority,
        String,
    ) {
        let (owner, owner_device_id) = identity(&[1; 32], &[2; 32]);
        let (editor, editor_device_id) = identity(&[3; 32], &[4; 32]);
        let grant_payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(),
            version: 1,
            grant_id: "editor".into(),
            workspace_id: "workspace".into(),
            person_id: editor.person_id.clone(),
            role: WorkspaceRole::Editor,
            access_epoch: Some(1),
        };
        let signed_grant = sign_json_envelope(
            &[2; 32],
            serde_json::to_value(&grant_payload).unwrap(),
            &owner_device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let grant = WorkspaceGrant {
            payload: grant_payload,
            signer_key_id: signed_grant.signer_key_id,
            signature: signed_grant.signature,
        };
        let advertisement_payload = PeerAdvertisementPayload {
            kind: "peer-advertisement".into(),
            version: 1,
            workspace_id: "workspace".into(),
            person_id: editor.person_id.clone(),
            device_id: editor_device_id.clone(),
            instance_id: Some("slot-1".into()),
            endpoint: "remote-endpoint".into(),
            issued_at: "1970-01-01T00:00:00Z".into(),
            route_sequence: None,
            expires_at: None,
            device_name: None,
            user_agent: None,
        };
        let signed_advertisement = sign_json_envelope(
            &[4; 32],
            serde_json::to_value(&advertisement_payload).unwrap(),
            &editor_device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let advertisement = PeerAdvertisement {
            payload: advertisement_payload,
            signer_key_id: signed_advertisement.signer_key_id,
            signature: signed_advertisement.signature,
        };
        let bundle = json!({ "advertisement": advertisement, "publicKey": editor.public_key,
            "certificates": editor.certificates, "grant": grant });
        let handshake = json!({ "workspaceId": "workspace", "peer": bundle,
            "capabilities": ["iroh-gossip-v1", "automerge-sync-v1"] });
        let snapshot = WorkspaceWriteAuthorizationSnapshot {
            workspace_id: "workspace".into(),
            genesis_owner: owner.clone(),
            genesis_epoch: 1,
            expected_current_owner: owner.clone(),
            document: AutoCommit::new().save(),
            ownership_transfers: vec![],
            succession_claims: vec![],
            revocations: vec![],
            device_revocations: vec![],
            departures: vec![],
        };
        (handshake, snapshot, owner, editor_device_id)
    }

    #[test]
    fn signed_editor_is_admitted_only_on_its_signed_transport_endpoint() {
        let (handshake, snapshot, _, device_id) = signed_editor();
        let admitted = admit_mesh_peer(handshake.clone(), &snapshot, "remote-endpoint", 0).unwrap();
        assert_eq!(admitted.device_id, device_id);
        assert_eq!(admitted.role, WorkspaceRole::Editor);
        assert_eq!(admitted.instance_id.as_deref(), Some("slot-1"));
        assert_eq!(
            admit_mesh_peer(handshake.clone(), &snapshot, "other-endpoint", 0).unwrap_err(),
            "Mesh peer endpoint does not match transport"
        );
        let mut no_grant = handshake;
        no_grant["peer"].as_object_mut().unwrap().remove("grant");
        assert!(admit_mesh_peer(no_grant, &snapshot, "remote-endpoint", 0).is_err());
    }

    #[test]
    fn signed_device_revocation_rejects_editor_before_document_sync() {
        let (handshake, mut snapshot, owner, device_id) = signed_editor();
        let mut sessions = MeshAuthenticatedSessions::default();
        sessions
            .admit(handshake.clone(), &snapshot, "remote-endpoint", 0)
            .unwrap();
        let mut invalid = snapshot.clone();
        invalid.workspace_id.clear();
        assert!(sessions.refresh(&invalid, 0).is_err());
        assert!(sessions.peer("remote-endpoint").is_some());
        let owner_device_id = public_key_id(&public_key_from_seed(&[2; 32]).unwrap()).unwrap();
        let mut document = AutoCommit::new();
        document.put(ROOT, "title", "board").unwrap();
        let workspace_heads = document
            .get_heads()
            .iter()
            .map(ToString::to_string)
            .collect();
        snapshot.document = document.save();
        let payload = WorkspaceDeviceRevocationPayload {
            kind: "workspace-device-revocation".into(),
            version: 1,
            workspace_id: "workspace".into(),
            person_id: handshake["peer"]["advertisement"]["payload"]["personId"]
                .as_str()
                .unwrap()
                .into(),
            device_id,
            workspace_heads,
            revoked_at: "1970-01-01T00:00:00.000Z".into(),
        };
        let signed = sign_json_envelope(
            &[2; 32],
            serde_json::to_value(&payload).unwrap(),
            &owner_device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        snapshot
            .device_revocations
            .push(WorkspaceDeviceRevocationEvidence {
                record: WorkspaceDeviceRevocation {
                    payload,
                    signer_key_id: signed.signer_key_id,
                    signature: signed.signature,
                },
                signer: owner,
            });
        assert_eq!(
            admit_mesh_peer(handshake, &snapshot, "remote-endpoint", 0).unwrap_err(),
            "Mesh peer access is revoked"
        );
        assert_eq!(
            sessions.refresh(&snapshot, 0).unwrap(),
            vec!["remote-endpoint"]
        );
        assert!(sessions.peer("remote-endpoint").is_none());
    }
}
