use super::*;

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload, WorkspaceAuthority,
    WorkspaceChangeAuthorization, WorkspaceChangeAuthorizationPayload, WorkspaceGrant,
    WorkspaceGrantPayload, WorkspaceRole, WorkspaceWriteAuthorizationSnapshot,
    public_key_from_seed, public_key_id, sign_device_certificate, sign_json_envelope,
};
use automerge::{
    AutoCommit, ROOT, ReadDoc,
    transaction::{CommitOptions, Transactable},
};

fn authority(
    seed: [u8; 32],
    device_seed: [u8; 32],
) -> (WorkspaceAuthority, [u8; 32], String, Vec<DeviceCertificate>) {
    let public_key = public_key_from_seed(&seed).unwrap();
    let person_id = public_key_id(&public_key).unwrap();
    let device_public_key = public_key_from_seed(&device_seed).unwrap();
    let device_id = public_key_id(&device_public_key).unwrap();
    let certificate = sign_device_certificate(
        &seed,
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
            certificates: vec![certificate.clone()],
        },
        device_seed,
        device_id,
        vec![certificate],
    )
}

fn grant(
    owner: &WorkspaceAuthority,
    owner_seed: &[u8; 32],
    editor: &WorkspaceAuthority,
    epoch: u64,
) -> WorkspaceGrant {
    let payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: format!("editor-{epoch}"),
        workspace_id: "workspace".into(),
        person_id: editor.person_id.clone(),
        role: WorkspaceRole::Editor,
        access_epoch: Some(epoch),
    };
    let signed = sign_json_envelope(
        owner_seed,
        serde_json::to_value(&payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    WorkspaceGrant {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    }
}

fn grant_hash(grant: &WorkspaceGrant) -> String {
    let value = serde_json::to_value(grant).unwrap();
    let canonical = crate::identity::canonicalize_json(&value).unwrap();
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn change_proof(
    authority: &WorkspaceAuthority,
    device_seed: &[u8; 32],
    device_id: &str,
    certificates: &[DeviceCertificate],
    hashes: &[String],
    grant: Option<WorkspaceGrant>,
) -> IncomingWorkspaceChangeAuthorization {
    let payload = WorkspaceChangeAuthorizationPayload {
        kind: "workspace-changes".into(),
        version: 1,
        workspace_id: "workspace".into(),
        hashes: hashes.to_vec(),
        person_id: authority.person_id.clone(),
        device_id: device_id.into(),
    };
    let signed = sign_json_envelope(
        device_seed,
        serde_json::to_value(&payload).unwrap(),
        device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    IncomingWorkspaceChangeAuthorization {
        signed: WorkspaceChangeAuthorization {
            payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        },
        public_key: authority.public_key.clone(),
        certificates: certificates.to_vec(),
        grant,
    }
}

fn change_metadata(grant: &WorkspaceGrant, person_id: &str, device_id: &str) -> String {
    serde_json::json!({
        "kind": "workspace-change-metadata",
        "version": 1,
        "authorityGrantHash": grant_hash(grant),
        "personId": person_id,
        "deviceId": device_id,
        "message": "edit"
    })
    .to_string()
}

fn snapshot(owner: WorkspaceAuthority, document: Vec<u8>) -> WorkspaceWriteAuthorizationSnapshot {
    WorkspaceWriteAuthorizationSnapshot {
        workspace_id: "workspace".into(),
        genesis_owner: owner.clone(),
        genesis_epoch: 1,
        expected_current_owner: owner,
        document,
        ownership_transfers: vec![],
        succession_claims: vec![],
        revocations: vec![],
        device_revocations: vec![],
        departures: vec![],
    }
}

fn document_with_editor_change(
    grant: &WorkspaceGrant,
    editor: &WorkspaceAuthority,
    editor_device_id: &str,
) -> (AutoCommit, String, String) {
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "genesis", "owner").unwrap();
    doc.commit();
    let genesis = doc.get_heads()[0].to_string();
    doc.put(ROOT, "editor", "edit").unwrap();
    doc.commit_with(CommitOptions::default().with_message(change_metadata(
        grant,
        &editor.person_id,
        editor_device_id,
    )));
    let editor_change = doc
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .find(|hash| hash != &genesis)
        .unwrap();
    (doc, genesis, editor_change)
}

#[test]
fn actual_change_metadata_binds_editor_proof_to_signed_grant() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([11; 32], [12; 32]);
    let (editor, editor_device_seed, editor_device_id, editor_certs) =
        authority([13; 32], [14; 32]);
    let old_grant = grant(&owner, &[11; 32], &editor, 1);
    let (mut doc, genesis, editor_change) =
        document_with_editor_change(&old_grant, &editor, &editor_device_id);
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &editor,
            &editor_device_seed,
            &editor_device_id,
            &editor_certs,
            std::slice::from_ref(&editor_change),
            Some(old_grant.clone()),
        ),
    ];
    let snapshot = snapshot(owner, doc.save());
    let evaluate = |now_ms| {
        evaluate_causal_admission(CausalAdmissionInput {
            records: records.clone(),
            snapshot: snapshot.clone(),
            pending_change_bytes: vec![],
            now_ms,
        })
        .unwrap()
    };
    let at_epoch = evaluate(0);
    let far_future = evaluate(i128::MAX / 3);
    assert_eq!(at_epoch, far_future);
    assert_eq!(at_epoch.decisions.len(), 2);
    assert!(
        at_epoch
            .decisions
            .iter()
            .all(|entry| matches!(entry.status, CausalAdmissionStatus::Admitted { .. }))
    );
    let projected = AutoCommit::load(&at_epoch.authorized_document).unwrap();
    assert_eq!(
        projected
            .get(ROOT, "editor")
            .unwrap()
            .unwrap()
            .0
            .to_string(),
        "\"edit\""
    );
}

#[test]
fn authorized_projection_bytes_ignore_pending_change_arrival_order() {
    let (owner, device_seed, device_id, certificates) = authority([17; 32], [18; 32]);
    let mut root = AutoCommit::new();
    root.put(ROOT, "root", "value").unwrap();
    root.commit();
    let root_change = root.get_changes(&[]).into_iter().next().unwrap();
    let root_hash = root_change.hash().to_string();
    let mut left = root.fork();
    left.set_actor(automerge::ActorId::from(&b"left-actor"[..]));
    left.put(ROOT, "left", "value").unwrap();
    left.commit();
    let left_change = left.get_changes(&[]).into_iter().last().unwrap();
    let mut right = root.fork();
    right.set_actor(automerge::ActorId::from(&b"right-actor"[..]));
    right.put(ROOT, "right", "value").unwrap();
    right.commit();
    let right_change = right.get_changes(&[]).into_iter().last().unwrap();
    let left_hash = left_change.hash().to_string();
    let right_hash = right_change.hash().to_string();
    let records = vec![
        change_proof(
            &owner,
            &device_seed,
            &device_id,
            &certificates,
            &[root_hash],
            None,
        ),
        change_proof(
            &owner,
            &device_seed,
            &device_id,
            &certificates,
            &[left_hash],
            None,
        ),
        change_proof(
            &owner,
            &device_seed,
            &device_id,
            &certificates,
            &[right_hash],
            None,
        ),
    ];
    let snapshot = snapshot(owner, root.save());
    let evaluate = |pending_change_bytes| {
        evaluate_causal_admission(CausalAdmissionInput {
            records: records.clone(),
            snapshot: snapshot.clone(),
            pending_change_bytes,
            now_ms: 0,
        })
        .unwrap()
    };
    let forward = evaluate(vec![
        left_change.raw_bytes().to_vec(),
        right_change.raw_bytes().to_vec(),
    ]);
    let reverse = evaluate(vec![
        right_change.raw_bytes().to_vec(),
        left_change.raw_bytes().to_vec(),
    ]);
    assert_eq!(forward.authorized_document, reverse.authorized_document);
}

#[test]
fn regrant_cannot_rebind_existing_editor_change_hash() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([21; 32], [22; 32]);
    let (editor, editor_device_seed, editor_device_id, editor_certs) =
        authority([23; 32], [24; 32]);
    let old_grant = grant(&owner, &[21; 32], &editor, 1);
    let newer_grant = grant(&owner, &[21; 32], &editor, 3);
    let (mut doc, genesis, editor_change) =
        document_with_editor_change(&old_grant, &editor, &editor_device_id);
    let mut snap = snapshot(owner.clone(), doc.save());
    let revocation_payload = crate::WorkspaceRevocationPayload {
        kind: "workspace-revocation".into(),
        version: 1,
        workspace_id: "workspace".into(),
        owner_person_id: owner.person_id.clone(),
        person_id: editor.person_id.clone(),
        epoch: 2,
        workspace_heads: vec![genesis.clone()],
        revoked_at: "2099-01-01T00:00:00.000Z".into(),
    };
    let signed_revocation = sign_json_envelope(
        &[21; 32],
        serde_json::to_value(&revocation_payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    snap.revocations.push(crate::WorkspaceRevocation {
        payload: revocation_payload,
        signer_key_id: signed_revocation.signer_key_id,
        signature: signed_revocation.signature,
    });
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &editor,
            &editor_device_seed,
            &editor_device_id,
            &editor_certs,
            std::slice::from_ref(&editor_change),
            Some(newer_grant),
        ),
    ];
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot: snap,
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap_or_else(|error| panic!("causal validation must ignore receiver clock: {error}"));
    let editor_decision = result
        .decisions
        .iter()
        .find(|entry| entry.hash == editor_change)
        .unwrap();
    assert!(
        matches!(
            &editor_decision.status,
            CausalAdmissionStatus::Quarantined { reason }
                if reason.contains("grant provenance")
        ),
        "new grant must not rebind old editor change"
    );
    let projected = AutoCommit::load(&result.authorized_document).unwrap();
    assert!(projected.get(ROOT, "editor").unwrap().is_none());
}

#[test]
fn owner_proof_cannot_rebind_legacy_editor_change_after_revocation() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([51; 32], [52; 32]);
    let (editor, _, editor_device_id, _) = authority([53; 32], [54; 32]);
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "genesis", "owner").unwrap();
    doc.commit();
    let genesis = doc.get_heads()[0].to_string();
    doc.put(ROOT, "legacy-editor", "edit").unwrap();
    doc.commit_with(
        CommitOptions::default().with_message(
            serde_json::json!({
                "version": 1,
                "transactionId": "legacy-1",
                "action": "set",
                "entityIds": ["legacy-editor"],
                "personId": editor.person_id,
                "deviceId": editor_device_id
            })
            .to_string(),
        ),
    );
    let editor_hash = doc.get_heads()[0].to_string();
    let mut snapshot = snapshot(owner.clone(), doc.save());
    let revocation_payload = crate::WorkspaceRevocationPayload {
        kind: "workspace-revocation".into(),
        version: 1,
        workspace_id: "workspace".into(),
        owner_person_id: owner.person_id.clone(),
        person_id: editor.person_id.clone(),
        epoch: 2,
        workspace_heads: vec![genesis.clone()],
        revoked_at: "2099-01-01T00:00:00.000Z".into(),
    };
    let signed = sign_json_envelope(
        &[51; 32],
        serde_json::to_value(&revocation_payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    snapshot.revocations.push(crate::WorkspaceRevocation {
        payload: revocation_payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    });
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[editor_hash.clone()],
            None,
        ),
    ];
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    let decision = result
        .decisions
        .iter()
        .find(|entry| entry.hash == editor_hash)
        .unwrap();
    assert!(
        matches!(&decision.status, CausalAdmissionStatus::Quarantined { reason }
            if reason.contains("identity metadata")),
        "owner cannot rebind prior editor identity metadata"
    );
}

#[test]
fn owner_proof_cannot_rebind_identityless_legacy_change_outside_frontier() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([61; 32], [62; 32]);
    let (editor, _, _, _) = authority([63; 32], [64; 32]);
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "genesis", "owner").unwrap();
    doc.commit();
    let genesis = doc.get_heads()[0].to_string();
    doc.put(ROOT, "legacy-editor", "edit").unwrap();
    doc.commit();
    let editor_hash = doc.get_heads()[0].to_string();
    let mut snapshot = snapshot(owner.clone(), doc.save());
    let revocation_payload = crate::WorkspaceRevocationPayload {
        kind: "workspace-revocation".into(),
        version: 1,
        workspace_id: "workspace".into(),
        owner_person_id: owner.person_id.clone(),
        person_id: editor.person_id,
        epoch: 2,
        workspace_heads: vec![genesis.clone()],
        revoked_at: "2099-01-01T00:00:00.000Z".into(),
    };
    let signed = sign_json_envelope(
        &[61; 32],
        serde_json::to_value(&revocation_payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    snapshot.revocations.push(crate::WorkspaceRevocation {
        payload: revocation_payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    });
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[editor_hash.clone()],
            None,
        ),
    ];
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    let decision = result
        .decisions
        .iter()
        .find(|entry| entry.hash == editor_hash)
        .unwrap();
    assert!(
        matches!(&decision.status, CausalAdmissionStatus::Quarantined { reason }
            if reason.contains("identity metadata")),
        "owner cannot rebind identityless legacy non-genesis change outside frontier"
    );
}

#[test]
fn pending_raw_change_with_missing_dependency_is_retained_pending() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([31; 32], [32; 32]);
    let mut source = AutoCommit::new();
    source
        .put(ROOT, "parent", "present in source only")
        .unwrap();
    source.commit();
    source.put(ROOT, "value", "child").unwrap();
    source.commit();
    let child = source.get_changes(&[]).into_iter().last().unwrap();
    let child_hash = child.hash().to_string();
    let record = change_proof(
        &owner,
        &owner_device_seed,
        &owner_device_id,
        &owner_certs,
        std::slice::from_ref(&child_hash),
        None,
    );
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records: vec![record],
        snapshot: snapshot(owner, AutoCommit::new().save()),
        pending_change_bytes: vec![child.raw_bytes().to_vec()],
        now_ms: 0,
    })
    .unwrap();
    assert!(
        matches!(
            &result.decisions[0].status,
            CausalAdmissionStatus::Pending { reason } if reason.contains("dependency is missing")
        ),
        "missing dependency must stay pending"
    );
    let projection = AutoCommit::load(&result.authorized_document).unwrap();
    assert!(projection.get(ROOT, "value").unwrap().is_none());
}
