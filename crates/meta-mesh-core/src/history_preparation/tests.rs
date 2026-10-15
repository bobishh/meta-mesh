use super::*;
use crate::causal_admission::CausalAdmissionStatus;
use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, IncomingWorkspaceChangeAuthorization,
    WorkspaceChangeAuthorization, WorkspaceChangeAuthorizationPayload,
    WorkspaceWriteAuthorizationSnapshot, public_key_from_seed, public_key_id,
    sign_device_certificate, sign_json_envelope,
};
use automerge::{AutoCommit, ROOT, ReadDoc, transaction::Transactable};

struct Fixture {
    source: CausalAdmissionInput,
    signer: HistoryPreparationSigner,
    device_seed: [u8; 32],
    owner_seed: [u8; 32],
}

fn fixture() -> Fixture {
    let owner_seed = [121; 32];
    let device_seed = [122; 32];
    let public_key = public_key_from_seed(&owner_seed).unwrap();
    let person_id = public_key_id(&public_key).unwrap();
    let device_public_key = public_key_from_seed(&device_seed).unwrap();
    let device_id = public_key_id(&device_public_key).unwrap();
    let cert = sign_device_certificate(
        &owner_seed,
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
    let owner = WorkspaceAuthority {
        person_id: person_id.clone(),
        public_key,
        certificates: vec![cert.clone()],
    };
    let signer = HistoryPreparationSigner {
        person_id,
        device_id,
        certificates: vec![cert],
    };
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "title", "Retained board").unwrap();
    doc.commit();
    let hashes = doc.get_heads().iter().map(ToString::to_string).collect();
    let record = proof(&owner, &signer, &device_seed, hashes);
    Fixture {
        source: CausalAdmissionInput {
            snapshot: WorkspaceWriteAuthorizationSnapshot {
                workspace_id: "workspace".into(),
                genesis_owner: owner.clone(),
                genesis_epoch: 1,
                expected_current_owner: owner,
                document: doc.save(),
                ownership_transfers: vec![],
                succession_claims: vec![],
                revocations: vec![],
                device_revocations: vec![],
                departures: vec![],
            },
            records: vec![record],
            pending_change_bytes: vec![],
            now_ms: 1_900_000_000_000,
        },
        signer,
        device_seed,
        owner_seed,
    }
}

fn proof(
    owner: &WorkspaceAuthority,
    signer: &HistoryPreparationSigner,
    seed: &[u8; 32],
    hashes: Vec<String>,
) -> IncomingWorkspaceChangeAuthorization {
    let payload = WorkspaceChangeAuthorizationPayload {
        kind: "workspace-changes".into(),
        version: 1,
        workspace_id: "workspace".into(),
        hashes,
        person_id: signer.person_id.clone(),
        device_id: signer.device_id.clone(),
    };
    let signed = sign_json_envelope(
        seed,
        serde_json::to_value(&payload).unwrap(),
        &signer.device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    IncomingWorkspaceChangeAuthorization {
        signed: WorkspaceChangeAuthorization {
            payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        },
        public_key: owner.public_key.clone(),
        certificates: signer.certificates.clone(),
        grant: None,
    }
}

#[test]
fn given_same_source_under_different_admission_policies_when_preparing_then_keep_revisions_distinct()
 {
    let f = fixture();
    assert_ne!(
        source_revision_for_policy(&f.source, "mesh-causal-admission@1").unwrap(),
        source_revision_for_policy(&f.source, "mesh-causal-admission@2").unwrap()
    );
}

#[test]
fn given_owner_signed_history_when_preparing_then_derive_projection_and_retain_exact_source_evidence()
 {
    let f = fixture();
    let original = f.source.clone();
    let prepared = prepare_workspace_history(f.source, f.signer).unwrap();
    assert_eq!(prepared.source(), &original);
    assert_eq!(prepared.admission().decisions.len(), 1);
    assert!(matches!(
        prepared.admission().decisions[0].status,
        CausalAdmissionStatus::Admitted { .. }
    ));
    assert_eq!(
        prepared.source_heads(),
        original.records[0].signed.payload.hashes
    );
    assert_eq!(prepared.owner(), &original.snapshot.expected_current_owner);
    assert_eq!(prepared.authority_digest().len(), 43);
    assert_eq!(prepared.admission_revision().len(), 43);
    assert!(prepared.assert_source_current(&original).is_ok());
}

#[test]
fn given_unsigned_injected_change_when_preparing_then_archive_raw_evidence_but_exclude_it_from_admitted_state()
 {
    let mut f = fixture();
    let mut raw = AutoCommit::load(&f.source.snapshot.document).unwrap();
    raw.put(ROOT, "title", "Unauthorized overwrite").unwrap();
    raw.commit();
    let hostile = raw.get_heads()[0].to_string();
    f.source.snapshot.document = raw.save();
    let exact_source = f.source.snapshot.document.clone();
    let prepared = prepare_workspace_history(f.source, f.signer).unwrap();
    assert_eq!(prepared.source().snapshot.document, exact_source);
    assert!(
        prepared
            .admission()
            .decisions
            .iter()
            .any(|decision| decision.hash == hostile
                && matches!(decision.status, CausalAdmissionStatus::Quarantined { .. }))
    );
    let admitted = AutoCommit::load(&prepared.admission().authorized_document).unwrap();
    assert_eq!(
        admitted.get(ROOT, "title").unwrap().unwrap().0.as_str(),
        Some("Retained board")
    );
}

#[test]
fn given_pending_signed_change_with_missing_dependency_when_preparing_then_retain_original_bytes_and_pending_classification()
 {
    let mut f = fixture();
    let mut raw = AutoCommit::load(&f.source.snapshot.document).unwrap();
    raw.put(ROOT, "dependency", "missing").unwrap();
    raw.commit();
    raw.put(ROOT, "pending", "retain").unwrap();
    raw.commit();
    let change = raw.get_changes(&[]).last().unwrap().clone();
    let hash = change.hash().to_string();
    let bytes = change.raw_bytes().to_vec();
    f.source.pending_change_bytes.push(bytes.clone());
    f.source.records.push(proof(
        &f.source.snapshot.genesis_owner,
        &f.signer,
        &f.device_seed,
        vec![hash.clone()],
    ));
    let prepared = prepare_workspace_history(f.source, f.signer).unwrap();
    assert_eq!(prepared.source().pending_change_bytes, vec![bytes]);
    assert!(
        prepared
            .admission()
            .decisions
            .iter()
            .any(|decision| decision.hash == hash
                && matches!(decision.status, CausalAdmissionStatus::Pending { .. }))
    );
}

#[test]
fn given_prepared_source_when_any_authority_proof_or_raw_basis_changes_then_reject_stale_preparation()
 {
    let f = fixture();
    let original = f.source.clone();
    let prepared = prepare_workspace_history(f.source, f.signer).unwrap();
    let mut clock = original.clone();
    clock.now_ms += 1000;
    assert!(
        prepared.assert_source_current(&clock).is_ok(),
        "Clock is not a causal revision"
    );
    let mut document = original.clone();
    document.snapshot.document.push(0);
    let mut proof = original.clone();
    proof.records[0].signed.signature.push('x');
    let mut pending = original.clone();
    pending.pending_change_bytes.push(vec![1]);
    let mut authority = original.clone();
    authority.snapshot.genesis_epoch += 1;
    for changed in [document, proof, pending, authority] {
        assert!(prepared.assert_source_current(&changed).is_err());
    }
}

#[test]
fn given_delegated_owner_device_when_complete_chain_exists_then_prepare_without_root_private_key() {
    let mut f = fixture();
    let leaf_seed = [123; 32];
    let public_key = public_key_from_seed(&leaf_seed).unwrap();
    let device_id = public_key_id(&public_key).unwrap();
    let leaf = sign_device_certificate(
        &f.device_seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: f.signer.person_id.clone(),
            device_id: device_id.clone(),
            device_public_key: public_key,
            issuer_certificate_hash: Some(
                crate::certificate_hash(&f.signer.certificates[0]).unwrap(),
            ),
            can_enroll_devices: false,
        },
        &f.signer.device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    f.signer.device_id = device_id;
    f.signer.certificates.insert(0, leaf);
    let prepared = prepare_workspace_history(f.source.clone(), f.signer.clone()).unwrap();
    assert_eq!(prepared.signer().certificates, f.signer.certificates);
    f.signer.certificates.pop();
    assert!(prepare_workspace_history(f.source, f.signer).is_err());
}

#[test]
fn given_other_person_or_forged_chain_when_preparing_then_reject_before_creating_a_token() {
    for alteration in ["person", "device", "signature", "owner", "epoch"] {
        let mut f = fixture();
        match alteration {
            "person" => f.signer.person_id = "editor".into(),
            "device" => f.signer.device_id = "unknown".into(),
            "signature" => f.signer.certificates[0].signature = "forged".into(),
            "owner" => {
                f.source.snapshot.expected_current_owner.public_key =
                    public_key_from_seed(&[124; 32]).unwrap()
            }
            "epoch" => f.source.snapshot.genesis_epoch = 0,
            _ => unreachable!(),
        }
        assert!(
            prepare_workspace_history(f.source, f.signer).is_err(),
            "Accepted {alteration}"
        );
    }
}

#[test]
fn given_valid_device_revocation_when_preparing_then_deny_even_if_all_old_changes_were_admitted() {
    let mut f = fixture();
    let signed = sign_json_envelope(&f.owner_seed, serde_json::json!({
        "kind": "workspace-device-revocation", "version": 1, "workspaceId": "workspace",
        "personId": f.signer.person_id, "deviceId": f.signer.device_id,
        "workspaceHeads": f.source.records[0].signed.payload.hashes, "revokedAt": "2026-10-14T10:00:00.000Z"
    }), &f.source.snapshot.genesis_owner.person_id, DEFAULT_SIGNATURE_DOMAIN).unwrap();
    let record = serde_json::from_value(serde_json::to_value(signed).unwrap()).unwrap();
    f.source
        .snapshot
        .device_revocations
        .push(crate::WorkspaceDeviceRevocationEvidence {
            record,
            signer: f.source.snapshot.genesis_owner.clone(),
        });
    assert!(
        matches!(prepare_workspace_history(f.source, f.signer), Err(error)
        if error == "History preparation signing device or person is no longer active")
    );
}

#[path = "adversarial_tests.rs"]
mod adversarial_tests;

#[path = "capture_tests.rs"]
mod capture_tests;
