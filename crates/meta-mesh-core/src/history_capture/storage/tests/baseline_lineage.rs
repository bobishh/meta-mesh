use super::*;
use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, WorkspaceChangeAuthorization,
    WorkspaceChangeAuthorizationPayload,
    history_baseline::{
        HISTORY_BASELINE_DOMAIN, HistoryBaselineParent, VerifiedHistoryBaselineAttestation,
    },
    history_capture::{HistoryArchiveObjectBinding, HistoryArchiveWriter, history_control_value},
};
use automerge::{AutoCommit, ROOT, transaction::Transactable};

#[derive(Default)]
struct Objects(Vec<Value>);
impl HistoryArchiveWriter for Objects {
    fn write(
        &mut self,
        id: &str,
        bytes: &[u8],
        binding: &HistoryArchiveObjectBinding,
    ) -> Result<(), String> {
        self.0
            .push(json!({"objectId":id,"bytes":URL_SAFE_NO_PAD.encode(bytes),"binding":binding}));
        Ok(())
    }
}

fn proof(
    source: &CausalAdmissionInput,
    signer: &HistoryPreparationSigner,
    seed: &[u8; 32],
    hashes: Vec<String>,
) -> IncomingWorkspaceChangeAuthorization {
    let payload = WorkspaceChangeAuthorizationPayload {
        kind: "workspace-changes".into(),
        version: 1,
        workspace_id: source.snapshot.workspace_id.clone(),
        hashes,
        person_id: signer.person_id.clone(),
        device_id: signer.device_id.clone(),
    };
    let signature = crate::sign_json_envelope(
        seed,
        serde_json::to_value(&payload).unwrap(),
        &signer.device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    IncomingWorkspaceChangeAuthorization {
        signed: WorkspaceChangeAuthorization {
            payload,
            signer_key_id: signature.signer_key_id,
            signature: signature.signature,
        },
        public_key: source.snapshot.expected_current_owner.public_key.clone(),
        certificates: signer.certificates.clone(),
        grant: None,
    }
}

fn source_with_document(
    mut source: CausalAdmissionInput,
    mut document: AutoCommit,
) -> CausalAdmissionInput {
    let owner = &source.snapshot.expected_current_owner;
    let signer = HistoryPreparationSigner {
        person_id: owner.person_id.clone(),
        device_id: owner.certificates[0].payload.device_id.clone(),
        certificates: owner.certificates.clone(),
    };
    // These fixtures contain only this Owner's newly authored operations. This extra
    // test proof is not a production shortcut for admitting a network baseline.
    let hashes = document
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .collect();
    source.snapshot.document = document.save();
    source.pending_change_bytes.clear();
    source.records = vec![proof(&source, &signer, &[152; 32], hashes)];
    source
}

fn fresh_source() -> CausalAdmissionInput {
    let (capture, _) = captured_fixture();
    let mut document = AutoCommit::new();
    document.put(ROOT, "title", "Lineage state").unwrap();
    document.commit();
    source_with_document(capture.preparation().source().clone(), document)
}

fn capture_source(
    source: CausalAdmissionInput,
    epoch: u64,
    signer: Option<HistoryPreparationSigner>,
) -> VerifiedHistoryArchiveCapture {
    let owner = &source.snapshot.expected_current_owner;
    let signer = signer.unwrap_or_else(|| HistoryPreparationSigner {
        person_id: owner.person_id.clone(),
        device_id: owner.certificates[0].payload.device_id.clone(),
        certificates: owner.certificates.clone(),
    });
    let originals = HistoryOriginalEvidence {
        control_json: serde_json::to_vec(&history_control_value(&source.snapshot).unwrap())
            .unwrap(),
        authorization_json: source
            .records
            .iter()
            .map(|record| serde_json::to_vec(record).unwrap())
            .collect(),
    };
    capture_workspace_history(
        prepare_workspace_history(source, signer).unwrap(),
        epoch,
        originals,
    )
    .unwrap()
}

fn storage_for(capture: &VerifiedHistoryArchiveCapture) -> VerifiedHistoryArchiveStorage {
    let mut objects = Objects::default();
    let catalogue = capture.write_catalogue(&mut objects).unwrap();
    let fixture = json!({"catalogue":catalogue,"objects":objects.0});
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap()
}

fn coverage_for(
    capture: &VerifiedHistoryArchiveCapture,
) -> crate::history_archive_coverage::VerifiedHistoryArchiveCoverage {
    let storage = storage_for(capture);
    let seed = std::array::from_fn(|i| i as u8 + 1);
    let authority = crate::history_archive_coverage::HistoryArchiveCoverageAuthority {
        service_public_key: crate::public_key_from_seed(&seed).unwrap(),
        scope_id: storage.scope_id().into(),
        policy_revision: 7,
    };
    let data = format!("native-lineage-data-{:06}", capture.history_epoch());
    let directory = format!("native-lineage-directory-{:06}", capture.history_epoch());
    let (data_receipt, directory_receipt) =
        coverage_receipt_pair(&storage, &authority, &seed, &data, &directory);
    storage
        .verify_coverage(
            &authority,
            coverage_proof(&data, &directory, &data_receipt, &directory_receipt),
        )
        .unwrap()
}

fn attest(
    capture: &VerifiedHistoryArchiveCapture,
    parent: HistoryBaselineParent<'_>,
    seed: &[u8; 32],
) -> VerifiedHistoryBaselineAttestation {
    let coverage = coverage_for(capture);
    let rebase = capture
        .preparation()
        .rebase(capture.history_epoch(), coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined.propose_baseline(parent).unwrap();
    let signed = crate::sign_json_envelope(
        seed,
        serde_json::to_value(proposal.payload()).unwrap(),
        &proposal.payload().device_id,
        HISTORY_BASELINE_DOMAIN,
    )
    .unwrap();
    proposal
        .confirm(
            &serde_json::to_vec(&signed).unwrap(),
            capture.preparation().source(),
        )
        .unwrap()
}

fn can_propose(capture: &VerifiedHistoryArchiveCapture, parent: HistoryBaselineParent<'_>) -> bool {
    let coverage = coverage_for(capture);
    let rebase = capture
        .preparation()
        .rebase(capture.history_epoch(), coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    joined.propose_baseline(parent).is_ok()
}

#[test]
fn given_verified_parent_and_admitted_basis_when_advancing_then_bind_exact_next_epoch_and_parent() {
    let original = fresh_source();
    let first = capture_source(original.clone(), 1, None);
    let parent = attest(&first, HistoryBaselineParent::Initial, &[152; 32]);
    let mut document = AutoCommit::load(parent.document()).unwrap();
    document
        .put(ROOT, "title", "Second admitted state")
        .unwrap();
    document.commit();
    let next = capture_source(source_with_document(original, document), 2, None);
    let child = attest(&next, HistoryBaselineParent::Previous(&parent), &[152; 32]);
    assert_eq!(
        child.envelope().payload.previous_baseline_id.as_deref(),
        Some(parent.envelope().payload.baseline_id.as_str())
    );
    assert_eq!(child.envelope().payload.history_epoch, 2);
    assert_eq!(child.envelope().payload.control_epoch, 1);
    assert_ne!(
        child.envelope().payload.baseline_id,
        parent.envelope().payload.baseline_id
    );
}

#[test]
fn given_skipped_replayed_or_unrelated_basis_when_proposing_successor_then_reject_without_losing_parent()
 {
    let original = fresh_source();
    let first = capture_source(original.clone(), 1, None);
    let parent = attest(&first, HistoryBaselineParent::Initial, &[152; 32]);
    let source = source_with_document(original, AutoCommit::load(parent.document()).unwrap());
    assert!(!can_propose(
        &capture_source(source.clone(), 2, None),
        HistoryBaselineParent::Initial
    ));
    assert!(!can_propose(
        &capture_source(source.clone(), 3, None),
        HistoryBaselineParent::Previous(&parent)
    ));
    assert!(!can_propose(
        &capture_source(source, 1, None),
        HistoryBaselineParent::Previous(&parent)
    ));
    let unrelated = capture_source(fresh_source(), 2, None);
    assert!(!can_propose(
        &unrelated,
        HistoryBaselineParent::Previous(&parent)
    ));
    assert_eq!(parent.envelope().payload.history_epoch, 1);
    assert!(can_propose(&first, HistoryBaselineParent::Initial));
}

fn add_revocation(source: &mut CausalAdmissionInput) {
    let mut document = AutoCommit::load(&source.snapshot.document).unwrap();
    let payload = crate::WorkspaceRevocationPayload {
        kind: "workspace-revocation".into(),
        version: 1,
        workspace_id: source.snapshot.workspace_id.clone(),
        owner_person_id: source.snapshot.expected_current_owner.person_id.clone(),
        person_id: "revoked-member".into(),
        epoch: 2,
        workspace_heads: document
            .get_heads()
            .iter()
            .map(ToString::to_string)
            .collect(),
        revoked_at: "2026-10-15T00:00:00.000Z".into(),
    };
    let signed = crate::sign_json_envelope(
        &[151; 32],
        serde_json::to_value(payload).unwrap(),
        &source.snapshot.genesis_owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    source
        .snapshot
        .revocations
        .push(serde_json::from_value(serde_json::to_value(signed).unwrap()).unwrap());
}

#[test]
fn given_parent_with_signed_revocation_when_source_omits_it_then_reject_authority_rollback() {
    let mut original = fresh_source();
    add_revocation(&mut original);
    let first = capture_source(original.clone(), 1, None);
    let parent = attest(&first, HistoryBaselineParent::Initial, &[152; 32]);
    let mut document = AutoCommit::load(&original.snapshot.document).unwrap();
    document
        .merge(&mut AutoCommit::load(parent.document()).unwrap())
        .unwrap();
    document.put(ROOT, "title", "Retained authority").unwrap();
    document.commit_with(
        automerge::transaction::CommitOptions::default().with_message(
            crate::canonicalize_json(&json!({"kind":"workspace-change-metadata","version":1,
            "personId":original.snapshot.expected_current_owner.person_id,
            "deviceId":original.snapshot.expected_current_owner.certificates[0].payload.device_id}))
            .unwrap(),
        ),
    );
    let retained = source_with_document(original, document);
    let second = capture_source(retained.clone(), 2, None);
    assert!(can_propose(
        &second,
        HistoryBaselineParent::Previous(&parent)
    ));
    let mut rollback = retained;
    rollback.snapshot.revocations.clear();
    let missing = capture_source(rollback, 2, None);
    assert!(!can_propose(
        &missing,
        HistoryBaselineParent::Previous(&parent)
    ));
}

fn next_owner() -> (WorkspaceAuthority, HistoryPreparationSigner) {
    let root = crate::public_key_from_seed(&[171; 32]).unwrap();
    let person_id = crate::public_key_id(&root).unwrap();
    let public_key = crate::public_key_from_seed(&[172; 32]).unwrap();
    let device_id = crate::public_key_id(&public_key).unwrap();
    let root_cert = crate::sign_device_certificate(
        &[171; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: person_id.clone(),
            device_id: device_id.clone(),
            device_public_key: public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    let owner = WorkspaceAuthority {
        person_id: person_id.clone(),
        public_key: root,
        certificates: vec![root_cert.clone()],
    };
    let leaf_public = crate::public_key_from_seed(&[173; 32]).unwrap();
    let leaf_id = crate::public_key_id(&leaf_public).unwrap();
    let leaf = crate::sign_device_certificate(
        &[172; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: person_id.clone(),
            device_id: leaf_id.clone(),
            device_public_key: leaf_public,
            issuer_certificate_hash: Some(crate::certificate_hash(&root_cert).unwrap()),
            can_enroll_devices: true,
        },
        device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    (
        owner,
        HistoryPreparationSigner {
            person_id,
            device_id: leaf_id,
            certificates: vec![leaf, root_cert],
        },
    )
}

fn grant(
    person: &str,
    owner: &WorkspaceAuthority,
    workspace: &str,
    role: crate::WorkspaceRole,
) -> crate::WorkspaceGrant {
    let payload = crate::WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: format!("baseline-transfer-{person}"),
        workspace_id: workspace.into(),
        person_id: person.into(),
        role,
        access_epoch: Some(2),
        automation: None,
    };
    let signed = crate::sign_json_envelope(
        &[151; 32],
        serde_json::to_value(payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    serde_json::from_value(serde_json::to_value(signed).unwrap()).unwrap()
}

#[test]
fn given_verified_ownership_transfer_when_next_owner_device_signs_then_use_new_control_epoch_and_complete_chain()
 {
    let original = fresh_source();
    let first = capture_source(original.clone(), 1, None);
    let parent = attest(&first, HistoryBaselineParent::Initial, &[152; 32]);
    let mut source = source_with_document(original, AutoCommit::load(parent.document()).unwrap());
    let (next, signer) = next_owner();
    let old = &source.snapshot.genesis_owner;
    let payload = crate::WorkspaceOwnershipTransferPayload {
        kind: "workspace-ownership-transfer".into(),
        version: 1,
        workspace_id: source.snapshot.workspace_id.clone(),
        from_owner_person_id: old.person_id.clone(),
        to_owner_person_id: next.person_id.clone(),
        to_owner_public_key: next.public_key.clone(),
        to_owner_certificates: next.certificates.clone(),
        to_owner_grant: grant(
            &next.person_id,
            old,
            &source.snapshot.workspace_id,
            crate::WorkspaceRole::Owner,
        ),
        former_owner_grant: grant(
            &old.person_id,
            old,
            &source.snapshot.workspace_id,
            crate::WorkspaceRole::Editor,
        ),
        workspace_heads: vec![parent.envelope().payload.genesis_hash.clone()],
        epoch: 2,
        transferred_at: "2026-10-15T00:00:00.000Z".into(),
    };
    let signed = crate::sign_json_envelope(
        &[152; 32],
        serde_json::to_value(payload).unwrap(),
        &old.certificates[0].payload.device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    source
        .snapshot
        .ownership_transfers
        .push(serde_json::from_value(serde_json::to_value(signed).unwrap()).unwrap());
    source.snapshot.expected_current_owner = next;
    let mut document = AutoCommit::load(&source.snapshot.document).unwrap();
    document.put(ROOT, "title", "New Owner state").unwrap();
    document.commit();
    let changed = document
        .get_heads()
        .iter()
        .map(ToString::to_string)
        .collect();
    source.snapshot.document = document.save();
    source
        .records
        .push(proof(&source, &signer, &[173; 32], changed));
    let second = capture_source(source.clone(), 2, Some(signer.clone()));
    let child = attest(
        &second,
        HistoryBaselineParent::Previous(&parent),
        &[173; 32],
    );
    assert_eq!(child.envelope().payload.control_epoch, 2);
    assert_eq!(child.envelope().payload.person_id, signer.person_id);
    assert_eq!(child.envelope().payload.certificates, signer.certificates);
    assert_eq!(child.envelope().payload.certificates.len(), 2);
    assert!(prepare_workspace_history(source, first.preparation().signer().clone()).is_err());
}
