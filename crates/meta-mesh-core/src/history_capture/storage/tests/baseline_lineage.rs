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

#[test]
fn given_current_content_over_signature_budget_when_receiving_compact_basis_then_use_document_budget_separately() {
    use sha2::{Digest, Sha256};
    let source = fresh_source();
    let mut document = AutoCommit::load(&source.snapshot.document).unwrap();
    let mut current_content = String::new();
    for index in 0u64..8192 {
        for byte in Sha256::digest(index.to_be_bytes()) { current_content.push_str(&format!("{byte:02x}")); }
    }
    document.put(ROOT, "largeCurrentDescription", current_content).unwrap();
    document.commit();
    let capture = capture_source(source_with_document(source, document), 1, None);
    let mut objects = Objects::default();
    let catalogue = capture.write_catalogue(&mut objects).unwrap();
    let fixture = json!({"catalogue":catalogue,"objects":objects.0});
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture.verify_storage_directory(&scope, &root, &mut reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    assert!(rebase.document().len() > crate::history_baseline::MAX_HISTORY_BASELINE_BYTES);
    let trusted = super::baseline::signed_scope_snapshot(&capture.preparation().source().snapshot.workspace_id, capture.preparation().owner());
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    let signed = super::baseline::sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152; 32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let received = crate::history_baseline::verify_received_owner_attested_history_baseline(&signed, rebase.document(), &scope,
        coverage.authority(), &trusted, None, &mut reader).unwrap();
    assert_eq!(received.document(), rebase.document());
}

#[test]
fn given_archived_entity_versions_when_reading_one_then_verify_exact_dependency_bytes_and_preserve_original_classification() {
    use automerge::transaction::CommitOptions;
    let source = fresh_source();
    let mut document = AutoCommit::load(&source.snapshot.document).unwrap();
    document.put(ROOT, "title", "Signed item version").unwrap();
    document.commit_with(CommitOptions::default().with_time(10).with_message(json!({
        "version":1,"action":"editItem","entityIds":["item-1"],
        "personId":source.snapshot.expected_current_owner.person_id,
        "deviceId":source.snapshot.expected_current_owner.certificates[0].payload.device_id
    }).to_string()));
    let admitted_hash = document.get_heads()[0].to_string();
    let mut source = source_with_document(source, document);
    let mut document = AutoCommit::load(&source.snapshot.document).unwrap();
    document.put(ROOT, "title", "Unsigned original stays quarantined").unwrap();
    document.commit_with(CommitOptions::default().with_time(20).with_message(json!({
        "version":1,"action":"editItem","entityIds":["item-1"]
    }).to_string()));
    let quarantined_hash = document.get_heads()[0].to_string();
    source.snapshot.document = document.save();
    let capture = capture_source(source, 1, None);
    let mut objects = Objects::default();
    let catalogue = capture.write_catalogue(&mut objects).unwrap();
    let fixture = json!({"catalogue":catalogue,"objects":objects.0});
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture.verify_storage_directory(&scope, &root, &mut reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    let trusted = super::baseline::signed_scope_snapshot(&capture.preparation().source().snapshot.workspace_id, capture.preparation().owner());
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    let signed = super::baseline::sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152;32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let received = crate::history_baseline::verify_received_owner_attested_history_baseline(&signed, rebase.document(), &scope,
        coverage.authority(), &trusted, None, &mut reader).unwrap();
    let selected = crate::history_capture::read_archived_entity_version(&received, &scope, "item-1", &admitted_hash, &mut reader).unwrap();
    assert_eq!(selected.change_hash, admitted_hash);
    assert!(matches!(selected.observation, crate::causal_admission::CausalAdmissionStatus::Admitted { .. }));
    assert_eq!(selected.original_authorizations.len(), 1);
    let mut reconstructed = AutoCommit::load(&selected.document).unwrap();
    assert_eq!(reconstructed.get_heads()[0].to_string(), admitted_hash);
    assert_eq!(automerge::Change::from_bytes(selected.original_change).unwrap().hash().to_string(), admitted_hash);
    let quarantined = crate::history_capture::read_archived_entity_version(&received, &scope, "item-1", &quarantined_hash, &mut reader).unwrap();
    assert!(matches!(quarantined.observation, crate::causal_admission::CausalAdmissionStatus::Quarantined { .. }));
    assert!(quarantined.original_authorizations.is_empty());
    assert!(crate::history_capture::read_archived_entity_version(&received, &scope, "different-item", &admitted_hash, &mut reader).is_err());
    reader.revoke_after_download = true;
    assert!(crate::history_capture::read_archived_entity_version(&received, &scope, "item-1", &admitted_hash, &mut reader).is_err());
}

#[test]
fn given_imported_item_without_transaction_metadata_when_reading_archived_version_then_native_derives_original_entity_membership() {
    use automerge::{ObjType, ReadDoc, transaction::CommitOptions};
    let source = fresh_source();
    let mut document = AutoCommit::load(&source.snapshot.document).unwrap();
    let entities = document.put_object(ROOT, "entities", ObjType::Map).unwrap();
    let item = document.put_object(&entities, "legacy-item", ObjType::Map).unwrap();
    document.put(&item, "id", "legacy-item").unwrap();
    document.put(&item, "title", "Original imported item").unwrap();
    document.commit_with(CommitOptions::default().with_time(10));
    let hash = document.get_heads()[0].to_string();
    let capture = capture_source(source_with_document(source, document), 1, None);
    let mut objects = Objects::default();
    let catalogue = capture.write_catalogue(&mut objects).unwrap();
    let fixture = json!({"catalogue":catalogue,"objects":objects.0});
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture.verify_storage_directory(&scope, &root, &mut reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    let trusted = super::baseline::signed_scope_snapshot(&capture.preparation().source().snapshot.workspace_id, capture.preparation().owner());
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    let signed = super::baseline::sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152;32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let received = crate::history_baseline::verify_received_owner_attested_history_baseline(&signed, rebase.document(), &scope,
        coverage.authority(), &trusted, None, &mut reader).unwrap();
    let selected = crate::history_capture::read_archived_entity_version(&received, &scope, "legacy-item", &hash, &mut reader).unwrap();
    let document = AutoCommit::load(&selected.document).unwrap();
    let entities = document.get(ROOT, "entities").unwrap().unwrap().1;
    let item = document.get(&entities, "legacy-item").unwrap().unwrap().1;
    assert_eq!(document.get(&item, "title").unwrap().unwrap().0.as_str(), Some("Original imported item"));
    assert!(crate::history_capture::read_archived_entity_version(&received, &scope, "unrelated-item", &hash, &mut reader).is_err());
}

#[test]
fn given_authorized_peer_plaintext_proofs_when_verifying_owner_basis_then_require_signed_paths_without_rusty_read_keys() {
    struct Plain(BTreeMap<String, Vec<u8>>);
    impl crate::history_capture::HistoryArchivePlaintextReader for Plain {
        fn ensure_current(&mut self) -> Result<(), String> { Ok(()) }
        fn read(&mut self, id: &str) -> Result<Vec<u8>, String> { self.0.get(id).cloned().ok_or("missing plaintext proof".into()) }
    }
    let capture = capture_source(fresh_source(), 1, None);
    let mut objects = Objects::default();
    let catalogue = capture.write_catalogue(&mut objects).unwrap();
    let mut plain = Plain(objects.0.iter().map(|object| (object["objectId"].as_str().unwrap().to_owned(),
        URL_SAFE_NO_PAD.decode(object["bytes"].as_str().unwrap()).unwrap())).collect());
    let fixture = json!({"catalogue":catalogue,"objects":objects.0});
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture.verify_storage_directory(&scope, &root, &mut reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    let trusted = super::baseline::signed_scope_snapshot(&capture.preparation().source().snapshot.workspace_id, capture.preparation().owner());
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    let signed = super::baseline::sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152;32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let received = crate::history_baseline::verify_received_owner_attested_peer_history_baseline(&signed, rebase.document(), &trusted,
        None, &mut plain).unwrap();
    assert_eq!(received.document(), rebase.document());
    assert_eq!(received.storage_verification(), "public-receipts-only");
    let source_head = &proposal.payload().source_heads[0];
    let head_record_id = fixture["objects"].as_array().unwrap().iter().find_map(|object| {
        let bytes = URL_SAFE_NO_PAD.decode(object["bytes"].as_str()?).ok()?;
        let record = serde_json::from_slice::<crate::history_capture::HistoryCapturedChange>(&bytes).ok()?;
        (record.hash == *source_head).then(|| object["objectId"].as_str().unwrap().to_owned())
    }).unwrap();
    let original_head = plain.0.remove(&head_record_id).unwrap();
    assert!(crate::history_baseline::verify_received_owner_attested_peer_history_baseline(&signed, rebase.document(), &trusted,
        None, &mut plain).is_err());
    plain.0.insert(head_record_id, original_head);
    let mut changed = rebase.document().to_vec();
    changed[0] ^= 1;
    assert!(crate::history_baseline::verify_received_owner_attested_peer_history_baseline(&signed, &changed, &trusted,
        None, &mut plain).is_err());
    let root_id = &proposal.payload().archive.root.object_id;
    plain.0.get_mut(root_id).unwrap()[0] ^= 1;
    assert!(crate::history_baseline::verify_received_owner_attested_peer_history_baseline(&signed, rebase.document(), &trusted,
        None, &mut plain).is_err());
    plain.0.remove(root_id);
    assert!(crate::history_baseline::verify_received_owner_attested_peer_history_baseline(&signed, rebase.document(), &trusted,
        None, &mut plain).is_err());
}

#[test]
fn given_retained_prebasis_snapshot_when_cold_replica_reads_prefix_then_verify_exact_archived_changes_without_admitting_them() {
    let mut source = fresh_source();
    let prefix = source.snapshot.document.clone();
    let mut raw = AutoCommit::load(&prefix).unwrap();
    raw.put(ROOT, "title", "Unsigned historical observation stays quarantined").unwrap();
    raw.commit();
    source.snapshot.document = raw.save();
    let original = source.snapshot.document.clone();
    let next_source_template = source.clone();
    let capture = capture_source(source, 1, None);
    let mut objects = Objects::default();
    let catalogue = capture.write_catalogue(&mut objects).unwrap();
    let fixture = json!({"catalogue":catalogue,"objects":objects.0});
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture.verify_storage_directory(&scope, &root, &mut reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    let trusted = super::baseline::signed_scope_snapshot(&capture.preparation().source().snapshot.workspace_id, capture.preparation().owner());
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    let signed = super::baseline::sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152;32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let received = crate::history_baseline::verify_received_owner_attested_history_baseline(&signed, rebase.document(), &scope,
        coverage.authority(), &trusted, None, &mut reader).unwrap();
    crate::history_capture::verify_archived_snapshot(&received, &scope, &prefix, &mut reader).unwrap();
    crate::history_capture::verify_archived_snapshot(&received, &scope, &original, &mut reader).unwrap();
    assert_eq!(received.document(), rebase.document());
    let mut pending = AutoCommit::load(&original).unwrap();
    pending.put(ROOT, "title", "Missing predecessor").unwrap(); pending.commit();
    pending.put(ROOT, "title", "Uncaptured queued bytes").unwrap(); pending.commit();
    let queued_changes = pending.get_changes(&[]);
    let mut queued_snapshot = original.clone();
    queued_snapshot.extend_from_slice(queued_changes.last().unwrap().raw_bytes());
    assert!(AutoCommit::load(&queued_snapshot).is_ok());
    assert!(crate::history_capture::verify_archived_snapshot(&received, &scope, &queued_snapshot, &mut reader).is_err());
    let mut uncovered = AutoCommit::load(&original).unwrap();
    uncovered.put(ROOT, "title", "Uncaptured original must never disappear").unwrap();
    uncovered.commit();
    assert!(crate::history_capture::verify_archived_snapshot(&received, &scope, &uncovered.save(), &mut reader).is_err());
    assert!(crate::history_capture::verify_archived_snapshot(&received, &scope, rebase.document(), &mut reader).is_err());
    assert!(received.verify_previous_baseline(&received).is_err());
    // A confirmed storage conflict keeps the original epoch. Re-admit and recapture
    // the newly signed branch before choosing a new fence, rather than widening the old one.
    let concurrent_bytes = uncovered.save();
    let recapture = capture_source(source_with_document(next_source_template.clone(), uncovered), 1, None);
    let mut recaptured_objects = Objects::default();
    let recaptured_catalogue = recapture.write_catalogue(&mut recaptured_objects).unwrap();
    let (mut recaptured_reader, recaptured_root, _, _) = objects_and_directory(&json!({"catalogue":recaptured_catalogue,"objects":recaptured_objects.0}), &scope);
    let recaptured_storage = recapture.verify_storage_directory(&scope, &recaptured_root, &mut recaptured_reader).unwrap();
    let recaptured_coverage = complete_coverage(&recaptured_storage);
    let recaptured_rebase = recapture.preparation().rebase(1, recaptured_coverage.data_transition_id()).unwrap();
    let recaptured_joined = recapture.bind_rebase(&recaptured_rebase, &recaptured_coverage).unwrap();
    let recaptured_proposal = recaptured_joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    let recaptured_signed = super::baseline::sign_payload(serde_json::to_value(recaptured_proposal.payload()).unwrap(), &[152;32],
        &recaptured_proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let recaptured = crate::history_baseline::verify_received_owner_attested_history_baseline(&recaptured_signed,
        recaptured_rebase.document(), &scope, recaptured_coverage.authority(), &trusted, None, &mut recaptured_reader).unwrap();
    crate::history_capture::verify_archived_snapshot(&recaptured, &scope, &concurrent_bytes, &mut recaptured_reader).unwrap();
    assert_ne!(recaptured.envelope().payload.baseline_id, received.envelope().payload.baseline_id);
    let next = capture_source(source_with_document(next_source_template, AutoCommit::load(rebase.document()).unwrap()), 2, None);
    let mut next_objects = Objects::default();
    let next_catalogue = next.write_catalogue(&mut next_objects).unwrap();
    let (mut next_reader, next_root, _, _) = objects_and_directory(&json!({"catalogue":next_catalogue,"objects":next_objects.0}), &scope);
    let next_storage = next.verify_storage_directory(&scope, &next_root, &mut next_reader).unwrap();
    let next_coverage = complete_coverage(&next_storage);
    let next_rebase = next.preparation().rebase(2, next_coverage.data_transition_id()).unwrap();
    let parent = received.proposal_parent();
    let next_joined = next.bind_rebase(&next_rebase, &next_coverage).unwrap();
    let next_proposal = next_joined.propose_owner_attested_baseline(HistoryBaselineParent::Previous(&parent), &trusted).unwrap();
    let next_signed = super::baseline::sign_payload(serde_json::to_value(next_proposal.payload()).unwrap(), &[152;32],
        &next_proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let child = crate::history_baseline::verify_received_owner_attested_history_baseline(&next_signed, next_rebase.document(), &scope,
        next_coverage.authority(), &trusted, Some(&received), &mut next_reader).unwrap();
    child.verify_previous_baseline(&received).unwrap();
    assert!(received.verify_previous_baseline(&child).is_err());

}
