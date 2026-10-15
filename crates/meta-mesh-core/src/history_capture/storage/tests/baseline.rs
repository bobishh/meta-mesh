use super::*;
use crate::{
    DEFAULT_SIGNATURE_DOMAIN,
    history_baseline::{HISTORY_BASELINE_DOMAIN, HistoryBaselineParent},
    sign_json_envelope,
};
use automerge::{AutoCommit, ROOT, transaction::Transactable};

pub(super) fn sign_payload(
    payload: serde_json::Value,
    seed: &[u8; 32],
    signer: &str,
    domain: &str,
) -> Vec<u8> {
    serde_json::to_vec(&sign_json_envelope(seed, payload, signer, domain).unwrap()).unwrap()
}

fn signed_initial_fixture() -> (
    Vec<u8>,
    Vec<u8>,
    crate::history_archive_crypto::HistoryArchiveEncryptionScope,
    crate::history_archive_coverage::HistoryArchiveCoverageAuthority,
    Reader,
) {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut local_reader, locator_root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &locator_root, &mut local_reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let basis = capture
        .bind_rebase(&rebase, &coverage)
        .unwrap();
    let proposal = basis
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    let payload = serde_json::to_value(proposal.payload()).unwrap();
    let signed = sign_payload(
        payload,
        &[152; 32],
        &proposal.payload().device_id,
        HISTORY_BASELINE_DOMAIN,
    );
    let (reader, _, _, _) = objects_and_directory(&fixture, &scope);
    (signed, rebase.document().to_vec(), scope, coverage.authority().clone(), reader)
}

#[test]
fn given_untouched_policy_two_archive_when_cold_receiving_and_selecting_original_then_preserve_old_observation_and_exact_proof() {
    use automerge::transaction::CommitOptions;
    use crate::history_capture::source::{self, EncryptedSource};
    let frozen: Value = serde_json::from_slice(&std::fs::read(FIXTURE).unwrap()).unwrap();
    let (signed, current_basis, scope, authority, _) = signed_initial_fixture();
    let mut envelope: Value = serde_json::from_slice(&signed).unwrap();
    let payload = &mut envelope["payload"];
    let (mut reader, locator_root, mut data_ids, catalogue_ciphertext) = objects_and_directory(&frozen, &scope);
    data_ids.sort_unstable(); data_ids.dedup();
    let seed = std::array::from_fn(|index| index as u8 + 1);
    payload["archive"] = frozen["catalogue"].clone();
    payload["locatorRoot"] = serde_json::to_value(&locator_root).unwrap();
    payload["admissionPolicy"] = json!("mesh-causal-admission@2");
    payload["admissionRevision"] = frozen["catalogue"]["admissionRevision"].clone();
    payload["storage"]["dataReceipt"] = serde_json::from_slice(&signed_coverage_receipt(
        &catalogue_ciphertext, payload["storage"]["dataTransitionId"].as_str().unwrap(), &data_ids,
        scope.key_epoch, &authority, &seed)).unwrap();
    payload["storage"]["directoryReceipt"] = serde_json::from_slice(&signed_coverage_receipt(
        &locator_root.root.ciphertext_id, payload["storage"]["directoryTransitionId"].as_str().unwrap(),
        &[locator_root.root.ciphertext_id.clone()], scope.key_epoch, &authority, &seed)).unwrap();

    // A signed historical attestation binds its original admission revision in
    // the compact genesis too. None of the frozen archive objects are rewritten.
    let mut current = AutoCommit::load(&current_basis).unwrap();
    let mut metadata: Value = serde_json::from_str(current.get_changes(&[])[0].message().unwrap()).unwrap();
    metadata["admissionRevision"] = payload["admissionRevision"].clone();
    let mut basis = AutoCommit::new();
    basis.put(ROOT, "title", "Native admitted original").unwrap();
    basis.commit_with(CommitOptions::default().with_time(0).with_message(crate::canonicalize_json(&metadata).unwrap()));
    let document = basis.save();
    assert_eq!(crate::history_rebase::history_current_state_digest(&document).unwrap(), payload["stateDigest"]);
    payload["documentDigest"] = json!(history_archive_object_id(&document));
    payload["genesisHash"] = json!(basis.get_heads()[0].to_string());
    let mut id_input = payload.clone();
    id_input.as_object_mut().unwrap().remove("baselineId");
    payload["baselineId"] = json!(history_archive_object_id(crate::canonicalize_json(&id_input).unwrap().as_bytes()));
    let signed = sign_payload(payload.clone(), &[152;32], payload["deviceId"].as_str().unwrap(), HISTORY_BASELINE_DOMAIN);
    let received = crate::history_baseline::verify_received_history_baseline(&signed, &document, &scope, &authority, None, &mut reader).unwrap();
    assert_eq!(received.envelope().payload.admission_policy, "mesh-causal-admission@2");
    assert_eq!(serde_json::to_value(&received.envelope().payload.archive).unwrap(), frozen["catalogue"]);

    // The frozen vector predates entity indexes. Read one exact selected change
    // and proof by its authenticated hash path, without reclassifying the record.
    let catalogue = &received.envelope().payload.archive;
    let mut source = EncryptedSource { reader: &mut reader, scope: &scope, locator_root: &locator_root };
    let hash = frozen["expected"]["pendingHash"].as_str().unwrap();
    let record: crate::history_capture::HistoryCapturedChange = serde_json::from_slice(&source::index_record(
        &catalogue.context, &catalogue.root, &format!("change/{hash}"), &mut source).unwrap()).unwrap();
    assert_eq!(record.admission_policy, "mesh-causal-admission@2");
    assert!(matches!(record.observation, crate::causal_admission::CausalAdmissionStatus::Pending { .. }));
    let mut context = catalogue.context.clone(); context.index_id = format!("change/{hash}/bytes");
    assert_eq!(source::bytes(&context, &record.bytes, 1024*1024, &mut source).unwrap(), decode(&frozen["originals"]["pending"][0]));
    let reference: HistoryArchiveBytesReference = serde_json::from_slice(&source::index_record(
        &catalogue.context, &catalogue.root, "proof/0000000000000001", &mut source).unwrap()).unwrap();
    context.index_id = "source-proof/0000000000000001".into();
    assert_eq!(source::bytes(&context, &reference, 1024*1024, &mut source).unwrap(), decode(&frozen["originals"]["authorizations"][1]));
}

pub(super) fn signed_scope_snapshot(workspace_id: &str, owner: &crate::WorkspaceAuthority) -> crate::ScopeAuthoritySnapshot {
    let creator = crate::ScopeAuthority {
        person_id: owner.person_id.clone(),
        public_key: owner.public_key.clone(),
        certificates: owner.certificates.clone(),
    };
    let payload = crate::create_scope_genesis_payload(crate::ScopeGenesisPayloadInput {
        scope_id: workspace_id.into(), creator,
    }).unwrap();
    let signed = sign_json_envelope(&[152; 32], serde_json::to_value(&payload).unwrap(),
        owner.certificates[0].payload.device_id.clone(), crate::DEFAULT_SIGNATURE_DOMAIN).unwrap();
    let genesis = crate::SignedEnvelope {
        payload: serde_json::from_value(signed.payload).unwrap(),
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    };
    crate::ScopeAuthoritySnapshot {
        genesis, grants: vec![], grant_issuers: vec![], revocations: vec![],
        control_transfers: vec![], succession_transfers: vec![],
    }
}

#[test]
fn given_native_verified_compact_basis_when_preparing_new_signed_tail_then_admit_without_synthetic_genesis() {
    let (first, fixture) = captured_fixture();
    let storage_scope = scope();
    let (mut local_reader, locator_root, _, _) = objects_and_directory(&fixture, &storage_scope);
    let storage = first.verify_storage_directory(&storage_scope, &locator_root, &mut local_reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = first.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    let trusted = signed_scope_snapshot(&first.preparation().source().snapshot.workspace_id,
        first.preparation().owner());
    let basis = first.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = basis
        .propose_owner_attested_baseline(crate::history_baseline::HistoryBaselineParent::Initial, &trusted).unwrap();
    let signed = sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152; 32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let (mut reader, _, _, _) = objects_and_directory(&fixture, &storage_scope);
    let received = crate::history_baseline::verify_received_owner_attested_history_baseline(
        &signed, rebase.document(), &storage_scope, coverage.authority(), &trusted, None, &mut reader).unwrap();

    let mut document = AutoCommit::load(received.document()).unwrap();
    document.put(ROOT, "title", "Bounded active tail").unwrap();
    document.commit();
    let tail_hashes = document.get_changes(&[]).into_iter()
        .filter(|change| change.hash().to_string() != received.envelope().payload.genesis_hash)
        .map(|change| change.hash().to_string()).collect::<Vec<_>>();
    assert!(!tail_hashes.is_empty());
    let mut source = first.preparation().source().clone();
    source.snapshot.document = document.save();
    let payload = crate::WorkspaceChangeAuthorizationPayload {
        kind: "workspace-changes".into(), version: 1, workspace_id: source.snapshot.workspace_id.clone(),
        hashes: tail_hashes.clone(), person_id: source.snapshot.expected_current_owner.person_id.clone(),
        device_id: first.preparation().signer().device_id.clone(),
    };
    let signed_value = crate::sign_json_envelope(&[152; 32], serde_json::to_value(&payload).unwrap(),
        &first.preparation().signer().device_id, DEFAULT_SIGNATURE_DOMAIN).unwrap();
    source.records = vec![crate::IncomingWorkspaceChangeAuthorization {
        signed: crate::WorkspaceChangeAuthorization { payload, signer_key_id: signed_value.signer_key_id,
            signature: signed_value.signature },
        public_key: source.snapshot.expected_current_owner.public_key.clone(),
        certificates: first.preparation().signer().certificates.clone(), grant: None,
    }];
    source.pending_change_bytes.clear();
    let next = crate::history_preparation::prepare_workspace_history_from_basis(
        source.clone(), first.preparation().signer().clone(), &received).unwrap();
    assert!(next.admission().decisions.iter().any(|decision|
        decision.hash == received.envelope().payload.genesis_hash &&
            matches!(decision.status, crate::causal_admission::CausalAdmissionStatus::Admitted { .. })));
    assert!(tail_hashes.iter().all(|hash| next.admission().decisions.iter().any(|decision|
        &decision.hash == hash && matches!(decision.status, crate::causal_admission::CausalAdmissionStatus::Admitted { .. }))));

    let mut disconnected = source;
    let mut foreign = AutoCommit::new();
    foreign.put(ROOT, "title", "Unrelated root").unwrap();
    foreign.commit();
    disconnected.snapshot.document = foreign.save();
    assert!(crate::history_preparation::prepare_workspace_history_from_basis(
        disconnected, first.preparation().signer().clone(), &received).is_err());
}

#[test]
fn given_trusted_scope_genesis_when_receiving_owner_attested_v2_then_skip_full_source_replay() {
    let (capture, fixture) = captured_fixture();
    let storage_scope = scope();
    let (mut local_reader, locator_root, _, _) = objects_and_directory(&fixture, &storage_scope);
    let storage = capture.verify_storage_directory(&storage_scope, &locator_root, &mut local_reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let owner = capture.preparation().owner();
    let workspace_id = capture.preparation().source().snapshot.workspace_id.clone();
    let trusted = signed_scope_snapshot(&workspace_id, owner);
    let proposal = joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    assert_eq!(proposal.payload().version, 2);
    assert_eq!(proposal.payload().required_reader_capability, "workspace-history-baseline@2");
    assert_eq!(proposal.payload().scope_control_epoch, Some(1));
    assert!(proposal.payload().scope_authority.is_some());
    assert!(proposal.payload().current_control.is_some());
    let signed = sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152; 32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let (mut reader, _, _, _) = objects_and_directory(&fixture, &storage_scope);

    let received = crate::history_baseline::verify_received_owner_attested_history_baseline(
        &signed, rebase.document(), &storage_scope, coverage.authority(), &trusted, None, &mut reader,
    ).unwrap();
    assert_eq!(received.owner().person_id, owner.person_id);
    assert_eq!(received.document(), rebase.document());
    assert!(reader.downloads.len() < 32, "bounded receiver must not read archived source document");

    let mut forged: Value = serde_json::to_value(proposal.payload()).unwrap();
    forged["currentControl"]["expectedCurrentOwner"]["personId"] = json!("forged-current-owner");
    let mut unsigned = forged.clone();
    unsigned.as_object_mut().unwrap().remove("baselineId");
    forged["baselineId"] = json!(history_archive_object_id(crate::canonicalize_json(&unsigned).unwrap().as_bytes()));
    let forged = sign_payload(forged, &[152; 32], &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let (mut reader, _, _, _) = objects_and_directory(&fixture, &storage_scope);
    assert!(crate::history_baseline::verify_received_owner_attested_history_baseline(
        &forged, rebase.document(), &storage_scope, coverage.authority(), &trusted, None, &mut reader,
    ).is_err());
}

#[test]
fn given_owner_attested_baseline_when_trusted_scope_is_different_or_legacy_then_reject() {
    let (capture, fixture) = captured_fixture();
    let storage_scope = scope();
    let (mut local_reader, locator_root, _, _) = objects_and_directory(&fixture, &storage_scope);
    let storage = capture.verify_storage_directory(&storage_scope, &locator_root, &mut local_reader).unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture.preparation().rebase(1, coverage.data_transition_id()).unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let owner = capture.preparation().owner();
    let workspace_id = capture.preparation().source().snapshot.workspace_id.clone();
    let trusted = signed_scope_snapshot(&workspace_id, owner);
    let proposal = joined.propose_owner_attested_baseline(HistoryBaselineParent::Initial, &trusted).unwrap();
    let signed = sign_payload(serde_json::to_value(proposal.payload()).unwrap(), &[152; 32],
        &proposal.payload().device_id, HISTORY_BASELINE_DOMAIN);
    let wrong_scope = signed_scope_snapshot(&format!("{workspace_id}-other"), owner);
    let (mut reader, _, _, _) = objects_and_directory(&fixture, &storage_scope);
    assert!(crate::history_baseline::verify_received_owner_attested_history_baseline(
        &signed, rebase.document(), &storage_scope, coverage.authority(), &wrong_scope, None, &mut reader,
    ).is_err());

    let (legacy, basis, legacy_scope, authority, mut legacy_reader) = signed_initial_fixture();
    let legacy_trust = signed_scope_snapshot(&workspace_id, owner);
    assert!(crate::history_baseline::verify_received_owner_attested_history_baseline(
        &legacy, &basis, &legacy_scope, &authority, &legacy_trust, None, &mut legacy_reader,
    ).is_err());
}

#[test]
fn given_signed_owner_basis_and_cold_archive_when_receiving_then_verify_owner_control_basis_and_receipts()
{
    let (signed, basis, scope, authority, mut reader) = signed_initial_fixture();
    let received = crate::history_baseline::verify_received_history_baseline(
        &signed, &basis, &scope, &authority, None, &mut reader,
    )
    .unwrap();
    assert_eq!(received.original_json(), signed);
    assert_eq!(received.document(), basis);
    assert_eq!(received.envelope().payload.kind, "workspace-history-baseline");
    assert_eq!(received.owner().person_id, received.envelope().payload.person_id);
}

#[test]
fn given_received_baseline_when_state_pin_or_signed_receipt_changes_then_reject_without_token()
{
    let (signed, basis, scope, authority, mut reader) = signed_initial_fixture();
    let mut wrong_basis = basis.clone();
    wrong_basis.push(0);
    assert!(crate::history_baseline::verify_received_history_baseline(
        &signed, &wrong_basis, &scope, &authority, None, &mut reader,
    ).is_err());

    let mut wrong_authority = authority.clone();
    wrong_authority.scope_id.push_str("-wrong");
    assert!(crate::history_baseline::verify_received_history_baseline(
        &signed, &basis, &scope, &wrong_authority, None, &mut reader,
    ).is_err());

    let mut envelope: Value = serde_json::from_slice(&signed).unwrap();
    envelope["payload"]["storage"]["dataReceipt"]["signature"] = json!("A".repeat(86));
    let mut payload = envelope["payload"].clone();
    payload.as_object_mut().unwrap().remove("baselineId");
    let baseline_id = history_archive_object_id(crate::canonicalize_json(&payload).unwrap().as_bytes());
    envelope["payload"]["baselineId"] = json!(baseline_id);
    let forged_receipt = sign_payload(
        envelope["payload"].clone(), &[152; 32],
        envelope["payload"]["deviceId"].as_str().unwrap(), HISTORY_BASELINE_DOMAIN,
    );
    assert!(crate::history_baseline::verify_received_history_baseline(
        &forged_receipt, &basis, &scope, &authority, None, &mut reader,
    ).is_err());
}

#[test]
fn given_owner_signed_baseline_when_authority_revision_claim_changes_then_reject() {
    let (signed, basis, scope, authority, mut reader) = signed_initial_fixture();
    let mut envelope: Value = serde_json::from_slice(&signed).unwrap();
    let claimed_authority = URL_SAFE_NO_PAD.encode([31; 32]);
    envelope["payload"]["authorityRevision"] = json!(claimed_authority);
    envelope["payload"]["archive"]["authorityRevision"] = json!(claimed_authority);
    let mut payload = envelope["payload"].clone();
    payload.as_object_mut().unwrap().remove("baselineId");
    let baseline_id = history_archive_object_id(crate::canonicalize_json(&payload).unwrap().as_bytes());
    envelope["payload"]["baselineId"] = json!(baseline_id);
    let forged_authority = sign_payload(
        envelope["payload"].clone(),
        &[152; 32],
        envelope["payload"]["deviceId"].as_str().unwrap(),
        HISTORY_BASELINE_DOMAIN,
    );

    assert!(crate::history_baseline::verify_received_history_baseline(
        &forged_authority, &basis, &scope, &authority, None, &mut reader,
    ).is_err());
}

#[test]
fn given_complete_owner_preparation_when_signing_initial_baseline_then_retain_verified_attestation()
{
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    let payload = serde_json::to_value(proposal.payload()).unwrap();
    assert_eq!(payload["kind"], "workspace-history-baseline");
    assert_eq!(payload["admissionPolicy"], crate::causal_admission::CAUSAL_ADMISSION_POLICY_ID);
    assert_eq!(payload["version"], 1);
    assert_eq!(payload["historyEpoch"], 1);
    assert!(payload["previousBaselineId"].is_null());
    assert_eq!(payload["transitionId"], coverage.data_transition_id());
    assert_ne!(payload["sourceHeads"], payload["admittedHeads"]);

    let mut id_input = payload.clone();
    id_input.as_object_mut().unwrap().remove("baselineId");
    assert_eq!(
        payload["baselineId"],
        crate::history_archive::history_archive_object_id(
            crate::canonicalize_json(&id_input).unwrap().as_bytes()
        )
    );
    assert_eq!(
        payload["archive"],
        serde_json::to_value(coverage.catalogue()).unwrap()
    );
    assert_eq!(
        payload["locatorRoot"],
        serde_json::to_value(coverage.locator_root()).unwrap()
    );
    assert_eq!(
        payload["storage"]["dataReceipt"],
        serde_json::to_value(coverage.data_receipt()).unwrap()
    );
    assert_eq!(
        payload["storage"]["directoryReceipt"],
        serde_json::to_value(coverage.directory_receipt()).unwrap()
    );
    assert_eq!(
        payload["certificates"],
        serde_json::to_value(&capture.preparation().signer().certificates).unwrap()
    );

    let signed_json = sign_payload(
        payload.clone(),
        &[152; 32],
        &proposal.payload().device_id,
        HISTORY_BASELINE_DOMAIN,
    );
    let retry = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    assert_eq!(retry.payload().baseline_id, proposal.payload().baseline_id);
    assert_eq!(
        signed_json,
        sign_payload(
            serde_json::to_value(retry.payload()).unwrap(),
            &[152; 32],
            &retry.payload().device_id,
            HISTORY_BASELINE_DOMAIN,
        )
    );
    let source = capture.preparation().source().clone();
    let attestation = proposal.confirm(&signed_json, &source).unwrap();
    assert_eq!(attestation.envelope().payload, *proposal.payload());
    assert_eq!(attestation.original_json(), signed_json);
    assert_eq!(attestation.document(), rebase.document());
    assert_eq!(attestation.owner(), capture.preparation().owner());

    let mut changed_time_only = source.clone();
    changed_time_only.now_ms += 1;
    let formatted = format!("\n {} \t", String::from_utf8(signed_json.clone()).unwrap());
    let formatted_attestation = proposal
        .confirm(formatted.as_bytes(), &changed_time_only)
        .unwrap();
    assert_eq!(formatted_attestation.original_json(), formatted.as_bytes());
}

#[test]
fn given_only_portable_archive_objects_when_a_cold_receiver_reads_control_then_recover_exact_original_bytes()
{
    let (_, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, locator_root, _, _) = branched_directory(&fixture, &scope);
    let catalogue: crate::history_capture::HistoryArchiveCatalogue =
        serde_json::from_value(fixture["catalogue"].clone()).unwrap();

    let control = crate::history_capture::read_history_archive_control(
        &scope,
        &catalogue,
        &locator_root,
        &mut reader,
    )
    .unwrap();

    assert_eq!(control, decode(&fixture["originals"]["control"]));
    assert!(reader.downloads.len() >= 4, "cold reader traverses both indexes and data parts");
}

#[test]
fn given_portable_control_lookup_when_scope_or_reader_guard_changes_then_reject_before_returning_bytes()
{
    let (_, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, locator_root, _, _) = objects_and_directory(&fixture, &scope);
    let catalogue: crate::history_capture::HistoryArchiveCatalogue =
        serde_json::from_value(fixture["catalogue"].clone()).unwrap();
    let mut wrong_root = locator_root.clone();
    wrong_root.context.workspace_id.push_str("-other");
    assert!(crate::history_capture::read_history_archive_control(
        &scope, &catalogue, &wrong_root, &mut reader,
    )
    .is_err());

    let (mut revoked, locator_root, _, _) = objects_and_directory(&fixture, &scope);
    revoked.revoke_after_download = true;
    assert!(crate::history_capture::read_history_archive_control(
        &scope, &catalogue, &locator_root, &mut revoked,
    )
    .is_err());
}

#[test]
fn given_signed_baseline_when_domain_key_payload_or_parent_changes_then_reject() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    let payload = serde_json::to_value(proposal.payload()).unwrap();
    let signer = proposal.payload().device_id.clone();
    let source = capture.preparation().source().clone();
    let valid = sign_payload(
        payload.clone(),
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );

    assert!(proposal.confirm(&valid, &source).is_ok());
    assert!(
        proposal
            .confirm(
                &sign_payload(payload.clone(), &[152; 32], &signer, "MATCH/1"),
                &source,
            )
            .is_err()
    );
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    payload.clone(),
                    &[153; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );

    for (path, value) in [
        ("stateDigest", json!("substituted-state")),
        ("documentDigest", json!("substituted-document")),
        ("genesisHash", json!("substituted-genesis")),
        ("historyEpoch", json!(2)),
        ("controlEpoch", json!(2)),
        ("sourceHeads", json!(["substituted-source"])),
        ("admittedHeads", json!(["substituted-admitted"])),
        ("baselineId", json!("substituted-baseline-id")),
        ("previousBaselineId", json!("unverified-parent")),
        ("requiredReaderCapability", json!("other-policy")),
    ] {
        let mut altered = payload.clone();
        altered[path] = value;
        assert!(
            proposal
                .confirm(
                    &sign_payload(altered, &[152; 32], &signer, HISTORY_BASELINE_DOMAIN),
                    &source,
                )
                .is_err(),
            "accepted altered {path}"
        );
    }
    let mut changed_receipt = payload.clone();
    changed_receipt["storage"]["authority"]["policyRevision"] = json!(8);
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_receipt,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );
    let mut changed_locator = payload.clone();
    changed_locator["locatorRoot"]["root"]["ciphertextId"] = json!("substituted-ciphertext");
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_locator,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );
    let mut changed_data_receipt = payload.clone();
    changed_data_receipt["storage"]["dataReceipt"]["signature"] = json!("substituted-signature");
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_data_receipt,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );
    let mut changed_directory_receipt = payload.clone();
    changed_directory_receipt["storage"]["directoryReceipt"]["signature"] =
        json!("substituted-signature");
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_directory_receipt,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN,
                ),
                &source,
            )
            .is_err()
    );
}

#[test]
fn given_stale_or_malformed_owner_envelope_when_confirming_then_reject() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    let payload = serde_json::to_value(proposal.payload()).unwrap();
    let signer = proposal.payload().device_id.clone();
    let valid = sign_payload(
        payload.clone(),
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );
    let source = capture.preparation().source();
    let mut stale = source.clone();
    stale.pending_change_bytes.push(vec![b' ']);
    assert!(proposal.confirm(&valid, &stale).is_err());

    assert!(proposal.confirm(&[], source).is_err());
    assert!(
        proposal
            .confirm(
                &vec![b' '; crate::history_baseline::MAX_HISTORY_BASELINE_BYTES + 1],
                source
            )
            .is_err()
    );
    assert!(
        proposal
            .confirm(
                &sign_payload(payload.clone(), &[152; 32], &signer, "wrong-domain"),
                source,
            )
            .is_err()
    );

    let mut unknown_outer: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    unknown_outer["extra"] = json!(true);
    assert!(
        proposal
            .confirm(&serde_json::to_vec(&unknown_outer).unwrap(), source)
            .is_err()
    );

    let mut omitted_null: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    omitted_null["payload"]
        .as_object_mut()
        .unwrap()
        .remove("previousBaselineId");
    assert!(
        proposal
            .confirm(&serde_json::to_vec(&omitted_null).unwrap(), source)
            .is_err()
    );

    let mut unsigned_unknown_certificate_outer: serde_json::Value =
        serde_json::from_slice(&valid).unwrap();
    unsigned_unknown_certificate_outer["payload"]["certificates"][0]["unexpected"] =
        json!("injected-after-signing");
    assert!(
        proposal
            .confirm(
                &serde_json::to_vec(&unsigned_unknown_certificate_outer).unwrap(),
                source,
            )
            .is_err()
    );
    let mut unsigned_unknown_certificate_payload: serde_json::Value =
        serde_json::from_slice(&valid).unwrap();
    unsigned_unknown_certificate_payload["payload"]["certificates"][0]["payload"]["unexpected"] =
        json!("injected-after-signing");
    assert!(
        proposal
            .confirm(
                &serde_json::to_vec(&unsigned_unknown_certificate_payload).unwrap(),
                source,
            )
            .is_err()
    );
    let duplicate_certificate_key = String::from_utf8(valid.clone()).unwrap().replacen(
        "\"canEnrollDevices\":true",
        "\"canEnrollDevices\":true,\"canEnrollDevices\":true",
        1,
    );
    assert!(
        proposal
            .confirm(duplicate_certificate_key.as_bytes(), source)
            .is_err()
    );

    let mut unknown_certificate = payload.clone();
    unknown_certificate["certificates"][0]["injected"] = json!("untrusted");
    let signed_with_unknown_certificate = sign_payload(
        unknown_certificate,
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );
    assert!(
        proposal
            .confirm(&signed_with_unknown_certificate, source)
            .is_err()
    );

    let mut omitted_certificate_field = payload;
    omitted_certificate_field["certificates"][0]["payload"]
        .as_object_mut()
        .unwrap()
        .remove("canEnrollDevices");
    let signed_with_omission = sign_payload(
        omitted_certificate_field,
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );
    assert!(proposal.confirm(&signed_with_omission, source).is_err());

    let duplicate_payload = String::from_utf8(valid).unwrap().replacen(
        "\"signerKeyId\":",
        "\"signerKeyId\":\"duplicate\",\"signerKeyId\":",
        1,
    );
    assert!(
        proposal
            .confirm(duplicate_payload.as_bytes(), source)
            .is_err()
    );
}
