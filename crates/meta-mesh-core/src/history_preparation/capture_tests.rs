use super::*;
use crate::history_archive::{
    HistoryArchiveIndexPage, HistoryArchiveIndexRoot, HistoryArchiveTreeContext,
    history_archive_object_id, verify_history_archive_index_page,
};
use crate::history_capture::{
    HistoryArchiveBytesReference, HistoryArchiveObjectBinding, HistoryArchiveWriter,
    HistoryCapturedChange,
};
use crate::history_capture::{
    HistoryOriginalEvidence, capture_workspace_history, history_control_value,
};
use std::collections::BTreeMap;

fn originals(source: &CausalAdmissionInput) -> HistoryOriginalEvidence {
    HistoryOriginalEvidence {
        control_json: serde_json::to_vec_pretty(&history_control_value(&source.snapshot).unwrap())
            .unwrap(),
        authorization_json: source
            .records
            .iter()
            .map(|record| serde_json::to_vec_pretty(record).unwrap())
            .collect(),
    }
}

#[derive(Default)]
struct Store {
    objects: BTreeMap<String, Vec<u8>>,
    bindings: Vec<(String, HistoryArchiveObjectBinding)>,
}
impl HistoryArchiveWriter for Store {
    fn write(
        &mut self,
        id: &str,
        bytes: &[u8],
        binding: &HistoryArchiveObjectBinding,
    ) -> Result<(), String> {
        assert_eq!(id, history_archive_object_id(bytes));
        assert!(
            bytes.len()
                <= if binding.object_kind == "part" {
                    256 * 1024
                } else {
                    64 * 1024
                }
        );
        if let Some(old) = self.objects.insert(id.into(), bytes.to_vec()) {
            assert_eq!(old, bytes);
        }
        self.bindings.push((id.into(), binding.clone()));
        Ok(())
    }
}
fn entries(
    store: &Store,
    context: &HistoryArchiveTreeContext,
    root: &HistoryArchiveIndexRoot,
) -> Vec<(String, String)> {
    match verify_history_archive_index_page(context, root, &store.objects[&root.object_id]).unwrap()
    {
        HistoryArchiveIndexPage::Leaf(page) => page
            .entries
            .into_iter()
            .map(|entry| (entry.key, entry.object_id))
            .collect(),
        HistoryArchiveIndexPage::Branch(page) => page
            .children
            .iter()
            .flat_map(|child| entries(store, context, child))
            .collect(),
    }
}
fn read_bytes(
    store: &Store,
    context: &HistoryArchiveTreeContext,
    reference: &HistoryArchiveBytesReference,
) -> Vec<u8> {
    let parts = entries(store, context, &reference.root);
    assert_eq!(parts.len() as u64, reference.part_count);
    let mut bytes = Vec::new();
    for (i, (key, id)) in parts.iter().enumerate() {
        assert_eq!(key, &format!("{i:016x}"));
        bytes.extend_from_slice(&store.objects[id]);
    }
    assert_eq!(bytes.len() as u64, reference.byte_length);
    bytes
}

#[test]
fn given_verified_capture_when_writing_catalogue_then_derive_actual_hash_dependencies_and_admission()
 {
    let mut f = fixture();
    let mut raw = AutoCommit::load(&f.source.snapshot.document).unwrap();
    raw.put(ROOT, "unsigned", "quarantine this").unwrap();
    raw.commit();
    let unsigned_hash = raw.get_heads()[0].to_string();
    f.source.snapshot.document = raw.save();
    raw.put(ROOT, "missing", "absent dependency").unwrap();
    raw.commit();
    raw.put(ROOT, "pending", "preserved original").unwrap();
    raw.commit();
    let pending = raw.get_changes(&[]).last().unwrap().clone();
    f.source
        .pending_change_bytes
        .push(pending.raw_bytes().to_vec());
    f.source.records.push(proof(
        &f.source.snapshot.genesis_owner,
        &f.signer,
        &f.device_seed,
        vec![pending.hash().to_string()],
    ));
    let evidence = originals(&f.source);
    let original_proofs = evidence.authorization_json.clone();
    let capture = capture_workspace_history(
        prepare_workspace_history(f.source.clone(), f.signer).unwrap(),
        7,
        evidence,
    )
    .unwrap();
    let mut store = Store::default();
    let catalogue = capture.write_catalogue(&mut store).unwrap();
    assert_eq!(
        (
            catalogue.change_count,
            catalogue.admitted_count,
            catalogue.pending_count,
            catalogue.quarantined_count
        ),
        (3, 1, 1, 1)
    );
    assert_eq!(catalogue.capture_revision, capture.capture_revision());
    assert_eq!(
        catalogue.admission_revision,
        capture.preparation().admission_revision()
    );
    assert_eq!(catalogue.context.history_epoch, 7);
    let saved = entries(&store, &catalogue.context, &catalogue.root)
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let document: HistoryArchiveBytesReference =
        serde_json::from_slice(&store.objects[&saved["document"]]).unwrap();
    let mut context = catalogue.context.clone();
    context.index_id = "source-document".into();
    assert_eq!(
        read_bytes(&store, &context, &document),
        f.source.snapshot.document
    );
    for (index, expected) in original_proofs.iter().enumerate() {
        let reference: HistoryArchiveBytesReference =
            serde_json::from_slice(&store.objects[&saved[&format!("proof/{index:016x}")]]).unwrap();
        context.index_id = format!("source-proof/{index:016x}");
        assert_eq!(&read_bytes(&store, &context, &reference), expected);
    }
    let record: HistoryCapturedChange =
        serde_json::from_slice(&store.objects[&saved[&format!("change/{}", pending.hash())]])
            .unwrap();
    assert_eq!(record.hash, pending.hash().to_string());
    assert!(matches!(
        record.observation,
        CausalAdmissionStatus::Pending { .. }
    ));
    context.index_id = format!("change/{}/dependencies", pending.hash());
    let deps: Vec<String> =
        serde_json::from_slice(&read_bytes(&store, &context, &record.dependencies)).unwrap();
    assert_eq!(
        deps,
        pending
            .deps()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    context.index_id = format!("change/{}/authorizations", pending.hash());
    let proofs = entries(&store, &context, &record.authorizations);
    assert_eq!(
        proofs,
        vec![(
            format!("{:016x}", 1),
            saved[&format!("proof/{:016x}", 1)].clone()
        )]
    );
    let record: HistoryCapturedChange =
        serde_json::from_slice(&store.objects[&saved[&format!("change/{unsigned_hash}")]]).unwrap();
    assert!(matches!(
        record.observation,
        CausalAdmissionStatus::Quarantined { .. }
    ));
    assert_eq!(record.authorizations.count, 0);
    assert!(
        store
            .bindings
            .iter()
            .all(|(_, binding)| binding.context.workspace_id == "workspace"
                && binding.context.history_epoch == 7)
    );
}

#[test]
fn given_archive_write_failure_when_exporting_then_keep_preparation_and_retry_the_same_plaintext_catalogue()
 {
    struct Fail;
    impl HistoryArchiveWriter for Fail {
        fn write(
            &mut self,
            _: &str,
            _: &[u8],
            _: &HistoryArchiveObjectBinding,
        ) -> Result<(), String> {
            Err("Archive quota".into())
        }
    }
    let f = fixture();
    let capture = capture_workspace_history(
        prepare_workspace_history(f.source.clone(), f.signer).unwrap(),
        1,
        originals(&f.source),
    )
    .unwrap();
    assert_eq!(
        capture.write_catalogue(&mut Fail).err().as_deref(),
        Some("Archive quota")
    );
    assert_eq!(capture.preparation().source(), &f.source);
    let mut first = Store::default();
    let mut second = Store::default();
    assert_eq!(
        capture.write_catalogue(&mut first).unwrap(),
        capture.write_catalogue(&mut second).unwrap()
    );
    assert_eq!(first.objects, second.objects);
    assert_eq!(first.bindings, second.bindings);
}

#[test]
fn given_native_preparation_when_capturing_then_bind_exact_original_control_and_proof_bytes() {
    let f = fixture();
    let evidence = originals(&f.source);
    let control = evidence.control_json.clone();
    let proofs = evidence.authorization_json.clone();
    let prepared = prepare_workspace_history(f.source.clone(), f.signer).unwrap();
    let capture = capture_workspace_history(prepared, 1, evidence).unwrap();
    assert_eq!(capture.original_control(), control);
    assert_eq!(capture.original_authorizations(), proofs);
    assert_eq!(capture.preparation().source(), &f.source);
    assert_eq!(capture.history_epoch(), 1);
    assert_eq!(capture.capture_revision().len(), 43);
}

#[test]
fn given_different_original_encoding_when_capturing_then_preserve_it_and_bind_a_distinct_revision()
{
    let f = fixture();
    let first = capture_workspace_history(
        prepare_workspace_history(f.source.clone(), f.signer.clone()).unwrap(),
        1,
        originals(&f.source),
    )
    .unwrap();
    let mut second = originals(&f.source);
    second.authorization_json[0].extend_from_slice(b" \n");
    let second = capture_workspace_history(
        prepare_workspace_history(f.source.clone(), f.signer).unwrap(),
        1,
        second,
    )
    .unwrap();
    assert_eq!(
        first.preparation().admission_revision(),
        second.preparation().admission_revision()
    );
    assert_ne!(first.capture_revision(), second.capture_revision());
    assert!(second.original_authorizations()[0].ends_with(b" \n"));
}

#[test]
fn given_omitted_optional_grant_when_capturing_then_preserve_the_original_without_materializing_null()
 {
    let f = fixture();
    let mut evidence = originals(&f.source);
    let mut proof = serde_json::to_value(&f.source.records[0]).unwrap();
    proof.as_object_mut().unwrap().remove("grant");
    evidence.authorization_json[0] = serde_json::to_vec_pretty(&proof).unwrap();
    let capture = capture_workspace_history(
        prepare_workspace_history(f.source, f.signer).unwrap(),
        1,
        evidence,
    )
    .unwrap();
    assert!(
        !std::str::from_utf8(&capture.original_authorizations()[0])
            .unwrap()
            .contains("grant")
    );
}

#[test]
fn given_replaced_missing_extra_or_ambiguous_original_evidence_when_capturing_then_fail_closed() {
    for alteration in [
        "signature",
        "control",
        "missing",
        "extra",
        "duplicate-key",
        "duplicate-nested",
        "unknown",
        "document",
        "epoch",
    ] {
        let f = fixture();
        let mut evidence = originals(&f.source);
        match alteration {
            "signature" => {
                let mut value = serde_json::to_value(&f.source.records[0]).unwrap();
                value["signed"]["signature"] = serde_json::json!("substituted");
                evidence.authorization_json[0] = serde_json::to_vec(&value).unwrap();
            }
            "control" => {
                let mut value = history_control_value(&f.source.snapshot).unwrap();
                value["genesisEpoch"] = serde_json::json!(2);
                evidence.control_json = serde_json::to_vec(&value).unwrap();
            }
            "missing" => evidence.authorization_json.clear(),
            "extra" => evidence
                .authorization_json
                .push(evidence.authorization_json[0].clone()),
            "duplicate-key" => {
                let text = std::str::from_utf8(&evidence.authorization_json[0]).unwrap();
                evidence.authorization_json[0] = text
                    .replacen('{', "{\"publicKey\":\"ignored-first-value\",", 1)
                    .into_bytes();
            }
            "duplicate-nested" => {
                let text = std::str::from_utf8(&evidence.authorization_json[0]).unwrap();
                evidence.authorization_json[0] = text
                    .replacen("\"payload\": {", "\"payload\": {\"version\":0,", 1)
                    .into_bytes();
            }
            "unknown" => {
                let mut value = serde_json::to_value(&f.source.records[0]).unwrap();
                value["signed"]["payload"]["futurePermission"] = serde_json::json!(true);
                evidence.authorization_json[0] = serde_json::to_vec(&value).unwrap();
            }
            "document" => {
                let mut value = history_control_value(&f.source.snapshot).unwrap();
                value["document"] = serde_json::json!([]);
                evidence.control_json = serde_json::to_vec(&value).unwrap();
            }
            "epoch" => {}
            _ => unreachable!(),
        }
        let prepared = prepare_workspace_history(f.source, f.signer).unwrap();
        assert!(
            capture_workspace_history(
                prepared,
                if alteration == "epoch" { 0 } else { 1 },
                evidence
            )
            .is_err(),
            "Accepted {alteration}"
        );
    }
}

#[test]
fn given_absent_signed_null_when_capturing_then_reject_instead_of_reconstructing_a_different_signed_payload()
 {
    let f = fixture();
    let mut evidence = originals(&f.source);
    let mut value = serde_json::to_value(&f.source.records[0]).unwrap();
    value["certificates"][0]["payload"]
        .as_object_mut()
        .unwrap()
        .remove("issuerCertificateHash");
    evidence.authorization_json[0] = serde_json::to_vec(&value).unwrap();
    assert!(
        capture_workspace_history(
            prepare_workspace_history(f.source, f.signer).unwrap(),
            1,
            evidence
        )
        .is_err()
    );
}

#[test]
fn given_legacy_control_without_defaulted_empty_arrays_when_capturing_then_preserve_original_and_reject_omitted_nonempty_evidence()
 {
    let f = fixture();
    let mut evidence = originals(&f.source);
    let mut control = history_control_value(&f.source.snapshot).unwrap();
    for key in [
        "ownershipTransfers",
        "successionClaims",
        "revocations",
        "deviceRevocations",
        "departures",
    ] {
        control.as_object_mut().unwrap().remove(key);
    }
    let original = serde_json::to_vec_pretty(&control).unwrap();
    evidence.control_json = original.clone();
    let capture = capture_workspace_history(
        prepare_workspace_history(f.source.clone(), f.signer.clone()).unwrap(),
        1,
        evidence,
    )
    .unwrap();
    assert_eq!(capture.original_control(), original);

    let signed = sign_json_envelope(&f.owner_seed, serde_json::json!({
        "kind": "workspace-device-revocation", "version": 1, "workspaceId": "workspace",
        "personId": f.signer.person_id, "deviceId": public_key_id(&public_key_from_seed(&[154; 32]).unwrap()).unwrap(),
        "workspaceHeads": f.source.records[0].signed.payload.hashes, "revokedAt": "2026-10-14T10:00:00.000Z"
    }), &f.source.snapshot.genesis_owner.person_id, DEFAULT_SIGNATURE_DOMAIN).unwrap();
    let mut changed = f.source.clone();
    changed
        .snapshot
        .device_revocations
        .push(crate::WorkspaceDeviceRevocationEvidence {
            record: serde_json::from_value(serde_json::to_value(signed).unwrap()).unwrap(),
            signer: f.source.snapshot.genesis_owner.clone(),
        });
    let mut evidence = originals(&changed);
    evidence.control_json = original;
    assert!(
        capture_workspace_history(
            prepare_workspace_history(changed, f.signer).unwrap(),
            1,
            evidence
        )
        .is_err()
    );
}

#[test]
fn given_many_changes_and_large_original_proof_when_exporting_then_bound_pages_and_preserve_duplicate_parts_and_pending_originals()
 {
    let mut f = fixture();
    let mut raw = AutoCommit::load(&f.source.snapshot.document).unwrap();
    for index in 0..130 {
        raw.put(ROOT, "unsigned", index as i64).unwrap();
        raw.commit();
    }
    f.source.snapshot.document = raw.save();
    let last = raw.get_changes(&[]).last().unwrap().raw_bytes().to_vec();
    f.source.pending_change_bytes = vec![last.clone(), last.clone()];
    f.source.records = vec![f.source.records[0].clone(); 130];
    let mut evidence = originals(&f.source);
    evidence.authorization_json[0].extend(vec![b' '; 3 * 256 * 1024 + 37]);
    let expected_large = evidence.authorization_json[0].clone();
    let capture = capture_workspace_history(
        prepare_workspace_history(f.source.clone(), f.signer).unwrap(),
        1,
        evidence,
    )
    .unwrap();
    let mut store = Store::default();
    let catalogue = capture.write_catalogue(&mut store).unwrap();
    assert_eq!(catalogue.change_count, 131);
    assert_eq!(catalogue.authorization_count, 130);
    assert_eq!(catalogue.pending_original_count, 2);
    assert!(catalogue.root.height > 0);
    let saved = entries(&store, &catalogue.context, &catalogue.root)
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let reference: HistoryArchiveBytesReference =
        serde_json::from_slice(&store.objects[&saved["proof/0000000000000000"]]).unwrap();
    let mut context = catalogue.context.clone();
    context.index_id = "source-proof/0000000000000000".into();
    assert_eq!(read_bytes(&store, &context, &reference), expected_large);
    let parts = entries(&store, &context, &reference.root);
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[1].1, parts[2].1);
    let binding_one = store
        .bindings
        .iter()
        .find(|(id, binding)| {
            id == &parts[1].1 && binding.context == context && binding.part_index == 1
        })
        .unwrap();
    let binding_two = store
        .bindings
        .iter()
        .find(|(id, binding)| {
            id == &parts[2].1 && binding.context == context && binding.part_index == 2
        })
        .unwrap();
    assert_ne!(binding_one.1, binding_two.1);
    for index in 0..2 {
        let reference: HistoryArchiveBytesReference =
            serde_json::from_slice(&store.objects[&saved[&format!("pending/{index:016x}")]])
                .unwrap();
        context.index_id = format!("source-pending/{index:016x}");
        assert_eq!(read_bytes(&store, &context, &reference), last);
    }
    let first_hash = &f.source.records[0].signed.payload.hashes[0];
    let record: HistoryCapturedChange =
        serde_json::from_slice(&store.objects[&saved[&format!("change/{first_hash}")]]).unwrap();
    assert_eq!(record.authorizations.count, 130);
    assert!(record.authorizations.height > 0);
}

#[test]
fn given_compressed_pending_change_when_exporting_then_keep_exact_compressed_original_and_actual_dependencies()
 {
    let mut f = fixture();
    let mut raw = AutoCommit::load(&f.source.snapshot.document).unwrap();
    raw.put(ROOT, "missing", "dependency not in the source")
        .unwrap();
    raw.commit();
    raw.put(
        ROOT,
        "pending",
        "Retain compressed original. ".repeat(10_000),
    )
    .unwrap();
    raw.commit();
    let mut pending = raw.get_changes(&[]).last().unwrap().clone();
    let original = pending.bytes().into_owned();
    assert!(original.len() < pending.raw_bytes().len());
    f.source.pending_change_bytes.push(original.clone());
    f.source.records.push(proof(
        &f.source.snapshot.genesis_owner,
        &f.signer,
        &f.device_seed,
        vec![pending.hash().to_string()],
    ));
    let evidence = originals(&f.source);
    let capture = capture_workspace_history(
        prepare_workspace_history(f.source, f.signer).unwrap(),
        1,
        evidence,
    )
    .unwrap();
    let mut store = Store::default();
    let catalogue = capture.write_catalogue(&mut store).unwrap();
    let saved = entries(&store, &catalogue.context, &catalogue.root)
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let record: HistoryCapturedChange =
        serde_json::from_slice(&store.objects[&saved[&format!("change/{}", pending.hash())]])
            .unwrap();
    let mut context = catalogue.context.clone();
    context.index_id = format!("change/{}/bytes", pending.hash());
    assert_eq!(read_bytes(&store, &context, &record.bytes), original);
    assert!(matches!(
        record.observation,
        CausalAdmissionStatus::Pending { .. }
    ));
}
