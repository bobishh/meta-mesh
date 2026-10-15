use super::*;
use crate::{DEFAULT_SIGNATURE_DOMAIN, sign_json_envelope};
use crate::{
    WorkspaceAuthority, WorkspaceWriteAuthorizationSnapshot,
    authorization::{
        IncomingWorkspaceChangeAuthorization, WorkspaceChangeAuthorization,
        WorkspaceChangeAuthorizationPayload,
    },
    causal_admission::CausalAdmissionInput,
    history_preparation::{HistoryPreparationSigner, prepare_workspace_history},
};
use automerge::marks::{ExpandMark, Mark};
use automerge::{
    ActorId, AutoCommit, ObjType, ROOT, ReadDoc, ScalarValue, Value as AutomergeValue,
    transaction::Transactable,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packages/mesh-replication/fixtures/history-capture-v1.json"
);
fn decode(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

fn prepared_fixture() -> (
    crate::history_preparation::VerifiedHistoryPreparation,
    CausalAdmissionInput,
) {
    let fixture: Value = serde_json::from_slice(&std::fs::read(FIXTURE).unwrap()).unwrap();
    let control_bytes = decode(&fixture["originals"]["control"]);
    let mut control: Value = serde_json::from_slice(&control_bytes).unwrap();
    let document = decode(&fixture["originals"]["document"]);
    control["document"] = json!(document);
    let snapshot: WorkspaceWriteAuthorizationSnapshot = serde_json::from_value(control).unwrap();
    let records: Vec<IncomingWorkspaceChangeAuthorization> = fixture["originals"]["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| serde_json::from_slice(&decode(value)).unwrap())
        .collect();
    let pending_change_bytes = fixture["originals"]["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    let source = CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes,
        now_ms: 1_900_000_000_000,
    };
    let owner: WorkspaceAuthority = source.snapshot.expected_current_owner.clone();
    let signer = HistoryPreparationSigner {
        person_id: owner.person_id.clone(),
        device_id: owner.certificates[0].payload.device_id.clone(),
        certificates: owner.certificates.clone(),
    };
    let prepared = prepare_workspace_history(source.clone(), signer).unwrap();
    (prepared, source)
}

#[test]
fn given_mixed_admission_history_when_rebasing_then_retain_only_admitted_current_state_in_one_retryable_basis()
 {
    let (prepared, source) = prepared_fixture();
    let original = prepared.source().clone();
    let rebased = prepared
        .rebase(9, "native-rebase-transition-00001")
        .unwrap();
    let mut document = AutoCommit::load(rebased.document()).unwrap();
    assert_eq!(
        document.get(ROOT, "title").unwrap().unwrap().0.to_string(),
        "\"Native admitted original\""
    );
    assert!(document.get(ROOT, "pending").unwrap().is_none());
    assert!(document.get(ROOT, "missing").unwrap().is_none());
    let basis_changes = document.get_changes(&[]);
    assert_eq!(basis_changes.len(), 1);
    assert_eq!(rebased.genesis_hash(), basis_changes[0].hash().to_string());
    let basis_marker: Value = serde_json::from_str(basis_changes[0].message().unwrap()).unwrap();
    assert_eq!(basis_marker["kind"], "workspace-history-basis");
    assert_eq!(basis_marker["historyEpoch"], 9);
    assert_eq!(
        basis_marker["transitionId"],
        "native-rebase-transition-00001"
    );
    assert_eq!(rebased.node_count(), 2);
    assert_eq!(
        history_current_state_digest(rebased.document()).unwrap(),
        rebased.state_digest()
    );
    assert_eq!(rebased.history_epoch(), 9);
    assert_eq!(rebased.transition_id(), "native-rebase-transition-00001");
    assert_eq!(rebased.admission_revision(), prepared.admission_revision());
    assert_eq!(rebased.authority_revision(), prepared.authority_digest());
    assert_eq!(rebased.document_digest().len(), 43);
    assert_eq!(rebased.genesis_hash().len(), 64);
    let retry = prepared
        .rebase(9, "native-rebase-transition-00001")
        .unwrap();
    assert_eq!(retry.document(), rebased.document());
    assert_eq!(prepared.source(), &original);
    assert_eq!(prepared.source(), &source);
}

fn signer_from(source: &CausalAdmissionInput) -> HistoryPreparationSigner {
    let owner = &source.snapshot.expected_current_owner;
    HistoryPreparationSigner {
        person_id: owner.person_id.clone(),
        device_id: owner.certificates[0].payload.device_id.clone(),
        certificates: owner.certificates.clone(),
    }
}

fn source_for_document(
    mut source: CausalAdmissionInput,
    document: Vec<u8>,
    signer: &HistoryPreparationSigner,
    hashes: &[String],
) -> CausalAdmissionInput {
    source.snapshot.document = document;
    source.pending_change_bytes.clear();
    source.records = hashes
        .chunks(256)
        .map(|batch| {
            let payload = WorkspaceChangeAuthorizationPayload {
                kind: "workspace-changes".into(),
                version: 1,
                workspace_id: source.snapshot.workspace_id.clone(),
                hashes: batch.to_vec(),
                person_id: signer.person_id.clone(),
                device_id: signer.device_id.clone(),
            };
            let signed = sign_json_envelope(
                &[152; 32],
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
                public_key: source.snapshot.expected_current_owner.public_key.clone(),
                certificates: signer.certificates.clone(),
                grant: None,
            }
        })
        .collect();
    source
}

fn document_hashes(document: &[u8]) -> Vec<String> {
    let mut raw = AutoCommit::load(document).unwrap();
    raw.get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .collect()
}

#[test]
fn given_invalid_epoch_or_transition_when_rebasing_then_reject_without_changing_prepared_source() {
    let (prepared, source) = prepared_fixture();
    let original = prepared.source().clone();
    assert!(
        prepared
            .rebase(0, "native-rebase-transition-invalid")
            .is_err()
    );
    assert!(prepared.rebase(9, "short").is_err());
    assert_eq!(prepared.source(), &original);
    assert_eq!(prepared.source(), &source);
}

#[test]
fn given_owner_signed_typed_current_state_when_rebasing_then_preserve_canonical_state_digest() {
    let (_, source) = prepared_fixture();
    let signer = signer_from(&source);
    let mut raw = AutoCommit::new().with_actor(ActorId::from(vec![211; 16]));
    let map = raw.put_object(ROOT, "map", ObjType::Map).unwrap();
    raw.put(&map, "bytes", ScalarValue::Bytes(vec![0, 7, 255]))
        .unwrap();
    raw.put(&map, "int", ScalarValue::Int(-42)).unwrap();
    raw.put(&map, "uint", ScalarValue::Uint(u64::MAX)).unwrap();
    raw.put(&map, "float", ScalarValue::F64(-0.0)).unwrap();
    raw.put(&map, "timestamp", ScalarValue::Timestamp(1_900_000_000_000))
        .unwrap();
    let list = raw.put_object(ROOT, "list", ObjType::List).unwrap();
    raw.insert(&list, 0, "plain list value").unwrap();
    raw.insert(&list, 1, ScalarValue::Uint(9007199254740991))
        .unwrap();
    let text = raw.put_object(ROOT, "unicodeText", ObjType::Text).unwrap();
    raw.splice_text(&text, 0, 0, "plain Unicode: café 🧭")
        .unwrap();
    let _table = raw.put_object(ROOT, "table", ObjType::Table).unwrap();
    raw.put(ROOT, "counter", ScalarValue::Counter(1.into()))
        .unwrap();
    raw.increment(ROOT, "counter", 2).unwrap();
    raw.commit();
    let document = raw.save();
    let expected_digest = history_current_state_digest(&document);
    let hashes = document_hashes(&document);
    let input = source_for_document(source, document, &signer, &hashes);
    let prepared = prepare_workspace_history(input, signer).unwrap();
    let rebase = prepared
        .rebase(11, "native-typed-rebase-transition-00001")
        .unwrap();
    assert_eq!(
        history_current_state_digest(rebase.document()).unwrap(),
        expected_digest.unwrap()
    );
    let copied = AutoCommit::load(rebase.document()).unwrap();
    let (map_value, map_id) = copied.get(ROOT, "map").unwrap().unwrap();
    assert_eq!(map_value, AutomergeValue::Object(ObjType::Map));
    assert_eq!(copied.object_type(&map_id).unwrap(), ObjType::Map);
    let (bytes, _) = copied.get(&map_id, "bytes").unwrap().unwrap();
    assert!(
        matches!(bytes, AutomergeValue::Scalar(value) if matches!(value.as_ref(), ScalarValue::Bytes(value) if value == &[0, 7, 255]))
    );
    let (integer, _) = copied.get(&map_id, "int").unwrap().unwrap();
    assert!(
        matches!(integer, AutomergeValue::Scalar(value) if matches!(value.as_ref(), ScalarValue::Int(-42)))
    );
    let (timestamp, _) = copied.get(&map_id, "timestamp").unwrap().unwrap();
    assert!(
        matches!(timestamp, AutomergeValue::Scalar(value) if matches!(value.as_ref(), ScalarValue::Timestamp(1_900_000_000_000)))
    );
    let (table_value, _table_id) = copied.get(ROOT, "table").unwrap().unwrap();
    assert_eq!(table_value, AutomergeValue::Object(ObjType::Table));
    let (list_value, list_id) = copied.get(ROOT, "list").unwrap().unwrap();
    assert_eq!(list_value, AutomergeValue::Object(ObjType::List));
    assert_eq!(copied.object_type(&list_id).unwrap(), ObjType::List);
    let (text_value, text_id) = copied.get(ROOT, "unicodeText").unwrap().unwrap();
    assert_eq!(text_value, AutomergeValue::Object(ObjType::Text));
    assert_eq!(copied.object_type(&text_id).unwrap(), ObjType::Text);
    assert_eq!(
        copied
            .spans(&text_id)
            .unwrap()
            .map(|span| span.as_str().to_owned())
            .collect::<String>(),
        "plain Unicode: café 🧭"
    );
    let (counter, _) = copied.get(ROOT, "counter").unwrap().unwrap();
    assert!(
        matches!(counter, AutomergeValue::Scalar(value) if matches!(value.as_ref(), ScalarValue::Counter(value) if i64::from(value) == 3))
    );
    let (uint, _) = copied.get(&map_id, "uint").unwrap().unwrap();
    assert!(
        matches!(uint, AutomergeValue::Scalar(value) if matches!(value.as_ref(), ScalarValue::Uint(u64::MAX)))
    );
    let (float, _) = copied.get(&map_id, "float").unwrap().unwrap();
    assert!(
        matches!(float, AutomergeValue::Scalar(value) if matches!(value.as_ref(), ScalarValue::F64(value) if value.to_bits() == (-0.0f64).to_bits()))
    );
    assert_eq!(rebase.node_count(), 13);
    assert!(
        AutoCommit::load(rebase.document())
            .unwrap()
            .get_changes(&[])
            .len()
            == 1
    );
}

#[test]
fn given_equal_state_with_large_signed_history_when_rebasing_then_emit_one_bounded_basis_change() {
    let (_, base_source) = prepared_fixture();
    let signer = signer_from(&base_source);
    let mut common_state_digest: Option<String> = None;
    for count in [1_000usize, 10_000, 100_000] {
        let mut raw = AutoCommit::new().with_actor(ActorId::from(vec![212; 16]));
        raw.put(ROOT, "stable", "initial value").unwrap();
        raw.commit();
        for index in 0..count {
            raw.put(ROOT, "stable", format!("transient-{index:06}"))
                .unwrap();
            raw.commit();
        }
        raw.put(ROOT, "stable", "same admitted value").unwrap();
        raw.commit();
        let document = raw.save();
        let before_digest = history_current_state_digest(&document).unwrap();
        let hashes = raw
            .get_changes(&[])
            .iter()
            .map(|change| change.hash().to_string())
            .collect::<Vec<_>>();
        assert!(hashes.len() > 1);
        assert!(hashes.chunks(256).count() <= 20_000);
        let input = source_for_document(base_source.clone(), document, &signer, &hashes);
        let prepared = prepare_workspace_history(input, signer.clone()).unwrap();
        let rebase = prepared
            .rebase(13, &format!("native-large-history-rebase-{count:06}"))
            .unwrap();
        assert_eq!(rebase.state_digest(), before_digest);
        if let Some(expected) = &common_state_digest {
            assert_eq!(&before_digest, expected);
        } else {
            common_state_digest = Some(before_digest.clone());
        }
        assert_eq!(rebase.node_count(), 2);
        assert_eq!(
            AutoCommit::load(rebase.document())
                .unwrap()
                .get_changes(&[])
                .len(),
            1
        );
        assert!(
            rebase.document().len() < 2 * 1024,
            "rebased basis for {count} prior changes was {} bytes",
            rebase.document().len()
        );
    }
}

#[test]
fn given_conflicted_or_marked_text_when_rebasing_then_reject_without_mutating_source() {
    let (base, base_source) = prepared_fixture();
    let signer = signer_from(&base_source);
    let mut left = AutoCommit::load(&base_source.snapshot.document).unwrap();
    let mut right = left.fork();
    left.put(ROOT, "conflicted", "left value").unwrap();
    left.commit();
    right.put(ROOT, "conflicted", "right value").unwrap();
    right.commit();
    left.merge(&mut right).unwrap();
    let conflict_doc = left.save();
    let conflict_source = source_for_document(
        base_source.clone(),
        conflict_doc.clone(),
        &signer,
        &document_hashes(&conflict_doc),
    );
    let conflict_prepared = prepare_workspace_history(conflict_source, signer.clone()).unwrap();
    let before = conflict_prepared.source().clone();
    assert!(
        conflict_prepared
            .rebase(15, "native-conflicted-rebase-transition-01")
            .is_err()
    );
    assert_eq!(conflict_prepared.source(), &before);

    let mut marked = AutoCommit::new().with_actor(ActorId::from(vec![213; 16]));
    let text = marked.put_object(ROOT, "text", ObjType::Text).unwrap();
    marked.splice_text(&text, 0, 0, "marked text").unwrap();
    marked
        .mark(
            &text,
            Mark {
                start: 0,
                end: 6,
                name: "bold".into(),
                value: ScalarValue::Boolean(true),
            },
            ExpandMark::None,
        )
        .unwrap();
    marked.commit();
    let marked_doc = marked.save();
    let marked_source = source_for_document(
        base_source,
        marked_doc.clone(),
        &signer,
        &document_hashes(&marked_doc),
    );
    let marked_prepared = prepare_workspace_history(marked_source, signer).unwrap();
    let before = marked_prepared.source().clone();
    assert!(
        marked_prepared
            .rebase(15, "native-marked-rebase-transition-0001")
            .is_err()
    );
    assert_eq!(marked_prepared.source(), &before);
    assert_eq!(
        base.source().snapshot.document.len(),
        before.snapshot.document.len()
    );
}

#[test]
fn given_empty_admitted_state_when_rebasing_then_emit_one_zero_time_marked_retryable_genesis() {
    let (_, mut source) = prepared_fixture();
    let signer = signer_from(&source);
    let empty = AutoCommit::new().save();
    source = source_for_document(source, empty, &signer, &[]);
    let prepared = prepare_workspace_history(source.clone(), signer).unwrap();
    let first = prepared
        .rebase(17, "native-empty-rebase-transition-0001")
        .unwrap();
    let retry = prepared
        .rebase(17, "native-empty-rebase-transition-0001")
        .unwrap();
    let different = prepared
        .rebase(17, "native-empty-rebase-transition-0002")
        .unwrap();
    assert_eq!(first.document(), retry.document());
    assert_ne!(first.genesis_hash(), different.genesis_hash());
    assert_eq!(first.node_count(), 1);
    let mut document = AutoCommit::load(first.document()).unwrap();
    let changes = document.get_changes(&[]);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].hash().to_string(), first.genesis_hash());
    assert_eq!(changes[0].timestamp(), 0);
    let marker: Value = serde_json::from_str(changes[0].message().unwrap()).unwrap();
    assert_eq!(marker["kind"], "workspace-history-basis");
    assert_eq!(marker["historyEpoch"], 17);
    assert_eq!(
        marker["transitionId"],
        "native-empty-rebase-transition-0001"
    );
    assert_eq!(
        history_current_state_digest(first.document()).unwrap(),
        first.state_digest()
    );
    assert_eq!(prepared.source(), &source);
}

#[test]
fn given_embedded_block_text_when_rebasing_then_reject_without_mutating_source() {
    let (_, base_source) = prepared_fixture();
    let signer = signer_from(&base_source);
    let mut block = AutoCommit::new().with_actor(ActorId::from(vec![214; 16]));
    let text = block.put_object(ROOT, "text", ObjType::Text).unwrap();
    block.splice_text(&text, 0, 0, "before").unwrap();
    block.insert_object(&text, 6, ObjType::Map).unwrap();
    block.commit();
    let block_doc = block.save();
    let block_source = source_for_document(
        base_source.clone(),
        block_doc.clone(),
        &signer,
        &document_hashes(&block_doc),
    );
    let block_prepared = prepare_workspace_history(block_source, signer.clone()).unwrap();
    let original = block_prepared.source().clone();
    assert!(
        block_prepared
            .rebase(19, "native-block-rebase-transition-0001")
            .is_err()
    );
    assert_eq!(block_prepared.source(), &original);
}
