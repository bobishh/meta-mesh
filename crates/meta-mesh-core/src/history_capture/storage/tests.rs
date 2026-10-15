use super::*;
use crate::{
    WorkspaceAuthority,
    authorization::{IncomingWorkspaceChangeAuthorization, WorkspaceWriteAuthorizationSnapshot},
    causal_admission::CausalAdmissionInput,
    history_archive::{HistoryArchiveTreeContext, history_archive_object_id},
    history_archive_coverage::HistoryArchiveCoverageProof,
    history_archive_crypto::{HistoryArchiveEncryptionBinding, open_history_archive_object},
    history_capture::{HistoryOriginalEvidence, capture_workspace_history},
    history_locator::{
        HistoryArchiveLocatorBranch, HistoryArchiveLocatorEntry, HistoryArchiveLocatorLeaf,
        HistoryArchiveLocatorPointer, HistoryArchiveLocatorRoot,
    },
    history_preparation::{HistoryPreparationSigner, prepare_workspace_history},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod baseline;
mod baseline_lineage;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packages/mesh-replication/fixtures/history-capture-v1.json"
);

#[test]
fn given_shared_browser_binding_when_native_hashes_context_then_match_portable_lookup_key() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../packages/mesh-replication/fixtures/history-archive-locators-v1.json"
    ))
    .unwrap();
    let binding: HistoryArchiveEncryptionBinding =
        serde_json::from_value(fixture["binding"].clone()).unwrap();
    assert_eq!(binding_key(&binding).unwrap(), fixture["bindingKey"]);
}

fn decode(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}
fn canonical(value: &Value) -> Vec<u8> {
    crate::canonicalize_json(value).unwrap().into_bytes()
}

fn captured_fixture() -> (VerifiedHistoryArchiveCapture, Value) {
    let mut fixture: Value = serde_json::from_slice(&std::fs::read(FIXTURE).unwrap()).unwrap();
    let control_bytes = decode(&fixture["originals"]["control"]);
    let mut control: Value = serde_json::from_slice(&control_bytes).unwrap();
    let document = decode(&fixture["originals"]["document"]);
    control["document"] = json!(document);
    let snapshot: WorkspaceWriteAuthorizationSnapshot = serde_json::from_value(control).unwrap();
    let authorization_bytes = fixture["originals"]["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect::<Vec<_>>();
    let records: Vec<IncomingWorkspaceChangeAuthorization> = authorization_bytes
        .iter()
        .map(|bytes| serde_json::from_slice(bytes).unwrap())
        .collect();
    let pending_change_bytes = fixture["originals"]["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    let owner: WorkspaceAuthority = serde_json::from_value(
        fixture["originals"]["control"]
            .as_str()
            .map(|_| {
                let value: Value =
                    serde_json::from_slice(&decode(&fixture["originals"]["control"])).unwrap();
                value["genesisOwner"].clone()
            })
            .unwrap(),
    )
    .unwrap();
    let device_id = owner.certificates[0].payload.device_id.clone();
    let capture = capture_workspace_history(
        prepare_workspace_history(
            CausalAdmissionInput {
                records,
                snapshot,
                pending_change_bytes,
                now_ms: 1_900_000_000_000,
            },
            HistoryPreparationSigner {
                person_id: owner.person_id.clone(),
                device_id,
                certificates: owner.certificates.clone(),
            },
        )
        .unwrap(),
        1,
        HistoryOriginalEvidence {
            control_json: control_bytes,
            authorization_json: authorization_bytes,
        },
    )
    .unwrap();
    // The frozen vector retains its original @2 observations. Current-producer
    // storage tests need current policy roots without rewriting that old evidence.
    #[derive(Default)]
    struct CurrentObjects(BTreeMap<String, Value>);
    impl crate::history_capture::HistoryArchiveWriter for CurrentObjects {
        fn write(&mut self, id: &str, bytes: &[u8], binding: &HistoryArchiveObjectBinding) -> Result<(), String> {
            let key = crate::canonicalize_json(&json!({"objectId":id,"binding":binding}))?;
            self.0.insert(key, json!({"objectId":id,"bytes":URL_SAFE_NO_PAD.encode(bytes),"binding":binding}));
            Ok(())
        }
    }
    let mut objects = CurrentObjects::default();
    fixture["catalogue"] = serde_json::to_value(capture.write_catalogue(&mut objects).unwrap()).unwrap();
    fixture["objects"] = json!(objects.0.into_values().collect::<Vec<_>>());
    (capture, fixture)
}

#[derive(Default)]
struct Reader {
    objects: BTreeMap<String, EncryptedHistoryArchiveObject>,
    revoked: bool,
    revoke_after_download: bool,
    downloads: Vec<String>,
}
impl HistoryArchiveEncryptedReader for Reader {
    fn ensure_current(&mut self) -> Result<(), String> {
        if self.revoked {
            Err("revoked".into())
        } else {
            Ok(())
        }
    }
    fn download(&mut self, id: &str) -> Result<EncryptedHistoryArchiveObject, String> {
        self.downloads.push(id.to_owned());
        let object = self
            .objects
            .get(id)
            .cloned()
            .ok_or_else(|| "missing ciphertext".to_string())?;
        if self.revoke_after_download {
            self.revoked = true;
        }
        Ok(object)
    }
}

fn scope() -> HistoryArchiveEncryptionScope {
    HistoryArchiveEncryptionScope {
        scope_id: "storage-test-scope".into(),
        key_epoch: 1,
        key: [37; 32],
    }
}

fn seal(
    scope: &HistoryArchiveEncryptionScope,
    binding: &HistoryArchiveEncryptionBinding,
    bytes: &[u8],
    nonce_number: u64,
) -> EncryptedHistoryArchiveObject {
    let mut aad = serde_json::to_value(binding)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    aad.insert("purpose".into(), json!("archive"));
    aad.insert("scopeId".into(), json!(scope.scope_id));
    aad.insert("keyEpoch".into(), json!(scope.key_epoch));
    let aad = format!(
        "MESH-HISTORY/1/archive-object\0{}",
        crate::canonicalize_json(&Value::Object(aad)).unwrap()
    );
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&nonce_number.to_be_bytes());
    let encrypted = Aes256Gcm::new_from_slice(&scope.key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: bytes,
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    EncryptedHistoryArchiveObject {
        version: 1,
        scope_id: scope.scope_id.clone(),
        key_epoch: scope.key_epoch,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(encrypted),
    }
}

fn objects_and_directory(
    fixture: &Value,
    scope: &HistoryArchiveEncryptionScope,
) -> (Reader, HistoryArchiveLocatorRoot, Vec<String>, String) {
    let objects = fixture["objects"].as_array().unwrap();
    let mut reader = Reader::default();
    let mut entries = Vec::new();
    let mut data_ids = Vec::new();
    let mut catalogue_ciphertext_id = String::new();
    for (i, item) in objects.iter().enumerate() {
        let plain = decode(&item["bytes"]);
        let b = &item["binding"];
        let binding = HistoryArchiveEncryptionBinding {
            workspace_id: b["workspaceId"].as_str().unwrap().into(),
            history_epoch: b["historyEpoch"].as_u64().unwrap(),
            index_id: b["indexId"].as_str().unwrap().into(),
            object_id: item["objectId"].as_str().unwrap().into(),
            object_kind: b["objectKind"].as_str().unwrap().into(),
            part_index: b["partIndex"].as_u64().unwrap(),
            part_count: b["partCount"].as_u64().unwrap(),
        };
        let key = history_archive_object_id(canonical(&json!({"workspaceId":binding.workspace_id,"historyEpoch":binding.history_epoch,"indexId":binding.index_id,"objectId":binding.object_id,"objectKind":binding.object_kind,"partIndex":binding.part_index,"partCount":binding.part_count})).as_slice());
        let sealed = seal(scope, &binding, &plain, i as u64 + 1);
        let id = history_archive_object_id(&canonical(&serde_json::to_value(&sealed).unwrap()));
        reader.objects.insert(id.clone(), sealed);
        if b["indexId"] == "catalogue"
            && item["objectId"] == fixture["catalogue"]["root"]["objectId"]
        {
            catalogue_ciphertext_id = id.clone();
        }
        entries.push(HistoryArchiveLocatorEntry {
            key,
            ciphertext_id: id.clone(),
        });
        data_ids.push(id);
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    let context = HistoryArchiveTreeContext {
        workspace_id: fixture["catalogue"]["context"]["workspaceId"]
            .as_str()
            .unwrap()
            .into(),
        history_epoch: fixture["catalogue"]["context"]["historyEpoch"]
            .as_u64()
            .unwrap(),
        index_id: "archive-locators".into(),
    };
    let page = HistoryArchiveLocatorLeaf {
        kind: "workspace-history-locator-page".into(),
        version: 1,
        context: context.clone(),
        height: 0,
        entries: entries.clone(),
    };
    let bytes = canonical(&serde_json::to_value(page).unwrap());
    let object_id = history_archive_object_id(&bytes);
    let binding = HistoryArchiveEncryptionBinding {
        workspace_id: context.workspace_id.clone(),
        history_epoch: context.history_epoch,
        index_id: context.index_id.clone(),
        object_id: object_id.clone(),
        object_kind: "page".into(),
        part_index: 0,
        part_count: 1,
    };
    let sealed = seal(scope, &binding, &bytes, 1000);
    let ciphertext_id =
        history_archive_object_id(&canonical(&serde_json::to_value(&sealed).unwrap()));
    reader.objects.insert(ciphertext_id.clone(), sealed);
    let pointer = HistoryArchiveLocatorPointer {
        object_id,
        ciphertext_id,
        height: 0,
        count: entries.len() as u64,
        first: entries.first().map(|e| e.key.clone()),
        last: entries.last().map(|e| e.key.clone()),
    };
    (
        reader,
        HistoryArchiveLocatorRoot {
            kind: "workspace-history-locator-root".into(),
            version: 1,
            context,
            root: pointer,
        },
        data_ids,
        catalogue_ciphertext_id,
    )
}

fn branched_directory(
    fixture: &Value,
    scope: &HistoryArchiveEncryptionScope,
) -> (Reader, HistoryArchiveLocatorRoot, Vec<String>, String) {
    let (mut reader, flat_root, ids, catalogue_id) = objects_and_directory(fixture, scope);
    let flat_cipher = reader.objects.get(&flat_root.root.ciphertext_id).unwrap();
    let flat_binding = HistoryArchiveEncryptionBinding {
        workspace_id: flat_root.context.workspace_id.clone(),
        history_epoch: flat_root.context.history_epoch,
        index_id: flat_root.context.index_id.clone(),
        object_id: flat_root.root.object_id.clone(),
        object_kind: "page".into(),
        part_index: 0,
        part_count: 1,
    };
    let bytes = open_history_archive_object(
        scope,
        &flat_binding,
        &flat_root.root.ciphertext_id,
        flat_cipher,
    )
    .unwrap();
    let flat: HistoryArchiveLocatorLeaf = serde_json::from_slice(&bytes).unwrap();
    let mut pointers = Vec::new();
    for (index, chunk) in flat.entries.chunks(17).enumerate() {
        let leaf = HistoryArchiveLocatorLeaf {
            entries: chunk.to_vec(),
            ..flat.clone()
        };
        let bytes = canonical(&serde_json::to_value(&leaf).unwrap());
        let object_id = history_archive_object_id(&bytes);
        let binding = HistoryArchiveEncryptionBinding {
            object_id: object_id.clone(),
            ..flat_binding.clone()
        };
        let encrypted = seal(scope, &binding, &bytes, 2000 + index as u64);
        let ciphertext_id =
            history_archive_object_id(&canonical(&serde_json::to_value(&encrypted).unwrap()));
        reader.objects.insert(ciphertext_id.clone(), encrypted);
        pointers.push(HistoryArchiveLocatorPointer {
            object_id,
            ciphertext_id,
            height: 0,
            count: chunk.len() as u64,
            first: chunk.first().map(|entry| entry.key.clone()),
            last: chunk.last().map(|entry| entry.key.clone()),
        });
    }
    let branch = HistoryArchiveLocatorBranch {
        kind: "workspace-history-locator-page".into(),
        version: 1,
        context: flat_root.context.clone(),
        height: 1,
        children: pointers,
    };
    let bytes = canonical(&serde_json::to_value(branch).unwrap());
    let object_id = history_archive_object_id(&bytes);
    let binding = HistoryArchiveEncryptionBinding {
        object_id: object_id.clone(),
        ..flat_binding
    };
    let encrypted = seal(scope, &binding, &bytes, 3000);
    let ciphertext_id =
        history_archive_object_id(&canonical(&serde_json::to_value(&encrypted).unwrap()));
    reader.objects.insert(ciphertext_id.clone(), encrypted);
    let root = HistoryArchiveLocatorRoot {
        root: HistoryArchiveLocatorPointer {
            object_id,
            ciphertext_id,
            height: 1,
            count: flat.entries.len() as u64,
            first: flat.entries.first().map(|entry| entry.key.clone()),
            last: flat.entries.last().map(|entry| entry.key.clone()),
        },
        ..flat_root
    };
    (reader, root, ids, catalogue_id)
}

#[test]
fn given_complete_native_capture_and_authenticated_directory_when_verifying_then_match_every_stored_object()
 {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, data_ids, catalogue_ciphertext_id) =
        objects_and_directory(&fixture, &scope);
    let verified = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    assert_eq!(
        serde_json::to_value(verified.catalogue()).unwrap(),
        fixture["catalogue"]
    );
    let expected_data = data_ids
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(verified.data_ciphertext_ids(), &expected_data);
    assert_eq!(
        verified.directory_ciphertext_ids(),
        &[root.root.ciphertext_id.clone()].into_iter().collect()
    );
    assert_eq!(verified.scope_id(), scope.scope_id);
    assert_eq!(verified.key_epoch(), scope.key_epoch);
    assert_eq!(verified.key_digest(), history_archive_object_id(&scope.key));
    assert_eq!(verified.catalogue_ciphertext_id(), catalogue_ciphertext_id);
}

#[test]
fn given_missing_or_corrupt_ciphertext_when_verifying_then_reject() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (reader, root, data_ids, _) = objects_and_directory(&fixture, &scope);
    let mut missing = reader;
    missing.objects.remove(&data_ids[0]);
    assert!(
        capture
            .verify_storage_directory(&scope, &root, &mut missing)
            .is_err()
    );

    let (mut corrupt_directory, root, _, _) = objects_and_directory(&fixture, &scope);
    corrupt_directory
        .objects
        .get_mut(&root.root.ciphertext_id)
        .unwrap()
        .ciphertext
        .push('A');
    assert!(
        capture
            .verify_storage_directory(&scope, &root, &mut corrupt_directory)
            .is_err()
    );

    let (mut corrupt_data, root, data_ids, _) = objects_and_directory(&fixture, &scope);
    corrupt_data
        .objects
        .get_mut(&data_ids[0])
        .unwrap()
        .ciphertext
        .push('A');
    assert!(
        capture
            .verify_storage_directory(&scope, &root, &mut corrupt_data)
            .is_err()
    );
}

#[test]
fn given_substituted_directory_epoch_or_scope_when_verifying_then_reject() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let mut wrong_epoch = root.clone();
    wrong_epoch.context.history_epoch = 2;
    assert!(
        capture
            .verify_storage_directory(&scope, &wrong_epoch, &mut reader)
            .is_err()
    );
    let mut wrong_index = root.clone();
    wrong_index.context.index_id = "catalogue".into();
    assert!(
        capture
            .verify_storage_directory(&scope, &wrong_index, &mut reader)
            .is_err()
    );
    let wrong_scope = HistoryArchiveEncryptionScope {
        scope_id: "other-scope".into(),
        ..scope.clone()
    };
    assert!(
        capture
            .verify_storage_directory(&wrong_scope, &root, &mut reader)
            .is_err()
    );
}

#[test]
fn given_revoked_reader_guard_when_verifying_then_stop_before_using_directory() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    reader.revoked = true;
    assert_eq!(
        capture
            .verify_storage_directory(&scope, &root, &mut reader)
            .err()
            .unwrap(),
        "revoked"
    );
    assert!(reader.downloads.is_empty());
}

#[test]
fn given_extra_authenticated_locator_entry_when_verifying_then_reject() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, mut root, data_ids, _) = objects_and_directory(&fixture, &scope);
    let old_id = root.root.ciphertext_id.clone();
    let encrypted = reader.objects.get(&old_id).unwrap();
    let old_binding = HistoryArchiveEncryptionBinding {
        workspace_id: root.context.workspace_id.clone(),
        history_epoch: root.context.history_epoch,
        index_id: root.context.index_id.clone(),
        object_id: root.root.object_id.clone(),
        object_kind: "page".into(),
        part_index: 0,
        part_count: 1,
    };
    let bytes = open_history_archive_object(&scope, &old_binding, &old_id, encrypted).unwrap();
    let mut leaf: HistoryArchiveLocatorLeaf = serde_json::from_slice(&bytes).unwrap();
    let fake_binding = json!({"workspaceId":root.context.workspace_id,"historyEpoch":root.context.history_epoch,
        "indexId":"catalogue","objectId":history_archive_object_id(b"unlisted"),"objectKind":"record","partIndex":0,"partCount":1});
    leaf.entries.push(HistoryArchiveLocatorEntry {
        key: history_archive_object_id(&canonical(&fake_binding)),
        ciphertext_id: data_ids[0].clone(),
    });
    leaf.entries.sort_by(|a, b| a.key.cmp(&b.key));
    let page_bytes = canonical(&serde_json::to_value(leaf.clone()).unwrap());
    let object_id = history_archive_object_id(&page_bytes);
    let binding = HistoryArchiveEncryptionBinding {
        object_id: object_id.clone(),
        ..old_binding
    };
    let replacement = seal(&scope, &binding, &page_bytes, 99_999);
    let ciphertext_id =
        history_archive_object_id(&canonical(&serde_json::to_value(&replacement).unwrap()));
    reader.objects.insert(ciphertext_id.clone(), replacement);
    root.root = HistoryArchiveLocatorPointer {
        object_id,
        ciphertext_id,
        height: 0,
        count: leaf.entries.len() as u64,
        first: leaf.entries.first().map(|entry| entry.key.clone()),
        last: leaf.entries.last().map(|entry| entry.key.clone()),
    };
    assert!(
        capture
            .verify_storage_directory(&scope, &root, &mut reader)
            .is_err()
    );
}

#[test]
fn given_revocation_during_download_when_verifying_then_abort_and_preserve_reader_objects() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let before = reader.objects.clone();
    reader.revoke_after_download = true;
    assert_eq!(
        capture
            .verify_storage_directory(&scope, &root, &mut reader)
            .err()
            .unwrap(),
        "revoked"
    );
    assert_eq!(reader.downloads.len(), 1);
    assert_eq!(reader.objects, before);
}

#[test]
fn given_branched_authenticated_directory_when_verifying_then_visit_and_return_all_three_pages() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, data_ids, catalogue_id) = branched_directory(&fixture, &scope);
    let verified = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    assert_eq!(
        serde_json::to_value(verified.catalogue()).unwrap(),
        fixture["catalogue"]
    );
    assert_eq!(
        verified.data_ciphertext_ids(),
        &data_ids.into_iter().collect()
    );
    assert_eq!(verified.catalogue_ciphertext_id(), catalogue_id);
    assert_eq!(verified.directory_ciphertext_ids().len(), 3);
    assert!(
        verified
            .directory_ciphertext_ids()
            .contains(&root.root.ciphertext_id)
    );
}

fn coverage_digest(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut input = b"MESH-HISTORY/1/coverage-set\0".to_vec();
    input.extend_from_slice(&canonical(value));
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

fn coverage_request_id(
    authority: &crate::history_archive_coverage::HistoryArchiveCoverageAuthority,
    root: &str,
    transition: &str,
    summary: &crate::history_archive_coverage::HistoryArchiveCoverageSummary,
) -> String {
    use sha2::{Digest, Sha256};
    let authority = serde_json::to_value(authority).unwrap();
    let summary = serde_json::to_value(summary).unwrap();
    let mut input = b"MESH-HISTORY/1/coverage-request\0".to_vec();
    input.extend_from_slice(&canonical(&json!({"authority":authority,"archiveRootId":root,"transitionId":transition,"summary":summary})));
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

fn signed_coverage_receipt(
    root: &str,
    transition: &str,
    objects: &[String],
    key_epoch: u64,
    authority: &crate::history_archive_coverage::HistoryArchiveCoverageAuthority,
    seed: &[u8; 32],
) -> Vec<u8> {
    use crate::history_archive_coverage::HistoryArchiveCoverageSummary;
    let public_key = crate::public_key_from_seed(seed).unwrap();
    let service_id = crate::public_key_id(&public_key).unwrap();
    let set = objects
        .iter()
        .map(|object_id| json!({"objectId":object_id,"keyEpoch":key_epoch}))
        .collect::<Vec<_>>();
    let leaf = HistoryArchiveCoverageSummary {
        height: 0,
        object_count: set.len() as u64,
        first_object_id: objects.first().unwrap().clone(),
        last_object_id: objects.last().unwrap().clone(),
        root_covered: objects.iter().any(|id| id == root),
        set_digest: coverage_digest(
            &json!({"kind":"archive-coverage-set-leaf","version":1,"objects":set}),
        ),
    };
    let branch = HistoryArchiveCoverageSummary {
        height: 1,
        object_count: leaf.object_count,
        first_object_id: leaf.first_object_id.clone(),
        last_object_id: leaf.last_object_id.clone(),
        root_covered: leaf.root_covered,
        set_digest: coverage_digest(
            &json!({"kind":"archive-coverage-set-branch","version":1,"archiveRootId":root,"children":[leaf]}),
        ),
    };
    let request_id = coverage_request_id(authority, root, transition, &branch);
    let payload = json!({"kind":"blind-archive-coverage-aggregate-receipt","version":1,"serviceId":service_id,
        "scopeId":authority.scope_id,"policyRevision":authority.policy_revision,"requestId":request_id,
        "archiveRootId":root,"height":branch.height,"objectCount":branch.object_count,
        "firstObjectId":branch.first_object_id,"lastObjectId":branch.last_object_id,
        "setDigest":branch.set_digest,"rootCovered":branch.root_covered});
    serde_json::to_vec(&crate::sign_json_envelope(seed, payload, &service_id, "RUSTY/2").unwrap())
        .unwrap()
}

fn coverage_storage() -> (
    VerifiedHistoryArchiveStorage,
    crate::history_archive_coverage::HistoryArchiveCoverageAuthority,
    [u8; 32],
) {
    let (capture, fixture) = captured_fixture();
    let mut scope = scope();
    scope.key_epoch = 3;
    scope.scope_id = "opaque-coverage-fixture".into();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let seed = std::array::from_fn(|index| index as u8 + 1);
    let service_public_key = crate::public_key_from_seed(&seed).unwrap();
    let authority = crate::history_archive_coverage::HistoryArchiveCoverageAuthority {
        service_public_key,
        scope_id: "opaque-coverage-fixture".into(),
        policy_revision: 7,
    };
    (storage, authority, seed)
}

#[test]
fn given_native_storage_and_two_signed_exact_sets_when_verifying_coverage_then_retain_both_pins() {
    let (storage, authority, seed) = coverage_storage();
    let data_ids = storage
        .data_ciphertext_ids()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let directory_ids = storage
        .directory_ciphertext_ids()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let data_transition = "native-data-transition-00001";
    let directory_transition = "native-directory-transition-00001";
    let data_receipt = signed_coverage_receipt(
        storage.catalogue_ciphertext_id(),
        data_transition,
        &data_ids,
        storage.key_epoch(),
        &authority,
        &seed,
    );
    let directory_receipt = signed_coverage_receipt(
        &storage.locator_root().root.ciphertext_id,
        directory_transition,
        &directory_ids,
        storage.key_epoch(),
        &authority,
        &seed,
    );
    let verified = storage
        .verify_coverage(
            &authority,
            HistoryArchiveCoverageProof {
                data_transition_id: data_transition,
                directory_transition_id: directory_transition,
                data_receipt: &data_receipt,
                directory_receipt: &directory_receipt,
            },
        )
        .unwrap();
    assert_eq!(verified.catalogue(), storage.catalogue());
    assert_eq!(verified.locator_root(), storage.locator_root());
    assert_eq!(verified.key_epoch(), storage.key_epoch());
    assert_eq!(verified.key_digest(), storage.key_digest());
    assert_eq!(verified.authority(), &authority);
    assert_eq!(verified.data_transition_id(), data_transition);
    assert_eq!(verified.directory_transition_id(), directory_transition);
}

fn coverage_proof<'a>(
    data_transition_id: &'a str,
    directory_transition_id: &'a str,
    data_receipt: &'a [u8],
    directory_receipt: &'a [u8],
) -> crate::history_archive_coverage::HistoryArchiveCoverageProof<'a> {
    crate::history_archive_coverage::HistoryArchiveCoverageProof {
        data_transition_id,
        directory_transition_id,
        data_receipt,
        directory_receipt,
    }
}

fn coverage_receipt_pair(
    storage: &VerifiedHistoryArchiveStorage,
    authority: &crate::history_archive_coverage::HistoryArchiveCoverageAuthority,
    seed: &[u8; 32],
    data_transition: &str,
    directory_transition: &str,
) -> (Vec<u8>, Vec<u8>) {
    let data_ids = storage
        .data_ciphertext_ids()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let directory_ids = storage
        .directory_ciphertext_ids()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    (
        signed_coverage_receipt(
            storage.catalogue_ciphertext_id(),
            data_transition,
            &data_ids,
            storage.key_epoch(),
            authority,
            seed,
        ),
        signed_coverage_receipt(
            &storage.locator_root().root.ciphertext_id,
            directory_transition,
            &directory_ids,
            storage.key_epoch(),
            authority,
            seed,
        ),
    )
}

fn complete_coverage(
    storage: &VerifiedHistoryArchiveStorage,
) -> crate::history_archive_coverage::VerifiedHistoryArchiveCoverage {
    let seed = std::array::from_fn(|index| index as u8 + 1);
    let authority = crate::history_archive_coverage::HistoryArchiveCoverageAuthority {
        service_public_key: crate::public_key_from_seed(&seed).unwrap(),
        scope_id: storage.scope_id().into(),
        policy_revision: 7,
    };
    let data_transition = "native-basis-data-transition-00001";
    let directory_transition = "native-basis-directory-transition-00001";
    let (data_receipt, directory_receipt) = coverage_receipt_pair(
        storage,
        &authority,
        &seed,
        data_transition,
        directory_transition,
    );
    storage
        .verify_coverage(
            &authority,
            coverage_proof(
                data_transition,
                directory_transition,
                &data_receipt,
                &directory_receipt,
            ),
        )
        .unwrap()
}

#[test]
fn given_admitted_rebase_and_exact_covered_capture_when_binding_then_retain_original_owner_and_frontier()
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
    let source = capture.preparation().source().clone();

    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    assert!(std::ptr::eq(joined.capture(), &capture));
    assert!(std::ptr::eq(joined.rebase(), &rebase));
    assert!(std::ptr::eq(joined.coverage(), &coverage));
    assert_eq!(
        joined.capture().preparation().source_heads(),
        capture.preparation().source_heads()
    );
    assert_eq!(
        joined.capture().preparation().owner(),
        capture.preparation().owner()
    );
    joined.assert_source_current(&source).unwrap();
    let mut stale = source.clone();
    stale.pending_change_bytes.clear();
    assert!(joined.assert_source_current(&stale).is_err());
    assert_eq!(capture.preparation().source(), &source);
    assert!(capture.bind_rebase(&rebase, &coverage).is_ok());
}

#[test]
fn given_equal_state_with_different_evidence_epoch_or_transition_when_binding_then_reject_without_consuming_tokens()
 {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let source = capture.preparation().source().clone();
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let wrong_epoch = capture
        .preparation()
        .rebase(2, coverage.data_transition_id())
        .unwrap();
    let wrong_transition = capture
        .preparation()
        .rebase(1, "native-different-transition-00001")
        .unwrap();
    let mut other_source = source.clone();
    other_source.pending_change_bytes.clear();
    let other_preparation =
        prepare_workspace_history(other_source, capture.preparation().signer().clone()).unwrap();
    let different_evidence = other_preparation
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    assert_eq!(different_evidence.state_digest(), rebase.state_digest());
    assert_ne!(
        different_evidence.admission_revision(),
        rebase.admission_revision()
    );
    for candidate in [&wrong_epoch, &wrong_transition, &different_evidence] {
        assert!(capture.bind_rebase(candidate, &coverage).is_err());
    }
    // Whitespace changes exact original capture evidence but not semantic admission.
    let mut original_control = capture.original_control().to_vec();
    original_control.push(b' ');
    let other_capture = capture_workspace_history(
        prepare_workspace_history(source.clone(), capture.preparation().signer().clone()).unwrap(),
        1,
        HistoryOriginalEvidence {
            control_json: original_control,
            authorization_json: capture.original_authorizations().to_vec(),
        },
    )
    .unwrap();
    assert_eq!(
        other_capture.preparation().admission_revision(),
        capture.preparation().admission_revision()
    );
    assert_ne!(other_capture.capture_revision(), capture.capture_revision());
    assert!(other_capture.bind_rebase(&rebase, &coverage).is_err());
    assert_eq!(capture.preparation().source(), &source);
    assert!(capture.bind_rebase(&rebase, &coverage).is_ok());
}

#[test]
fn given_another_authorized_owner_device_when_binding_its_basis_then_reject_preparing_signer_substitution()
 {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let public_key = crate::public_key_from_seed(&[153; 32]).unwrap();
    let device_id = crate::public_key_id(&public_key).unwrap();
    let person_id = capture.preparation().owner().person_id.clone();
    let certificate = crate::sign_device_certificate(
        &[151; 32],
        crate::DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: person_id.clone(),
            device_id: device_id.clone(),
            device_public_key: public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &person_id,
        crate::DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    let other = prepare_workspace_history(
        capture.preparation().source().clone(),
        HistoryPreparationSigner {
            person_id,
            device_id,
            certificates: vec![certificate],
        },
    )
    .unwrap();
    let other_rebase = other.rebase(1, coverage.data_transition_id()).unwrap();
    let matching_rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    assert_eq!(
        other_rebase.admission_revision(),
        matching_rebase.admission_revision()
    );
    assert_eq!(other_rebase.state_digest(), matching_rebase.state_digest());
    assert!(capture.bind_rebase(&other_rebase, &coverage).is_err());
    assert!(capture.bind_rebase(&matching_rebase, &coverage).is_ok());
}

#[test]
fn given_root_covered_subset_or_swapped_receipts_when_verifying_then_reject() {
    let (storage, authority, seed) = coverage_storage();
    let data_transition = "native-data-transition-00002";
    let directory_transition = "native-directory-transition-00002";
    let (data_receipt, directory_receipt) = coverage_receipt_pair(
        &storage,
        &authority,
        &seed,
        data_transition,
        directory_transition,
    );

    let mut subset_ids = storage
        .data_ciphertext_ids()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let remove_at = subset_ids
        .iter()
        .position(|id| id != storage.catalogue_ciphertext_id())
        .unwrap();
    subset_ids.remove(remove_at);
    let subset = signed_coverage_receipt(
        storage.catalogue_ciphertext_id(),
        data_transition,
        &subset_ids,
        storage.key_epoch(),
        &authority,
        &seed,
    );
    assert!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: &subset,
                    directory_receipt: &directory_receipt
                }
            )
            .is_err()
    );

    let wrong_epoch = signed_coverage_receipt(
        storage.catalogue_ciphertext_id(),
        data_transition,
        &storage
            .data_ciphertext_ids()
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        storage.key_epoch() + 1,
        &authority,
        &seed,
    );
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                coverage_proof(
                    data_transition,
                    directory_transition,
                    &wrong_epoch,
                    &directory_receipt
                )
            )
            .err()
            .unwrap(),
        "Archive coverage receipt does not match exact Native set and preparation"
    );

    assert!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: &directory_receipt,
                    directory_receipt: &data_receipt
                }
            )
            .is_err()
    );
}

#[test]
fn given_wrong_pins_authority_or_signature_when_verifying_then_reject() {
    let (storage, authority, seed) = coverage_storage();
    let data_transition = "native-data-transition-00003";
    let directory_transition = "native-directory-transition-00003";
    let (data_receipt, directory_receipt) = coverage_receipt_pair(
        &storage,
        &authority,
        &seed,
        data_transition,
        directory_transition,
    );
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                coverage_proof(
                    data_transition,
                    data_transition,
                    &data_receipt,
                    &directory_receipt
                )
            )
            .err()
            .unwrap(),
        "Archive coverage scope or directory preparation binding mismatch"
    );
    assert!(
        storage
            .verify_coverage(
                &authority,
                coverage_proof(
                    "native-data-transition-replay",
                    directory_transition,
                    &data_receipt,
                    &directory_receipt
                )
            )
            .is_err()
    );
    assert!(
        storage
            .verify_coverage(
                &authority,
                coverage_proof(
                    data_transition,
                    "native-directory-transition-replay",
                    &data_receipt,
                    &directory_receipt
                )
            )
            .is_err()
    );
    let mut wrong_scope = authority.clone();
    wrong_scope.scope_id = "different-scope".into();
    assert!(
        storage
            .verify_coverage(
                &wrong_scope,
                coverage_proof(
                    data_transition,
                    directory_transition,
                    &data_receipt,
                    &directory_receipt
                )
            )
            .is_err()
    );
    let mut wrong_policy = authority.clone();
    wrong_policy.policy_revision += 1;
    assert!(
        storage
            .verify_coverage(
                &wrong_policy,
                coverage_proof(
                    data_transition,
                    directory_transition,
                    &data_receipt,
                    &directory_receipt
                )
            )
            .is_err()
    );
    let mut wrong_key = authority.clone();
    wrong_key.service_public_key = crate::public_key_from_seed(&[92; 32]).unwrap();
    assert!(
        storage
            .verify_coverage(
                &wrong_key,
                coverage_proof(
                    data_transition,
                    directory_transition,
                    &data_receipt,
                    &directory_receipt
                )
            )
            .is_err()
    );

    let mut forged: Value = serde_json::from_slice(&data_receipt).unwrap();
    let mut signature = URL_SAFE_NO_PAD
        .decode(forged["signature"].as_str().unwrap())
        .unwrap();
    signature[0] ^= 1;
    forged["signature"] = json!(URL_SAFE_NO_PAD.encode(signature));
    let forged = serde_json::to_vec(&forged).unwrap();
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                coverage_proof(
                    data_transition,
                    directory_transition,
                    &forged,
                    &directory_receipt
                )
            )
            .err()
            .unwrap(),
        "Invalid archive coverage service signature"
    );

    // Failed verification does not consume or mutate the storage evidence.
    let (valid_data, valid_directory) = coverage_receipt_pair(
        &storage,
        &authority,
        &seed,
        data_transition,
        directory_transition,
    );
    assert!(
        storage
            .verify_coverage(
                &authority,
                coverage_proof(
                    data_transition,
                    directory_transition,
                    &valid_data,
                    &valid_directory
                )
            )
            .is_ok()
    );
}

#[test]
fn given_extra_missing_or_duplicated_receipt_fields_when_verifying_then_reject() {
    let (storage, authority, seed) = coverage_storage();
    let data_transition = "native-data-transition-00004";
    let directory_transition = "native-directory-transition-00004";
    let (data_receipt, directory_receipt) = coverage_receipt_pair(
        &storage,
        &authority,
        &seed,
        data_transition,
        directory_transition,
    );

    let mut extra: Value = serde_json::from_slice(&data_receipt).unwrap();
    extra["unexpected"] = json!(true);
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: &serde_json::to_vec(&extra).unwrap(),
                    directory_receipt: &directory_receipt,
                }
            )
            .err()
            .unwrap(),
        "Invalid archive coverage receipt schema"
    );
    let mut extra_payload: Value = serde_json::from_slice(&data_receipt).unwrap();
    extra_payload["payload"]["unexpected"] = json!(true);
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: &serde_json::to_vec(&extra_payload).unwrap(),
                    directory_receipt: &directory_receipt,
                }
            )
            .err()
            .unwrap(),
        "Invalid archive coverage receipt schema"
    );
    let mut missing: Value = serde_json::from_slice(&data_receipt).unwrap();
    missing["payload"]
        .as_object_mut()
        .unwrap()
        .remove("rootCovered");
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: &serde_json::to_vec(&missing).unwrap(),
                    directory_receipt: &directory_receipt,
                }
            )
            .err()
            .unwrap(),
        "Invalid archive coverage receipt schema"
    );
    let raw = String::from_utf8(data_receipt.clone()).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: raw.as_bytes(),
                    directory_receipt: &directory_receipt,
                }
            )
            .err()
            .unwrap(),
        "Invalid archive coverage receipt schema"
    );
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: &data_receipt,
                    directory_receipt: &[],
                }
            )
            .err()
            .unwrap(),
        "Invalid archive coverage receipt schema"
    );
    assert_eq!(
        storage
            .verify_coverage(
                &authority,
                HistoryArchiveCoverageProof {
                    data_transition_id: data_transition,
                    directory_transition_id: directory_transition,
                    data_receipt: &vec![b' '; 8193],
                    directory_receipt: &directory_receipt,
                }
            )
            .err()
            .unwrap(),
        "Archive coverage receipt exceeds size limit"
    );
}
