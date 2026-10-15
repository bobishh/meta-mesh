use super::*;
use crate::{
    history_archive::{HistoryArchiveTreeContext, history_archive_object_id},
    history_archive_crypto::{EncryptedHistoryArchiveObject, HistoryArchiveEncryptionScope},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

fn context() -> HistoryArchiveTreeContext {
    HistoryArchiveTreeContext {
        workspace_id: "workspace".into(),
        history_epoch: 7,
        index_id: "archive-locators".into(),
    }
}

fn make_pointer(
    bytes: &[u8],
    height: u8,
    count: u64,
    first: Option<&str>,
    last: Option<&str>,
) -> HistoryArchiveLocatorPointer {
    HistoryArchiveLocatorPointer {
        object_id: history_archive_object_id(bytes),
        ciphertext_id: "A".repeat(43),
        height,
        count,
        first: first.map(str::to_owned),
        last: last.map(str::to_owned),
    }
}

fn canonical(value: &Value) -> Vec<u8> {
    crate::canonicalize_json(value).unwrap().into_bytes()
}
fn hash(bytes: &[u8]) -> String {
    history_archive_object_id(bytes)
}

fn root(pointer: HistoryArchiveLocatorPointer) -> HistoryArchiveLocatorRoot {
    HistoryArchiveLocatorRoot {
        kind: "workspace-history-locator-root".into(),
        version: 1,
        context: context(),
        root: pointer,
    }
}

#[test]
fn given_valid_leaf_when_verifying_then_bind_hash_context_and_pointer_range() {
    let key = hash(b"binding");
    let page = json!({ "kind": "workspace-history-locator-page", "version": 1, "context": context(), "height": 0,
        "entries": [{"key": key, "ciphertextId": hash(b"ciphertext")}] });
    let bytes = canonical(&page);
    let pointer = make_pointer(&bytes, 0, 1, Some(&key), Some(&key));
    let verified = verify_history_locator_page(&root(pointer.clone()), &pointer, &bytes).unwrap();
    assert!(matches!(verified, HistoryArchiveLocatorPage::Leaf(_)));
}

#[test]
fn given_changed_page_metadata_when_verifying_then_reject() {
    let key = hash(b"binding");
    let page = json!({ "kind": "workspace-history-locator-page", "version": 1, "context": context(), "height": 0,
        "entries": [{"key": key, "ciphertextId": hash(b"ciphertext")}] });
    let bytes = canonical(&page);
    let pointer = make_pointer(&bytes, 0, 2, Some(&key), Some(&key));
    assert!(verify_history_locator_page(&root(pointer.clone()), &pointer, &bytes).is_err());
    let mut wrong_root = root(pointer.clone());
    wrong_root.context.history_epoch += 1;
    assert!(verify_history_locator_page(&wrong_root, &pointer, &bytes).is_err());
}

#[test]
fn given_ordered_branch_when_verifying_then_require_equal_child_height_and_unique_ranges() {
    let mut keys = [hash(b"one"), hash(b"two")];
    keys.sort();
    let child = |key: &str, object: &str, cipher: &str| HistoryArchiveLocatorPointer {
        object_id: hash(object.as_bytes()),
        ciphertext_id: hash(cipher.as_bytes()),
        height: 0,
        count: 1,
        first: Some(key.into()),
        last: Some(key.into()),
    };
    let children = vec![
        child(&keys[0], "page-one", "cipher-one"),
        child(&keys[1], "page-two", "cipher-two"),
    ];
    let page = serde_json::to_value(HistoryArchiveLocatorBranch {
        kind: "workspace-history-locator-page".into(),
        version: 1,
        context: context(),
        height: 1,
        children: children.clone(),
    })
    .unwrap();
    let bytes = canonical(&page);
    let pointer = make_pointer(&bytes, 1, 2, Some(&keys[0]), Some(&keys[1]));
    assert!(matches!(
        verify_history_locator_page(&root(pointer.clone()), &pointer, &bytes).unwrap(),
        HistoryArchiveLocatorPage::Branch(_)
    ));

    let mut duplicated = children;
    duplicated[1].object_id = duplicated[0].object_id.clone();
    let page = serde_json::to_value(HistoryArchiveLocatorBranch {
        kind: "workspace-history-locator-page".into(),
        version: 1,
        context: context(),
        height: 1,
        children: duplicated,
    })
    .unwrap();
    let bytes = canonical(&page);
    let pointer = make_pointer(&bytes, 1, 2, Some(&keys[0]), Some(&keys[1]));
    assert!(verify_history_locator_page(&root(pointer.clone()), &pointer, &bytes).is_err());
}

#[test]
fn given_overflowing_untrusted_child_counts_when_verifying_then_reject_without_panicking() {
    let mut keys = [hash(b"overflow-one"), hash(b"overflow-two")];
    keys.sort();
    let children = keys
        .iter()
        .enumerate()
        .map(|(index, key)| HistoryArchiveLocatorPointer {
            object_id: hash(format!("page-{index}").as_bytes()),
            ciphertext_id: hash(format!("cipher-{index}").as_bytes()),
            height: 0,
            count: u64::MAX,
            first: Some(key.clone()),
            last: Some(key.clone()),
        })
        .collect();
    let page = serde_json::to_value(HistoryArchiveLocatorBranch {
        kind: "workspace-history-locator-page".into(),
        version: 1,
        context: context(),
        height: 1,
        children,
    })
    .unwrap();
    let bytes = canonical(&page);
    let pointer = make_pointer(&bytes, 1, 2, Some(&keys[0]), Some(&keys[1]));
    assert!(verify_history_locator_page(&root(pointer.clone()), &pointer, &bytes).is_err());
}

#[test]
fn given_impossible_locator_pointer_cardinality_when_validating_then_reject() {
    let key_a = hash(b"pointer-a");
    let key_b = hash(b"pointer-b");
    let (first, last) = if key_a < key_b {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };
    let singleton_with_range = HistoryArchiveLocatorPointer {
        object_id: hash(b"object"),
        ciphertext_id: hash(b"cipher"),
        height: 0,
        count: 1,
        first: Some(first),
        last: Some(last),
    };
    assert!(valid_pointer(&singleton_with_range).is_err());
    let too_many_leaf_entries = HistoryArchiveLocatorPointer {
        object_id: hash(b"object"),
        ciphertext_id: hash(b"cipher"),
        height: 0,
        count: 65,
        first: Some(hash(b"first")),
        last: Some(hash(b"last")),
    };
    assert!(valid_pointer(&too_many_leaf_entries).is_err());
}

#[test]
fn given_unknown_fields_or_omitted_nullable_pointer_fields_when_verifying_then_reject() {
    let empty = json!({ "kind": "workspace-history-locator-page", "version": 1, "context": context(), "height": 0, "entries": [] });
    let bytes = canonical(&empty);
    let pointer = make_pointer(&bytes, 0, 0, None, None);
    let mut page_with_extra = empty.clone();
    page_with_extra["extra"] = json!(true);
    let extra_bytes = canonical(&page_with_extra);
    let extra_pointer = make_pointer(&extra_bytes, 0, 0, None, None);
    assert!(
        verify_history_locator_page(&root(extra_pointer.clone()), &extra_pointer, &extra_bytes)
            .is_err()
    );

    let mut root_value = serde_json::to_value(root(pointer)).unwrap();
    root_value["root"].as_object_mut().unwrap().remove("first");
    assert!(serde_json::from_value::<HistoryArchiveLocatorRoot>(root_value).is_err());
}

#[test]
fn given_encrypted_page_when_opening_then_check_ciphertext_and_page_bindings() {
    let scope = HistoryArchiveEncryptionScope {
        scope_id: "scope".into(),
        key_epoch: 1,
        key: [9; 32],
    };
    let page = json!({ "kind": "workspace-history-locator-page", "version": 1, "context": context(), "height": 0, "entries": [] });
    let plaintext = canonical(&page);
    let object_id = hash(&plaintext);
    let binding = crate::history_archive_crypto::HistoryArchiveEncryptionBinding {
        workspace_id: "workspace".into(),
        history_epoch: 7,
        index_id: "archive-locators".into(),
        object_id: object_id.clone(),
        object_kind: "page".into(),
        part_index: 0,
        part_count: 1,
    };
    let mut aad_value = serde_json::to_value(&binding)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    aad_value.insert("purpose".into(), json!("archive"));
    aad_value.insert("scopeId".into(), json!(scope.scope_id));
    aad_value.insert("keyEpoch".into(), json!(scope.key_epoch));
    let aad = format!(
        "MESH-HISTORY/1/archive-object\0{}",
        crate::canonicalize_json(&Value::Object(aad_value)).unwrap()
    );
    let nonce = [7; 12];
    let encrypted_bytes = Aes256Gcm::new_from_slice(&scope.key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    let encrypted = EncryptedHistoryArchiveObject {
        version: 1,
        scope_id: scope.scope_id.clone(),
        key_epoch: scope.key_epoch,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(encrypted_bytes),
    };
    let ciphertext_id = hash(&canonical(&serde_json::to_value(&encrypted).unwrap()));
    let pointer = HistoryArchiveLocatorPointer {
        object_id,
        ciphertext_id,
        height: 0,
        count: 0,
        first: None,
        last: None,
    };
    let root = root(pointer.clone());
    assert!(matches!(
        open_history_locator_page(&scope, &root, &pointer, &encrypted).unwrap(),
        HistoryArchiveLocatorPage::Leaf(_)
    ));

    let mut wrong_root = root.clone();
    wrong_root.context.history_epoch += 1;
    assert!(open_history_locator_page(&scope, &wrong_root, &pointer, &encrypted).is_err());
}

#[test]
fn given_only_shared_encrypted_locator_pages_when_cold_reader_looks_up_binding_then_open_leaf() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../packages/mesh-replication/fixtures/history-archive-locators-v1.json"
    ))
    .unwrap();
    let scope_data = &fixture["scope"];
    let scope = HistoryArchiveEncryptionScope {
        scope_id: scope_data["scopeId"].as_str().unwrap().into(),
        key_epoch: scope_data["keyEpoch"].as_u64().unwrap(),
        key: URL_SAFE_NO_PAD
            .decode(fixture["key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let root: HistoryArchiveLocatorRoot = serde_json::from_value(fixture["root"].clone()).unwrap();
    assert_eq!((root.root.height, root.root.count), (1, 65));

    let load_encrypted = |ciphertext_id: &str| -> EncryptedHistoryArchiveObject {
        let saved = fixture["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|saved| saved["ciphertextId"] == ciphertext_id)
            .expect("fixture contains encrypted page");
        let pointer_binding = &saved["binding"];
        assert_eq!(pointer_binding["workspaceId"], root.context.workspace_id);
        assert_eq!(pointer_binding["historyEpoch"], root.context.history_epoch);
        assert_eq!(pointer_binding["indexId"], root.context.index_id);
        assert_eq!(pointer_binding["objectId"], saved["objectId"]);
        assert_eq!(pointer_binding["objectKind"], "page");
        assert_eq!(pointer_binding["partIndex"], 0);
        assert_eq!(pointer_binding["partCount"], 1);
        serde_json::from_value(saved["object"].clone()).unwrap()
    };

    let encrypted_root = load_encrypted(&root.root.ciphertext_id);
    let root_page = open_history_locator_page(&scope, &root, &root.root, &encrypted_root).unwrap();
    let HistoryArchiveLocatorPage::Branch(branch) = root_page else {
        panic!("65 locators require the fixture's branch root");
    };
    let binding_key = fixture["bindingKey"].as_str().unwrap();
    let mut found = None;
    for child in &branch.children {
        let encrypted = load_encrypted(&child.ciphertext_id);
        let page = open_history_locator_page(&scope, &root, child, &encrypted).unwrap();
        let HistoryArchiveLocatorPage::Leaf(leaf) = page else {
            panic!("branch child must be a leaf");
        };
        if let Some(entry) = leaf.entries.iter().find(|entry| entry.key == binding_key) {
            found = Some(entry.ciphertext_id.clone());
        }
    }
    assert_eq!(found.as_deref(), fixture["expectedCiphertextId"].as_str());
}
