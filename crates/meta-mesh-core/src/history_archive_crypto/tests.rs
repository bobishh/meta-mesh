use super::*;
use crate::history_archive::history_archive_object_id;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

fn fixture() -> (
    HistoryArchiveEncryptionScope,
    HistoryArchiveEncryptionBinding,
    String,
    EncryptedHistoryArchiveObject,
    Vec<u8>,
) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../packages/mesh-replication/fixtures/history-archive-crypto-v1.json"
    ))
    .unwrap();
    (
        HistoryArchiveEncryptionScope {
            scope_id: v["scope"]["scopeId"].as_str().unwrap().into(),
            key_epoch: v["scope"]["keyEpoch"].as_u64().unwrap(),
            key: URL_SAFE_NO_PAD
                .decode(v["key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
        serde_json::from_value(v["binding"].clone()).unwrap(),
        v["ciphertextId"].as_str().unwrap().into(),
        serde_json::from_value(v["object"].clone()).unwrap(),
        URL_SAFE_NO_PAD
            .decode(v["plaintext"].as_str().unwrap())
            .unwrap(),
    )
}
fn object_id(object: &EncryptedHistoryArchiveObject) -> String {
    history_archive_object_id(
        crate::canonicalize_json(&serde_json::to_value(object).unwrap())
            .unwrap()
            .as_bytes(),
    )
}

#[test]
fn given_shared_browser_archive_ciphertext_when_native_opens_then_recover_exact_original_bytes() {
    let (scope, binding, id, object, expected) = fixture();
    assert_eq!(object_id(&object), id);
    assert_eq!(
        open_history_archive_object(&scope, &binding, &id, &object).unwrap(),
        expected
    );
}

#[test]
fn given_valid_ciphertext_when_scope_history_index_kind_or_part_position_changes_then_native_rejects()
 {
    let (scope, binding, id, object, _) = fixture();
    for alteration in [
        "workspace",
        "epoch",
        "index",
        "kind",
        "position",
        "count",
        "object",
    ] {
        let mut changed = binding.clone();
        match alteration {
            "workspace" => changed.workspace_id = "other".into(),
            "epoch" => changed.history_epoch += 1,
            "index" => changed.index_id = "other".into(),
            "kind" => {
                changed.object_kind = "record".into();
                changed.part_index = 0;
                changed.part_count = 1;
            }
            "position" => changed.part_index -= 1,
            "count" => changed.part_count += 1,
            "object" => changed.object_id = history_archive_object_id(b"other"),
            _ => unreachable!(),
        }
        assert!(
            open_history_archive_object(&scope, &changed, &id, &object).is_err(),
            "Accepted {alteration}"
        );
    }
    for altered in [
        HistoryArchiveEncryptionScope {
            scope_id: "other".into(),
            ..scope.clone()
        },
        HistoryArchiveEncryptionScope {
            key_epoch: 4,
            ..scope.clone()
        },
        HistoryArchiveEncryptionScope {
            key: [99; 32],
            ..scope.clone()
        },
    ] {
        assert!(open_history_archive_object(&altered, &binding, &id, &object).is_err());
    }
}

#[test]
fn given_rehashed_corruption_or_noncanonical_encoding_when_native_opens_then_fail_closed() {
    let (scope, binding, id, object, _) = fixture();
    let mut corrupt = object.clone();
    let mut bytes = URL_SAFE_NO_PAD.decode(&corrupt.ciphertext).unwrap();
    bytes[0] ^= 1;
    corrupt.ciphertext = URL_SAFE_NO_PAD.encode(bytes);
    assert!(open_history_archive_object(&scope, &binding, &id, &corrupt).is_err());
    assert!(open_history_archive_object(&scope, &binding, &object_id(&corrupt), &corrupt).is_err());
    for alteration in ["nonce", "padded", "empty", "oversize", "version"] {
        let mut bad = object.clone();
        match alteration {
            "nonce" => bad.nonce.push('='),
            "padded" => bad.ciphertext.push('='),
            "empty" => bad.ciphertext.clear(),
            "oversize" => bad.ciphertext = "A".repeat(350_000),
            "version" => bad.version = 2,
            _ => unreachable!(),
        }
        assert!(open_history_archive_object(&scope, &binding, &object_id(&bad), &bad).is_err());
    }
}

#[test]
fn given_invalid_bindings_or_unknown_fields_when_native_decodes_then_reject_unsupported_schema() {
    let (scope, binding, id, object, _) = fixture();
    for (field, value) in [
        ("historyEpoch", json!(0)),
        ("historyEpoch", json!(9_007_199_254_740_992u64)),
        ("partIndex", json!(4)),
        ("partCount", json!(0)),
        ("objectKind", json!("attachment")),
        ("indexId", json!("")),
        ("objectId", json!("-".repeat(43))),
    ] {
        let mut value_binding = serde_json::to_value(&binding).unwrap();
        value_binding[field] = value;
        let decoded = serde_json::from_value(value_binding).unwrap();
        assert!(open_history_archive_object(&scope, &decoded, &id, &object).is_err());
    }
    let mut raw = serde_json::to_value(&object).unwrap();
    raw["unknown"] = json!(true);
    assert!(serde_json::from_value::<EncryptedHistoryArchiveObject>(raw).is_err());
    let mut raw = serde_json::to_value(&binding).unwrap();
    raw["unknown"] = json!(true);
    assert!(serde_json::from_value::<HistoryArchiveEncryptionBinding>(raw).is_err());
}

#[test]
fn given_a_native_catalogue_object_when_the_bounded_sink_seals_it_then_only_bound_ciphertext_is_emitted() {
    let (scope, mut binding, _, _, _) = fixture();
    let plaintext = b"native archive sink payload";
    binding.object_id = history_archive_object_id(plaintext);
    let nonce = [73u8; 12];
    let (ciphertext_id, encrypted) = seal_history_archive_object(&scope, &binding, &nonce, plaintext).unwrap();
    assert_ne!(ciphertext_id, binding.object_id);
    assert_eq!(open_history_archive_object(&scope, &binding, &ciphertext_id, &encrypted).unwrap(), plaintext);
    let mut changed = binding.clone();
    changed.index_id.push_str("-other");
    assert!(open_history_archive_object(&scope, &changed, &ciphertext_id, &encrypted).is_err());
    assert!(seal_history_archive_object(&scope, &binding, &[0u8; 11], plaintext).is_err());
    assert!(seal_history_archive_object(&scope, &binding, &nonce, b"substituted bytes").is_err());
}
