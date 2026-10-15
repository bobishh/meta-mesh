use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureObject {
    object_id: String,
    bytes: String,
}
#[derive(Deserialize)]
struct Fixture {
    context: HistoryArchiveTreeContext,
    root: HistoryArchiveIndexRoot,
    entries: Vec<HistoryArchiveIndexEntry>,
    objects: Vec<FixtureObject>,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../../packages/mesh-replication/fixtures/history-archive-v1.json"
    ))
    .unwrap()
}
fn bytes(f: &Fixture, id: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(
            &f.objects
                .iter()
                .find(|record| record.object_id == id)
                .unwrap()
                .bytes,
        )
        .unwrap()
}
fn canonical(value: &Value) -> Vec<u8> {
    crate::canonicalize_json(value).unwrap().into_bytes()
}

#[test]
fn given_empty_root_when_a_nullable_range_field_is_omitted_then_reject_instead_of_inventing_null() {
    let root = json!({ "objectId": history_archive_object_id(b"empty"), "height": 0,
        "count": 0, "first": null, "last": null });
    assert!(serde_json::from_value::<HistoryArchiveIndexRoot>(root.clone()).is_ok());
    for field in ["first", "last"] {
        let mut missing = root.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<HistoryArchiveIndexRoot>(missing).is_err(),
            "Accepted absent {field} as explicit null"
        );
    }
}

#[test]
fn given_shared_browser_fixture_when_native_reads_then_verify_identical_hashes_ranges_and_utf16_order()
 {
    let f = fixture();
    let root_bytes = bytes(&f, &f.root.object_id);
    assert_eq!(history_archive_object_id(&root_bytes), f.root.object_id);
    let HistoryArchiveIndexPage::Branch(branch) =
        verify_history_archive_index_page(&f.context, &f.root, &root_bytes).unwrap()
    else {
        panic!("Expected branch")
    };
    let mut entries = Vec::new();
    for child in branch.children {
        let HistoryArchiveIndexPage::Leaf(leaf) =
            verify_history_archive_index_page(&f.context, &child, &bytes(&f, &child.object_id))
                .unwrap()
        else {
            panic!("Expected leaf")
        };
        entries.extend(leaf.entries);
    }
    assert_eq!(entries, f.entries);
    assert_eq!(entries[70].key, "😀");
    assert_eq!(entries[71].key, "\u{e000}");
}

#[test]
fn given_scope_or_root_metadata_changes_when_reading_then_reject_even_before_an_absence_is_claimed()
{
    let f = fixture();
    let raw = bytes(&f, &f.root.object_id);
    for context in [
        HistoryArchiveTreeContext {
            workspace_id: "other".into(),
            ..f.context.clone()
        },
        HistoryArchiveTreeContext {
            history_epoch: 8,
            ..f.context.clone()
        },
        HistoryArchiveTreeContext {
            index_id: "other".into(),
            ..f.context.clone()
        },
    ] {
        assert!(verify_history_archive_index_page(&context, &f.root, &raw).is_err());
    }
    let mut root = f.root.clone();
    root.count += 1;
    assert!(verify_history_archive_index_page(&f.context, &root, &raw).is_err());
    root = f.root.clone();
    root.first = Some("wrong".into());
    assert!(verify_history_archive_index_page(&f.context, &root, &raw).is_err());
}

#[test]
fn given_committed_hostile_page_schemas_when_verifying_then_reject_without_relying_on_a_hash_mismatch()
 {
    let f = fixture();
    let source: Value = serde_json::from_slice(&bytes(&f, &f.root.object_id)).unwrap();
    for alteration in [
        "overlap",
        "duplicate",
        "unknown",
        "unsafe",
        "version",
        "height",
    ] {
        let mut page = source.clone();
        match alteration {
            "overlap" => page["children"][1]["first"] = page["children"][0]["last"].clone(),
            "duplicate" => {
                page["children"][1]["objectId"] = page["children"][0]["objectId"].clone()
            }
            "unknown" => page["unrecognized"] = json!(true),
            "unsafe" => page["children"][0]["count"] = json!(MAX_HISTORY_ARCHIVE_INTEGER),
            "version" => page["version"] = json!(2),
            "height" => page["height"] = json!(MAX_HISTORY_ARCHIVE_DEPTH),
            _ => unreachable!(),
        }
        let raw = canonical(&page);
        let mut root = f.root.clone();
        root.object_id = history_archive_object_id(&raw);
        assert!(
            verify_history_archive_index_page(&f.context, &root, &raw).is_err(),
            "Accepted {alteration}"
        );
    }
}

#[test]
fn given_noncanonical_or_corrupt_bytes_when_verifying_then_reject_without_normalization() {
    let f = fixture();
    let mut raw = bytes(&f, &f.root.object_id);
    raw.push(b' ');
    let mut root = f.root.clone();
    root.object_id = history_archive_object_id(&raw);
    assert!(verify_history_archive_index_page(&f.context, &root, &raw).is_err());
    assert!(verify_history_archive_index_page(&f.context, &f.root, b"not JSON").is_err());
    assert!(
        verify_history_archive_index_page(
            &f.context,
            &f.root,
            &vec![0; MAX_HISTORY_ARCHIVE_PAGE_BYTES + 1]
        )
        .is_err()
    );
}

#[test]
fn given_rust_scalar_order_differs_from_browser_utf16_when_leaf_keys_are_swapped_then_reject_the_incompatible_order()
 {
    let f = fixture();
    let root_page: Value = serde_json::from_slice(&bytes(&f, &f.root.object_id)).unwrap();
    let mut child: HistoryArchiveIndexRoot =
        serde_json::from_value(root_page["children"][1].clone()).unwrap();
    let mut leaf: Value = serde_json::from_slice(&bytes(&f, &child.object_id)).unwrap();
    let entries = leaf["entries"].as_array_mut().unwrap();
    let last = entries.len() - 1;
    entries.swap(last - 1, last);
    child.last = Some("😀".into());
    let raw = canonical(&leaf);
    child.object_id = history_archive_object_id(&raw);
    assert!(verify_history_archive_index_page(&f.context, &child, &raw).is_err());
}
