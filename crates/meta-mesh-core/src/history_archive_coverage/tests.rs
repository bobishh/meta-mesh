use super::*;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/mesh-replication/fixtures/history-archive-coverage-v1.json"
    )))
    .unwrap()
}
fn id(n: usize) -> String {
    format!("{n:08x}{}", "A".repeat(35))
}

#[test]
fn given_shared_browser_coverage_vectors_when_native_derives_then_match_every_tree_shape_and_signature()
 {
    let fixture = fixture();
    let authority: HistoryArchiveCoverageAuthority =
        serde_json::from_value(fixture["authority"].clone()).unwrap();
    for set in fixture["sets"].as_array().unwrap() {
        let count = set["count"].as_u64().unwrap() as usize;
        let root = set["root"].as_str().unwrap();
        let summary = derive_history_archive_coverage(root, 3, (0..count).map(id)).unwrap();
        assert_eq!(serde_json::to_value(&summary).unwrap(), set["summary"]);
        let bytes = serde_json::to_vec(&set["receipt"]).unwrap();
        let receipt = verify_receipt(
            &bytes,
            &authority,
            root,
            fixture["transitionId"].as_str().unwrap(),
            &summary,
        )
        .unwrap();
        assert_eq!(serde_json::to_value(receipt).unwrap(), set["receipt"]);
    }
}

#[test]
fn given_a_large_lazy_expected_set_when_native_derives_then_consume_in_order_with_canonical_height()
{
    let mut consumed = 0;
    let source = (0..100_000).map(|n| {
        consumed += 1;
        id(n)
    });
    let summary = derive_history_archive_coverage(&id(99_999), 3, source).unwrap();
    assert_eq!(consumed, 100_000);
    assert_eq!(summary.height, 4);
    assert_eq!(summary.object_count, 100_000);
    assert!(summary.root_covered);
}

#[test]
fn given_empty_unordered_duplicate_or_invalid_expected_ids_when_deriving_then_reject() {
    for objects in [
        vec![],
        vec![id(1), id(0)],
        vec![id(0), id(0)],
        vec!["invalid".into()],
    ] {
        assert!(derive_history_archive_coverage(&id(0), 3, objects).is_err());
    }
    assert!(derive_history_archive_coverage(&id(0), u64::MAX, [id(0)]).is_err());
    assert!(derive_history_archive_coverage("invalid", 3, [id(0)]).is_err());
}
