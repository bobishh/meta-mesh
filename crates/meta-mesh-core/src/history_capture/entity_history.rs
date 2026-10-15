//! Selected archived versions consume an opaque verified baseline. No host supplied classification grants authority.
use super::{HistoryCapturedChange, HistoryArchiveBytesReference, HistoryArchiveEncryptedReader, HistoryArchiveObjectBinding};
use crate::{history_archive::{HistoryArchiveIndexPage, HistoryArchiveIndexRoot, HistoryArchiveTreeContext, verify_history_archive_index_page},
    history_archive_crypto::HistoryArchiveEncryptionScope, history_baseline::VerifiedReceivedHistoryBaseline,
    causal_admission::CausalAdmissionStatus};
use automerge::{AutoCommit, Change, ChangeHash};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use super::source::{self, HistoryArchiveSource, EncryptedSource, PlaintextSource};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedArchivedEntityVersion {
    pub workspace_id: String,
    pub entity_id: String,
    pub change_hash: String,
    pub baseline_id: String,
    pub history_epoch: u64,
    pub observation: CausalAdmissionStatus,
    pub document: Vec<u8>,
    pub original_change: Vec<u8>,
    pub original_authorizations: Vec<Vec<u8>>,
}
const MAX_SELECTED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SELECTED_CHANGES: usize = 1_048_576;

fn entries(context: &HistoryArchiveTreeContext, root: &HistoryArchiveIndexRoot, reader: &mut impl HistoryArchiveSource)
    -> Result<Vec<(String, String)>, String> {
    if root.count > 20_000 { return Err("Selected original proof set exceeds limit".into()); }
    let mut queue = vec![root.clone()];
    let mut seen = BTreeSet::new();
    let mut found = BTreeMap::new();
    while let Some(pointer) = queue.pop() {
        reader.ensure_current()?;
        if !seen.insert(pointer.object_id.clone()) || seen.len() > 21_024 { return Err("Invalid archived proof index cycle or bound".into()); }
        let bytes = reader.read_bound(&HistoryArchiveObjectBinding { context: context.clone(), object_kind: "page".into(), part_index: 0, part_count: 1 }, &pointer.object_id)?;
        match verify_history_archive_index_page(context, &pointer, &bytes)? {
            HistoryArchiveIndexPage::Leaf(page) => for entry in page.entries {
                if found.insert(entry.key, entry.object_id).is_some() { return Err("Duplicate archived proof index key".into()); }
            },
            HistoryArchiveIndexPage::Branch(page) => queue.extend(page.children),
        }
    }
    if found.len() as u64 != root.count { return Err("Archived proof count differs from its signed index".into()); }
    Ok(found.into_iter().collect())
}

/// Verify original bytes and bounded dependency closure under the signed catalogue, preserving its original observation.
/// This never authorizes the old change anew; restoring is a separate fresh command under current rights.
pub fn read_archived_entity_version(basis: &VerifiedReceivedHistoryBaseline, scope: &HistoryArchiveEncryptionScope,
    entity_id: &str, hash: &str, reader: &mut impl HistoryArchiveEncryptedReader) -> Result<VerifiedArchivedEntityVersion, String> {
    let payload = &basis.envelope().payload;
    if scope.scope_id != payload.storage.authority.scope_id || scope.key_epoch != payload.storage.key_epoch {
        return Err("Selected history version differs from its verified scope".into());
    }
    read_from_source(basis, entity_id, hash, &mut EncryptedSource { reader, scope, locator_root: &payload.locator_root })
}
pub fn read_archived_peer_entity_version(basis: &VerifiedReceivedHistoryBaseline, entity_id: &str, hash: &str,
    reader: &mut impl super::HistoryArchivePlaintextReader) -> Result<VerifiedArchivedEntityVersion, String> {
    read_from_source(basis, entity_id, hash, &mut PlaintextSource { reader })
}
fn read_from_source(basis: &VerifiedReceivedHistoryBaseline, entity_id: &str, hash: &str,
    reader: &mut impl HistoryArchiveSource) -> Result<VerifiedArchivedEntityVersion, String> {
    let mut bounded = source::BoundedSource::new(reader, 512 * 1024 * 1024, 1_048_576);
    let reader = &mut bounded;
    super::history_entity_index_id(entity_id)?;
    if hash.len() != 64 || hash.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte)) {
        return Err("Invalid selected history version hash".into());
    }
    let payload = &basis.envelope().payload;
    let catalogue = &payload.archive;
    let mut pending = vec![hash.to_owned()];
    let mut changes = BTreeMap::<String, Change>::new();
    let mut total = 0u64;
    let mut selected = None;
    let child = |index_id: String| HistoryArchiveTreeContext { index_id, ..catalogue.context.clone() };
    while let Some(current) = pending.pop() {
        if changes.contains_key(&current) { continue; }
        reader.ensure_current()?;
        if changes.len() >= MAX_SELECTED_CHANGES { return Err("Selected history dependency closure exceeds limit".into()); }
        let encoded = source::index_record(&catalogue.context, &catalogue.root, &format!("change/{current}"), reader)?;
        let captured: HistoryCapturedChange = serde_json::from_slice(&encoded).map_err(|_| "Malformed original history change record")?;
        if captured.kind != "workspace-history-archive-record" || captured.version != 1 || captured.hash != current ||
            captured.workspace_id != payload.workspace_id || captured.history_epoch != payload.history_epoch ||
            captured.capture_revision != catalogue.capture_revision || captured.admission_revision != catalogue.admission_revision ||
            captured.authority_revision != catalogue.authority_revision || captured.admission_policy != payload.admission_policy {
            return Err("Selected original history record differs from signed catalogue provenance".into());
        }
        let bytes = source::bytes(&child(format!("change/{current}/bytes")),
            &captured.bytes, MAX_SELECTED_BYTES, reader)?;
        total = total.checked_add(bytes.len() as u64).ok_or("Selected history byte count overflow")?;
        if total > MAX_SELECTED_BYTES { return Err("Selected history dependency bytes exceed limit".into()); }
        let change = Change::from_bytes(bytes.clone()).map_err(|_| "Invalid original archived change bytes")?;
        if change.hash().to_string() != current || change.deps().len() as u64 != captured.dependency_count {
            return Err("Original archived hash or dependency count changed".into());
        }
        let encoded_deps = source::bytes(
            &child(format!("change/{current}/dependencies")), &captured.dependencies, MAX_SELECTED_BYTES, reader)?;
        total = total.checked_add(encoded_deps.len() as u64).ok_or("Selected dependency byte count overflow")?;
        if total > MAX_SELECTED_BYTES { return Err("Selected history dependency bytes exceed limit".into()); }
        let deps: Vec<String> = serde_json::from_slice(&encoded_deps).map_err(|_| "Invalid archived dependency list")?;
        if deps != change.deps().iter().map(ToString::to_string).collect::<Vec<_>>() { return Err("Archived dependencies differ from signed original change bytes".into()); }
        if current == hash {
            selected = Some((captured, bytes));
        }
        pending.extend(deps);
        changes.insert(current, change);
    }
    let (captured, original_change) = selected.ok_or("Selected original history change is unavailable")?;
    let proof_context = child(format!("change/{hash}/authorizations"));
    let mut original_authorizations = Vec::new();
    for (ordinal, id) in entries(&proof_context, &captured.authorizations, reader)? {
        if ordinal.len() != 16 || !ordinal.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) { return Err("Invalid original proof ordinal".into()); }
        let reference_json = reader.read_bound(&HistoryArchiveObjectBinding { context: catalogue.context.clone(), object_kind: "record".into(), part_index: 0, part_count: 1 }, &id)?;
        let reference: HistoryArchiveBytesReference = serde_json::from_slice(&reference_json).map_err(|_| "Invalid original proof byte reference")?;
        let proof = source::bytes(&child(format!("source-proof/{ordinal}")),
            &reference, MAX_SELECTED_BYTES, reader)?;
        total = total.checked_add(proof.len() as u64).ok_or("Selected original proof byte count overflow")?;
        if total > MAX_SELECTED_BYTES { return Err("Selected original proof bytes exceed limit".into()); }
        let record: crate::IncomingWorkspaceChangeAuthorization = serde_json::from_slice(&proof).map_err(|_| "Invalid original proof JSON")?;
        if record.signed.payload.workspace_id != payload.workspace_id || !record.signed.payload.hashes.iter().any(|value| value == hash) {
            return Err("Selected original proof targets another workspace or change".into());
        }
        original_authorizations.push(proof);
    }
    let mut document = AutoCommit::new();
    document.apply_changes(changes.into_values().collect::<Vec<_>>()).map_err(|_| "Selected history dependencies cannot be reconstructed")?;
    let selected_hash = ChangeHash::from_str(hash).map_err(|_| "Invalid selected change hash")?;
    if document.get_heads() != vec![selected_hash] { return Err("Selected history dependencies are missing or contain unrelated heads".into()); }
    let original = Change::from_bytes(original_change.clone()).map_err(|_| "Selected original change is invalid")?;
    let metadata = super::catalogue::archive_change_metadata(&mut document, &original)?.ok_or("Selected original has no derivable entity membership")?;
    if !metadata.entity_ids.iter().any(|value| value == entity_id) || captured.metadata.as_ref() != Some(&metadata) {
        return Err("Selected change does not belong to this entity index".into());
    }
    reader.ensure_current()?;
    Ok(VerifiedArchivedEntityVersion { workspace_id: payload.workspace_id.clone(), entity_id: entity_id.into(), change_hash: hash.into(),
        baseline_id: payload.baseline_id.clone(), history_epoch: payload.history_epoch, observation: captured.observation,
        document: document.save(), original_change, original_authorizations })
}
