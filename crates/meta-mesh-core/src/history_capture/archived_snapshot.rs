//! Covered historical snapshots are acknowledgements, never input to the active compact epoch.
use super::{HistoryCapturedChange, HistoryArchiveEncryptedReader, source::{self, HistoryArchiveSource, EncryptedSource}};
use crate::{history_baseline::VerifiedReceivedHistoryBaseline, history_archive_crypto::HistoryArchiveEncryptionScope,
    history_archive::HistoryArchiveTreeContext};
use automerge::AutoCommit;

/// Every original change must be present byte-for-byte in the Owner-signed catalogue.
/// This preserves its archived observation; it grants no new authoring authority.
pub fn verify_archived_snapshot(basis: &VerifiedReceivedHistoryBaseline, scope: &HistoryArchiveEncryptionScope,
    document: &[u8], reader: &mut impl HistoryArchiveEncryptedReader) -> Result<(), String> {
    let payload = &basis.envelope().payload;
    if scope.scope_id != payload.storage.authority.scope_id || scope.key_epoch != payload.storage.key_epoch {
        return Err("Historical snapshot differs from its verified archive scope".into());
    }
    verify_source(basis, document, &mut EncryptedSource { reader, scope, locator_root: &payload.locator_root })
}

fn verify_source(basis: &VerifiedReceivedHistoryBaseline, document: &[u8], reader: &mut impl HistoryArchiveSource) -> Result<(), String> {
    if document.is_empty() || document.len() > 256 * 1024 * 1024 { return Err("Historical snapshot exceeds its byte bound".into()); }
    let mut original = AutoCommit::load(document).map_err(|_| "Invalid historical snapshot document")?;
    if !original.get_missing_deps(&[]).is_empty() {
        return Err("Historical snapshot contains unresolved original changes; retain it for causal recovery".into());
    }
    let changes = original.get_changes(&[]);
    let payload = &basis.envelope().payload;
    if changes.is_empty() || changes.len() > 1_048_576 || changes.len() as u64 > payload.archive.change_count {
        return Err("Historical snapshot exceeds its signed archive change bound".into());
    }
    let mut bounded = source::BoundedSource::new(reader, 512 * 1024 * 1024, 1_048_576);
    for change in changes {
        bounded.ensure_current()?;
        let hash = change.hash().to_string();
        let record = source::index_record(&payload.archive.context, &payload.archive.root, &format!("change/{hash}"), &mut bounded)?;
        let captured: HistoryCapturedChange = serde_json::from_slice(&record).map_err(|_| "Invalid historical archive record")?;
        if captured.kind != "workspace-history-archive-record" || captured.version != 1 || captured.hash != hash ||
            captured.workspace_id != payload.workspace_id || captured.history_epoch != payload.history_epoch ||
            captured.capture_revision != payload.archive.capture_revision || captured.admission_revision != payload.archive.admission_revision ||
            captured.authority_revision != payload.archive.authority_revision || captured.admission_policy != payload.admission_policy {
            return Err("Historical snapshot change differs from its signed archive provenance".into());
        }
        let context = HistoryArchiveTreeContext { index_id: format!("change/{hash}/bytes"), ..payload.archive.context.clone() };
        let archived = source::bytes(&context, &captured.bytes, 256 * 1024 * 1024, &mut bounded)?;
        if archived != change.raw_bytes() { return Err("Historical snapshot original bytes differ from its signed archive".into()); }
    }
    bounded.ensure_current()
}
