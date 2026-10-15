//! Owner authority admission from an authorized encrypted peer channel.
//! Public storage receipts remain public evidence; plaintext paths never claim AES correspondence.
use super::{VerifiedReceivedHistoryBaseline, receive::{verify_owner_attested_core, verify_received_receipt}};
use crate::history_capture::{HistoryArchiveBytesReference, HistoryArchivePlaintextReader, HistoryCapturedChange,
    source::{HistoryArchiveSource, PlaintextSource, BoundedSource, index_record}};

pub fn verify_received_owner_attested_peer_history_baseline(
    signed_json: &[u8], baseline_document: &[u8], trusted_scope_authority: &crate::ScopeAuthoritySnapshot,
    previous: Option<&VerifiedReceivedHistoryBaseline>, reader: &mut impl HistoryArchivePlaintextReader,
) -> Result<VerifiedReceivedHistoryBaseline, String> {
    reader.ensure_current()?;
    let received = verify_owner_attested_core(signed_json, baseline_document, trusted_scope_authority, previous)?;
    let payload = &received.envelope().payload;
    // The service pin is public, retained inside the authenticated Owner envelope.
    // These signatures attest their exact ciphertext set; this read path does not assert
    // that the peer's plaintext set corresponds to that ciphertext set.
    verify_received_receipt(&payload.storage.data_receipt, &payload.storage.authority,
        &payload.storage.data_receipt.payload.archive_root_id, &payload.storage.data_transition_id)?;
    verify_received_receipt(&payload.storage.directory_receipt, &payload.storage.authority,
        &payload.locator_root.root.ciphertext_id, &payload.storage.directory_transition_id)?;
    let mut plaintext = PlaintextSource { reader };
    let mut source = BoundedSource::new(&mut plaintext, 64 * 1024 * 1024, 16_384);
    let catalogue = &payload.archive;
    for (key, maximum) in [("control", 64 * 1024 * 1024), ("document", 256 * 1024 * 1024)] {
        let raw = index_record(&catalogue.context, &catalogue.root, key, &mut source)?;
        let reference: HistoryArchiveBytesReference = serde_json::from_slice(&raw).map_err(|_| "Invalid peer archive source reference")?;
        if reference.kind != "workspace-history-bytes" || reference.version != 1 || reference.byte_length > maximum ||
            reference.part_count != reference.byte_length.div_ceil(256 * 1024) || reference.root.count != reference.part_count {
            return Err("Peer archive source reference exceeds its signed bounds".into());
        }
    }
    for hash in &payload.source_heads {
        let raw = index_record(&catalogue.context, &catalogue.root, &format!("change/{hash}"), &mut source)?;
        let record: HistoryCapturedChange = serde_json::from_slice(&raw).map_err(|_| "Invalid peer source frontier record")?;
        if record.kind != "workspace-history-archive-record" || record.version != 1 || record.hash != *hash ||
            record.workspace_id != payload.workspace_id || record.history_epoch != payload.history_epoch ||
            record.admission_revision != catalogue.admission_revision || record.authority_revision != catalogue.authority_revision ||
            record.capture_revision != catalogue.capture_revision || record.admission_policy != payload.admission_policy {
            return Err("Peer archive does not cover the signed original source frontier".into());
        }
    }
    source.ensure_current()?;
    Ok(received)
}
