//! Original evidence capture consumes Native preparation; it never activates a baseline.
use crate::{WorkspaceWriteAuthorizationSnapshot, history_preparation::VerifiedHistoryPreparation};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

mod catalogue;
mod archived_snapshot;
mod entity_history;
mod original_json;
pub(crate) mod source;
mod storage;
mod writer;

pub use archived_snapshot::verify_archived_snapshot;
pub use entity_history::{VerifiedArchivedEntityVersion, read_archived_entity_version, read_archived_peer_entity_version};
pub use source::HistoryArchivePlaintextReader;
pub use catalogue::{HistoryArchiveCatalogue, HistoryCapturedChange, HistoryCapturedChangeMetadata, HistoryCapturedEntityIndex, history_entity_index_id};
pub use storage::{
    HistoryArchiveEncryptedReader, VerifiedHistoryArchiveStorage,
    read_history_archive_control, read_history_archive_source_document,
    resolve_history_archive_ciphertext_id,
};
pub use writer::{HistoryArchiveBytesReference, HistoryArchiveObjectBinding, HistoryArchiveWriter};

pub struct HistoryOriginalEvidence {
    /// Original control JSON, with the snapshot's `document` field omitted.
    pub control_json: Vec<u8>,
    /// One original incoming authorization JSON per preparation input record, in order.
    pub authorization_json: Vec<Vec<u8>>,
}

pub struct VerifiedHistoryArchiveCapture {
    preparation: VerifiedHistoryPreparation,
    history_epoch: u64,
    originals: HistoryOriginalEvidence,
    capture_revision: String,
}

impl VerifiedHistoryArchiveCapture {
    pub fn preparation(&self) -> &VerifiedHistoryPreparation {
        &self.preparation
    }
    pub fn history_epoch(&self) -> u64 {
        self.history_epoch
    }
    pub fn original_control(&self) -> &[u8] {
        &self.originals.control_json
    }
    pub fn original_authorizations(&self) -> &[Vec<u8>] {
        &self.originals.authorization_json
    }
    pub fn capture_revision(&self) -> &str {
        &self.capture_revision
    }
}

pub fn capture_workspace_history(
    preparation: VerifiedHistoryPreparation,
    history_epoch: u64,
    originals: HistoryOriginalEvidence,
) -> Result<VerifiedHistoryArchiveCapture, String> {
    if history_epoch == 0 || history_epoch > crate::history_archive::MAX_HISTORY_ARCHIVE_INTEGER {
        return Err("Invalid history capture epoch".into());
    }
    if originals.authorization_json.len() != preparation.source().records.len() {
        return Err("Original history authorization count differs from Native preparation".into());
    }
    let size = originals
        .authorization_json
        .iter()
        .try_fold(originals.control_json.len(), |total, bytes| {
            total.checked_add(bytes.len())
        });
    if size.is_none_or(|size| size > 128 * 1024 * 1024)
        || originals.control_json.len() > 64 * 1024 * 1024
    {
        return Err("Original history evidence exceeds size limit".into());
    }
    original_json::verify(
        &originals.control_json,
        &history_control_value(&preparation.source().snapshot)?,
        original_json::Defaults::Control,
    )?;
    for (bytes, record) in originals
        .authorization_json
        .iter()
        .zip(&preparation.source().records)
    {
        let value =
            serde_json::to_value(record).map_err(|_| "Invalid history authorization encoding")?;
        original_json::verify(bytes, &value, original_json::Defaults::Authorization)?;
    }
    let mut digest = Sha256::new();
    digest.update(b"MESH-HISTORY/1/original-capture\0");
    digest.update(preparation.admission_revision().as_bytes());
    digest.update(history_epoch.to_be_bytes());
    digest.update((originals.control_json.len() as u64).to_be_bytes());
    digest.update(&originals.control_json);
    digest.update((originals.authorization_json.len() as u64).to_be_bytes());
    for bytes in &originals.authorization_json {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    Ok(VerifiedHistoryArchiveCapture {
        preparation,
        history_epoch,
        originals,
        capture_revision: URL_SAFE_NO_PAD.encode(digest.finalize()),
    })
}

/// Helper for callers constructing the original control container. Individual
/// original envelopes belong in that container without reserialization.
pub fn history_control_value(
    snapshot: &WorkspaceWriteAuthorizationSnapshot,
) -> Result<serde_json::Value, String> {
    // Do not expand a potentially 256-MiB Automerge save into a JSON number array.
    Ok(serde_json::json!({
        "workspaceId": snapshot.workspace_id, "genesisOwner": snapshot.genesis_owner,
        "genesisEpoch": snapshot.genesis_epoch, "expectedCurrentOwner": snapshot.expected_current_owner,
        "ownershipTransfers": snapshot.ownership_transfers, "successionClaims": snapshot.succession_claims,
        "revocations": snapshot.revocations, "deviceRevocations": snapshot.device_revocations,
        "departures": snapshot.departures,
    }))
}

pub(crate) fn verify_exact_history_json(
    bytes: &[u8],
    expected: &serde_json::Value,
) -> Result<(), String> {
    original_json::verify(bytes, expected, original_json::Defaults::None)
}

pub(crate) fn verify_history_control_json(
    bytes: &[u8],
    snapshot: &WorkspaceWriteAuthorizationSnapshot,
) -> Result<(), String> {
    original_json::verify(
        bytes,
        &history_control_value(snapshot)?,
        original_json::Defaults::Control,
    )
}
