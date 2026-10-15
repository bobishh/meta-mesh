//! Owner attestation preparation; network admission and activation require separate policy.
use crate::{
    DeviceCertificate, WorkspaceAuthority,
    causal_admission::CausalAdmissionInput,
    history_archive_coverage::{HistoryArchiveAggregateReceipt, HistoryArchiveCoverageAuthority},
    history_basis::VerifiedHistoryBasisArchive,
    history_capture::HistoryArchiveCatalogue,
    history_locator::HistoryArchiveLocatorRoot,
};
use serde::{Deserialize, Serialize};

mod confirmation;
mod proposal;
mod receive;
mod peer;

pub use receive::{VerifiedReceivedHistoryBaseline, verify_received_history_baseline,
    verify_received_owner_attested_history_baseline};
pub use peer::verify_received_owner_attested_peer_history_baseline;

pub const HISTORY_BASELINE_DOMAIN: &str = "MESH-HISTORY/1";
pub const HISTORY_BASELINE_CAPABILITY: &str = "workspace-history-baseline@2";
pub const HISTORY_BASELINE_LEGACY_CAPABILITY: &str = "workspace-history-baseline@1";
pub const MAX_HISTORY_BASELINE_BYTES: usize = 64 * 1024;
/// Current compact document content has a separate budget from its bounded signed envelope.
pub const MAX_HISTORY_BASIS_DOCUMENT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_ATTESTED_HISTORY_BASELINE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryBaselineStorage {
    pub authority: HistoryArchiveCoverageAuthority,
    pub key_epoch: u64,
    pub key_digest: String,
    pub data_transition_id: String,
    pub directory_transition_id: String,
    pub data_receipt: HistoryArchiveAggregateReceipt,
    pub directory_receipt: HistoryArchiveAggregateReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryBaselinePayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub baseline_id: String,
    pub history_epoch: u64,
    pub control_epoch: u64,
    pub previous_baseline_id: Option<String>,
    pub transition_id: String,
    pub source_heads: Vec<String>,
    pub admitted_heads: Vec<String>,
    pub admission_policy: String,
    pub admission_revision: String,
    pub authority_revision: String,
    pub person_id: String,
    pub device_id: String,
    pub certificates: Vec<DeviceCertificate>,
    pub state_digest: String,
    pub document_digest: String,
    pub genesis_hash: String,
    pub archive: HistoryArchiveCatalogue,
    pub locator_root: HistoryArchiveLocatorRoot,
    pub storage: HistoryBaselineStorage,
    pub required_reader_capability: String,
    pub required_writer_capability: String,
    /// Present only in the bounded current-owner attestation format. Receiver
    /// must compare its signed genesis against an independently trusted invite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_authority: Option<crate::ScopeAuthoritySnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_control_epoch: Option<u64>,
    /// Fresh owner-attested control state. Original records remain unchanged;
    /// the attestation does not claim to replay their historical admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_control: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryBaselineEnvelope {
    pub payload: HistoryBaselinePayload,
    pub signer_key_id: String,
    pub signature: String,
}

/// Not host-constructible or deserializable. This is not an activated baseline.
pub struct VerifiedHistoryBaselineAttestation {
    envelope: HistoryBaselineEnvelope,
    original_json: Vec<u8>,
    document: Vec<u8>,
    owner: WorkspaceAuthority,
    control: serde_json::Value,
}
impl VerifiedHistoryBaselineAttestation {
    pub fn envelope(&self) -> &HistoryBaselineEnvelope {
        &self.envelope
    }
    pub fn original_json(&self) -> &[u8] {
        &self.original_json
    }
    pub fn document(&self) -> &[u8] {
        &self.document
    }
    pub fn owner(&self) -> &WorkspaceAuthority {
        &self.owner
    }
}

pub enum HistoryBaselineParent<'a> {
    Initial,
    Previous(&'a VerifiedHistoryBaselineAttestation),
}
pub struct HistoryBaselineProposal<'a> {
    basis: &'a VerifiedHistoryBasisArchive<'a>,
    payload: HistoryBaselinePayload,
}
impl<'a> VerifiedHistoryBasisArchive<'a> {
    pub fn propose_baseline(
        &'a self,
        parent: HistoryBaselineParent<'_>,
    ) -> Result<HistoryBaselineProposal<'a>, String> {
        proposal::prepare(self, parent)
    }

    /// Prepare a compact Owner-attested current state. This is an explicit
    /// policy transition: the scope ledger must be trusted by the receiving
    /// invite/bootstrap path and its current controller must be this Owner.
    pub fn propose_owner_attested_baseline(
        &'a self,
        parent: HistoryBaselineParent<'_>,
        scope_authority: &crate::ScopeAuthoritySnapshot,
    ) -> Result<HistoryBaselineProposal<'a>, String> {
        proposal::prepare_owner_attested(self, parent, scope_authority)
    }
}
impl HistoryBaselineProposal<'_> {
    pub fn payload(&self) -> &HistoryBaselinePayload {
        &self.payload
    }
    pub fn confirm(
        &self,
        signed_json: &[u8],
        current: &CausalAdmissionInput,
    ) -> Result<VerifiedHistoryBaselineAttestation, String> {
        confirmation::confirm(self, signed_json, current)
    }
}
