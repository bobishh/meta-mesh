//! Full-history validation is a preparation step, never an ordinary write shortcut.
use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, WorkspaceAuthority,
    causal_admission::{CausalAdmissionInput, CausalAdmissionPlan, evaluate_causal_admission},
    certificate_hash, verify_device_certificate_chain,
};
use automerge::AutoCommit;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryPreparationSigner {
    pub person_id: String,
    pub device_id: String,
    pub certificates: Vec<DeviceCertificate>,
}

/// Not deserializable or host-constructible. This token is not baseline activation
/// authority: archive coverage and the signed transition must still be verified.
pub struct VerifiedHistoryPreparation {
    source: CausalAdmissionInput,
    admission: CausalAdmissionPlan,
    owner: WorkspaceAuthority,
    signer: HistoryPreparationSigner,
    source_heads: Vec<String>,
    authority_digest: String,
    admission_revision: String,
}

impl VerifiedHistoryPreparation {
    pub fn source(&self) -> &CausalAdmissionInput {
        &self.source
    }
    pub fn admission(&self) -> &CausalAdmissionPlan {
        &self.admission
    }
    pub fn owner(&self) -> &WorkspaceAuthority {
        &self.owner
    }
    pub fn signer(&self) -> &HistoryPreparationSigner {
        &self.signer
    }
    pub fn source_heads(&self) -> &[String] {
        &self.source_heads
    }
    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }

    pub fn assert_source_current(&self, source: &CausalAdmissionInput) -> Result<(), String> {
        if source_revision(source)? != self.admission_revision {
            return Err("History preparation source or authority changed".into());
        }
        Ok(())
    }
}

pub fn prepare_workspace_history(
    source: CausalAdmissionInput,
    signer: HistoryPreparationSigner,
) -> Result<VerifiedHistoryPreparation, String> {
    // Retain exact evidence, including pending and rejected originals. The caller
    // cannot replace the derived admission projection with a claimed cache result.
    validate_source_bounds(&source)?;
    let admission = evaluate_causal_admission(source.clone())?;
    finish_preparation(source, signer, admission)
}

/// Prepare a new bounded history capture from a Native-verified compact basis.
/// The basis handle admits the ordinary signed tail; the host cannot turn the
/// compact document into a synthetic genesis or claim its own admission.
pub fn prepare_workspace_history_from_basis(
    source: CausalAdmissionInput,
    signer: HistoryPreparationSigner,
    basis: &crate::history_baseline::VerifiedReceivedHistoryBaseline,
) -> Result<VerifiedHistoryPreparation, String> {
    validate_source_bounds(&source)?;
    let admission = basis.admit_tail(source.clone())?;
    finish_preparation(source, signer, admission)
}

fn finish_preparation(
    source: CausalAdmissionInput,
    signer: HistoryPreparationSigner,
    admission: CausalAdmissionPlan,
) -> Result<VerifiedHistoryPreparation, String> {
    let context = crate::authorization::ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(
        &source.snapshot,
        source.now_ms,
    )?;
    if signer.person_id != context.current_owner.person_id {
        return Err("Only the current workspace owner may prepare a history baseline".into());
    }
    let identity = PublicIdentity {
        person_id: context.current_owner.person_id.clone(),
        public_key: context.current_owner.public_key.clone(),
        display_name: String::new(),
    };
    let signer = verified_signer(signer, &identity)?;
    if context.device_was_revoked(&signer.person_id, &signer.device_id)
        || source
            .snapshot
            .departures
            .iter()
            .any(|evidence| evidence.record.payload.person_id == signer.person_id)
    {
        return Err("History preparation signing device or person is no longer active".into());
    }
    if source.snapshot.genesis_epoch == 0
        || source.snapshot.genesis_epoch > crate::history_archive::MAX_HISTORY_ARCHIVE_INTEGER
    {
        return Err("Invalid history preparation control epoch".into());
    }
    let mut raw = AutoCommit::load(&source.snapshot.document)
        .map_err(|_| "Invalid history source document")?;
    let mut source_heads = raw
        .get_heads()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    source_heads.sort_unstable();
    let authority_digest = authority_digest(&source)?;
    let admission_revision = source_revision(&source)?;
    Ok(VerifiedHistoryPreparation {
        source,
        admission,
        owner: context.current_owner,
        signer,
        source_heads,
        authority_digest,
        admission_revision,
    })
}

fn verified_signer(
    signer: HistoryPreparationSigner,
    identity: &PublicIdentity,
) -> Result<HistoryPreparationSigner, String> {
    verify_device_certificate_chain(
        identity,
        &signer.device_id,
        &signer.certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    let mut by_hash = HashMap::new();
    let mut devices = HashSet::new();
    for cert in &signer.certificates {
        if !devices.insert(&cert.payload.device_id) {
            return Err("Ambiguous history signing certificate evidence".into());
        }
        by_hash.insert(certificate_hash(cert)?, cert);
    }
    let mut current = signer
        .certificates
        .iter()
        .find(|cert| cert.payload.device_id == signer.device_id)
        .ok_or("Missing history signing device certificate")?;
    let mut certificates = Vec::new();
    loop {
        certificates.push(current.clone());
        let Some(issuer) = &current.payload.issuer_certificate_hash else {
            break;
        };
        current = by_hash
            .get(issuer)
            .ok_or("Missing history signing certificate ancestor")?;
    }
    Ok(HistoryPreparationSigner {
        certificates,
        ..signer
    })
}

fn validate_source_bounds(source: &CausalAdmissionInput) -> Result<(), String> {
    let total = source
        .pending_change_bytes
        .iter()
        .try_fold(source.snapshot.document.len(), |sum, bytes| {
            sum.checked_add(bytes.len())
        });
    if total.is_none_or(|size| size > 256 * 1024 * 1024) || source.records.len() > 20_000 {
        return Err("History preparation evidence exceeds size limit".into());
    }
    let proof_size = source.records.iter().try_fold(0usize, |sum, record| {
        sum.checked_add(serde_json::to_vec(record).ok()?.len())
    });
    if proof_size.is_none_or(|size| size > 64 * 1024 * 1024) {
        return Err("History preparation proof evidence exceeds size limit".into());
    }
    Ok(())
}

pub(crate) fn authority_digest(source: &CausalAdmissionInput) -> Result<String, String> {
    authority_digest_snapshot(&source.snapshot)
}

pub(crate) fn authority_digest_snapshot(
    s: &crate::WorkspaceWriteAuthorizationSnapshot,
) -> Result<String, String> {
    let authority = serde_json::json!({
        "workspaceId": s.workspace_id, "genesisOwner": s.genesis_owner, "genesisEpoch": s.genesis_epoch,
        "expectedCurrentOwner": s.expected_current_owner, "ownershipTransfers": s.ownership_transfers,
        "successionClaims": s.succession_claims, "revocations": s.revocations,
        "deviceRevocations": s.device_revocations, "departures": s.departures,
    });
    let bytes = crate::canonicalize_json(&authority)?;
    let mut digest = Sha256::new();
    digest.update(b"MESH-HISTORY/1/authority\0");
    digest.update(bytes.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest.finalize()))
}

// Length-delimited exact bytes avoid expanding an Automerge save into a giant
// JSON array. Receiver wall-clock metadata is deliberately outside this revision.
fn source_revision(source: &CausalAdmissionInput) -> Result<String, String> {
    source_revision_for_policy(source, crate::causal_admission::CAUSAL_ADMISSION_POLICY_ID)
}

fn source_revision_for_policy(
    source: &CausalAdmissionInput,
    policy: &str,
) -> Result<String, String> {
    validate_source_bounds(source)?;
    let mut digest = Sha256::new();
    digest.update(b"MESH-HISTORY/1/preparation-source\0");
    digest.update((policy.len() as u64).to_be_bytes());
    digest.update(policy.as_bytes());
    digest.update(authority_digest(source)?.as_bytes());
    digest.update((source.snapshot.document.len() as u64).to_be_bytes());
    digest.update(&source.snapshot.document);
    digest.update((source.records.len() as u64).to_be_bytes());
    for record in &source.records {
        let value =
            serde_json::to_value(record).map_err(|_| "Invalid history authorization evidence")?;
        let bytes = crate::canonicalize_json(&value)?;
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes.as_bytes());
    }
    digest.update((source.pending_change_bytes.len() as u64).to_be_bytes());
    for bytes in &source.pending_change_bytes {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    Ok(URL_SAFE_NO_PAD.encode(digest.finalize()))
}

#[cfg(test)]
mod tests;
