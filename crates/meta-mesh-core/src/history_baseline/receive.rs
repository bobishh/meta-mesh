use super::*;
use crate::{
    PublicIdentity, SignedEnvelope, WorkspaceAuthority, WorkspaceWriteAuthorizationSnapshot,
    authorization::{ValidatedWorkspaceWriteAuthorizationContext, WorkspaceDepartureEvidence,
        WorkspaceDeviceRevocationEvidence},
    history_archive::history_archive_object_id,
    history_archive_coverage::{HistoryArchiveCoverageSummary, verify_receipt},
    history_archive_crypto::HistoryArchiveEncryptionScope,
    history_capture::{HistoryArchiveEncryptedReader, HistoryArchiveObjectBinding, read_history_archive_control,
        read_history_archive_source_document, resolve_history_archive_ciphertext_id,
        verify_history_control_json, verify_exact_history_json},
    history_preparation::authority_digest_snapshot,
    history_rebase::history_current_state_digest,
};
use automerge::AutoCommit;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Exact control container stored by the original archive. The source document
/// is a separate bounded byte tree and never expands into JSON integer arrays.
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchivedControl {
    workspace_id: String,
    genesis_owner: WorkspaceAuthority,
    genesis_epoch: u64,
    expected_current_owner: WorkspaceAuthority,
    #[serde(default)]
    ownership_transfers: Vec<crate::WorkspaceOwnershipTransfer>,
    #[serde(default)]
    succession_claims: Vec<crate::WorkspaceSuccessionClaim>,
    #[serde(default)]
    revocations: Vec<crate::WorkspaceRevocation>,
    #[serde(default)]
    device_revocations: Vec<WorkspaceDeviceRevocationEvidence>,
    #[serde(default)]
    departures: Vec<WorkspaceDepartureEvidence>,
}

/// Cold-receiver proof of a signed Owner basis plus its archived control and
/// storage evidence. This is a verified candidate for the host's atomic pointer
/// CAS; it does not activate, rewrite or retire local history.
pub struct VerifiedReceivedHistoryBaseline {
    envelope: HistoryBaselineEnvelope,
    original_json: Vec<u8>,
    document: Vec<u8>,
    control_json: Vec<u8>,
    owner: WorkspaceAuthority,
    control: Value,
    encrypted_correspondence: bool,
}

fn validate_basis_document_length(length: usize) -> Result<(), String> {
    if length == 0 || length > MAX_HISTORY_BASIS_DOCUMENT_BYTES { return Err("Compact history document exceeds its content size limit".into()); }
    Ok(())
}

/// Verify the bounded v2 bootstrap path. `trusted_scope_creator` must come
/// from an already admitted invitation or previously verified scope state; a
/// self-signed genesis copied from the network is not a trust anchor.
pub fn verify_received_owner_attested_history_baseline(
    signed_json: &[u8],
    baseline_document: &[u8],
    scope: &HistoryArchiveEncryptionScope,
    pinned_storage: &HistoryArchiveCoverageAuthority,
    trusted_scope_authority: &crate::ScopeAuthoritySnapshot,
    previous: Option<&VerifiedReceivedHistoryBaseline>,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<VerifiedReceivedHistoryBaseline, String> {
    let mut received = verify_owner_attested_core(signed_json, baseline_document, trusted_scope_authority, previous)?;
    let payload = &received.envelope.payload;
    if scope.key_epoch == 0 || payload.storage.key_epoch != scope.key_epoch ||
        payload.storage.key_digest != history_archive_object_id(&scope.key) ||
        &payload.storage.authority != pinned_storage || pinned_storage.scope_id != scope.scope_id {
        return Err("Received baseline storage scope is not pinned".into());
    }
    verify_coverage(payload, scope, pinned_storage, reader)?;
    reader.ensure_current()?;
    received.encrypted_correspondence = true;
    Ok(received)
}

/// One authority path for encrypted storage and authorized peer plaintext relay.
/// Storage correspondence is established separately by the selected read adapter.
pub(super) fn verify_owner_attested_core(
    signed_json: &[u8], baseline_document: &[u8],
    trusted_scope_authority: &crate::ScopeAuthoritySnapshot,
    previous: Option<&VerifiedReceivedHistoryBaseline>,
) -> Result<VerifiedReceivedHistoryBaseline, String> {
    validate_basis_document_length(baseline_document.len())?;
    if signed_json.len() > MAX_ATTESTED_HISTORY_BASELINE_BYTES {
        return Err("Owner-attested baseline exceeds size limit".into());
    }
    let envelope: HistoryBaselineEnvelope = serde_json::from_slice(signed_json)
        .map_err(|_| "Invalid received owner-attested baseline schema")?;
    verify_exact_history_json(
        signed_json,
        &serde_json::to_value(&envelope).map_err(|_| "Invalid received baseline encoding")?,
    )?;
    let payload = &envelope.payload;
    let scope_snapshot = payload.scope_authority.as_ref()
        .ok_or("Owner-attested baseline lacks signed scope authority")?;
    let current_control = payload.current_control.as_ref()
        .ok_or("Owner-attested baseline lacks current control checkpoint")?;
    let claimed_scope_epoch = payload.scope_control_epoch
        .ok_or("Owner-attested baseline lacks scope control epoch")?;
    if payload.kind != "workspace-history-baseline"
        || payload.version != 2
        || payload.required_reader_capability != HISTORY_BASELINE_CAPABILITY
        || payload.required_writer_capability != HISTORY_BASELINE_CAPABILITY
        || payload.workspace_id.is_empty()
        || payload.history_epoch == 0
        || payload.control_epoch == 0
        || payload.storage.key_epoch == 0
        || !canonical_digest(&payload.storage.key_digest)
        || payload.archive.kind != "workspace-history-catalogue" || payload.archive.version != 1
        || payload.archive.admission_revision != payload.admission_revision
        || payload.archive.authority_revision != payload.authority_revision
        || payload.archive.context.workspace_id != payload.workspace_id
        || payload.archive.context.history_epoch != payload.history_epoch
        || payload.archive.context.index_id != "catalogue"
        || payload.locator_root.context.workspace_id != payload.workspace_id
        || payload.locator_root.context.history_epoch != payload.history_epoch
        || payload.locator_root.context.index_id != "archive-locators"
        || payload.locator_root.kind != "workspace-history-locator-root" || payload.locator_root.version != 1
        || payload.storage.data_transition_id == payload.storage.directory_transition_id
        || payload.archive.change_count > 1_048_576
        || payload.archive.change_count != payload.archive.admitted_count
            .checked_add(payload.archive.pending_count)
            .and_then(|count| count.checked_add(payload.archive.quarantined_count))
            .ok_or("Archive classification count overflow")?
        || !matches!(payload.admission_policy.as_str(),
            "mesh-causal-admission@1" | "mesh-causal-admission@2" | "mesh-causal-admission@3")
    {
        return Err("Invalid owner-attested baseline context or required policy floor".into());
    }
    let mut id_input = serde_json::to_value(payload).map_err(|_| "Invalid baseline payload")?;
    id_input.as_object_mut().ok_or("Invalid baseline payload")?.remove("baselineId");
    if payload.baseline_id != history_archive_object_id(crate::canonicalize_json(&id_input)?.as_bytes()) {
        return Err("Owner-attested baseline identifier does not match its payload".into());
    }
    for hashes in [&payload.source_heads, &payload.admitted_heads] {
        if hashes.len() > 256 || hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("Owner-attested baseline frontier is not canonical".into());
        }
    }

    // The embedded ledger is signed by this baseline. Its root must also match
    // the independently trusted invite anchor, and its validated controller
    // must be the current baseline signer.
    let validated_scope = crate::validate_scope_authority(scope_snapshot)?;
    let genesis_creator = &scope_snapshot.genesis.payload.creator;
    let trusted_creator = &trusted_scope_authority.genesis.payload.creator;
    let merged_scope = crate::merge_scope_authority_snapshots_at(
        Some(trusted_scope_authority), scope_snapshot, 0,
    )?;
    if validated_scope.scope_id != payload.workspace_id
        || validated_scope.control_epoch != claimed_scope_epoch
        || trusted_scope_authority.genesis.payload.scope_id != payload.workspace_id
        || genesis_creator.person_id != trusted_creator.person_id
        || genesis_creator.public_key != trusted_creator.public_key
        || merged_scope != *scope_snapshot
        || validated_scope.controller.person_id != payload.person_id
    {
        return Err("Baseline Owner is not the trusted current scope controller".into());
    }
    let control_bytes = crate::canonicalize_json(current_control)?.into_bytes();
    if control_bytes.len() > 64 * 1024 {
        return Err("Owner-attested control checkpoint exceeds size limit".into());
    }
    let control: ArchivedControl = serde_json::from_slice(&control_bytes)
        .map_err(|_| "Invalid owner-attested current control checkpoint")?;
    if serde_json::to_value(&control).map_err(|_| "Invalid current control checkpoint")? != *current_control {
        return Err("Owner-attested control checkpoint is not in its exact schema".into());
    }
    let checkpoint_epoch = control.ownership_transfers.iter().map(|item| item.payload.epoch)
        .chain(control.succession_claims.iter().map(|item| item.payload.epoch))
        .chain(std::iter::once(control.genesis_epoch)).max().unwrap_or(0);
    let mut authority_hash = Sha256::new();
    authority_hash.update(b"MESH-HISTORY/1/authority\0");
    authority_hash.update(crate::canonicalize_json(current_control)?.as_bytes());
    if control.workspace_id != payload.workspace_id
        || control.expected_current_owner.person_id != validated_scope.controller.person_id
        || control.expected_current_owner.public_key != validated_scope.controller.public_key
        || control.expected_current_owner.certificates != validated_scope.controller.certificates
        || checkpoint_epoch != payload.control_epoch
        || URL_SAFE_NO_PAD.encode(authority_hash.finalize()) != payload.authority_revision
    {
        return Err("Owner-attested current control checkpoint does not match its signed authority".into());
    }
    if let Some(previous) = previous {
        let old = &previous.envelope.payload;
        if payload.previous_baseline_id.as_deref() != Some(old.baseline_id.as_str())
            || payload.history_epoch != old.history_epoch.checked_add(1).ok_or("History epoch overflow")?
            || old.scope_authority.as_ref().is_some_and(|scope| scope.genesis != scope_snapshot.genesis)
            || !super::proposal::preserves_control(&previous.control, current_control)
        {
            return Err("Owner-attested baseline does not extend the verified current state".into());
        }
    }

    let owner = WorkspaceAuthority {
        person_id: validated_scope.controller.person_id.clone(),
        public_key: validated_scope.controller.public_key.clone(),
        certificates: validated_scope.controller.certificates.clone(),
    };
    let identity = PublicIdentity { person_id: owner.person_id.clone(),
        public_key: owner.public_key.clone(), display_name: String::new() };
    crate::verify_device_signed_envelope(&identity, &payload.device_id, &payload.certificates,
        &SignedEnvelope { payload: payload.clone(), signer_key_id: envelope.signer_key_id.clone(),
            signature: envelope.signature.clone() }, HISTORY_BASELINE_DOMAIN)?;
    verify_basis_document(payload, baseline_document)?;
    let saved_control = current_control.clone();
    Ok(VerifiedReceivedHistoryBaseline { envelope, original_json: signed_json.to_vec(),
        document: baseline_document.to_vec(), control_json: control_bytes, owner, control: saved_control, encrypted_correspondence: false })
}


impl VerifiedReceivedHistoryBaseline {
    pub fn envelope(&self) -> &HistoryBaselineEnvelope { &self.envelope }
    pub fn original_json(&self) -> &[u8] { &self.original_json }
    pub fn document(&self) -> &[u8] { &self.document }
    pub fn control_json(&self) -> &[u8] { &self.control_json }
    pub fn owner(&self) -> &WorkspaceAuthority { &self.owner }
    pub fn storage_verification(&self) -> &'static str {
        if self.encrypted_correspondence { "encrypted-correspondence" } else { "public-receipts-only" }
    }

    /// Admit a bounded active tail against this opaque, Native-verified basis.
    /// The compact basis root is trusted only because this handle verified its
    /// Owner attestation and independent scope anchor; every subsequent change
    /// still needs its ordinary signed authorization and causal dependencies.
    pub fn admit_tail(
        &self,
        input: crate::causal_admission::CausalAdmissionInput,
    ) -> Result<crate::causal_admission::CausalAdmissionPlan, String> {
        let payload = &self.envelope.payload;
        if input.snapshot.workspace_id != payload.workspace_id {
            return Err("History tail belongs to another workspace".into());
        }
        let current_control = crate::history_capture::history_control_value(&input.snapshot)?;
        if !super::proposal::preserves_control(&self.control, &current_control) {
            return Err("History tail authority does not extend its verified basis".into());
        }
        let mut compact = automerge::AutoCommit::load(&self.document)
            .map_err(|_| "Verified history basis is corrupt")?;
        let compact_changes = compact.get_changes(&[]);
        if compact_changes.len() != 1 || compact_changes[0].hash().to_string() != payload.genesis_hash {
            return Err("Verified compact history basis must contain one root change".into());
        }
        let basis_hash = compact_changes[0].hash().to_string();
        let mut active = automerge::AutoCommit::load(&input.snapshot.document)
            .map_err(|_| "History tail document is invalid")?;
        let active_changes = active.get_changes(&[]);
        if !active_changes.iter().any(|change| change.hash().to_string() == basis_hash)
            || active_changes.iter().filter(|change| change.deps().is_empty()).count() != 1
        {
            return Err("History tail does not descend from the verified compact basis".into());
        }
        crate::causal_admission::evaluate_causal_admission_from_history_basis(input, &basis_hash)
    }

    /// Historical lookup follows only the exact signed parent and preserved authority ledger.
    pub fn verify_previous_baseline(&self, previous: &VerifiedReceivedHistoryBaseline) -> Result<(), String> {
        let payload = &self.envelope.payload;
        let old = &previous.envelope.payload;
        if payload.workspace_id != old.workspace_id || payload.previous_baseline_id.as_deref() != Some(old.baseline_id.as_str()) ||
            payload.history_epoch != old.history_epoch.checked_add(1).ok_or("History epoch overflow")? ||
            old.scope_authority.as_ref().is_some_and(|scope| Some(&scope.genesis) != payload.scope_authority.as_ref().map(|value| &value.genesis)) ||
            !super::proposal::preserves_control(&previous.control, &self.control) {
            return Err("Historical baseline is not the exact verified predecessor".into());
        }
        Ok(())
    }

    /// A received baseline becomes a proposal parent only after this Native
    /// verifier has authenticated its exact owner signature and scope anchor.
    pub fn proposal_parent(&self) -> super::VerifiedHistoryBaselineAttestation {
        super::VerifiedHistoryBaselineAttestation { envelope: self.envelope.clone(),
            original_json: self.original_json.clone(), document: self.document.clone(),
            owner: self.owner.clone(), control: self.control.clone() }
    }
}

/// Authenticate a baseline using the current Owner ledger recovered through its
/// signed archive roots. Historical author classifications are not replayed on
/// this path; they remain original archive observations for separate inspection.
/// The caller must CAS the returned exact parent and preserve its prior bytes.
pub fn verify_received_history_baseline(
    signed_json: &[u8],
    baseline_document: &[u8],
    scope: &HistoryArchiveEncryptionScope,
    pinned_storage: &HistoryArchiveCoverageAuthority,
    previous: Option<&VerifiedReceivedHistoryBaseline>,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<VerifiedReceivedHistoryBaseline, String> {
    validate_basis_document_length(baseline_document.len())?;
    if signed_json.len() > MAX_HISTORY_BASELINE_BYTES {
        return Err("History baseline envelope exceeds size limit".into());
    }
    let envelope: HistoryBaselineEnvelope = serde_json::from_slice(signed_json)
        .map_err(|_| "Invalid received history baseline schema")?;
    verify_exact_history_json(
        signed_json,
        &serde_json::to_value(&envelope).map_err(|_| "Invalid received history baseline encoding")?,
    )?;
    let payload = &envelope.payload;
    validate_payload_basics(payload, scope, pinned_storage)?;

    // The archive roots are untrusted until the recovered control chain verifies
    // the signer. Local scope/key bounds and guarded reads constrain this lookup.
    let control_bytes = read_history_archive_control(scope, &payload.archive, &payload.locator_root, reader)?;
    let source_document = read_history_archive_source_document(scope, &payload.archive, &payload.locator_root, reader)?;
    let control: ArchivedControl = serde_json::from_slice(&control_bytes)
        .map_err(|_| "Invalid archived workspace control schema")?;
    let snapshot = WorkspaceWriteAuthorizationSnapshot {
        workspace_id: control.workspace_id,
        genesis_owner: control.genesis_owner,
        genesis_epoch: control.genesis_epoch,
        expected_current_owner: control.expected_current_owner,
        document: source_document.clone(),
        ownership_transfers: control.ownership_transfers,
        succession_claims: control.succession_claims,
        revocations: control.revocations,
        device_revocations: control.device_revocations,
        departures: control.departures,
    };
    verify_history_control_json(&control_bytes, &snapshot)?;
    let control_value = crate::history_capture::history_control_value(&snapshot)?;
    verify_parent(payload, previous, &control_value, &source_document)?;

    let authority = HistoryArchiveCoverageAuthority {
        service_public_key: pinned_storage.service_public_key.clone(),
        scope_id: pinned_storage.scope_id.clone(),
        policy_revision: pinned_storage.policy_revision,
    };
    let authority_revision = authority_digest_snapshot(&snapshot)?;
    let context = ValidatedWorkspaceWriteAuthorizationContext::from_snapshot_causal(&snapshot)?;
    let owner = context.current_owner.clone();
    let control_epoch = control_epoch(&snapshot);
    if snapshot.workspace_id != payload.workspace_id
        || authority != payload.storage.authority
        || authority_revision != payload.authority_revision
        || control_epoch != payload.control_epoch
        || owner.person_id != payload.person_id
        || context.person_was_departed(&payload.person_id)
        || context.device_was_revoked(&payload.person_id, &payload.device_id)
    {
        return Err("Received baseline differs from current archived Owner authority".into());
    }
    let identity = PublicIdentity {
        person_id: owner.person_id.clone(),
        public_key: owner.public_key.clone(),
        display_name: String::new(),
    };
    crate::verify_device_signed_envelope(
        &identity,
        &payload.device_id,
        &payload.certificates,
        &SignedEnvelope {
            payload: payload.clone(),
            signer_key_id: envelope.signer_key_id.clone(),
            signature: envelope.signature.clone(),
        },
        HISTORY_BASELINE_DOMAIN,
    )?;

    verify_source_heads(payload, &source_document)?;
    verify_basis_document(payload, baseline_document)?;
    verify_coverage(payload, scope, pinned_storage, reader)?;
    reader.ensure_current()?;
    Ok(VerifiedReceivedHistoryBaseline {
        envelope,
        original_json: signed_json.to_vec(),
        document: baseline_document.to_vec(),
        control_json: control_bytes,
        owner,
        control: control_value,
        encrypted_correspondence: true,
    })
}

fn validate_payload_basics(
    payload: &HistoryBaselinePayload,
    scope: &HistoryArchiveEncryptionScope,
    pinned_storage: &HistoryArchiveCoverageAuthority,
) -> Result<(), String> {
    if payload.kind != "workspace-history-baseline"
        || payload.version != 1
        || payload.workspace_id.is_empty()
        || payload.history_epoch == 0
        || payload.control_epoch == 0
        || payload.required_reader_capability != HISTORY_BASELINE_LEGACY_CAPABILITY
        || payload.required_writer_capability != HISTORY_BASELINE_LEGACY_CAPABILITY
        || payload.scope_authority.is_some() || payload.scope_control_epoch.is_some()
        || payload.current_control.is_some()
        || payload.storage.key_epoch != scope.key_epoch
        || payload.storage.key_digest != history_archive_object_id(&scope.key)
        || &payload.storage.authority != pinned_storage
        || payload.archive.kind != "workspace-history-catalogue"
        || payload.archive.version != 1
        || payload.archive.context.workspace_id != payload.workspace_id
        || payload.archive.context.history_epoch != payload.history_epoch
        || payload.archive.context.index_id != "catalogue"
        || payload.archive.admission_revision != payload.admission_revision
        || payload.archive.authority_revision != payload.authority_revision
        || payload.archive.change_count > 1_048_576
        || payload.archive.change_count
            != payload.archive.admitted_count.checked_add(payload.archive.pending_count)
                .and_then(|count| count.checked_add(payload.archive.quarantined_count))
                .ok_or("Archive classification count overflow")?
        || !matches!(payload.admission_policy.as_str(),
            "mesh-causal-admission@1" | "mesh-causal-admission@2" | "mesh-causal-admission@3")
        || payload.locator_root.kind != "workspace-history-locator-root"
        || payload.locator_root.version != 1
        || payload.locator_root.context.workspace_id != payload.workspace_id
        || payload.locator_root.context.history_epoch != payload.history_epoch
        || payload.locator_root.context.index_id != "archive-locators"
        || payload.storage.data_transition_id == payload.storage.directory_transition_id
    {
        return Err("Invalid received history baseline context or capability".into());
    }
    let mut id_input = serde_json::to_value(payload).map_err(|_| "Invalid baseline payload")?;
    id_input.as_object_mut().ok_or("Invalid baseline payload")?.remove("baselineId");
    let expected_id = history_archive_object_id(crate::canonicalize_json(&id_input)?.as_bytes());
    if payload.baseline_id != expected_id {
        return Err("Received baseline identifier does not match its payload".into());
    }
    for hashes in [&payload.source_heads, &payload.admitted_heads] {
        if hashes.len() > 256 || hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("Received baseline frontier is not canonical".into());
        }
    }
    if scope.key_epoch == 0 || pinned_storage.scope_id != scope.scope_id {
        return Err("Received baseline storage scope is not pinned".into());
    }
    Ok(())
}

fn verify_parent(
    payload: &HistoryBaselinePayload,
    previous: Option<&VerifiedReceivedHistoryBaseline>,
    current_control: &Value,
    source_document: &[u8],
) -> Result<(), String> {
    match previous {
        None if payload.history_epoch == 1 && payload.previous_baseline_id.is_none() => Ok(()),
        None => Err("Received baseline parent is not locally verified".into()),
        Some(previous) => {
            let parent = &previous.envelope.payload;
            if payload.workspace_id != parent.workspace_id
                || payload.history_epoch != parent.history_epoch.checked_add(1).ok_or("History epoch overflow")?
                || payload.previous_baseline_id.as_deref() != Some(parent.baseline_id.as_str())
                || payload.control_epoch < parent.control_epoch
                || !super::proposal::preserves_control(&previous.control, current_control)
            {
                return Err("Received baseline does not extend verified local parent".into());
            }
            let mut source = AutoCommit::load(source_document)
                .map_err(|_| "Invalid archived source document")?;
            if !source.get_changes(&[]).iter().any(|change| change.hash().to_string() == parent.genesis_hash) {
                return Err("Received baseline omits the previous verified basis".into());
            }
            Ok(())
        }
    }
}

fn verify_source_heads(payload: &HistoryBaselinePayload, source_document: &[u8]) -> Result<(), String> {
    let mut source = AutoCommit::load(source_document).map_err(|_| "Invalid archived source document")?;
    let mut heads = source.get_heads().iter().map(ToString::to_string).collect::<Vec<_>>();
    heads.sort_unstable();
    if heads != payload.source_heads {
        return Err("Received baseline source frontier differs from archived document".into());
    }
    Ok(())
}

fn verify_basis_document(payload: &HistoryBaselinePayload, document: &[u8]) -> Result<(), String> {
    if history_archive_object_id(document) != payload.document_digest
        || history_current_state_digest(document)? != payload.state_digest
    {
        return Err("Received baseline document digest or state differs".into());
    }
    let mut basis = AutoCommit::load(document).map_err(|_| "Invalid received baseline document")?;
    let changes = basis.get_changes(&[]);
    if changes.len() != 1 || changes[0].hash().to_string() != payload.genesis_hash
        || basis.get_heads().len() != 1
        || basis.get_heads()[0].to_string() != payload.genesis_hash
    {
        return Err("Received baseline is not a single admitted basis change".into());
    }
    let message: Value = serde_json::from_str(changes[0].message().ok_or("Missing baseline genesis metadata")?)
        .map_err(|_| "Invalid baseline genesis metadata")?;
    if message["kind"] != "workspace-history-basis"
        || message["version"] != 1
        || message["workspaceId"] != payload.workspace_id
        || message["historyEpoch"] != payload.history_epoch
        || message["transitionId"] != payload.transition_id
        || message["admissionRevision"] != payload.admission_revision
        || message["authorityRevision"] != payload.authority_revision
        || message["personId"] != payload.person_id
        || message["deviceId"] != payload.device_id
        || message["stateDigest"] != payload.state_digest
    {
        return Err("Received baseline genesis metadata differs from its attestation".into());
    }
    Ok(())
}

fn verify_coverage(
    payload: &HistoryBaselinePayload,
    scope: &HistoryArchiveEncryptionScope,
    authority: &HistoryArchiveCoverageAuthority,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<(), String> {
    let root_binding = HistoryArchiveObjectBinding {
        context: payload.archive.context.clone(),
        object_kind: "page".into(),
        part_index: 0,
        part_count: 1,
    };
    let catalogue_ciphertext = resolve_history_archive_ciphertext_id(
        scope,
        &payload.locator_root,
        &root_binding,
        &payload.archive.root.object_id,
        reader,
    )?;
    verify_received_receipt(
        &payload.storage.data_receipt,
        authority,
        &catalogue_ciphertext,
        &payload.storage.data_transition_id,
    )?;
    verify_received_receipt(
        &payload.storage.directory_receipt,
        authority,
        &payload.locator_root.root.ciphertext_id,
        &payload.storage.directory_transition_id,
    )?;
    Ok(())
}

pub(super) fn verify_received_receipt(
    receipt: &HistoryArchiveAggregateReceipt,
    authority: &HistoryArchiveCoverageAuthority,
    expected_root: &str,
    transition_id: &str,
) -> Result<(), String> {
    let p = &receipt.payload;
    if p.height == 0 || p.height >= 32 || p.object_count == 0 || p.object_count > 1_048_576
        || p.first_object_id.as_str() > p.last_object_id.as_str() || !p.root_covered
        || !canonical_digest(&p.first_object_id) || !canonical_digest(&p.last_object_id)
        || !canonical_digest(&p.set_digest)
    {
        return Err("Invalid received archive coverage summary".into());
    }
    let summary = HistoryArchiveCoverageSummary {
        height: p.height,
        object_count: p.object_count,
        first_object_id: p.first_object_id.clone(),
        last_object_id: p.last_object_id.clone(),
        set_digest: p.set_digest.clone(),
        root_covered: p.root_covered,
    };
    verify_receipt(
        &serde_json::to_vec(receipt).map_err(|_| "Invalid archive receipt encoding")?,
        authority,
        expected_root,
        transition_id,
        &summary,
    )?;
    Ok(())
}

fn control_epoch(snapshot: &WorkspaceWriteAuthorizationSnapshot) -> u64 {
    snapshot.ownership_transfers.iter().map(|item| item.payload.epoch)
        .chain(snapshot.succession_claims.iter().map(|item| item.payload.epoch))
        .chain(std::iter::once(snapshot.genesis_epoch)).max().unwrap_or(0)
}

fn canonical_digest(value: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(value) else { return false; };
    bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value
}

#[cfg(test)]
mod document_budget_tests {
    use super::*;
    #[test]
    fn signature_and_current_document_limits_are_distinct_without_allocating_large_buffers() {
        assert!(validate_basis_document_length(MAX_HISTORY_BASELINE_BYTES + 1).is_ok());
        assert!(validate_basis_document_length(MAX_HISTORY_BASIS_DOCUMENT_BYTES).is_ok());
        assert!(validate_basis_document_length(MAX_HISTORY_BASIS_DOCUMENT_BYTES + 1).is_err());
        assert!(validate_basis_document_length(0).is_err());
    }
}
