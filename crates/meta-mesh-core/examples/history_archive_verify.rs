//! Non-browser integration adapter; output is not baseline activation authority.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meta_mesh_core::{
    WorkspaceWriteAuthorizationSnapshot,
    causal_admission::CausalAdmissionInput,
    history_archive_coverage::{HistoryArchiveCoverageAuthority, HistoryArchiveCoverageProof},
    history_archive_crypto::{EncryptedHistoryArchiveObject, HistoryArchiveEncryptionScope},
    history_baseline::HistoryBaselineParent,
    history_capture::{
        HistoryArchiveEncryptedReader, HistoryOriginalEvidence, capture_workspace_history,
    },
    history_locator::HistoryArchiveLocatorRoot,
    history_preparation::{HistoryPreparationSigner, prepare_workspace_history},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read};

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    originals: Originals,
    history_epoch: u64,
    signer: Signer,
    scope: Scope,
    locator_root: HistoryArchiveLocatorRoot,
    authority: HistoryArchiveCoverageAuthority,
    data_transition_id: String,
    directory_transition_id: String,
    data_receipt: String,
    directory_receipt: String,
    objects: Vec<ObjectEntry>,
    #[serde(default)]
    propose_initial_baseline: bool,
    #[serde(default)]
    scope_authority: Option<meta_mesh_core::ScopeAuthoritySnapshot>,
    #[serde(default)]
    signed_baseline: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Originals {
    control: String,
    document: String,
    authorizations: Vec<String>,
    pending: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Signer {
    person_id: String,
    device_id: String,
    certificates: Vec<meta_mesh_core::DeviceCertificate>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    scope_id: String,
    key_epoch: u64,
    key: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObjectEntry {
    ciphertext_id: String,
    object: EncryptedHistoryArchiveObject,
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "Invalid verification input")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("Invalid verification input".into());
    }
    Ok(bytes)
}

#[derive(Default)]
struct MapReader(BTreeMap<String, EncryptedHistoryArchiveObject>);
impl HistoryArchiveEncryptedReader for MapReader {
    fn ensure_current(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn download(&mut self, ciphertext_id: &str) -> Result<EncryptedHistoryArchiveObject, String> {
        self.0
            .get(ciphertext_id)
            .cloned()
            .ok_or_else(|| "Missing archive ciphertext".into())
    }
}

fn verify(input: Input) -> Result<Value, String> {
    if input.signed_baseline.is_some() && !input.propose_initial_baseline {
        return Err("Baseline signature requires an explicit proposal request".into());
    }
    let control_json = decode(&input.originals.control)?;
    let mut control: Value =
        serde_json::from_slice(&control_json).map_err(|_| "Invalid verification input")?;
    let document = decode(&input.originals.document)?;
    if let Some(fields) = control.as_object_mut() {
        if fields.contains_key("document") {
            return Err("Invalid verification input".into());
        }
        fields.insert("document".into(), json!(document));
    } else {
        return Err("Invalid verification input".into());
    }
    let snapshot: WorkspaceWriteAuthorizationSnapshot =
        serde_json::from_value(control).map_err(|_| "Invalid verification input")?;
    let authorization_json = input
        .originals
        .authorizations
        .iter()
        .map(|value| decode(value))
        .collect::<Result<Vec<_>, _>>()?;
    let records = authorization_json
        .iter()
        .map(|bytes| {
            serde_json::from_slice(bytes).map_err(|_| "Invalid verification input".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let pending_change_bytes = input
        .originals
        .pending
        .iter()
        .map(|value| decode(value))
        .collect::<Result<Vec<_>, _>>()?;
    let source = CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes,
        now_ms: 0,
    };
    let prepared = prepare_workspace_history(
        source,
        HistoryPreparationSigner {
            person_id: input.signer.person_id,
            device_id: input.signer.device_id,
            certificates: input.signer.certificates,
        },
    )?;
    let rebase = prepared.rebase(input.history_epoch, &input.data_transition_id)?;
    let capture = capture_workspace_history(
        prepared,
        input.history_epoch,
        HistoryOriginalEvidence {
            control_json,
            authorization_json,
        },
    )?;
    let key = decode(&input.scope.key)?;
    let key: [u8; 32] = key.try_into().map_err(|_| "Invalid verification input")?;
    let scope = HistoryArchiveEncryptionScope {
        scope_id: input.scope.scope_id,
        key_epoch: input.scope.key_epoch,
        key,
    };
    let mut reader = MapReader::default();
    for entry in input.objects {
        if reader.0.insert(entry.ciphertext_id, entry.object).is_some() {
            return Err("Invalid verification input".into());
        }
    }
    let storage = capture.verify_storage_directory(&scope, &input.locator_root, &mut reader)?;
    let coverage = storage.verify_coverage(
        &input.authority,
        HistoryArchiveCoverageProof {
            data_transition_id: &input.data_transition_id,
            directory_transition_id: &input.directory_transition_id,
            data_receipt: input.data_receipt.as_bytes(),
            directory_receipt: input.directory_receipt.as_bytes(),
        },
    )?;
    let joined = capture.bind_rebase(&rebase, &coverage)?;
    let basis = joined.rebase();
    let mut document = automerge::AutoCommit::load(basis.document())
        .map_err(|_| "Invalid verified Native basis")?;
    let mut output = json!({
        "kind": "verified-history-archive-coverage",
        "version": 1,
        "catalogueRoot": coverage.catalogue().root,
        "locatorRoot": coverage.locator_root(),
        "captureRevision": coverage.catalogue().capture_revision,
        "authorityRevision": coverage.catalogue().authority_revision,
        "dataObjectCount": coverage.data_receipt().payload.object_count,
        "directoryObjectCount": coverage.directory_receipt().payload.object_count,
        "basis": {
            "historyEpoch": basis.history_epoch(), "transitionId": basis.transition_id(),
            "stateDigest": basis.state_digest(), "documentDigest": basis.document_digest(),
            "genesisHash": basis.genesis_hash(), "nodeCount": basis.node_count(),
            "changeCount": document.get_changes(&[]).len(), "byteLength": basis.document().len(),
        },
    });
    if input.propose_initial_baseline {
        let scope_authority = input
            .scope_authority
            .as_ref()
            .ok_or("Owner proposal requires signed scope authority")?;
        let proposal = joined
            .propose_owner_attested_baseline(HistoryBaselineParent::Initial, scope_authority)?;
        let attestation = input
            .signed_baseline
            .as_ref()
            .map(|bytes| proposal.confirm(bytes.as_bytes(), capture.preparation().source()))
            .transpose()?;
        output["ownerProposal"] = serde_json::to_value(proposal.payload())
            .map_err(|_| "Unable to encode Owner proposal")?;
        output["ownerAttestation"] = attestation
            .map(|record| {
                json!({
                    "baselineId":record.envelope().payload.baseline_id,
                    "historyEpoch":record.envelope().payload.history_epoch,
                    "deviceId":record.envelope().payload.device_id,
                })
            })
            .unwrap_or(Value::Null);
    }
    Ok(output)
}

fn main() -> Result<(), String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Unable to read verification input")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("Verification input exceeds size limit".into());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| "Invalid verification input")?;
    let output = verify(input)?;
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|_| "Unable to encode verification result")?
    );
    Ok(())
}
