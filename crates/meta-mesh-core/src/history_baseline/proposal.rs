use super::*;
use crate::{
    authority::MAX_WORKSPACE_HEADS,
    causal_admission::CausalAdmissionStatus,
    history_archive::{MAX_HISTORY_ARCHIVE_INTEGER, history_archive_object_id},
    history_capture::history_control_value,
};
use automerge::AutoCommit;
use serde_json::Value;

pub(super) fn prepare<'a>(
    basis: &'a VerifiedHistoryBasisArchive<'a>,
    parent: HistoryBaselineParent<'_>,
) -> Result<HistoryBaselineProposal<'a>, String> {
    let preparation = basis.capture().preparation();
    let source = &preparation.source().snapshot;
    let control_epoch = source
        .ownership_transfers
        .iter()
        .map(|record| record.payload.epoch)
        .chain(
            source
                .succession_claims
                .iter()
                .map(|record| record.payload.epoch),
        )
        .chain(std::iter::once(source.genesis_epoch))
        .max()
        .unwrap();
    if control_epoch == 0 || control_epoch > MAX_HISTORY_ARCHIVE_INTEGER {
        return Err("Invalid history baseline control epoch".into());
    }
    let rebase = basis.rebase();
    let previous_baseline_id = match parent {
        HistoryBaselineParent::Initial => {
            if rebase.history_epoch() != 1 {
                return Err("Initial history baseline must use epoch one".into());
            }
            None
        }
        HistoryBaselineParent::Previous(previous) => {
            let p = &previous.envelope.payload;
            if p.workspace_id != source.workspace_id
                || p.history_epoch.checked_add(1) != Some(rebase.history_epoch())
                || p.control_epoch > control_epoch
                || !preserves_control(&previous.control, &history_control_value(source)?)
                || !preparation.admission().decisions.iter().any(|decision| {
                    decision.hash == p.genesis_hash
                        && matches!(decision.status, CausalAdmissionStatus::Admitted { .. })
                })
            {
                return Err(
                    "History baseline parent, authority or admitted lineage changed".into(),
                );
            }
            Some(p.baseline_id.clone())
        }
    };
    let mut admitted = AutoCommit::load(&preparation.admission().authorized_document)
        .map_err(|_| "Invalid admitted history baseline source")?;
    let mut admitted_heads = admitted
        .get_heads()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    admitted_heads.sort_unstable();
    if preparation.source_heads().len() > MAX_WORKSPACE_HEADS
        || admitted_heads.len() > MAX_WORKSPACE_HEADS
    {
        return Err("History baseline frontier exceeds preparation limit".into());
    }
    let coverage = basis.coverage();
    let mut payload = HistoryBaselinePayload {
        kind: "workspace-history-baseline".into(),
        version: 1,
        workspace_id: source.workspace_id.clone(),
        baseline_id: String::new(),
        history_epoch: rebase.history_epoch(),
        control_epoch,
        previous_baseline_id,
        transition_id: rebase.transition_id().into(),
        source_heads: preparation.source_heads().to_vec(),
        admitted_heads,
        admission_policy: crate::causal_admission::CAUSAL_ADMISSION_POLICY_ID.into(),
        admission_revision: preparation.admission_revision().into(),
        authority_revision: preparation.authority_digest().into(),
        person_id: preparation.signer().person_id.clone(),
        device_id: preparation.signer().device_id.clone(),
        certificates: preparation.signer().certificates.clone(),
        state_digest: rebase.state_digest().into(),
        document_digest: rebase.document_digest().into(),
        genesis_hash: rebase.genesis_hash().into(),
        archive: coverage.catalogue().clone(),
        locator_root: coverage.locator_root().clone(),
        storage: HistoryBaselineStorage {
            authority: coverage.authority().clone(),
            key_epoch: coverage.key_epoch(),
            key_digest: coverage.key_digest().into(),
            data_transition_id: coverage.data_transition_id().into(),
            directory_transition_id: coverage.directory_transition_id().into(),
            data_receipt: coverage.data_receipt().clone(),
            directory_receipt: coverage.directory_receipt().clone(),
        },
        required_reader_capability: HISTORY_BASELINE_CAPABILITY.into(),
        required_writer_capability: HISTORY_BASELINE_CAPABILITY.into(),
    };
    let mut unsigned =
        serde_json::to_value(&payload).map_err(|_| "Invalid baseline payload encoding")?;
    unsigned.as_object_mut().unwrap().remove("baselineId");
    payload.baseline_id =
        history_archive_object_id(crate::canonicalize_json(&unsigned)?.as_bytes());
    let envelope_bound = HistoryBaselineEnvelope {
        signer_key_id: payload.device_id.clone(),
        payload: payload.clone(),
        signature: "A".repeat(86),
    };
    if serde_json::to_vec(&envelope_bound)
        .map_err(|_| "Invalid baseline payload encoding")?
        .len()
        > MAX_HISTORY_BASELINE_BYTES
    {
        return Err("History baseline envelope exceeds preparation limit".into());
    }
    Ok(HistoryBaselineProposal { basis, payload })
}

// These values are derived from verified typed snapshots, never arbitrary host JSON.
fn preserves_control(previous: &Value, current: &Value) -> bool {
    if previous["workspaceId"] != current["workspaceId"]
        || previous["genesisEpoch"] != current["genesisEpoch"]
        || previous["genesisOwner"]["personId"] != current["genesisOwner"]["personId"]
        || previous["genesisOwner"]["publicKey"] != current["genesisOwner"]["publicKey"]
    {
        return false;
    }
    for name in [
        "ownershipTransfers",
        "successionClaims",
        "revocations",
        "deviceRevocations",
        "departures",
    ] {
        let Some(old) = previous[name].as_array() else {
            return false;
        };
        let Some(new) = current[name].as_array() else {
            return false;
        };
        if !old.iter().all(|record| {
            new.iter().any(|candidate| {
                let authority = match name {
                    "deviceRevocations" => Some("signer"),
                    "departures" => Some("authority"),
                    _ => None,
                };
                if let Some(authority) = authority {
                    record["record"] == candidate["record"]
                        && record[authority]["personId"] == candidate[authority]["personId"]
                        && record[authority]["publicKey"] == candidate[authority]["publicKey"]
                } else {
                    record == candidate
                }
            })
        }) {
            return false;
        }
    }
    true
}
