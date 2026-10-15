use super::*;
use crate::{
    PublicIdentity, SignedEnvelope,
    history_capture::{history_control_value, verify_exact_history_json},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) fn confirm(
    proposal: &HistoryBaselineProposal<'_>,
    signed_json: &[u8],
    current: &CausalAdmissionInput,
) -> Result<VerifiedHistoryBaselineAttestation, String> {
    if signed_json.len() > MAX_HISTORY_BASELINE_BYTES {
        return Err("History baseline envelope exceeds size limit".into());
    }
    proposal.basis.assert_source_current(current)?;
    let envelope: HistoryBaselineEnvelope = serde_json::from_slice(signed_json)
        .map_err(|_| "Invalid history baseline envelope schema")?;
    verify_exact_history_json(
        signed_json,
        &serde_json::to_value(&envelope).map_err(|_| "Invalid history baseline encoding")?,
    )?;
    if envelope.payload != proposal.payload {
        return Err("History baseline signature does not cover exact Native proposal".into());
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&envelope.signature)
        .map_err(|_| "Invalid history baseline signature encoding")?;
    if signature.len() != 64 || URL_SAFE_NO_PAD.encode(&signature) != envelope.signature {
        return Err("Invalid history baseline signature encoding".into());
    }
    let preparation = proposal.basis.capture().preparation();
    let owner = preparation.owner();
    crate::verify_device_signed_envelope(
        &PublicIdentity {
            person_id: owner.person_id.clone(),
            public_key: owner.public_key.clone(),
            display_name: String::new(),
        },
        &proposal.payload.device_id,
        &proposal.payload.certificates,
        &SignedEnvelope {
            payload: envelope.payload.clone(),
            signer_key_id: envelope.signer_key_id.clone(),
            signature: envelope.signature.clone(),
        },
        HISTORY_BASELINE_DOMAIN,
    )?;
    Ok(VerifiedHistoryBaselineAttestation {
        envelope,
        original_json: signed_json.to_vec(),
        document: proposal.basis.rebase().document().to_vec(),
        owner: owner.clone(),
        control: history_control_value(&preparation.source().snapshot)?,
    })
}
