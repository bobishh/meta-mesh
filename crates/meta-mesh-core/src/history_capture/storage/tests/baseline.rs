use super::*;
use crate::{
    history_baseline::{HISTORY_BASELINE_DOMAIN, HistoryBaselineParent},
    sign_json_envelope,
};

fn sign_payload(
    payload: serde_json::Value,
    seed: &[u8; 32],
    signer: &str,
    domain: &str,
) -> Vec<u8> {
    serde_json::to_vec(&sign_json_envelope(seed, payload, signer, domain).unwrap()).unwrap()
}

#[test]
fn given_complete_owner_preparation_when_signing_initial_baseline_then_retain_verified_attestation()
{
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    let payload = serde_json::to_value(proposal.payload()).unwrap();
    assert_eq!(payload["kind"], "workspace-history-baseline");
    assert_eq!(payload["admissionPolicy"], "mesh-causal-admission@2");
    assert_eq!(payload["version"], 1);
    assert_eq!(payload["historyEpoch"], 1);
    assert!(payload["previousBaselineId"].is_null());
    assert_eq!(payload["transitionId"], coverage.data_transition_id());
    assert_ne!(payload["sourceHeads"], payload["admittedHeads"]);

    let mut id_input = payload.clone();
    id_input.as_object_mut().unwrap().remove("baselineId");
    assert_eq!(
        payload["baselineId"],
        crate::history_archive::history_archive_object_id(
            crate::canonicalize_json(&id_input).unwrap().as_bytes()
        )
    );
    assert_eq!(
        payload["archive"],
        serde_json::to_value(coverage.catalogue()).unwrap()
    );
    assert_eq!(
        payload["locatorRoot"],
        serde_json::to_value(coverage.locator_root()).unwrap()
    );
    assert_eq!(
        payload["storage"]["dataReceipt"],
        serde_json::to_value(coverage.data_receipt()).unwrap()
    );
    assert_eq!(
        payload["storage"]["directoryReceipt"],
        serde_json::to_value(coverage.directory_receipt()).unwrap()
    );
    assert_eq!(
        payload["certificates"],
        serde_json::to_value(&capture.preparation().signer().certificates).unwrap()
    );

    let signed_json = sign_payload(
        payload.clone(),
        &[152; 32],
        &proposal.payload().device_id,
        HISTORY_BASELINE_DOMAIN,
    );
    let retry = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    assert_eq!(retry.payload().baseline_id, proposal.payload().baseline_id);
    assert_eq!(
        signed_json,
        sign_payload(
            serde_json::to_value(retry.payload()).unwrap(),
            &[152; 32],
            &retry.payload().device_id,
            HISTORY_BASELINE_DOMAIN,
        )
    );
    let source = capture.preparation().source().clone();
    let attestation = proposal.confirm(&signed_json, &source).unwrap();
    assert_eq!(attestation.envelope().payload, *proposal.payload());
    assert_eq!(attestation.original_json(), signed_json);
    assert_eq!(attestation.document(), rebase.document());
    assert_eq!(attestation.owner(), capture.preparation().owner());

    let mut changed_time_only = source.clone();
    changed_time_only.now_ms += 1;
    let formatted = format!("\n {} \t", String::from_utf8(signed_json.clone()).unwrap());
    let formatted_attestation = proposal
        .confirm(formatted.as_bytes(), &changed_time_only)
        .unwrap();
    assert_eq!(formatted_attestation.original_json(), formatted.as_bytes());
}

#[test]
fn given_signed_baseline_when_domain_key_payload_or_parent_changes_then_reject() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    let payload = serde_json::to_value(proposal.payload()).unwrap();
    let signer = proposal.payload().device_id.clone();
    let source = capture.preparation().source().clone();
    let valid = sign_payload(
        payload.clone(),
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );

    assert!(proposal.confirm(&valid, &source).is_ok());
    assert!(
        proposal
            .confirm(
                &sign_payload(payload.clone(), &[152; 32], &signer, "MATCH/1"),
                &source,
            )
            .is_err()
    );
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    payload.clone(),
                    &[153; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );

    for (path, value) in [
        ("stateDigest", json!("substituted-state")),
        ("documentDigest", json!("substituted-document")),
        ("genesisHash", json!("substituted-genesis")),
        ("historyEpoch", json!(2)),
        ("controlEpoch", json!(2)),
        ("sourceHeads", json!(["substituted-source"])),
        ("admittedHeads", json!(["substituted-admitted"])),
        ("baselineId", json!("substituted-baseline-id")),
        ("previousBaselineId", json!("unverified-parent")),
        ("requiredReaderCapability", json!("other-policy")),
    ] {
        let mut altered = payload.clone();
        altered[path] = value;
        assert!(
            proposal
                .confirm(
                    &sign_payload(altered, &[152; 32], &signer, HISTORY_BASELINE_DOMAIN),
                    &source,
                )
                .is_err(),
            "accepted altered {path}"
        );
    }
    let mut changed_receipt = payload.clone();
    changed_receipt["storage"]["authority"]["policyRevision"] = json!(8);
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_receipt,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );
    let mut changed_locator = payload.clone();
    changed_locator["locatorRoot"]["root"]["ciphertextId"] = json!("substituted-ciphertext");
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_locator,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );
    let mut changed_data_receipt = payload.clone();
    changed_data_receipt["storage"]["dataReceipt"]["signature"] = json!("substituted-signature");
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_data_receipt,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN
                ),
                &source,
            )
            .is_err()
    );
    let mut changed_directory_receipt = payload.clone();
    changed_directory_receipt["storage"]["directoryReceipt"]["signature"] =
        json!("substituted-signature");
    assert!(
        proposal
            .confirm(
                &sign_payload(
                    changed_directory_receipt,
                    &[152; 32],
                    &signer,
                    HISTORY_BASELINE_DOMAIN,
                ),
                &source,
            )
            .is_err()
    );
}

#[test]
fn given_stale_or_malformed_owner_envelope_when_confirming_then_reject() {
    let (capture, fixture) = captured_fixture();
    let scope = scope();
    let (mut reader, root, _, _) = objects_and_directory(&fixture, &scope);
    let storage = capture
        .verify_storage_directory(&scope, &root, &mut reader)
        .unwrap();
    let coverage = complete_coverage(&storage);
    let rebase = capture
        .preparation()
        .rebase(1, coverage.data_transition_id())
        .unwrap();
    let joined = capture.bind_rebase(&rebase, &coverage).unwrap();
    let proposal = joined
        .propose_baseline(HistoryBaselineParent::Initial)
        .unwrap();
    let payload = serde_json::to_value(proposal.payload()).unwrap();
    let signer = proposal.payload().device_id.clone();
    let valid = sign_payload(
        payload.clone(),
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );
    let source = capture.preparation().source();
    let mut stale = source.clone();
    stale.pending_change_bytes.push(vec![b' ']);
    assert!(proposal.confirm(&valid, &stale).is_err());

    assert!(proposal.confirm(&[], source).is_err());
    assert!(
        proposal
            .confirm(
                &vec![b' '; crate::history_baseline::MAX_HISTORY_BASELINE_BYTES + 1],
                source
            )
            .is_err()
    );
    assert!(
        proposal
            .confirm(
                &sign_payload(payload.clone(), &[152; 32], &signer, "wrong-domain"),
                source,
            )
            .is_err()
    );

    let mut unknown_outer: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    unknown_outer["extra"] = json!(true);
    assert!(
        proposal
            .confirm(&serde_json::to_vec(&unknown_outer).unwrap(), source)
            .is_err()
    );

    let mut omitted_null: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    omitted_null["payload"]
        .as_object_mut()
        .unwrap()
        .remove("previousBaselineId");
    assert!(
        proposal
            .confirm(&serde_json::to_vec(&omitted_null).unwrap(), source)
            .is_err()
    );

    let mut unsigned_unknown_certificate_outer: serde_json::Value =
        serde_json::from_slice(&valid).unwrap();
    unsigned_unknown_certificate_outer["payload"]["certificates"][0]["unexpected"] =
        json!("injected-after-signing");
    assert!(
        proposal
            .confirm(
                &serde_json::to_vec(&unsigned_unknown_certificate_outer).unwrap(),
                source,
            )
            .is_err()
    );
    let mut unsigned_unknown_certificate_payload: serde_json::Value =
        serde_json::from_slice(&valid).unwrap();
    unsigned_unknown_certificate_payload["payload"]["certificates"][0]["payload"]["unexpected"] =
        json!("injected-after-signing");
    assert!(
        proposal
            .confirm(
                &serde_json::to_vec(&unsigned_unknown_certificate_payload).unwrap(),
                source,
            )
            .is_err()
    );
    let duplicate_certificate_key = String::from_utf8(valid.clone()).unwrap().replacen(
        "\"canEnrollDevices\":true",
        "\"canEnrollDevices\":true,\"canEnrollDevices\":true",
        1,
    );
    assert!(
        proposal
            .confirm(duplicate_certificate_key.as_bytes(), source)
            .is_err()
    );

    let mut unknown_certificate = payload.clone();
    unknown_certificate["certificates"][0]["injected"] = json!("untrusted");
    let signed_with_unknown_certificate = sign_payload(
        unknown_certificate,
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );
    assert!(
        proposal
            .confirm(&signed_with_unknown_certificate, source)
            .is_err()
    );

    let mut omitted_certificate_field = payload;
    omitted_certificate_field["certificates"][0]["payload"]
        .as_object_mut()
        .unwrap()
        .remove("canEnrollDevices");
    let signed_with_omission = sign_payload(
        omitted_certificate_field,
        &[152; 32],
        &signer,
        HISTORY_BASELINE_DOMAIN,
    );
    assert!(proposal.confirm(&signed_with_omission, source).is_err());

    let duplicate_payload = String::from_utf8(valid).unwrap().replacen(
        "\"signerKeyId\":",
        "\"signerKeyId\":\"duplicate\",\"signerKeyId\":",
        1,
    );
    assert!(
        proposal
            .confirm(duplicate_payload.as_bytes(), source)
            .is_err()
    );
}
