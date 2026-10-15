use super::*;
use automerge::{ActorId, AutoCommit, ROOT, transaction::Transactable};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

struct Fixture {
    source: WorkspaceWriteAuthorizationSnapshot,
    owner: WorkspaceAuthority,
    subject: WorkspaceAuthority,
    before: String,
    after: String,
    owner_device: String,
    subject_device: String,
}
fn fixture() -> Fixture {
    let (owner, _, owner_device, _) = authority([131; 32], [132; 32]);
    let (next, _, _, _) = authority([133; 32], [134; 32]);
    let (subject, _, subject_device, _) = authority([135; 32], [136; 32]);
    let mut document = AutoCommit::new().with_actor(ActorId::from(vec![137; 16]));
    document.put(ROOT, "before", true).unwrap();
    document.commit();
    let before = document.get_heads()[0].to_string();
    document.put(ROOT, "after", true).unwrap();
    document.commit();
    let after = document.get_heads()[0].to_string();
    let mut source = snapshot(owner.clone());
    source.document = document.save();
    source.expected_current_owner = next.clone();
    source.ownership_transfers.push(transfer(
        &owner,
        &[131; 32],
        &[132; 32],
        &owner_device,
        &next,
        vec![before.clone()],
        2,
    ));
    Fixture {
        source,
        owner,
        subject,
        before,
        after,
        owner_device,
        subject_device,
    }
}

#[test]
fn given_owner_device_removal_before_transfer_when_validating_new_owner_then_preserve_valid_historical_removal()
 {
    let mut f = fixture();
    f.source.device_revocations.push(device_revocation(
        &f.owner,
        &[132; 32],
        &f.owner_device,
        &f.subject.person_id,
        &f.subject_device,
        vec![f.before],
    ));
    let context = ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(&f.source, 0).unwrap();
    assert!(context.device_was_revoked(&f.subject.person_id, &f.subject_device));
}

#[test]
fn given_former_owner_device_removal_after_transfer_when_validating_then_reject_new_power_over_another_person()
 {
    let mut f = fixture();
    f.source.device_revocations.push(device_revocation(
        &f.owner,
        &[132; 32],
        &f.owner_device,
        &f.subject.person_id,
        &f.subject_device,
        vec![f.after],
    ));
    assert!(ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(&f.source, 0).is_err());
}

#[test]
fn given_former_owner_person_removal_after_transfer_when_validating_then_reject_new_power_over_another_person()
 {
    let mut f = fixture();
    f.source.revocations.push(revocation(
        &f.owner,
        &[131; 32],
        &f.subject.person_id,
        vec![f.after],
        2,
    ));
    assert!(ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(&f.source, 0).is_err());
}

#[test]
fn given_owner_person_removal_before_transfer_when_validating_then_preserve_valid_historical_removal()
 {
    let mut f = fixture();
    f.source.revocations.push(revocation(
        &f.owner,
        &[131; 32],
        &f.subject.person_id,
        vec![f.before],
        2,
    ));
    assert!(ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(&f.source, 0).is_ok());
}

#[test]
fn given_former_owner_removing_own_device_after_transfer_when_validating_then_preserve_separate_person_authority()
 {
    let mut f = fixture();
    f.source.device_revocations.push(device_revocation(
        &f.owner,
        &[132; 32],
        &f.owner_device,
        &f.owner.person_id,
        &f.owner_device,
        vec![f.after],
    ));
    let context = ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(&f.source, 0).unwrap();
    assert!(context.device_was_revoked(&f.owner.person_id, &f.owner_device));
}

#[test]
fn given_native_history_control_cases_when_exporting_interop_fixture_then_match_native_policy() {
    let mut cases: Vec<(String, WorkspaceWriteAuthorizationSnapshot, bool)> = Vec::new();

    let mut f = fixture();
    f.source.device_revocations.push(device_revocation(
        &f.owner,
        &[132; 32],
        &f.owner_device,
        &f.subject.person_id,
        &f.subject_device,
        vec![f.before],
    ));
    cases.push((
        "owner-device-removal-before-transfer".into(),
        f.source,
        true,
    ));

    let mut f = fixture();
    f.source.device_revocations.push(device_revocation(
        &f.owner,
        &[132; 32],
        &f.owner_device,
        &f.subject.person_id,
        &f.subject_device,
        vec![f.after],
    ));
    cases.push((
        "former-owner-device-removal-after-transfer".into(),
        f.source,
        false,
    ));

    let mut f = fixture();
    f.source.revocations.push(revocation(
        &f.owner,
        &[131; 32],
        &f.subject.person_id,
        vec![f.after],
        2,
    ));
    cases.push((
        "former-owner-person-removal-after-transfer".into(),
        f.source,
        false,
    ));

    let mut f = fixture();
    f.source.revocations.push(revocation(
        &f.owner,
        &[131; 32],
        &f.subject.person_id,
        vec![f.before],
        2,
    ));
    cases.push((
        "owner-person-removal-before-transfer".into(),
        f.source,
        true,
    ));

    let mut f = fixture();
    f.source.device_revocations.push(device_revocation(
        &f.owner,
        &[132; 32],
        &f.owner_device,
        &f.owner.person_id,
        &f.owner_device,
        vec![f.after],
    ));
    cases.push((
        "former-owner-removes-own-device-after-transfer".into(),
        f.source,
        true,
    ));

    let mut output = Vec::new();
    for (name, snapshot, allowed) in cases {
        assert_eq!(
            ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(&snapshot, 0).is_ok(),
            allowed,
            "Native policy mismatch for {name}"
        );
        let control = crate::history_capture::history_control_value(&snapshot).unwrap();
        output.push(json!({
            "name": name,
            "control": control,
            "document": URL_SAFE_NO_PAD.encode(&snapshot.document),
            "allowed": allowed,
        }));
    }
    let fixture: Value = json!({
        "kind": "history-control-fixture",
        "version": 1,
        "policy": crate::causal_admission::CAUSAL_ADMISSION_POLICY_ID,
        "cases": output,
    });
    if let Ok(path) = std::env::var("MESH_HISTORY_CONTROL_FIXTURE_OUTPUT") {
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
        )
        .unwrap();
    }
}
