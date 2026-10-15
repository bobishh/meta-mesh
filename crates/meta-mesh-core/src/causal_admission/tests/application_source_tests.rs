use super::*;

use crate::causal_admission::{
    CausalAdmissionInput, CausalAdmissionPlan, CausalAdmissionStatus, evaluate_causal_admission,
};
use automerge::{ObjType, ROOT, transaction::Transactable};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

fn source_base() -> (
    AutoCommit,
    WorkspaceAuthority,
    [u8; 32],
    String,
    Vec<DeviceCertificate>,
    String,
) {
    let (owner, device_seed, device_id, certificates) = authority([201; 32], [202; 32]);
    let mut doc = AutoCommit::new();
    let entities = doc.put_object(ROOT, "entities", ObjType::Map).unwrap();
    let board = doc.put_object(&entities, "board", ObjType::Map).unwrap();
    doc.put(&board, "id", "board").unwrap();
    doc.put(&board, "kind", "board").unwrap();
    let column = doc.put_object(&entities, "column", ObjType::Map).unwrap();
    doc.put(&column, "id", "column").unwrap();
    doc.put(&column, "kind", "column").unwrap();
    let placement = doc.put_object(&column, "placement", ObjType::Map).unwrap();
    doc.put(&placement, "parentId", "board").unwrap();
    doc.put(&placement, "rank", "0/1").unwrap();
    let card = doc.put_object(&entities, "card", ObjType::Map).unwrap();
    doc.put(&card, "id", "card").unwrap();
    doc.put(&card, "body", "Job details").unwrap();
    doc.put_object(&card, "values", ObjType::Map).unwrap();
    let placement = doc.put_object(&card, "placement", ObjType::Map).unwrap();
    doc.put(&placement, "parentId", "column").unwrap();
    doc.put(&placement, "rank", "0/1").unwrap();
    let metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "personId": owner.person_id, "deviceId": device_id,
    })
    .to_string();
    doc.commit_with(CommitOptions::default().with_message(metadata));
    let genesis = doc.get_changes(&[])[0].hash().to_string();
    (doc, owner, device_seed, device_id, certificates, genesis)
}

pub(super) fn source_data(text: &str, digest: &str, record_id: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "kind": "application-source-observation",
        "version": 1,
        "recordId": record_id,
        "workspaceId": "workspace",
        "cardId": "card",
        "applicationId": "workspace:card",
        "observation": {
            "phase": "original",
            "origin": "website",
            "status": "available",
            "observedAt": "2026-10-14T10:00:00.000Z",
            "jobUrl": "https://jobs.example.test/role",
            "company": "Example",
            "title": "Engineer",
            "text": text,
            "extractorVersion": "extractor-v1",
            "contentDigest": digest,
        }
    }))
    .unwrap()
}

fn source_refresh_data(text: &str, record_id: &str, original_id: &str) -> String {
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
    let mut data: serde_json::Value =
        serde_json::from_str(&source_data(text, &digest, record_id)).unwrap();
    data["observation"]["phase"] = serde_json::Value::String("refresh".into());
    data["observation"]["originalRecordId"] = serde_json::Value::String(original_id.into());
    serde_json::to_string(&data).unwrap()
}

pub(super) fn write_source(doc: &mut AutoCommit, record_id: &str, data: &str) {
    let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
    let id = format!("application-source:{record_id}");
    let source = doc.put_object(entities, &id, ObjType::Map).unwrap();
    doc.put(&source, "id", id.as_str()).unwrap();
    doc.put(&source, "kind", "application_source").unwrap();
    doc.put(&source, "title", "Application source").unwrap();
    doc.put(&source, "data", data).unwrap();
    doc.put(&source, "archivedAt", automerge::ScalarValue::Null)
        .unwrap();
    doc.put(&source, "createdAt", "2026-10-14T10:00:00.000Z")
        .unwrap();
    doc.put(&source, "updatedAt", "2026-10-14T10:00:00.000Z")
        .unwrap();
    let placement = doc.put_object(&source, "placement", ObjType::Map).unwrap();
    doc.put(&placement, "parentId", "card").unwrap();
    doc.put(&placement, "rank", "0/1").unwrap();
}

fn commit_owner_edit(doc: &mut AutoCommit, owner: &WorkspaceAuthority, device: &str) {
    let metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "personId": owner.person_id, "deviceId": device,
    })
    .to_string();
    doc.commit_with(CommitOptions::default().with_message(metadata));
}

fn add_valid_source(
    doc: &mut AutoCommit,
    owner: &WorkspaceAuthority,
    device: &str,
    record_id: &str,
) {
    add_source_text(doc, owner, device, record_id, "role details");
}

fn add_source_text(
    doc: &mut AutoCommit,
    owner: &WorkspaceAuthority,
    device: &str,
    record_id: &str,
    text: &str,
) {
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
    write_source(doc, record_id, &source_data(text, &digest, record_id));
    commit_owner_edit(doc, owner, device);
}

fn proof_set(
    doc: &mut AutoCommit,
    owner: &WorkspaceAuthority,
    device_seed: &[u8; 32],
    device_id: &str,
    certificates: &[DeviceCertificate],
) -> Vec<IncomingWorkspaceChangeAuthorization> {
    let hashes = doc
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .collect::<Vec<_>>();
    vec![change_proof(
        owner,
        device_seed,
        device_id,
        certificates,
        &hashes,
        None,
    )]
}

fn evaluate(
    mut doc: AutoCommit,
    owner: WorkspaceAuthority,
    seed: [u8; 32],
    device: String,
    certs: Vec<DeviceCertificate>,
) -> CausalAdmissionPlan {
    let records = proof_set(&mut doc, &owner, &seed, &device, &certs);
    let mut snapshot = snapshot(owner, doc.save());
    snapshot.workspace_id = "workspace".into();
    evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap()
}

#[test]
fn valid_owner_application_source_creation_is_admitted() {
    let (mut doc, owner, seed, device, certs, _) = source_base();
    let text = "role details";
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
    write_source(
        &mut doc,
        "source_1",
        &source_data(text, &digest, "source_1"),
    );
    let metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "personId": owner.person_id, "deviceId": device,
        "action": "createApplicationSource", "entityIds": ["application-source:source_1"]
    })
    .to_string();
    doc.commit_with(CommitOptions::default().with_message(metadata));

    let plan = evaluate(doc, owner, seed, device, certs);
    assert!(
        plan.decisions
            .iter()
            .all(|decision| matches!(decision.status, CausalAdmissionStatus::Admitted { .. })),
        "{:?}",
        plan.decisions
    );
}

#[test]
fn invalid_digest_application_source_creation_is_quarantined() {
    let (mut doc, owner, seed, device, certs, _) = source_base();
    write_source(
        &mut doc,
        "source_bad",
        &source_data(
            "role details",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "source_bad",
        ),
    );
    let metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "personId": owner.person_id, "deviceId": device,
    })
    .to_string();
    doc.commit_with(CommitOptions::default().with_message(metadata));

    let plan = evaluate(doc, owner, seed, device, certs);
    assert!(
        plan.decisions
            .iter()
            .any(|decision| matches!(decision.status, CausalAdmissionStatus::Quarantined { .. }))
    );
}

#[test]
fn refresh_requires_an_existing_original_for_the_same_application() {
    for original_id in ["original_source", "missing_source"] {
        let (mut doc, owner, seed, device, certs, _) = source_base();
        add_valid_source(&mut doc, &owner, &device, "original_source");
        let original_hash = doc.get_changes(&[]).last().unwrap().hash().to_string();
        write_source(
            &mut doc,
            "refresh_source",
            &source_refresh_data("refreshed details", "refresh_source", original_id),
        );
        commit_owner_edit(&mut doc, &owner, &device);
        let refresh_hash = doc.get_changes(&[]).last().unwrap().hash().to_string();
        let plan = evaluate(doc, owner, seed, device, certs);
        let original = plan
            .decisions
            .iter()
            .find(|decision| decision.hash == original_hash)
            .unwrap();
        let refresh = plan
            .decisions
            .iter()
            .find(|decision| decision.hash == refresh_hash)
            .unwrap();
        assert!(matches!(
            original.status,
            CausalAdmissionStatus::Admitted { .. }
        ));
        assert_eq!(
            matches!(refresh.status, CausalAdmissionStatus::Admitted { .. }),
            original_id == "original_source",
            "{:?}",
            plan.decisions
        );
    }
}

#[test]
fn refresh_reference_cycles_are_quarantined_without_recursive_validation() {
    let (mut doc, owner, seed, device, certs, _) = source_base();
    write_source(
        &mut doc,
        "refresh_a",
        &source_refresh_data("details a", "refresh_a", "refresh_b"),
    );
    write_source(
        &mut doc,
        "refresh_b",
        &source_refresh_data("details b", "refresh_b", "refresh_a"),
    );
    commit_owner_edit(&mut doc, &owner, &device);

    let plan = evaluate(doc, owner, seed, device, certs);
    assert!(
        plan.decisions
            .iter()
            .any(|decision| matches!(decision.status, CausalAdmissionStatus::Quarantined { .. }))
    );
}

#[test]
fn available_observation_rejects_non_union_reason_field() {
    let (mut doc, owner, seed, device, certs, _) = source_base();
    let text = "role details";
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
    let mut data: serde_json::Value =
        serde_json::from_str(&source_data(text, &digest, "source_reason")).unwrap();
    data["observation"]["reason"] = serde_json::Value::String("unexpected".into());
    write_source(
        &mut doc,
        "source_reason",
        &serde_json::to_string(&data).unwrap(),
    );
    commit_owner_edit(&mut doc, &owner, &device);

    let plan = evaluate(doc, owner, seed, device, certs);
    assert!(
        plan.decisions
            .iter()
            .any(|decision| matches!(decision.status, CausalAdmissionStatus::Quarantined { .. }))
    );
}

#[test]
fn scope_and_closed_schema_mismatches_are_quarantined() {
    for case in ["foreign-scope", "unknown-field", "credential-url"] {
        let (mut doc, owner, seed, device, certs, _) = source_base();
        let text = "role details";
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
        let mut data: serde_json::Value =
            serde_json::from_str(&source_data(text, &digest, "bad_source")).unwrap();
        match case {
            "foreign-scope" => {
                data["workspaceId"] = serde_json::Value::String("foreign-workspace".into());
                data["applicationId"] = serde_json::Value::String("foreign-workspace:card".into());
            }
            "unknown-field" => {
                data["unexpected"] = serde_json::Value::Bool(true);
            }
            "credential-url" => {
                data["observation"]["jobUrl"] =
                    serde_json::Value::String("https://user:secret@jobs.example.test/role".into());
            }
            _ => unreachable!(),
        }
        write_source(
            &mut doc,
            "bad_source",
            &serde_json::to_string(&data).unwrap(),
        );
        commit_owner_edit(&mut doc, &owner, &device);
        let plan = evaluate(doc, owner, seed, device, certs);
        assert!(
            plan.decisions.iter().any(|decision| matches!(
                decision.status,
                CausalAdmissionStatus::Quarantined { .. }
            )),
            "{case}: {:?}",
            plan.decisions
        );
    }
}

#[test]
fn an_admitted_application_source_cannot_be_edited_deleted_or_disguised() {
    for action in ["edit", "delete", "disguise"] {
        let (mut doc, owner, seed, device, certs, _) = source_base();
        add_valid_source(&mut doc, &owner, &device, "source_1");
        let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
        let id = "application-source:source_1";
        match action {
            "edit" => {
                let source = doc.get(entities, id).unwrap().unwrap().1;
                doc.put(&source, "title", "edited source").unwrap();
            }
            "delete" => doc.delete(entities, id).unwrap(),
            "disguise" => {
                let source = doc.get(entities, id).unwrap().unwrap().1;
                doc.put(&source, "kind", "note").unwrap();
            }
            _ => unreachable!(),
        }
        commit_owner_edit(&mut doc, &owner, &device);
        let plan = evaluate(doc, owner, seed, device, certs);
        assert!(
            plan.decisions.iter().any(|decision| matches!(
                decision.status,
                CausalAdmissionStatus::Quarantined { .. }
            )),
            "{action} was not quarantined: {:?}",
            plan.decisions
        );
    }
}

#[test]
fn editor_with_signed_workspace_grant_can_create_source_observation() {
    let (mut doc, owner, owner_seed, owner_device, owner_certs, genesis) = source_base();
    let (editor, editor_seed, editor_device, editor_certs) = authority([203; 32], [204; 32]);
    let editor_grant = grant(&owner, &[201; 32], &editor, 1);
    let text = "editor source details";
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
    write_source(
        &mut doc,
        "editor_source",
        &source_data(text, &digest, "editor_source"),
    );
    let metadata = change_metadata(&editor_grant, &editor.person_id, &editor_device);
    doc.commit_with(CommitOptions::default().with_message(metadata));
    let changes = doc.get_changes(&[]);
    let editor_hash = changes.last().unwrap().hash().to_string();
    let records = vec![
        change_proof(
            &owner,
            &owner_seed,
            &owner_device,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &editor,
            &editor_seed,
            &editor_device,
            &editor_certs,
            &[editor_hash],
            Some(editor_grant),
        ),
    ];
    let plan = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot: snapshot(owner, doc.save()),
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    assert!(
        plan.decisions
            .iter()
            .all(|decision| matches!(decision.status, CausalAdmissionStatus::Admitted { .. })),
        "{:?}",
        plan.decisions
    );
}

#[test]
fn distinct_concurrent_source_creations_survive_each_other() {
    let (mut base, owner, left_seed, left_device, left_certs, _) = source_base();
    let (right_owner, right_seed, right_device, right_certs) = authority([201; 32], [205; 32]);
    assert_eq!(owner.person_id, right_owner.person_id);
    let base_heads = base.get_heads();
    let mut left = base.fork();
    left.set_actor(automerge::ActorId::from(&b"source-left"[..]));
    add_valid_source(&mut left, &owner, &left_device, "left_source");
    let left_change = left.get_changes(&base_heads).remove(0);
    let mut right = base.fork();
    right.set_actor(automerge::ActorId::from(&b"source-right"[..]));
    add_valid_source(&mut right, &right_owner, &right_device, "right_source");
    let right_change = right.get_changes(&base_heads).remove(0);

    let mut raw = base.fork();
    raw.apply_changes(vec![left_change.clone(), right_change.clone()])
        .unwrap();
    let genesis = base.get_changes(&[])[0].hash().to_string();
    let records = vec![
        change_proof(
            &owner,
            &left_seed,
            &left_device,
            &left_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &owner,
            &left_seed,
            &left_device,
            &left_certs,
            &[left_change.hash().to_string()],
            None,
        ),
        change_proof(
            &right_owner,
            &right_seed,
            &right_device,
            &right_certs,
            &[right_change.hash().to_string()],
            None,
        ),
    ];
    let plan = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot: snapshot(owner, raw.save()),
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    assert!(
        plan.decisions
            .iter()
            .all(|decision| matches!(decision.status, CausalAdmissionStatus::Admitted { .. })),
        "{:?}",
        plan.decisions
    );
    let projected = AutoCommit::load(&plan.authorized_document).unwrap();
    let entities = projected.get(ROOT, "entities").unwrap().unwrap().1;
    assert!(
        projected
            .get(&entities, "application-source:left_source")
            .unwrap()
            .is_some()
    );
    assert!(
        projected
            .get(&entities, "application-source:right_source")
            .unwrap()
            .is_some()
    );
}

#[test]
fn conflicting_concurrent_creation_for_same_source_id_is_quarantined() {
    let (mut base, owner, left_seed, left_device, left_certs, _) = source_base();
    let (same_owner, right_seed, right_device, right_certs) = authority([201; 32], [210; 32]);
    let base_heads = base.get_heads();
    let mut left = base.fork();
    left.set_actor(automerge::ActorId::from(&b"same-source-left"[..]));
    add_source_text(
        &mut left,
        &owner,
        &left_device,
        "same_id",
        "left observation",
    );
    let left_change = left.get_changes(&base_heads).remove(0);
    let mut right = base.fork();
    right.set_actor(automerge::ActorId::from(&b"same-source-right"[..]));
    add_source_text(
        &mut right,
        &same_owner,
        &right_device,
        "same_id",
        "right observation",
    );
    let right_change = right.get_changes(&base_heads).remove(0);
    let mut raw = base.fork();
    raw.apply_changes(vec![left_change.clone(), right_change.clone()])
        .unwrap();
    let genesis = base.get_changes(&[])[0].hash().to_string();
    let plan = evaluate_causal_admission(CausalAdmissionInput {
        records: vec![
            change_proof(
                &owner,
                &left_seed,
                &left_device,
                &left_certs,
                &[genesis],
                None,
            ),
            change_proof(
                &owner,
                &left_seed,
                &left_device,
                &left_certs,
                &[left_change.hash().to_string()],
                None,
            ),
            change_proof(
                &same_owner,
                &right_seed,
                &right_device,
                &right_certs,
                &[right_change.hash().to_string()],
                None,
            ),
        ],
        snapshot: snapshot(owner, raw.save()),
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    for change in [left_change, right_change] {
        assert!(
            plan.decisions.iter().any(|decision| {
                decision.hash == change.hash().to_string()
                    && matches!(decision.status, CausalAdmissionStatus::Quarantined { .. })
            }),
            "conflicting source creation was not quarantined: {:?}",
            plan.decisions
        );
    }
}

#[test]
fn scoped_automation_grant_does_not_authorize_application_source_creation() {
    let (mut doc, owner, owner_seed, owner_device, owner_certs, genesis) = source_base();
    let (automation, automation_seed, automation_device, automation_certs) =
        authority([206; 32], [207; 32]);
    let payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: "automation-source-denied".into(),
        workspace_id: "workspace".into(),
        person_id: automation.person_id.clone(),
        role: WorkspaceRole::Automation,
        access_epoch: Some(1),
        automation: Some(automation_scope()),
    };
    let signed = sign_json_envelope(
        &[201; 32],
        serde_json::to_value(&payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    let grant = WorkspaceGrant {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    };
    assert_eq!(
        crate::verify_workspace_grant(
            &grant,
            "workspace",
            &automation.person_id,
            &crate::PublicIdentity {
                person_id: owner.person_id.clone(),
                public_key: owner.public_key.clone(),
                display_name: String::new()
            },
            &owner.certificates,
        )
        .unwrap(),
        WorkspaceRole::Automation,
    );
    let text = "automation cannot create source records";
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
    write_source(
        &mut doc,
        "automation_source",
        &source_data(text, &digest, "automation_source"),
    );
    let metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "authorityGrantHash": grant_hash(&grant),
        "personId": automation.person_id, "deviceId": automation_device,
    })
    .to_string();
    doc.commit_with(CommitOptions::default().with_message(metadata));
    let source_hash = doc.get_changes(&[]).last().unwrap().hash().to_string();
    let plan = evaluate_causal_admission(CausalAdmissionInput {
        records: vec![
            change_proof(
                &owner,
                &owner_seed,
                &owner_device,
                &owner_certs,
                &[genesis],
                None,
            ),
            change_proof(
                &automation,
                &automation_seed,
                &automation_device,
                &automation_certs,
                &[source_hash.clone()],
                Some(grant),
            ),
        ],
        snapshot: snapshot(owner, doc.save()),
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    assert!(
        plan.decisions.iter().any(|decision| {
            decision.hash == source_hash
                && matches!(decision.status, CausalAdmissionStatus::Quarantined { .. })
        }),
        "{:?}",
        plan.decisions
    );
}

#[test]
fn stale_concurrent_entities_map_rebind_is_quarantined_around_source_creation() {
    for action in ["rebind", "delete", "scalar"] {
        assert_stale_entities_map_change_quarantined(action);
    }
}

fn assert_stale_entities_map_change_quarantined(action: &str) {
    let (mut base, owner, owner_seed, owner_device, owner_certs, genesis) = source_base();
    let (same_owner, replacement_seed, replacement_device, replacement_certs) =
        authority([201; 32], [208; 32]);
    let base_heads = base.get_heads();
    let mut source_branch = base.fork();
    source_branch.set_actor(automerge::ActorId::from(&b"source-creator"[..]));
    add_valid_source(
        &mut source_branch,
        &owner,
        &owner_device,
        "protected_source",
    );
    let source_change = source_branch.get_changes(&base_heads).remove(0);

    let mut rebind_branch = base.fork();
    rebind_branch.set_actor(automerge::ActorId::from(&b"stale-map-replacer"[..]));
    match action {
        "rebind" => {
            rebind_branch
                .put_object(ROOT, "entities", ObjType::Map)
                .unwrap();
        }
        "delete" => rebind_branch.delete(ROOT, "entities").unwrap(),
        "scalar" => {
            rebind_branch
                .put(ROOT, "entities", "disguised map")
                .unwrap();
        }
        _ => unreachable!(),
    }
    let rebind_metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "personId": same_owner.person_id, "deviceId": replacement_device,
    })
    .to_string();
    rebind_branch.commit_with(CommitOptions::default().with_message(rebind_metadata));
    let rebind_change = rebind_branch.get_changes(&base_heads).remove(0);

    let mut raw = base.fork();
    raw.apply_changes(vec![source_change.clone(), rebind_change.clone()])
        .unwrap();
    let plan = evaluate_causal_admission(CausalAdmissionInput {
        records: vec![
            change_proof(
                &owner,
                &owner_seed,
                &owner_device,
                &owner_certs,
                &[genesis],
                None,
            ),
            change_proof(
                &owner,
                &owner_seed,
                &owner_device,
                &owner_certs,
                &[source_change.hash().to_string()],
                None,
            ),
            change_proof(
                &same_owner,
                &replacement_seed,
                &replacement_device,
                &replacement_certs,
                &[rebind_change.hash().to_string()],
                None,
            ),
        ],
        snapshot: snapshot(owner, raw.save()),
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    assert!(
        plan.decisions.iter().any(|decision| {
            decision.hash == source_change.hash().to_string()
                && matches!(decision.status, CausalAdmissionStatus::Admitted { .. })
        }),
        "source branch should remain admitted: {:?}",
        plan.decisions
    );
    assert!(
        plan.decisions.iter().any(|decision| {
            decision.hash == rebind_change.hash().to_string()
                && matches!(decision.status, CausalAdmissionStatus::Quarantined { .. })
        }),
        "stale root-map replacement should be quarantined: {:?}",
        plan.decisions
    );
    let projected = AutoCommit::load(&plan.authorized_document).unwrap();
    let entities = projected.get(ROOT, "entities").unwrap().unwrap().1;
    assert!(
        projected
            .get(&entities, "application-source:protected_source")
            .unwrap()
            .is_some()
    );
}

#[test]
fn entities_map_rebind_before_first_source_does_not_retroactively_quarantine_history() {
    let (mut doc, owner, owner_seed, owner_device, owner_certs, genesis) = source_base();
    let (same_owner, replacement_seed, replacement_device, replacement_certs) =
        authority([201; 32], [209; 32]);
    // A historical root-map replacement that preserves the card as a real item.
    let replacement = doc.put_object(ROOT, "entities", ObjType::Map).unwrap();
    let board = doc.put_object(&replacement, "board", ObjType::Map).unwrap();
    doc.put(&board, "id", "board").unwrap();
    doc.put(&board, "kind", "board").unwrap();
    let column = doc
        .put_object(&replacement, "column", ObjType::Map)
        .unwrap();
    doc.put(&column, "id", "column").unwrap();
    doc.put(&column, "kind", "column").unwrap();
    let placement = doc.put_object(&column, "placement", ObjType::Map).unwrap();
    doc.put(&placement, "parentId", "board").unwrap();
    doc.put(&placement, "rank", "0/1").unwrap();
    let card = doc.put_object(&replacement, "card", ObjType::Map).unwrap();
    doc.put(&card, "id", "card").unwrap();
    doc.put(&card, "body", "Job details").unwrap();
    doc.put_object(&card, "values", ObjType::Map).unwrap();
    let placement = doc.put_object(&card, "placement", ObjType::Map).unwrap();
    doc.put(&placement, "parentId", "column").unwrap();
    doc.put(&placement, "rank", "0/1").unwrap();
    let rebind_metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "personId": same_owner.person_id, "deviceId": replacement_device,
    })
    .to_string();
    doc.commit_with(CommitOptions::default().with_message(rebind_metadata));
    let rebind_hash = doc.get_changes(&[]).last().unwrap().hash().to_string();
    add_valid_source(&mut doc, &owner, &owner_device, "after_rebind");
    let source_hash = doc.get_changes(&[]).last().unwrap().hash().to_string();
    let plan = evaluate_causal_admission(CausalAdmissionInput {
        records: vec![
            change_proof(
                &owner,
                &owner_seed,
                &owner_device,
                &owner_certs,
                &[genesis],
                None,
            ),
            change_proof(
                &same_owner,
                &replacement_seed,
                &replacement_device,
                &replacement_certs,
                &[rebind_hash.clone()],
                None,
            ),
            change_proof(
                &owner,
                &owner_seed,
                &owner_device,
                &owner_certs,
                &[source_hash.clone()],
                None,
            ),
        ],
        snapshot: snapshot(owner, doc.save()),
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    assert!(
        plan.decisions
            .iter()
            .any(|decision| decision.hash == rebind_hash
                && matches!(decision.status, CausalAdmissionStatus::Admitted { .. })),
        "{:?}",
        plan.decisions
    );
    assert!(
        plan.decisions
            .iter()
            .any(|decision| decision.hash == source_hash
                && matches!(decision.status, CausalAdmissionStatus::Admitted { .. })),
        "{:?}",
        plan.decisions
    );
}

#[test]
fn large_unrelated_owner_edit_skips_source_root_hydration_gate() {
    let (mut doc, owner, _seed, device, _certs, _) = source_base();
    let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
    let card = doc.get(&entities, "card").unwrap().unwrap().1;
    doc.put(&card, "body", "ordinary board prose ".repeat(2_400))
        .unwrap();
    commit_owner_edit(&mut doc, &owner, &device);
    let change = doc.get_changes(&[]).last().unwrap().clone();
    let node = ChangeNode {
        hash: change.hash().to_string(),
        dependencies: change.deps().iter().map(ToString::to_string).collect(),
        authority: None,
        change,
    };
    assert!(!application_source_change_may_touch(&mut doc, &node));
}

#[test]
fn a_scalar_edit_near_long_unchanged_prose_inspects_only_its_own_operation() {
    let (mut doc, owner, _seed, device, _certs, _) = source_base();
    let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
    let card = doc.get(&entities, "card").unwrap().unwrap().1;
    doc.put(&card, "body", "retained narrative ".repeat(10_000))
        .unwrap();
    commit_owner_edit(&mut doc, &owner, &device);
    doc.put(&card, "title", "Small label change").unwrap();
    commit_owner_edit(&mut doc, &owner, &device);
    let change = doc.get_changes(&[]).last().unwrap().clone();
    assert_eq!(change.len(), 1);
    let node = ChangeNode {
        hash: change.hash().to_string(),
        dependencies: change.deps().iter().map(ToString::to_string).collect(),
        authority: None,
        change,
    };
    assert!(!application_source_change_may_touch(&mut doc, &node));
}

#[test]
fn source_in_initial_document_remains_protected_against_later_map_deletion() {
    let (_base, owner, seed, device, certs, _) = source_base();
    let mut doc = AutoCommit::new();
    let entities = doc.put_object(ROOT, "entities", ObjType::Map).unwrap();
    let card = doc.put_object(&entities, "card", ObjType::Map).unwrap();
    doc.put(&card, "id", "card").unwrap();
    doc.put(&card, "body", "Retained job description").unwrap();
    doc.put_object(&card, "values", ObjType::Map).unwrap();
    let text = "Original posting";
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
    write_source(
        &mut doc,
        "genesis_source",
        &source_data(text, &digest, "genesis_source"),
    );
    commit_owner_edit(&mut doc, &owner, &device);
    let source_hash = doc.get_changes(&[])[0].hash().to_string();
    doc.delete(ROOT, "entities").unwrap();
    commit_owner_edit(&mut doc, &owner, &device);
    let delete_hash = doc.get_changes(&[]).last().unwrap().hash().to_string();
    let plan = evaluate(doc, owner, seed, device, certs);
    assert!(
        plan.decisions
            .iter()
            .any(|decision| decision.hash == source_hash
                && matches!(decision.status, CausalAdmissionStatus::Admitted { .. }))
    );
    assert!(
        plan.decisions
            .iter()
            .any(|decision| decision.hash == delete_hash
                && matches!(decision.status, CausalAdmissionStatus::Quarantined { .. }))
    );
}

#[test]
fn a_text_kind_cannot_create_a_source_outside_its_reserved_namespace() {
    let (mut doc, owner, seed, device, certs, _) = source_base();
    let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
    let alias = doc
        .put_object(&entities, "unreserved-alias", ObjType::Map)
        .unwrap();
    doc.put(&alias, "id", "unreserved-alias").unwrap();
    let kind = doc.put_object(&alias, "kind", ObjType::Text).unwrap();
    doc.splice_text(&kind, 0, 0, "application_source").unwrap();
    commit_owner_edit(&mut doc, &owner, &device);
    let hash = doc.get_changes(&[]).last().unwrap().hash().to_string();
    let plan = evaluate(doc, owner, seed, device, certs);
    assert!(plan.decisions.iter().any(|decision| decision.hash == hash
        && matches!(decision.status, CausalAdmissionStatus::Quarantined { .. })));
}
