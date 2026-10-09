use super::*;

use crate::{
    AutomationGrantScope, DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload,
    WorkspaceAuthority, WorkspaceChangeAuthorization, WorkspaceChangeAuthorizationPayload,
    WorkspaceGrant, WorkspaceGrantPayload, WorkspaceRole, WorkspaceWriteAuthorizationSnapshot,
    public_key_from_seed, public_key_id, sign_device_certificate, sign_json_envelope,
};
use automerge::{
    AutoCommit, ObjType, ROOT, ReadDoc,
    transaction::{CommitOptions, Transactable},
};

fn authority(
    seed: [u8; 32],
    device_seed: [u8; 32],
) -> (WorkspaceAuthority, [u8; 32], String, Vec<DeviceCertificate>) {
    let public_key = public_key_from_seed(&seed).unwrap();
    let person_id = public_key_id(&public_key).unwrap();
    let device_public_key = public_key_from_seed(&device_seed).unwrap();
    let device_id = public_key_id(&device_public_key).unwrap();
    let certificate = sign_device_certificate(
        &seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: person_id.clone(),
            device_id: device_id.clone(),
            device_public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    (
        WorkspaceAuthority {
            person_id,
            public_key,
            certificates: vec![certificate.clone()],
        },
        device_seed,
        device_id,
        vec![certificate],
    )
}

fn grant(
    owner: &WorkspaceAuthority,
    owner_seed: &[u8; 32],
    editor: &WorkspaceAuthority,
    epoch: u64,
) -> WorkspaceGrant {
    let payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: format!("editor-{epoch}"),
        workspace_id: "workspace".into(),
        person_id: editor.person_id.clone(),
        role: WorkspaceRole::Editor,
        access_epoch: Some(epoch),

        automation: None,
    };
    let signed = sign_json_envelope(
        owner_seed,
        serde_json::to_value(&payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    WorkspaceGrant {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    }
}

fn visitor_grant(
    owner: &WorkspaceAuthority,
    owner_seed: &[u8; 32],
    visitor: &WorkspaceAuthority,
) -> WorkspaceGrant {
    let payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: "visitor-profile".into(),
        workspace_id: "workspace".into(),
        person_id: visitor.person_id.clone(),
        role: WorkspaceRole::Visitor,
        access_epoch: Some(1),

        automation: None,
    };
    let signed = sign_json_envelope(
        owner_seed,
        serde_json::to_value(&payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    WorkspaceGrant {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    }
}

fn grant_hash(grant: &WorkspaceGrant) -> String {
    let value = serde_json::to_value(grant).unwrap();
    let canonical = crate::identity::canonicalize_json(&value).unwrap();
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn change_proof(
    authority: &WorkspaceAuthority,
    device_seed: &[u8; 32],
    device_id: &str,
    certificates: &[DeviceCertificate],
    hashes: &[String],
    grant: Option<WorkspaceGrant>,
) -> IncomingWorkspaceChangeAuthorization {
    let payload = WorkspaceChangeAuthorizationPayload {
        kind: "workspace-changes".into(),
        version: 1,
        workspace_id: "workspace".into(),
        hashes: hashes.to_vec(),
        person_id: authority.person_id.clone(),
        device_id: device_id.into(),
    };
    let signed = sign_json_envelope(
        device_seed,
        serde_json::to_value(&payload).unwrap(),
        device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    IncomingWorkspaceChangeAuthorization {
        signed: WorkspaceChangeAuthorization {
            payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        },
        public_key: authority.public_key.clone(),
        certificates: certificates.to_vec(),
        grant,
    }
}

fn change_metadata(grant: &WorkspaceGrant, person_id: &str, device_id: &str) -> String {
    serde_json::json!({
        "kind": "workspace-change-metadata",
        "version": 1,
        "authorityGrantHash": grant_hash(grant),
        "personId": person_id,
        "deviceId": device_id,
        "message": "edit"
    })
    .to_string()
}

fn snapshot(owner: WorkspaceAuthority, document: Vec<u8>) -> WorkspaceWriteAuthorizationSnapshot {
    WorkspaceWriteAuthorizationSnapshot {
        workspace_id: "workspace".into(),
        genesis_owner: owner.clone(),
        genesis_epoch: 1,
        expected_current_owner: owner,
        document,
        ownership_transfers: vec![],
        succession_claims: vec![],
        revocations: vec![],
        device_revocations: vec![],
        departures: vec![],
    }
}

fn document_with_editor_change(
    grant: &WorkspaceGrant,
    editor: &WorkspaceAuthority,
    editor_device_id: &str,
) -> (AutoCommit, String, String) {
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "genesis", "owner").unwrap();
    doc.commit();
    let genesis = doc.get_heads()[0].to_string();
    doc.put(ROOT, "editor", "edit").unwrap();
    doc.commit_with(CommitOptions::default().with_message(change_metadata(
        grant,
        &editor.person_id,
        editor_device_id,
    )));
    let editor_change = doc
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .find(|hash| hash != &genesis)
        .unwrap();
    (doc, genesis, editor_change)
}

fn write_avatar(doc: &mut AutoCommit, person_id: &str, avatar: Option<&str>) {
    let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
    let profile_id = format!("member-profile:{person_id}");
    match avatar {
        Some(avatar) => {
            let profile = doc.put_object(entities, profile_id, ObjType::Map).unwrap();
            put_js_text(doc, &profile, "id", &format!("member-profile:{person_id}"));
            put_js_text(doc, &profile, "kind", "member_profile");
            put_js_text(doc, &profile, "personId", person_id);
            put_js_text(
                doc,
                &profile,
                "data",
                &serde_json::json!({
                    "avatarData": avatar, "changedAt": "2026-10-07T10:00:00Z"
                })
                .to_string(),
            );
            put_js_text(doc, &profile, "title", "Member profile");
            doc.put(&profile, "archivedAt", automerge::ScalarValue::Null)
                .unwrap();
            put_js_text(doc, &profile, "createdAt", "2026-10-07T10:00:00Z");
            put_js_text(doc, &profile, "updatedAt", "2026-10-07T10:00:00Z");
            let placement = doc.put_object(&profile, "placement", ObjType::Map).unwrap();
            doc.put(&placement, "parentId", automerge::ScalarValue::Null)
                .unwrap();
            put_js_text(doc, &placement, "rank", "0/1");
        }
        None => {
            doc.delete(entities, profile_id).unwrap();
        }
    }
}

fn put_js_text(doc: &mut AutoCommit, parent: &automerge::ObjId, key: &str, value: &str) {
    let text = doc.put_object(parent, key, ObjType::Text).unwrap();
    doc.splice_text(&text, 0, 0, value).unwrap();
}

fn automation_board() -> AutoCommit {
    let mut doc = AutoCommit::new();
    let entities = doc.put_object(ROOT, "entities", ObjType::Map).unwrap();
    let board = doc.put_object(&entities, "board", ObjType::Map).unwrap();
    put_js_text(&mut doc, &board, "id", "board");
    put_js_text(&mut doc, &board, "kind", "board");
    doc.put(&board, "archivedAt", automerge::ScalarValue::Null)
        .unwrap();
    doc.put(&board, "archiveColumnId", automerge::ScalarValue::Null)
        .unwrap();
    for id in ["lead", "interview", "rejected", "other"] {
        let column = doc.put_object(&entities, id, ObjType::Map).unwrap();
        put_js_text(&mut doc, &column, "id", id);
        put_js_text(&mut doc, &column, "kind", "column");
        doc.put(&column, "archivedAt", automerge::ScalarValue::Null)
            .unwrap();
        let placement = doc.put_object(&column, "placement", ObjType::Map).unwrap();
        put_js_text(&mut doc, &placement, "parentId", "board");
        put_js_text(&mut doc, &placement, "rank", "0/1");
    }
    let field = doc.put_object(&entities, "source", ObjType::Map).unwrap();
    put_js_text(&mut doc, &field, "id", "source");
    put_js_text(&mut doc, &field, "kind", "field");
    let field_placement = doc.put_object(&field, "placement", ObjType::Map).unwrap();
    put_js_text(&mut doc, &field_placement, "parentId", "board");
    put_js_text(&mut doc, &field_placement, "rank", "0/1");
    doc.commit();
    doc
}

fn write_automation_item(doc: &mut AutoCommit, id: &str, parent_id: &str, change_root: bool) {
    write_automation_item_with_message(doc, id, parent_id, change_root, None);
}

fn write_automation_item_with_message(
    doc: &mut AutoCommit,
    id: &str,
    parent_id: &str,
    change_root: bool,
    message: Option<String>,
) {
    let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
    let item = doc.put_object(entities, id, ObjType::Map).unwrap();
    put_js_text(doc, &item, "id", id);
    put_js_text(doc, &item, "title", "Company");
    put_js_text(doc, &item, "body", "Job description");
    doc.put(&item, "archivedAt", automerge::ScalarValue::Null)
        .unwrap();
    let values = doc.put_object(&item, "values", ObjType::Map).unwrap();
    put_js_text(doc, &values, "source", "website");
    let placement = doc.put_object(&item, "placement", ObjType::Map).unwrap();
    put_js_text(doc, &placement, "parentId", parent_id);
    put_js_text(doc, &placement, "rank", "0/1");
    if change_root {
        put_js_text(doc, &ROOT, "title", "tampered workspace");
    }
    match message {
        Some(message) => {
            doc.commit_with(CommitOptions::default().with_message(message));
        }
        None => {
            doc.commit();
        }
    }
}

fn automation_scope() -> AutomationGrantScope {
    AutomationGrantScope {
        version: 1,
        board_id: "board".into(),
        columns: crate::AutomationGrantColumns {
            lead: "lead".into(),
            interview: "interview".into(),
            rejected: "rejected".into(),
        },
        field_ids: vec!["source".into()],
        expires_at: 1_900_000_000_000,
    }
}

#[test]
fn automation_semantics_allow_lead_creation_and_reject_root_mutation() {
    for (change_root, expected) in [(false, true), (true, false)] {
        let mut doc = automation_board();
        let dependencies = doc.get_heads();
        write_automation_item(&mut doc, "new-card", "lead", change_root);
        let change = doc.get_changes(&[]).last().unwrap().clone();
        let node = ChangeNode {
            hash: change.hash().to_string(),
            dependencies: change.deps().iter().map(ToString::to_string).collect(),
            authority: None,
            change,
        };
        assert_eq!(
            automation_change_allowed(&mut doc, &node, &automation_scope()).is_ok(),
            expected,
            "base heads {dependencies:?}"
        );
    }
}

#[test]
fn automation_semantics_allow_status_move_and_reject_narrative_edit() {
    for (edit_title, expected) in [(false, true), (true, false)] {
        let mut doc = automation_board();
        write_automation_item(&mut doc, "existing-card", "other", false);
        let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
        let item = doc.get(entities, "existing-card").unwrap().unwrap().1;
        let placement = doc.get(&item, "placement").unwrap().unwrap().1;
        doc.put(&placement, "parentId", "interview").unwrap();
        if edit_title {
            doc.put(&item, "title", "changed narrative").unwrap();
        }
        doc.commit();
        let change = doc.get_changes(&[]).last().unwrap().clone();
        let node = ChangeNode {
            hash: change.hash().to_string(),
            dependencies: change.deps().iter().map(ToString::to_string).collect(),
            authority: None,
            change,
        };
        assert_eq!(
            automation_change_allowed(&mut doc, &node, &automation_scope()).is_ok(),
            expected
        );
    }
}

#[test]
fn automation_semantics_accept_json_encoded_workflow_from_domain_commands() {
    let mut doc = automation_board();
    write_automation_item(&mut doc, "existing-card", "other", false);
    let entities = doc.get(ROOT, "entities").unwrap().unwrap().1;
    let item = doc.get(entities, "existing-card").unwrap().unwrap().1;
    let placement = doc.get(&item, "placement").unwrap().unwrap().1;
    doc.put(&placement, "parentId", "interview").unwrap();
    doc.put(
        &item,
        "workflow",
        r#"{"columnId":"interview","changedAt":"2026-10-08T12:00:00.000Z"}"#,
    )
    .unwrap();
    doc.commit();
    let change = doc.get_changes(&[]).last().unwrap().clone();
    let node = ChangeNode {
        hash: change.hash().to_string(),
        dependencies: change.deps().iter().map(ToString::to_string).collect(),
        authority: None,
        change,
    };

    assert!(
        automation_change_allowed(&mut doc, &node, &automation_scope()).is_ok(),
        "canonical JSON-string workflow written by setItemWorkflow must validate"
    );
}

#[test]
fn concurrent_human_move_wins_over_automation_move_in_causal_projection() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([101; 32], [102; 32]);
    let (automation, automation_device_seed, automation_device_id, automation_certs) =
        authority([103; 32], [104; 32]);
    let mut base = automation_board();
    let owner_metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "transactionId": "seed-card", "action": "createItem", "entityIds": ["card"],
        "personId": owner.person_id, "deviceId": owner_device_id,
    })
    .to_string();
    write_automation_item_with_message(&mut base, "card", "other", false, Some(owner_metadata));
    let base_heads = base.get_heads();
    let automation_grant_payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: "automation-current".into(),
        workspace_id: "workspace".into(),
        person_id: automation.person_id.clone(),
        role: WorkspaceRole::Automation,
        access_epoch: Some(1),
        automation: Some(automation_scope()),
    };
    let automation_grant = {
        let signed = sign_json_envelope(
            &[101; 32],
            serde_json::to_value(&automation_grant_payload).unwrap(),
            &owner.person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        WorkspaceGrant {
            payload: automation_grant_payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        }
    };

    let mut human_branch = base.fork();
    let entities = human_branch.get(ROOT, "entities").unwrap().unwrap().1;
    let item = human_branch.get(entities, "card").unwrap().unwrap().1;
    let placement = human_branch.get(&item, "placement").unwrap().unwrap().1;
    human_branch
        .put(&placement, "parentId", "rejected")
        .unwrap();
    let human_metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "transactionId": "human-move", "action": "moveEntity", "entityIds": ["card"],
        "personId": owner.person_id, "deviceId": owner_device_id,
    })
    .to_string();
    human_branch.commit_with(CommitOptions::default().with_message(human_metadata));
    let human_change = human_branch.get_changes(&base_heads).remove(0);

    let mut automation_branch = base.fork();
    let entities = automation_branch.get(ROOT, "entities").unwrap().unwrap().1;
    let item = automation_branch.get(entities, "card").unwrap().unwrap().1;
    let placement = automation_branch
        .get(&item, "placement")
        .unwrap()
        .unwrap()
        .1;
    automation_branch
        .put(&placement, "parentId", "interview")
        .unwrap();
    let automation_metadata = serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "transactionId": "automation-move", "action": "moveEntity", "entityIds": ["card"],
        "personId": automation.person_id, "deviceId": automation_device_id,
        "authorityGrantHash": grant_hash(&automation_grant),
    })
    .to_string();
    automation_branch.commit_with(CommitOptions::default().with_message(automation_metadata));
    let automation_change = automation_branch.get_changes(&base_heads).remove(0);

    let mut raw_union = base.fork();
    raw_union
        .apply_changes(vec![human_change.clone(), automation_change.clone()])
        .unwrap();
    let all_base_hashes = base
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .collect::<Vec<_>>();
    let human_hash = human_change.hash().to_string();
    let automation_hash = automation_change.hash().to_string();
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records: vec![
            change_proof(
                &owner,
                &owner_device_seed,
                &owner_device_id,
                &owner_certs,
                &all_base_hashes,
                None,
            ),
            change_proof(
                &owner,
                &owner_device_seed,
                &owner_device_id,
                &owner_certs,
                std::slice::from_ref(&human_hash),
                None,
            ),
            change_proof(
                &automation,
                &automation_device_seed,
                &automation_device_id,
                &automation_certs,
                std::slice::from_ref(&automation_hash),
                Some(automation_grant),
            ),
        ],
        snapshot: snapshot(owner, raw_union.save()),
        pending_change_bytes: vec![],
        now_ms: 100,
    })
    .unwrap();
    assert!(matches!(
        result
            .decisions
            .iter()
            .find(|decision| decision.hash == human_hash)
            .unwrap()
            .status,
        CausalAdmissionStatus::Admitted {
            role: WorkspaceRole::Owner
        }
    ));
    assert!(
        matches!(
            result
                .decisions
                .iter()
                .find(|decision| decision.hash == automation_hash)
                .unwrap()
                .status,
            CausalAdmissionStatus::Quarantined { .. }
        ),
        "concurrent human move must quarantine stale automation proposal"
    );
    let projected = AutoCommit::load(&result.authorized_document).unwrap();
    let entities = projected.get(ROOT, "entities").unwrap().unwrap().1;
    let item = projected.get(entities, "card").unwrap().unwrap().1;
    let placement = projected.get(&item, "placement").unwrap().unwrap().1;
    let parent_value = projected.get(&placement, "parentId").unwrap().unwrap().0;
    assert_eq!(
        serde_json::from_str::<String>(&parent_value.to_string()).unwrap(),
        "rejected"
    );
}

fn visitor_avatar_document(
    mixed_root: bool,
    foreign_profile: bool,
    remove_avatar: bool,
) -> (
    WorkspaceAuthority,
    AutoCommit,
    Vec<IncomingWorkspaceChangeAuthorization>,
    String,
) {
    let (owner, owner_seed, owner_device_id, owner_certs) = authority([81; 32], [82; 32]);
    let (visitor, visitor_device_seed, visitor_device_id, visitor_certs) =
        authority([83; 32], [84; 32]);
    let grant = visitor_grant(&owner, &[81; 32], &visitor);
    let mut doc = AutoCommit::new();
    doc.put_object(ROOT, "entities", ObjType::Map).unwrap();
    doc.put(ROOT, "title", "Workspace").unwrap();
    doc.commit();
    let genesis = doc
        .get_changes(&[])
        .into_iter()
        .next()
        .unwrap()
        .hash()
        .to_string();
    let genesis_record = change_proof(
        &owner,
        &owner_seed,
        &owner_device_id,
        &owner_certs,
        &[genesis.clone()],
        None,
    );
    write_avatar(
        &mut doc,
        &visitor.person_id,
        Some("data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAfwAAfwAA"),
    );
    if mixed_root {
        doc.put(ROOT, "title", "Injected title").unwrap();
    }
    if foreign_profile {
        write_avatar(
            &mut doc,
            &owner.person_id,
            Some("data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAfwAAfwAA"),
        );
    }
    let visitor_metadata = || {
        serde_json::json!({
        "kind": "workspace-change-metadata", "version": 1,
        "personId": visitor.person_id, "deviceId": visitor_device_id,
        "action": "setMemberAvatar", "entityIds": [format!("member-profile:{}", visitor.person_id)]
    }).to_string()
    };
    doc.commit_with(CommitOptions::default().with_message(visitor_metadata()));
    if remove_avatar {
        write_avatar(&mut doc, &visitor.person_id, None);
        doc.commit_with(CommitOptions::default().with_message(visitor_metadata()));
    }
    let visitor_changes = doc
        .get_changes(&[])
        .into_iter()
        .map(|change| change.hash().to_string())
        .filter(|hash| hash != &genesis)
        .collect::<Vec<_>>();
    let visitor_record = change_proof(
        &visitor,
        &visitor_device_seed,
        &visitor_device_id,
        &visitor_certs,
        &visitor_changes,
        Some(grant.clone()),
    );
    (
        owner,
        doc,
        vec![genesis_record, visitor_record],
        visitor.person_id,
    )
}

#[test]
fn visitor_avatar_change_is_admitted_but_mixed_and_foreign_profile_changes_are_quarantined() {
    for (mixed_root, foreign_profile, remove_avatar, admitted) in [
        (false, false, false, true),
        (false, false, true, true),
        (true, false, false, false),
        (false, true, false, false),
    ] {
        let (owner, mut doc, records, _) =
            visitor_avatar_document(mixed_root, foreign_profile, remove_avatar);
        let plan = evaluate_causal_admission(CausalAdmissionInput {
            records,
            snapshot: snapshot(owner, doc.save()),
            pending_change_bytes: vec![],
            now_ms: 0,
        })
        .unwrap();
        let visitor_decisions = plan
            .decisions
            .iter()
            .filter(|decision| {
                matches!(
                    decision.status,
                    CausalAdmissionStatus::Admitted {
                        role: WorkspaceRole::Visitor
                    }
                ) || matches!(decision.status, CausalAdmissionStatus::Quarantined { .. })
            })
            .collect::<Vec<_>>();
        assert!(!visitor_decisions.is_empty());
        assert!(visitor_decisions.iter().all(|decision| matches!(
            decision.status,
            CausalAdmissionStatus::Admitted { .. }
        ) == admitted));
        if remove_avatar {
            assert_eq!(visitor_decisions.len(), 2);
        }
    }
}

#[test]
fn avatar_payload_requires_bounded_128_pixel_image_headers() {
    let data = |avatar_data: &str| {
        serde_json::json!({
            "avatarData": avatar_data, "changedAt": "2026-10-07T10:00:00Z"
        })
        .to_string()
    };
    assert!(valid_avatar_data(&data(
        "data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAfwAAfwAA"
    )));
    assert!(!valid_avatar_data(&data(
        "data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAPwAAfwAA"
    )));
    assert!(!valid_avatar_data(&data("data:image/webp;base64,AA==")));
}

#[test]
fn actual_change_metadata_binds_editor_proof_to_signed_grant() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([11; 32], [12; 32]);
    let (editor, editor_device_seed, editor_device_id, editor_certs) =
        authority([13; 32], [14; 32]);
    let old_grant = grant(&owner, &[11; 32], &editor, 1);
    let (mut doc, genesis, editor_change) =
        document_with_editor_change(&old_grant, &editor, &editor_device_id);
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &editor,
            &editor_device_seed,
            &editor_device_id,
            &editor_certs,
            std::slice::from_ref(&editor_change),
            Some(old_grant.clone()),
        ),
    ];
    let snapshot = snapshot(owner, doc.save());
    let evaluate = |now_ms| {
        evaluate_causal_admission(CausalAdmissionInput {
            records: records.clone(),
            snapshot: snapshot.clone(),
            pending_change_bytes: vec![],
            now_ms,
        })
        .unwrap()
    };
    let at_epoch = evaluate(0);
    let far_future = evaluate(i128::MAX / 3);
    assert_eq!(at_epoch, far_future);
    assert_eq!(at_epoch.decisions.len(), 2);
    assert!(
        at_epoch
            .decisions
            .iter()
            .all(|entry| matches!(entry.status, CausalAdmissionStatus::Admitted { .. }))
    );
    let projected = AutoCommit::load(&at_epoch.authorized_document).unwrap();
    assert_eq!(
        projected
            .get(ROOT, "editor")
            .unwrap()
            .unwrap()
            .0
            .to_string(),
        "\"edit\""
    );
}

#[test]
fn authorized_projection_bytes_ignore_pending_change_arrival_order() {
    let (owner, device_seed, device_id, certificates) = authority([17; 32], [18; 32]);
    let mut root = AutoCommit::new();
    root.put(ROOT, "root", "value").unwrap();
    root.commit();
    let root_change = root.get_changes(&[]).into_iter().next().unwrap();
    let root_hash = root_change.hash().to_string();
    let mut left = root.fork();
    left.set_actor(automerge::ActorId::from(&b"left-actor"[..]));
    left.put(ROOT, "left", "value").unwrap();
    left.commit();
    let left_change = left.get_changes(&[]).into_iter().last().unwrap();
    let mut right = root.fork();
    right.set_actor(automerge::ActorId::from(&b"right-actor"[..]));
    right.put(ROOT, "right", "value").unwrap();
    right.commit();
    let right_change = right.get_changes(&[]).into_iter().last().unwrap();
    let left_hash = left_change.hash().to_string();
    let right_hash = right_change.hash().to_string();
    let records = vec![
        change_proof(
            &owner,
            &device_seed,
            &device_id,
            &certificates,
            &[root_hash],
            None,
        ),
        change_proof(
            &owner,
            &device_seed,
            &device_id,
            &certificates,
            &[left_hash],
            None,
        ),
        change_proof(
            &owner,
            &device_seed,
            &device_id,
            &certificates,
            &[right_hash],
            None,
        ),
    ];
    let snapshot = snapshot(owner, root.save());
    let evaluate = |pending_change_bytes| {
        evaluate_causal_admission(CausalAdmissionInput {
            records: records.clone(),
            snapshot: snapshot.clone(),
            pending_change_bytes,
            now_ms: 0,
        })
        .unwrap()
    };
    let forward = evaluate(vec![
        left_change.raw_bytes().to_vec(),
        right_change.raw_bytes().to_vec(),
    ]);
    let reverse = evaluate(vec![
        right_change.raw_bytes().to_vec(),
        left_change.raw_bytes().to_vec(),
    ]);
    assert_eq!(forward.authorized_document, reverse.authorized_document);
}

#[test]
fn regrant_cannot_rebind_existing_editor_change_hash() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([21; 32], [22; 32]);
    let (editor, editor_device_seed, editor_device_id, editor_certs) =
        authority([23; 32], [24; 32]);
    let old_grant = grant(&owner, &[21; 32], &editor, 1);
    let newer_grant = grant(&owner, &[21; 32], &editor, 3);
    let (mut doc, genesis, editor_change) =
        document_with_editor_change(&old_grant, &editor, &editor_device_id);
    let mut snap = snapshot(owner.clone(), doc.save());
    let revocation_payload = crate::WorkspaceRevocationPayload {
        kind: "workspace-revocation".into(),
        version: 1,
        workspace_id: "workspace".into(),
        owner_person_id: owner.person_id.clone(),
        person_id: editor.person_id.clone(),
        epoch: 2,
        workspace_heads: vec![genesis.clone()],
        revoked_at: "2099-01-01T00:00:00.000Z".into(),
    };
    let signed_revocation = sign_json_envelope(
        &[21; 32],
        serde_json::to_value(&revocation_payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    snap.revocations.push(crate::WorkspaceRevocation {
        payload: revocation_payload,
        signer_key_id: signed_revocation.signer_key_id,
        signature: signed_revocation.signature,
    });
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &editor,
            &editor_device_seed,
            &editor_device_id,
            &editor_certs,
            std::slice::from_ref(&editor_change),
            Some(newer_grant),
        ),
    ];
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot: snap,
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap_or_else(|error| panic!("causal validation must ignore receiver clock: {error}"));
    let editor_decision = result
        .decisions
        .iter()
        .find(|entry| entry.hash == editor_change)
        .unwrap();
    assert!(
        matches!(
            &editor_decision.status,
            CausalAdmissionStatus::Quarantined { reason }
                if reason.contains("grant provenance")
        ),
        "new grant must not rebind old editor change"
    );
    let projected = AutoCommit::load(&result.authorized_document).unwrap();
    assert!(projected.get(ROOT, "editor").unwrap().is_none());
}

#[test]
fn owner_proof_cannot_rebind_legacy_editor_change_after_revocation() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([51; 32], [52; 32]);
    let (editor, _, editor_device_id, _) = authority([53; 32], [54; 32]);
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "genesis", "owner").unwrap();
    doc.commit();
    let genesis = doc.get_heads()[0].to_string();
    doc.put(ROOT, "legacy-editor", "edit").unwrap();
    doc.commit_with(
        CommitOptions::default().with_message(
            serde_json::json!({
                "version": 1,
                "transactionId": "legacy-1",
                "action": "set",
                "entityIds": ["legacy-editor"],
                "personId": editor.person_id,
                "deviceId": editor_device_id
            })
            .to_string(),
        ),
    );
    let editor_hash = doc.get_heads()[0].to_string();
    let mut snapshot = snapshot(owner.clone(), doc.save());
    let revocation_payload = crate::WorkspaceRevocationPayload {
        kind: "workspace-revocation".into(),
        version: 1,
        workspace_id: "workspace".into(),
        owner_person_id: owner.person_id.clone(),
        person_id: editor.person_id.clone(),
        epoch: 2,
        workspace_heads: vec![genesis.clone()],
        revoked_at: "2099-01-01T00:00:00.000Z".into(),
    };
    let signed = sign_json_envelope(
        &[51; 32],
        serde_json::to_value(&revocation_payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    snapshot.revocations.push(crate::WorkspaceRevocation {
        payload: revocation_payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    });
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[editor_hash.clone()],
            None,
        ),
    ];
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    let decision = result
        .decisions
        .iter()
        .find(|entry| entry.hash == editor_hash)
        .unwrap();
    assert!(
        matches!(&decision.status, CausalAdmissionStatus::Quarantined { reason }
            if reason.contains("identity metadata")),
        "owner cannot rebind prior editor identity metadata"
    );
}

#[test]
fn owner_proof_cannot_rebind_identityless_legacy_change_outside_frontier() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([61; 32], [62; 32]);
    let (editor, _, _, _) = authority([63; 32], [64; 32]);
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "genesis", "owner").unwrap();
    doc.commit();
    let genesis = doc.get_heads()[0].to_string();
    doc.put(ROOT, "legacy-editor", "edit").unwrap();
    doc.commit();
    let editor_hash = doc.get_heads()[0].to_string();
    let mut snapshot = snapshot(owner.clone(), doc.save());
    let revocation_payload = crate::WorkspaceRevocationPayload {
        kind: "workspace-revocation".into(),
        version: 1,
        workspace_id: "workspace".into(),
        owner_person_id: owner.person_id.clone(),
        person_id: editor.person_id,
        epoch: 2,
        workspace_heads: vec![genesis.clone()],
        revoked_at: "2099-01-01T00:00:00.000Z".into(),
    };
    let signed = sign_json_envelope(
        &[61; 32],
        serde_json::to_value(&revocation_payload).unwrap(),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    snapshot.revocations.push(crate::WorkspaceRevocation {
        payload: revocation_payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    });
    let records = vec![
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[genesis],
            None,
        ),
        change_proof(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &[editor_hash.clone()],
            None,
        ),
    ];
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes: vec![],
        now_ms: 0,
    })
    .unwrap();
    let decision = result
        .decisions
        .iter()
        .find(|entry| entry.hash == editor_hash)
        .unwrap();
    assert!(
        matches!(&decision.status, CausalAdmissionStatus::Quarantined { reason }
            if reason.contains("identity metadata")),
        "owner cannot rebind identityless legacy non-genesis change outside frontier"
    );
}

#[test]
fn pending_raw_change_with_missing_dependency_is_retained_pending() {
    let (owner, owner_device_seed, owner_device_id, owner_certs) = authority([31; 32], [32; 32]);
    let mut source = AutoCommit::new();
    source
        .put(ROOT, "parent", "present in source only")
        .unwrap();
    source.commit();
    source.put(ROOT, "value", "child").unwrap();
    source.commit();
    let child = source.get_changes(&[]).into_iter().last().unwrap();
    let child_hash = child.hash().to_string();
    let record = change_proof(
        &owner,
        &owner_device_seed,
        &owner_device_id,
        &owner_certs,
        std::slice::from_ref(&child_hash),
        None,
    );
    let result = evaluate_causal_admission(CausalAdmissionInput {
        records: vec![record],
        snapshot: snapshot(owner, AutoCommit::new().save()),
        pending_change_bytes: vec![child.raw_bytes().to_vec()],
        now_ms: 0,
    })
    .unwrap();
    assert!(
        matches!(
            &result.decisions[0].status,
            CausalAdmissionStatus::Pending { reason } if reason.contains("dependency is missing")
        ),
        "missing dependency must stay pending"
    );
    let projection = AutoCommit::load(&result.authorized_document).unwrap();
    assert!(projection.get(ROOT, "value").unwrap().is_none());
}

#[test]
fn admitted_order_matches_layer_scan_for_dags_and_rejects_cycles() {
    fn old_layer_scan(
        nodes: &[(String, Vec<String>)],
        included: &HashSet<String>,
    ) -> Result<Vec<String>, ()> {
        let mut remaining = included.clone();
        let mut ordered = Vec::with_capacity(remaining.len());
        while !remaining.is_empty() {
            let mut ready = remaining
                .iter()
                .filter(|hash| {
                    nodes
                        .iter()
                        .find(|(candidate, _)| candidate == *hash)
                        .is_some_and(|(_, dependencies)| {
                            dependencies.iter().all(|dep| !remaining.contains(dep))
                        })
                })
                .cloned()
                .collect::<Vec<_>>();
            ready.sort();
            if ready.is_empty() {
                return Err(());
            }
            for hash in ready {
                remaining.remove(&hash);
                ordered.push(hash);
            }
        }
        Ok(ordered)
    }

    let mut seed = 0x9e37_79b9_u32;
    for fixture in 0..100 {
        let count = 1 + fixture % 40;
        let mut nodes = Vec::with_capacity(count);
        for index in 0..count {
            let hash = format!("hash-{index:03}");
            let mut dependencies = Vec::new();
            for parent in 0..index {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if seed % 7 == 0 {
                    let parent_hash = format!("hash-{parent:03}");
                    dependencies.push(parent_hash.clone());
                    if fixture % 5 == 0 && seed % 2 == 0 {
                        dependencies.push(parent_hash);
                    }
                }
            }
            if fixture % 3 == 0 && index == count - 1 {
                dependencies.push("missing-parent".into());
            }
            nodes.push((hash, dependencies));
        }
        if fixture % 2 == 0 {
            nodes.reverse();
        }
        let included = nodes
            .iter()
            .map(|(hash, _)| hash.clone())
            .collect::<HashSet<_>>();
        let expected = old_layer_scan(&nodes, &included).unwrap();
        let actual = ordered_admitted_hashes(
            nodes
                .iter()
                .map(|(hash, deps)| (hash.as_str(), deps.as_slice())),
            &included,
        )
        .unwrap();
        assert_eq!(
            actual, expected,
            "frontier ordering differs for fixture {fixture}"
        );
    }

    let cyclic = vec![
        ("a".to_string(), vec!["b".to_string()]),
        ("b".to_string(), vec!["a".to_string()]),
    ];
    let included = cyclic
        .iter()
        .map(|(hash, _)| hash.clone())
        .collect::<HashSet<_>>();
    assert!(old_layer_scan(&cyclic, &included).is_err());
    assert_eq!(
        ordered_admitted_hashes(
            cyclic
                .iter()
                .map(|(hash, deps)| (hash.as_str(), deps.as_slice())),
            &included,
        ),
        Err("Authorized workspace change dependencies are cyclic".into())
    );
}

#[test]
fn admitted_order_handles_twenty_thousand_change_chain() {
    let nodes = (0..20_000)
        .map(|index| {
            let hash = format!("hash-{index:05}");
            let dependencies: Vec<String> = (index > 0)
                .then(|| format!("hash-{:05}", index - 1))
                .into_iter()
                .collect();
            (hash, dependencies)
        })
        .collect::<Vec<_>>();
    let included = nodes
        .iter()
        .map(|(hash, _)| hash.clone())
        .collect::<HashSet<_>>();
    let ordered = ordered_admitted_hashes(
        nodes
            .iter()
            .map(|(hash, deps)| (hash.as_str(), deps.as_slice())),
        &included,
    )
    .unwrap();
    assert_eq!(ordered.first().map(String::as_str), Some("hash-00000"));
    assert_eq!(ordered.last().map(String::as_str), Some("hash-19999"));
    assert_eq!(ordered.len(), nodes.len());
}

#[test]
fn identity_photo_removal_accepts_a_timestamped_null_avatar_but_not_other_payloads() {
    assert!(valid_avatar_data(r#"{"avatarData":null,"changedAt":"2026-10-09T14:00:00.000Z"}"#));
    assert!(!valid_avatar_data(r#"{"avatarData":null,"changedAt":"invalid"}"#));
    assert!(!valid_avatar_data(r#"{"avatarData":null,"changedAt":"2026-10-09T14:00:00.000Z","owner":true}"#));
}
