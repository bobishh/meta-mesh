use std::{
    collections::{HashMap, HashSet},
    fs,
};

use automerge::{
    AutoCommit, Change, ROOT,
    transaction::{CommitOptions, Transactable},
};
use meta_mesh_core::causal_admission::{
    CausalAdmissionInput, CausalAdmissionStatus, evaluate_causal_admission,
};
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload,
    IncomingWorkspaceChangeAuthorization, WorkspaceAuthority, WorkspaceChangeAuthorization,
    WorkspaceChangeAuthorizationPayload, WorkspaceGrant, WorkspaceGrantPayload,
    WorkspaceRevocation, WorkspaceRevocationPayload, WorkspaceRole,
    WorkspaceWriteAuthorizationSnapshot, public_key_from_seed, public_key_id,
    sign_device_certificate, sign_json_envelope,
};
use serde_json::Value;
use sha2::Digest;

const IDS: [&str; 5] = [
    "root",
    "inside",
    "outside",
    "regrant-edit",
    "depends-on-outside",
];

struct Fixture {
    owner: WorkspaceAuthority,
    owner_seed: [u8; 32],
    editor: WorkspaceAuthority,
    root_doc: AutoCommit,
    changes: HashMap<String, Change>,
    hashes: HashMap<String, String>,
    records: HashMap<(String, u64), IncomingWorkspaceChangeAuthorization>,
}

fn new_authority(
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

fn signed_grant(
    owner: &WorkspaceAuthority,
    owner_seed: &[u8; 32],
    editor: &WorkspaceAuthority,
    epoch: u64,
) -> WorkspaceGrant {
    let payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: format!("model-grant-{epoch}"),
        workspace_id: "workspace".into(),
        person_id: editor.person_id.clone(),
        role: WorkspaceRole::Editor,
        access_epoch: Some(epoch),
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
    let canonical = meta_mesh_core::canonicalize_json(&value).unwrap();
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(canonical.as_bytes()))
}

fn change_message(
    grant: &WorkspaceGrant,
    editor: &WorkspaceAuthority,
    device_id: &str,
    label: &str,
) -> String {
    serde_json::json!({
        "kind": "workspace-change-metadata",
        "version": 1,
        "authorityGrantHash": grant_hash(grant),
        "personId": editor.person_id,
        "deviceId": device_id,
        "transactionId": format!("tx-{label}"),
        "action": "set",
        "entityIds": [label],
        "message": label
    })
    .to_string()
}

fn branch_change(
    base: &mut AutoCommit,
    actor: &[u8],
    key: &str,
    message: String,
    time: i64,
) -> Change {
    let mut branch = base.fork();
    branch.set_actor(automerge::ActorId::from(actor));
    branch.put(ROOT, key, key).unwrap();
    branch.commit_with(
        CommitOptions::default()
            .with_message(message)
            .with_time(time),
    );
    branch.get_changes(&[]).into_iter().last().unwrap()
}

fn signed_record(
    authority: &WorkspaceAuthority,
    device_seed: &[u8; 32],
    device_id: &str,
    certificates: &[DeviceCertificate],
    hash: &str,
    grant: Option<WorkspaceGrant>,
) -> IncomingWorkspaceChangeAuthorization {
    let payload = WorkspaceChangeAuthorizationPayload {
        kind: "workspace-changes".into(),
        version: 1,
        workspace_id: "workspace".into(),
        hashes: vec![hash.into()],
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

fn make_fixture() -> Fixture {
    let (owner, owner_device_seed, owner_device_id, owner_certs) =
        new_authority([41; 32], [42; 32]);
    let (editor, editor_device_seed, editor_device_id, editor_certs) =
        new_authority([43; 32], [44; 32]);
    let old_grant = signed_grant(&owner, &[41; 32], &editor, 1);
    let new_grant = signed_grant(&owner, &[41; 32], &editor, 3);
    let mut root_doc = AutoCommit::new();
    root_doc.set_actor(automerge::ActorId::from(&b"owner-root"[..]));
    root_doc.put(ROOT, "root", "root").unwrap();
    root_doc.commit_with(CommitOptions::default().with_time(-10_000));
    let root = root_doc.get_changes(&[]).into_iter().last().unwrap();

    let inside = branch_change(
        &mut root_doc,
        b"editor-inside",
        "inside",
        change_message(&old_grant, &editor, &editor_device_id, "inside"),
        -10_000,
    );
    let outside = branch_change(
        &mut root_doc,
        b"editor-outside",
        "outside",
        change_message(&old_grant, &editor, &editor_device_id, "outside"),
        8_640_000_000_000,
    );
    let regrant = branch_change(
        &mut root_doc,
        b"editor-regrant",
        "regrant-edit",
        change_message(&new_grant, &editor, &editor_device_id, "regrant-edit"),
        -10_000,
    );
    let mut outside_base = AutoCommit::new();
    outside_base
        .apply_changes([root.clone(), outside.clone()])
        .unwrap();
    let child = branch_change(
        &mut outside_base,
        b"editor-outside-child",
        "depends-on-outside",
        change_message(&new_grant, &editor, &editor_device_id, "depends-on-outside"),
        -10_000,
    );

    let changes: HashMap<String, Change> = HashMap::from([
        ("root".into(), root),
        ("inside".into(), inside),
        ("outside".into(), outside),
        ("regrant-edit".into(), regrant),
        ("depends-on-outside".into(), child),
    ]);
    let hashes = changes
        .iter()
        .map(|(id, change)| (id.clone(), change.hash().to_string()))
        .collect::<HashMap<_, _>>();
    let mut records = HashMap::new();
    for id in ["inside", "outside"] {
        records.insert(
            (id.into(), 1),
            signed_record(
                &editor,
                &editor_device_seed,
                &editor_device_id,
                &editor_certs,
                &hashes[id],
                Some(old_grant.clone()),
            ),
        );
    }
    for id in ["regrant-edit", "depends-on-outside"] {
        records.insert(
            (id.into(), 3),
            signed_record(
                &editor,
                &editor_device_seed,
                &editor_device_id,
                &editor_certs,
                &hashes[id],
                Some(new_grant.clone()),
            ),
        );
    }
    records.insert(
        ("root".into(), 0),
        signed_record(
            &owner,
            &owner_device_seed,
            &owner_device_id,
            &owner_certs,
            &hashes["root"],
            None,
        ),
    );
    Fixture {
        owner,
        owner_seed: [41; 32],
        editor,
        root_doc,
        changes,
        hashes,
        records,
    }
}

fn model_input(fixture: &Fixture, state: &Value, replica: &str) -> CausalAdmissionInput {
    let raw = state["raw"].as_array().unwrap();
    let received = raw
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<HashSet<_>>();
    let proofs_value = if state["proofs"].is_object() {
        &state["proofs"][replica]
    } else {
        &state["proofs"]
    };
    let proofs = proofs_value
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    let mut records = vec![fixture.records[&(String::from("root"), 0)].clone()];
    for id in IDS
        .iter()
        .copied()
        .filter(|id| *id != "root" && received.contains(*id))
    {
        let epoch = if matches!(id, "inside" | "outside") {
            1
        } else {
            3
        };
        if epoch == 1 || proofs.contains("regrant") {
            records.push(fixture.records[&(id.to_string(), epoch)].clone());
        }
    }

    // Signed revocation frontier ends at `inside`; its verified ancestry contains
    // root and inside. Keep all other received changes as parseable pending bytes
    // so missing dependency states are represented without trusting a host DAG.
    let revocation_known = proofs.contains("revocation");
    let mut authority_doc = fixture.root_doc.clone();
    if revocation_known {
        authority_doc
            .apply_changes([fixture.changes["inside"].clone()])
            .unwrap();
    }
    let integrated = if revocation_known {
        HashSet::from([String::from("root"), String::from("inside")])
    } else {
        HashSet::from([String::from("root")])
    };
    let pending_change_bytes = IDS
        .iter()
        .copied()
        .filter(|id| received.contains(*id) && !integrated.contains(*id))
        .map(|id| fixture.changes[id].raw_bytes().to_vec())
        .collect::<Vec<_>>();
    let mut snapshot = WorkspaceWriteAuthorizationSnapshot {
        workspace_id: "workspace".into(),
        genesis_owner: fixture.owner.clone(),
        genesis_epoch: 1,
        expected_current_owner: fixture.owner.clone(),
        document: authority_doc.save(),
        ownership_transfers: vec![],
        succession_claims: vec![],
        revocations: vec![],
        device_revocations: vec![],
        departures: vec![],
    };
    if revocation_known {
        let payload = WorkspaceRevocationPayload {
            kind: "workspace-revocation".into(),
            version: 1,
            workspace_id: "workspace".into(),
            owner_person_id: fixture.owner.person_id.clone(),
            person_id: fixture.editor.person_id.clone(),
            epoch: 2,
            workspace_heads: vec![fixture.hashes["inside"].clone()],
            revoked_at: "2099-01-01T00:00:00.000Z".into(),
        };
        let signed = sign_json_envelope(
            &fixture.owner_seed,
            serde_json::to_value(&payload).unwrap(),
            &fixture.owner.person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        snapshot.revocations.push(WorkspaceRevocation {
            payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        });
    }
    CausalAdmissionInput {
        records,
        snapshot,
        pending_change_bytes,
        now_ms: state["clock"].as_i64().unwrap_or_default() as i128,
    }
}

fn ids(values: &Value) -> HashSet<String> {
    values
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn expected_statuses(view: &Value) -> HashMap<&'static str, HashSet<String>> {
    let view = view.as_array().unwrap();
    HashMap::from([
        ("admitted", ids(&view[0])),
        ("quarantined", ids(&view[1])),
        ("pending", ids(&view[2])),
    ])
}

#[test]
#[ignore = "requires fresh graph from formal/check_causal_admission.sh"]
fn causal_admission_matches_fresh_tlc_graph() {
    let graph_path = std::env::var("MESH_TLC_CAUSAL_ADMISSION_GRAPH")
        .expect("fresh TLC graph required in MESH_TLC_CAUSAL_ADMISSION_GRAPH");
    let graph: Value = serde_json::from_slice(&fs::read(graph_path).unwrap()).unwrap();
    let states = graph["states"].as_object().unwrap();
    assert!(!states.is_empty(), "TLC graph must contain states");
    let fixture = make_fixture();
    let mut evaluated_replica_states = 0usize;
    for (state_id, state) in states {
        for replica in ["R1", "R2"] {
            if state["dirty"][replica].as_bool().unwrap_or(false) {
                continue;
            }
            evaluated_replica_states += 1;
            let input = model_input(&fixture, state, replica);
            let plan = evaluate_causal_admission(input)
                .unwrap_or_else(|error| panic!("state {state_id} {replica}: {error}"));
            let expected = expected_statuses(&state["view"][replica]);
            let mut actual = HashMap::from([
                ("admitted", HashSet::new()),
                ("quarantined", HashSet::new()),
                ("pending", HashSet::new()),
            ]);
            for decision in &plan.decisions {
                let id = fixture
                    .hashes
                    .iter()
                    .find_map(|(id, hash)| (hash == &decision.hash).then_some(id.clone()))
                    .expect("Rust decision must map to a TLC candidate");
                let bucket = match decision.status {
                    CausalAdmissionStatus::Admitted { .. } => "admitted",
                    CausalAdmissionStatus::Quarantined { .. } => "quarantined",
                    CausalAdmissionStatus::Pending { .. } => "pending",
                };
                actual.get_mut(bucket).unwrap().insert(id);
            }
            assert_eq!(
                actual,
                expected,
                "TLC decision mismatch at {state_id} {replica}; edges={:?}",
                graph["edges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|edge| edge["to"].as_str() == Some(state_id))
                    .map(|edge| edge["action"].clone())
                    .collect::<Vec<_>>()
            );
            let mut projection = AutoCommit::load(&plan.authorized_document).unwrap();
            let projection_ids = projection
                .get_changes(&[])
                .iter()
                .filter_map(|change| {
                    fixture.hashes.iter().find_map(|(id, hash)| {
                        (hash == &change.hash().to_string()).then_some(id.clone())
                    })
                })
                .collect::<HashSet<_>>();
            assert_eq!(
                projection_ids, expected["admitted"],
                "projection mismatch at {state_id} {replica}"
            );
        }
    }
    println!(
        "Rust replay evaluated {evaluated_replica_states} clean model-state/replica snapshots across {} exported graph edges; graph edges were not individually replayed",
        graph["edges"].as_array().unwrap().len()
    );
}

#[test]
fn causal_admission_implementation_negative_controls() {
    let fixture = make_fixture();
    let state = serde_json::json!({
        "raw": ["root", "inside", "outside", "regrant-edit", "depends-on-outside"],
        "proofs": {"R1": ["revocation", "regrant"]},
        "clock": 10_000
    });
    let plan = evaluate_causal_admission(model_input(&fixture, &state, "R1")).unwrap();
    let status = |id: &str| {
        &plan
            .decisions
            .iter()
            .find(|decision| decision.hash == fixture.hashes[id])
            .expect("candidate decision")
            .status
    };
    assert!(
        matches!(status("outside"), CausalAdmissionStatus::Quarantined { .. }),
        "old-grant change outside signed frontier must stay quarantined"
    );
    assert!(
        matches!(
            status("depends-on-outside"),
            CausalAdmissionStatus::Pending { .. }
        ),
        "descendant of quarantined change must stay pending"
    );
    assert!(
        matches!(status("inside"), CausalAdmissionStatus::Admitted { .. }),
        "change inside signed frontier must stay admitted"
    );
    let mut projection = AutoCommit::load(&plan.authorized_document).unwrap();
    let hashes = projection
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .collect::<HashSet<_>>();
    assert!(
        !hashes.contains(&fixture.hashes["outside"]),
        "quarantined change must not enter projection"
    );
}
