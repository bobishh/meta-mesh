use super::application_source_tests::{source_data, write_source};
use super::*;

struct SourceFixture {
    doc: AutoCommit,
    owner: WorkspaceAuthority,
    owner_seed: [u8; 32],
    owner_device: String,
    owner_certs: Vec<DeviceCertificate>,
    worker: WorkspaceAuthority,
    worker_seed: [u8; 32],
    worker_device: String,
    worker_certs: Vec<DeviceCertificate>,
    grant: WorkspaceGrant,
    owner_hashes: Vec<String>,
}

impl SourceFixture {
    fn new(version: u8) -> Self {
        let (owner, owner_seed, owner_device, owner_certs) = authority([211; 32], [212; 32]);
        let (worker, worker_seed, worker_device, worker_certs) = authority([213; 32], [214; 32]);
        let mut scope = automation_scope();
        scope.version = version;
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(),
            version: 1,
            grant_id: format!("source-scope-{version}"),
            workspace_id: "workspace".into(),
            person_id: worker.person_id.clone(),
            role: WorkspaceRole::Automation,
            access_epoch: Some(1),
            automation: Some(scope),
        };
        let signed = sign_json_envelope(
            &[211; 32],
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
        let mut doc = automation_board();
        let owner_hashes = doc
            .get_changes(&[])
            .iter()
            .map(|change| change.hash().to_string())
            .collect();
        Self {
            doc,
            owner,
            owner_seed,
            owner_device,
            owner_certs,
            worker,
            worker_seed,
            worker_device,
            worker_certs,
            grant,
            owner_hashes,
        }
    }

    fn card(&mut self, parent: &str) {
        let entities = self.doc.get(ROOT, "entities").unwrap().unwrap().1;
        let card = self
            .doc
            .put_object(&entities, "card", ObjType::Map)
            .unwrap();
        self.doc.put(&card, "id", "card").unwrap();
        self.doc.put(&card, "title", "Editable label").unwrap();
        self.doc.put(&card, "body", "Job details").unwrap();
        self.doc.put_object(&card, "values", ObjType::Map).unwrap();
        self.doc
            .put(&card, "archivedAt", ScalarValue::Null)
            .unwrap();
        let placement = self
            .doc
            .put_object(&card, "placement", ObjType::Map)
            .unwrap();
        self.doc.put(&placement, "parentId", parent).unwrap();
        self.doc.put(&placement, "rank", "0/1").unwrap();
    }

    fn source(&mut self, id: &str, refresh: bool) {
        let text = "Actual page-derived Engineer description";
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
        let mut data: serde_json::Value =
            serde_json::from_str(&source_data(text, &digest, id)).unwrap();
        if refresh {
            data["observation"]["phase"] = "refresh".into();
            data["observation"]["originalRecordId"] = "original".into();
        }
        write_source(&mut self.doc, id, &serde_json::to_string(&data).unwrap());
    }

    fn owner_commit(&mut self) {
        self.doc.commit_with(
            CommitOptions::default().with_message(
                serde_json::json!({
                    "kind": "workspace-change-metadata", "version": 1,
                    "personId": self.owner.person_id, "deviceId": self.owner_device,
                })
                .to_string(),
            ),
        );
        self.owner_hashes
            .push(self.doc.get_changes(&[]).last().unwrap().hash().to_string());
    }

    fn move_card(&mut self) {
        let entities = self.doc.get(ROOT, "entities").unwrap().unwrap().1;
        let card = self.doc.get(&entities, "card").unwrap().unwrap().1;
        let placement = self.doc.get(&card, "placement").unwrap().unwrap().1;
        self.doc.put(&placement, "parentId", "interview").unwrap();
    }

    fn evaluate(mut self) -> (String, CausalAdmissionPlan) {
        self.doc
            .commit_with(CommitOptions::default().with_message(change_metadata(
                &self.grant,
                &self.worker.person_id,
                &self.worker_device,
            )));
        let hash = self.doc.get_changes(&[]).last().unwrap().hash().to_string();
        let plan = evaluate_causal_admission(CausalAdmissionInput {
            records: vec![
                change_proof(
                    &self.owner,
                    &self.owner_seed,
                    &self.owner_device,
                    &self.owner_certs,
                    &self.owner_hashes,
                    None,
                ),
                change_proof(
                    &self.worker,
                    &self.worker_seed,
                    &self.worker_device,
                    &self.worker_certs,
                    &[hash.clone()],
                    Some(self.grant),
                ),
            ],
            snapshot: snapshot(self.owner, self.doc.save()),
            pending_change_bytes: vec![],
            now_ms: 0,
        })
        .unwrap();
        (hash, plan)
    }
}

fn assert_worker_admitted(fixture: SourceFixture, expected: bool) {
    let (hash, plan) = fixture.evaluate();
    assert_eq!(
        plan.decisions.iter().any(|decision| decision.hash == hash
            && matches!(
                decision.status,
                CausalAdmissionStatus::Admitted {
                    role: WorkspaceRole::Automation
                }
            )),
        expected,
        "{:#?}",
        plan.decisions
    );
}

#[test]
fn only_explicit_v2_grant_admits_atomic_card_and_original_source() {
    for version in [1, 2] {
        let mut fixture = SourceFixture::new(version);
        fixture.card("lead");
        fixture.source("original", false);
        assert_worker_admitted(fixture, version == 2);
    }
}

#[test]
fn source_metadata_does_not_block_old_grant_moves_but_real_children_still_do() {
    for child in [false, true] {
        let mut fixture = SourceFixture::new(1);
        fixture.card("other");
        fixture.source("original", false);
        if child {
            let entities = fixture.doc.get(ROOT, "entities").unwrap().unwrap().1;
            let note = fixture
                .doc
                .put_object(&entities, "note", ObjType::Map)
                .unwrap();
            fixture.doc.put(&note, "kind", "document").unwrap();
            let placement = fixture
                .doc
                .put_object(&note, "placement", ObjType::Map)
                .unwrap();
            fixture.doc.put(&placement, "parentId", "card").unwrap();
        }
        fixture.owner_commit();
        fixture.move_card();
        assert_worker_admitted(fixture, !child);
    }
}

#[test]
fn only_v2_can_append_refresh_on_existing_original_without_rewriting_card() {
    for version in [1, 2] {
        for moved in [false, true] {
            let mut fixture = SourceFixture::new(version);
            fixture.card("other");
            fixture.source("original", false);
            fixture.owner_commit();
            fixture.source("refresh", true);
            if moved {
                fixture.move_card();
            }
            assert_worker_admitted(fixture, version == 2);
        }
    }
}

#[test]
fn v2_source_permission_cannot_launder_originals_or_expand_board_effects() {
    for case in [
        "existing-original",
        "two-records",
        "outside-board",
        "root-write",
        "edit-original",
    ] {
        let mut fixture = SourceFixture::new(2);
        fixture.card(if case == "outside-board" {
            "foreign-column"
        } else {
            "lead"
        });
        if case == "existing-original" {
            fixture.owner_commit();
        }
        if case == "edit-original" {
            fixture.source("original", false);
            fixture.owner_commit();
            let entities = fixture.doc.get(ROOT, "entities").unwrap().unwrap().1;
            let source = fixture
                .doc
                .get(&entities, "application-source:original")
                .unwrap()
                .unwrap()
                .1;
            fixture.doc.put(&source, "title", "Replacement").unwrap();
        } else {
            fixture.source("original", false);
        }
        if case == "two-records" {
            fixture.source("extra", false);
        }
        if case == "root-write" {
            fixture
                .doc
                .put(ROOT, "title", "Unapproved workspace edit")
                .unwrap();
        }
        assert_worker_admitted(fixture, false);
    }
}

#[test]
fn source_scope_version_is_signed_and_unknown_versions_are_not_authority() {
    for version in [1, 2, 3] {
        let fixture = SourceFixture::new(version);
        let result = crate::verify_workspace_grant(
            &fixture.grant,
            "workspace",
            &fixture.worker.person_id,
            &crate::PublicIdentity {
                person_id: fixture.owner.person_id.clone(),
                public_key: fixture.owner.public_key.clone(),
                display_name: String::new(),
            },
            &fixture.owner.certificates,
        );
        assert_eq!(result.is_ok(), version <= 2, "scope version {version}");
    }
}
