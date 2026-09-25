#[allow(dead_code)]
#[path = "support/tlc_graph.rs"]
mod tlc_graph;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::panic::{AssertUnwindSafe, catch_unwind};

use automerge::{AutoCommit, transaction::Transactable};
use meta_mesh_core::{
    AuthorityMergeInput, AuthorityMergeRecords, DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload,
    MemberGrantInput, OwnershipMergeInput, SignedEnvelope, WorkspaceAccessDecisionInput,
    WorkspaceAuthority, WorkspaceGrant, WorkspaceGrantPayload, WorkspaceOwnershipTransfer,
    WorkspaceOwnershipTransferPayload, WorkspaceRevocation, WorkspaceRevocationPayload,
    WorkspaceRole, WorkspaceWriteAuthorizationSnapshot, decide_workspace_access,
    has_conflicting_ownership_transfers, plan_authority_merge, plan_member_grant,
    plan_ownership_merge, public_key_from_seed, public_key_id, sign_device_certificate,
    sign_json_envelope,
};
use serde::Serialize;
use serde_json::{Value, json};
use tlc_graph::{Graph, action};

const WORKSPACE_ID: &str = "workspace";
const NOW_MS: u64 = 0;

#[derive(Clone)]
struct IdentityFixture {
    root_seed: [u8; 32],
    device_seed: [u8; 32],
    device_id: String,
    authority: WorkspaceAuthority,
}

impl IdentityFixture {
    fn new(root_byte: u8, device_byte: u8) -> Self {
        let root_seed = [root_byte; 32];
        let device_seed = [device_byte; 32];
        let public_key = public_key_from_seed(&root_seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &root_seed,
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
        Self {
            root_seed,
            device_seed,
            device_id,
            authority: WorkspaceAuthority {
                person_id,
                public_key,
                certificates: vec![certificate],
            },
        }
    }
}

#[derive(Clone)]
struct AuthorityHarness {
    identities: BTreeMap<&'static str, IdentityFixture>,
    member: IdentityFixture,
    document: Vec<u8>,
    workspace_heads: Vec<String>,
    credential: Value,
    grant: Option<WorkspaceGrant>,
    revocations: Vec<WorkspaceRevocation>,
    owner_name: &'static str,
    owner_epoch: u64,
    owner_history: Vec<&'static str>,
    ownership_records: Vec<WorkspaceOwnershipTransfer>,
    host_plans: HostApplicablePlanData,
}

/// Plan data that a host has actually applied or acted upon. These fields are
/// part of the concrete key: two protocol states are not merged merely because
/// their TLA+ authority projection is equal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
struct HostApplicablePlanData {
    changed_peers: BTreeMap<String, Value>,
    evicted_device_ids: BTreeSet<String>,
    evicted_person_ids: BTreeSet<String>,
    local_access_revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ConcreteAuthorityKey {
    credential: Value,
    grant: Option<WorkspaceGrant>,
    revocations: Vec<WorkspaceRevocation>,
    owner_name: &'static str,
    owner_epoch: u64,
    owner_history: Vec<&'static str>,
    ownership_records: Vec<WorkspaceOwnershipTransfer>,
    host_plans: HostApplicablePlanData,
}

#[derive(Clone, Debug)]
enum ExplorerAction {
    Grant(u64),
    Revoke(u64),
    Transfer(&'static str),
    Fork(&'static str),
    ReplayOwnershipHistory,
}

impl ExplorerAction {
    fn label(&self) -> String {
        match self {
            Self::Grant(epoch) => format!("Grant({epoch})"),
            Self::Revoke(epoch) => format!("Revoke({epoch})"),
            Self::Transfer(owner) => format!("Transfer({owner})"),
            Self::Fork(owner) => format!("Fork({owner})"),
            Self::ReplayOwnershipHistory => "ReplayOwnershipHistory".into(),
        }
    }
}

#[derive(Clone)]
struct ExplorerNode {
    harness: AuthorityHarness,
    model_state: String,
    trace: Vec<String>,
}

#[derive(Default)]
struct ExplorationEvidence {
    persisted_grants: usize,
    ignored_grants: usize,
    revocation_mutations: usize,
    blocked_grants: usize,
    reinvites: usize,
    ownership_adoptions: usize,
    delayed_history_replays: usize,
    conflicts: usize,
}

#[derive(Default)]
struct ActionEvidence {
    grant_persisted: bool,
    grant_ignored: bool,
    revocations_changed: bool,
    access_before: Option<WorkspaceRole>,
    access_after: Option<WorkspaceRole>,
    ownership_adoptions: usize,
    delayed_history_replay: bool,
    conflict: bool,
}

impl AuthorityHarness {
    fn new() -> Self {
        let identities = BTreeMap::from([
            ("alice", IdentityFixture::new(1, 2)),
            ("bob", IdentityFixture::new(3, 4)),
            ("carol", IdentityFixture::new(5, 6)),
        ]);
        let member = IdentityFixture::new(7, 8);
        let mut document = AutoCommit::new();
        document
            .put(automerge::ROOT, "authority", "anchor")
            .unwrap();
        document.commit();
        let workspace_heads = document
            .get_heads()
            .iter()
            .map(ToString::to_string)
            .collect();
        let document = document.save();
        let owner = &identities["alice"].authority;
        let credential = json!({
            "workspaceId": WORKSPACE_ID,
            "ownerPersonId": owner.person_id,
            "ownerPublicKey": owner.public_key,
            "ownerCertificates": owner.certificates,
            "ownerHistory": [],
            "catalog": {"revocations": []},
            "updatedAt": "1970-01-01T00:00:00.000Z"
        });
        Self {
            identities,
            member,
            document,
            workspace_heads,
            credential,
            grant: None,
            revocations: vec![],
            owner_name: "alice",
            // The executable Rust authority ledger starts at epoch 1. Model
            // epoch 0 is translated to it, preserving every ordering check.
            owner_epoch: 1,
            owner_history: vec![],
            ownership_records: vec![],
            host_plans: HostApplicablePlanData::default(),
        }
    }

    fn apply(&mut self, action: &ExplorerAction) -> ActionEvidence {
        let access_before = self.access_role();
        let mut evidence = match action {
            ExplorerAction::Grant(epoch) => self.grant(*epoch),
            ExplorerAction::Revoke(epoch) => self.revoke(*epoch),
            ExplorerAction::Transfer(next) => self.transfer(next),
            ExplorerAction::Fork(alternate) => self.fork(alternate),
            ExplorerAction::ReplayOwnershipHistory => self.replay_ownership_history(),
        };
        evidence.access_before = access_before;
        evidence.access_after = self.access_role();
        evidence
    }

    fn enabled_actions(&self) -> Vec<ExplorerAction> {
        let mut actions = vec![
            ExplorerAction::Grant(1),
            ExplorerAction::Grant(2),
            ExplorerAction::Revoke(1),
            ExplorerAction::Revoke(2),
        ];
        if !self.actual_conflicted() && model_epoch(self.owner_epoch) < 2 {
            for owner in ["alice", "bob", "carol"] {
                if owner != self.owner_name {
                    actions.push(ExplorerAction::Transfer(owner));
                }
            }
        }
        if !self.actual_conflicted() && self.owner_epoch > 1 {
            let accepted = self
                .ownership_records
                .iter()
                .find(|record| {
                    record.payload.epoch == self.owner_epoch
                        && record.payload.to_owner_person_id
                            == self.identities[self.owner_name].authority.person_id
                })
                .expect("current owner must have its accepted transfer");
            let previous = self.name_for_person(&accepted.payload.from_owner_person_id);
            for owner in ["alice", "bob", "carol"] {
                if owner != previous && owner != self.owner_name {
                    actions.push(ExplorerAction::Fork(owner));
                }
            }
        }
        if !self.ownership_records.is_empty() {
            actions.push(ExplorerAction::ReplayOwnershipHistory);
        }
        actions
    }

    fn grant(&mut self, model_epoch: u64) -> ActionEvidence {
        let owner = &self.identities[self.owner_name];
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(),
            version: 1,
            grant_id: format!("{}-member-{model_epoch}", self.owner_name),
            workspace_id: WORKSPACE_ID.into(),
            person_id: self.member.authority.person_id.clone(),
            role: WorkspaceRole::Editor,
            access_epoch: Some(runtime_epoch(model_epoch)),
        };
        let grant = signed(&owner.root_seed, &owner.authority.person_id, payload);
        let plan = plan_member_grant(MemberGrantInput::PersistLocal {
            credential: self.credential.clone(),
            local_person_id: self.member.authority.person_id.clone(),
            grant: Some(serde_json::to_value(grant).unwrap()),
            owner_certificates: serde_json::to_value(&owner.authority.certificates).unwrap(),
            updated_at: "1970-01-01T00:00:00.000Z".into(),
        })
        .unwrap();
        let persisted = plan.credential.is_some();
        if let Some(credential) = plan.credential {
            self.credential = credential;
        }
        self.grant = self
            .credential
            .get("localGrant")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .unwrap();
        if self.access_role() == Some(WorkspaceRole::Editor) {
            self.host_plans.local_access_revoked = false;
        }
        ActionEvidence {
            grant_persisted: persisted,
            grant_ignored: !persisted,
            ..ActionEvidence::default()
        }
    }

    fn revoke(&mut self, model_epoch: u64) -> ActionEvidence {
        let owner = &self.identities[self.owner_name];
        let payload = WorkspaceRevocationPayload {
            kind: "workspace-revocation".into(),
            version: 1,
            workspace_id: WORKSPACE_ID.into(),
            owner_person_id: owner.authority.person_id.clone(),
            person_id: self.member.authority.person_id.clone(),
            epoch: runtime_epoch(model_epoch),
            workspace_heads: self.workspace_heads.clone(),
            revoked_at: "1970-01-01T00:00:00.000Z".into(),
        };
        let revocation = signed(&owner.root_seed, &owner.authority.person_id, payload);
        let previous_revocations = self.revocations.clone();
        let plan = plan_authority_merge(AuthorityMergeInput {
            credential: self.credential.clone(),
            peers: vec![],
            local_person_id: self.member.authority.person_id.clone(),
            local_device_id: self.member.device_id.clone(),
            now_ms: NOW_MS,
            records: AuthorityMergeRecords::Revocations {
                records: vec![revocation],
            },
        })
        .unwrap();
        for peer in &plan.peers {
            self.host_plans
                .changed_peers
                .insert(peer.device_id.clone(), serde_json::to_value(peer).unwrap());
        }
        self.host_plans
            .evicted_device_ids
            .extend(plan.evict_device_ids.iter().cloned());
        self.host_plans
            .evicted_person_ids
            .extend(plan.evict_person_ids.iter().cloned());
        self.host_plans.local_access_revoked = plan.local_access_revoked;
        self.credential = plan.credential;
        self.revocations = serde_json::from_value(
            self.credential
                .pointer("/catalog/revocations")
                .cloned()
                .unwrap(),
        )
        .unwrap();
        ActionEvidence {
            revocations_changed: self.revocations != previous_revocations,
            ..ActionEvidence::default()
        }
    }

    fn transfer(&mut self, next_name: &'static str) -> ActionEvidence {
        let record = self.signed_transfer(self.owner_name, next_name, self.owner_epoch + 1);
        let plan = self.merge_ownership(record);
        assert!(!plan.conflicted, "normal transfer unexpectedly conflicted");
        assert_eq!(plan.steps.len(), 1, "normal transfer was not selected");
        let ownership_adoptions = plan.steps.len();
        self.apply_ownership_plan(plan);
        ActionEvidence {
            ownership_adoptions,
            ..ActionEvidence::default()
        }
    }

    fn fork(&mut self, alternate_name: &'static str) -> ActionEvidence {
        let accepted = self
            .ownership_records
            .iter()
            .find(|record| {
                record.payload.epoch == self.owner_epoch
                    && record.payload.to_owner_person_id
                        == self.identities[self.owner_name].authority.person_id
            })
            .expect("fork needs the just-accepted transfer");
        let previous_name = self.name_for_person(&accepted.payload.from_owner_person_id);
        let record = self.signed_transfer(previous_name, alternate_name, self.owner_epoch);
        let plan = self.merge_ownership(record);
        assert!(
            plan.conflicted,
            "alternative signed successor was not a conflict"
        );
        assert!(
            plan.steps.is_empty(),
            "conflict must stall authority adoption"
        );
        self.apply_ownership_plan(plan);
        ActionEvidence {
            conflict: true,
            ..ActionEvidence::default()
        }
    }

    fn replay_ownership_history(&mut self) -> ActionEvidence {
        let record = self
            .ownership_records
            .first()
            .expect("history replay requires an accepted transfer")
            .clone();
        let previous_conflict = self.actual_conflicted();
        let plan = self.merge_ownership(record);
        assert_eq!(plan.conflicted, previous_conflict);
        assert!(
            plan.steps.is_empty(),
            "old ownership history was adopted twice"
        );
        self.apply_ownership_plan(plan);
        ActionEvidence {
            delayed_history_replay: true,
            ..ActionEvidence::default()
        }
    }

    fn apply_ownership_plan(&mut self, plan: meta_mesh_core::OwnershipMergePlan) {
        for step in &plan.steps {
            self.owner_history
                .push(self.name_for_person(&step.record.payload.from_owner_person_id));
            self.owner_name = self.name_for_person(&step.record.payload.to_owner_person_id);
            self.owner_epoch = step.record.payload.epoch;
        }
        self.ownership_records = plan.accepted;
        self.sync_credential_authority();
    }

    fn concrete_key(&self) -> ConcreteAuthorityKey {
        // Identities, document bytes, and workspace heads are immutable signed
        // fixtures shared by every node; every mutable protocol and host field
        // is retained structurally below.
        ConcreteAuthorityKey {
            credential: canonical_json(self.credential.clone()),
            grant: self.grant.clone(),
            revocations: self.revocations.clone(),
            owner_name: self.owner_name,
            owner_epoch: self.owner_epoch,
            owner_history: self.owner_history.clone(),
            ownership_records: self.ownership_records.clone(),
            host_plans: self.host_plans.clone(),
        }
    }

    fn merge_ownership(
        &self,
        record: WorkspaceOwnershipTransfer,
    ) -> meta_mesh_core::OwnershipMergePlan {
        plan_ownership_merge(OwnershipMergeInput {
            workspace_id: WORKSPACE_ID.into(),
            current_owner: self.identities[self.owner_name].authority.clone(),
            owner_history: self
                .owner_history
                .iter()
                .map(|name| self.identities[name].authority.clone())
                .collect(),
            owner_epoch: self.owner_epoch,
            current: self.ownership_records.clone(),
            incoming: vec![serde_json::to_value(record).unwrap()],
            // The conformance member is distinct from every possible owner.
            revoked_people: HashSet::new(),
            now_ms: NOW_MS,
        })
        .unwrap()
    }

    fn signed_transfer(
        &self,
        from_name: &'static str,
        to_name: &'static str,
        epoch: u64,
    ) -> WorkspaceOwnershipTransfer {
        let from = &self.identities[from_name];
        let to = &self.identities[to_name];
        let to_owner_grant = signed(
            &from.root_seed,
            &from.authority.person_id,
            WorkspaceGrantPayload {
                kind: "workspace-grant".into(),
                version: 1,
                grant_id: format!("owner-{epoch}-{to_name}"),
                workspace_id: WORKSPACE_ID.into(),
                person_id: to.authority.person_id.clone(),
                role: WorkspaceRole::Owner,
                access_epoch: Some(epoch),
            },
        );
        let former_owner_grant = signed(
            &from.root_seed,
            &from.authority.person_id,
            WorkspaceGrantPayload {
                kind: "workspace-grant".into(),
                version: 1,
                grant_id: format!("former-{epoch}-{from_name}"),
                workspace_id: WORKSPACE_ID.into(),
                person_id: from.authority.person_id.clone(),
                role: WorkspaceRole::Editor,
                access_epoch: Some(epoch),
            },
        );
        let payload = WorkspaceOwnershipTransferPayload {
            kind: "workspace-ownership-transfer".into(),
            version: 1,
            workspace_id: WORKSPACE_ID.into(),
            from_owner_person_id: from.authority.person_id.clone(),
            to_owner_person_id: to.authority.person_id.clone(),
            to_owner_public_key: to.authority.public_key.clone(),
            to_owner_certificates: to.authority.certificates.clone(),
            to_owner_grant,
            former_owner_grant,
            workspace_heads: self.workspace_heads.clone(),
            epoch,
            transferred_at: "1970-01-01T00:00:00.000Z".into(),
        };
        signed(&from.device_seed, &from.device_id, payload)
    }

    fn sync_credential_authority(&mut self) {
        let current = &self.identities[self.owner_name].authority;
        let object = self.credential.as_object_mut().unwrap();
        object.insert("ownerPersonId".into(), json!(current.person_id));
        object.insert("ownerPublicKey".into(), json!(current.public_key));
        object.insert("ownerCertificates".into(), json!(current.certificates));
        object.insert(
            "ownerHistory".into(),
            json!(
                self.owner_history
                    .iter()
                    .map(|name| &self.identities[name].authority)
                    .collect::<Vec<_>>()
            ),
        );
    }

    fn assert_matches(&self, state: &Value, action: &str) {
        let expected_grant = number(state, "grantEpoch");
        let actual_grant = self
            .grant
            .as_ref()
            .map(|grant| model_epoch(grant.payload.effective_access_epoch()))
            .unwrap_or(0);
        assert_eq!(actual_grant, expected_grant, "grant epoch after {action}");

        let actual_seen = std::iter::once(0)
            .chain(
                self.revocations
                    .iter()
                    .map(|record| model_epoch(record.payload.epoch)),
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual_seen,
            numbers(state, "seenRevocations"),
            "revocations after {action}"
        );
        assert_eq!(
            actual_seen.iter().next_back().copied().unwrap(),
            number(state, "revokedThrough"),
            "revocation watermark after {action}"
        );

        assert_eq!(
            model_epoch(self.owner_epoch),
            number(state, "ownerEpoch"),
            "owner epoch after {action}"
        );
        assert_eq!(
            self.owner_name,
            string(state, "owner"),
            "selected owner after {action}"
        );
        assert_eq!(
            self.actual_owner_candidates(),
            strings(state, "ownerCandidates"),
            "owner candidates after {action}"
        );
        assert_eq!(
            self.actual_conflicted(),
            boolean(state, "conflicted"),
            "conflict after {action}"
        );
        assert_eq!(
            self.actual_owner_history(),
            owner_history(state),
            "owner history after {action}"
        );
        let decision = self.access_decision();
        if boolean(state, "conflicted") {
            assert!(
                decision
                    .unwrap_err()
                    .contains("Conflicting workspace ownership transitions"),
                "conflicted authority was usable after {action}"
            );
        } else {
            let expected = if boolean(state, "access") {
                WorkspaceRole::Editor
            } else {
                WorkspaceRole::Visitor
            };
            assert_eq!(decision.unwrap(), expected, "access after {action}");
        }
    }

    fn access_decision(&self) -> Result<WorkspaceRole, String> {
        decide_workspace_access(
            &WorkspaceAccessDecisionInput {
                snapshot: WorkspaceWriteAuthorizationSnapshot {
                    workspace_id: WORKSPACE_ID.into(),
                    genesis_owner: self.identities["alice"].authority.clone(),
                    genesis_epoch: 1,
                    expected_current_owner: self.identities[self.owner_name].authority.clone(),
                    document: self.document.clone(),
                    ownership_transfers: self.ownership_records.clone(),
                    succession_claims: vec![],
                    revocations: self.revocations.clone(),
                    device_revocations: vec![],
                    departures: vec![],
                },
                identity: self.member.authority.clone(),
                device_id: self.member.device_id.clone(),
                grant: self.grant.clone(),
                departures: vec![],
                legacy_authority_evidence: vec![],
            },
            i128::from(NOW_MS),
        )
    }

    fn access_role(&self) -> Option<WorkspaceRole> {
        self.access_decision().ok()
    }

    fn actual_conflicted(&self) -> bool {
        has_conflicting_ownership_transfers(
            &self
                .ownership_records
                .iter()
                .map(|record| serde_json::to_value(record).unwrap())
                .collect::<Vec<_>>(),
        )
    }

    fn actual_owner_candidates(&self) -> BTreeSet<String> {
        if self.ownership_records.is_empty() {
            return BTreeSet::from(["alice".into()]);
        }
        self.ownership_records
            .iter()
            .filter(|record| record.payload.epoch == self.owner_epoch)
            .map(|record| {
                self.name_for_person(&record.payload.to_owner_person_id)
                    .to_string()
            })
            .collect()
    }

    fn actual_owner_history(&self) -> BTreeSet<(u64, String, String)> {
        self.ownership_records
            .iter()
            .map(|record| {
                (
                    model_epoch(record.payload.epoch),
                    self.name_for_person(&record.payload.from_owner_person_id)
                        .to_string(),
                    self.name_for_person(&record.payload.to_owner_person_id)
                        .to_string(),
                )
            })
            .collect()
    }

    fn name_for_person(&self, person_id: &str) -> &'static str {
        self.identities
            .iter()
            .find_map(|(name, identity)| {
                (identity.authority.person_id == person_id).then_some(*name)
            })
            .expect("unknown authority person")
    }
}

#[test]
#[ignore = "requires freshly generated TLC graph; executed by formal/check.sh"]
fn tlc_authority_graph_refines_signed_rust_transitions() {
    let graph = Graph::load("MESH_TLC_AUTHORITY_GRAPH");
    let mut transitions = BTreeMap::new();
    for edge in &graph.edges {
        let key = (edge.from.clone(), normalized_action(&edge.action));
        if let Some(previous) = transitions.insert(key, edge.to.clone()) {
            assert_eq!(
                previous, edge.to,
                "nondeterministic AuthorityConformance edge for one labeled action"
            );
        }
    }

    let initial = AuthorityHarness::new();
    initial.assert_matches(&graph.states[&graph.initial], "Init");
    let initial_key = initial.concrete_key();
    let initial_fingerprint = concrete_fingerprint(&initial_key);
    let mut keys = vec![initial_key];
    let mut model_states = vec![graph.initial.clone()];
    let mut states_by_fingerprint = HashMap::from([(initial_fingerprint, vec![0usize])]);
    let mut queue = VecDeque::from([ExplorerNode {
        harness: initial,
        model_state: graph.initial.clone(),
        trace: Vec::new(),
    }]);
    let mut exercised = BTreeSet::new();
    let mut explored_edges = 0usize;
    let mut explored_states = 0usize;
    let mut evidence = ExplorationEvidence::default();

    while let Some(node) = queue.pop_front() {
        explored_states += 1;
        if explored_states % 500 == 0 {
            println!(
                "Rust authority progress: {explored_states} states processed, {} unique, {} queued, {explored_edges} edges",
                keys.len(),
                queue.len()
            );
        }
        for explorer_action in node.harness.enabled_actions() {
            let label = explorer_action.label();
            let mut trace = node.trace.clone();
            trace.push(label.clone());
            let target_id = transitions
                .get(&(node.model_state.clone(), normalized_action(&label)))
                .unwrap_or_else(|| {
                    panic!(
                        "unmapped concrete authority action {label}; trace={trace:?}; source={}",
                        graph.states[&node.model_state]
                    )
                })
                .clone();
            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut harness = node.harness.clone();
                let action_evidence = harness.apply(&explorer_action);
                harness.assert_matches(&graph.states[&target_id], &label);
                (harness, action_evidence)
            }));
            let (target, action_evidence) = result.unwrap_or_else(|error| {
                let message = error
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| error.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic");
                panic!(
                    "authority conformance failed: {message}\ntrace: {trace:?}\ntarget: {}",
                    graph.states[&target_id]
                );
            });

            exercised.insert(action(&label).0.to_string());
            explored_edges += 1;
            evidence.persisted_grants += usize::from(action_evidence.grant_persisted);
            evidence.ignored_grants += usize::from(action_evidence.grant_ignored);
            evidence.revocation_mutations += usize::from(action_evidence.revocations_changed);
            evidence.ownership_adoptions += action_evidence.ownership_adoptions;
            evidence.delayed_history_replays += usize::from(action_evidence.delayed_history_replay);
            evidence.conflicts += usize::from(action_evidence.conflict);
            if matches!(explorer_action, ExplorerAction::Grant(_)) {
                if action_evidence.access_before == Some(WorkspaceRole::Visitor)
                    && action_evidence.access_after == Some(WorkspaceRole::Visitor)
                    && action_evidence.grant_persisted
                {
                    evidence.blocked_grants += 1;
                }
                if action_evidence.access_before == Some(WorkspaceRole::Visitor)
                    && action_evidence.access_after == Some(WorkspaceRole::Editor)
                {
                    evidence.reinvites += 1;
                }
            }

            let key = target.concrete_key();
            let fingerprint = concrete_fingerprint(&key);
            let known_index = states_by_fingerprint
                .get(&fingerprint)
                .and_then(|indices| indices.iter().copied().find(|index| keys[*index] == key));
            if let Some(index) = known_index {
                // replayedHistory only bounds repetition of the model's delayed
                // input. It is TLC instrumentation, not Rust authority state,
                // and is the sole field ignored when a concrete state recurs.
                let previous = authority_projection(&graph.states[&model_states[index]]);
                let candidate = authority_projection(&graph.states[&target_id]);
                assert_eq!(
                    previous, candidate,
                    "one concrete authority state has incompatible abstractions; trace={trace:?}"
                );
            } else {
                let index = keys.len();
                keys.push(key);
                model_states.push(target_id.clone());
                states_by_fingerprint
                    .entry(fingerprint)
                    .or_default()
                    .push(index);
                queue.push_back(ExplorerNode {
                    harness: target,
                    model_state: target_id,
                    trace,
                });
            }
        }
    }
    assert_eq!(
        exercised,
        BTreeSet::from([
            "Fork".into(),
            "Grant".into(),
            "ReplayOwnershipHistory".into(),
            "Revoke".into(),
            "Transfer".into(),
        ])
    );
    assert!(evidence.persisted_grants > 0, "no grant plan was applied");
    assert!(evidence.ignored_grants > 0, "no delayed grant was ignored");
    assert!(
        evidence.revocation_mutations > 0,
        "no signed revocation mutated authority state"
    );
    assert!(
        evidence.blocked_grants > 0,
        "no old grant remained blocked by a revocation"
    );
    assert!(
        evidence.reinvites > 0,
        "no strictly newer reinvite restored access"
    );
    assert!(
        evidence.ownership_adoptions > 0,
        "no ownership plan step mutated authority state"
    );
    assert!(
        evidence.delayed_history_replays > 0,
        "no delayed ownership history was exercised"
    );
    assert!(
        evidence.conflicts > 0,
        "no conflicting ownership plan was returned"
    );
    println!(
        "Rust authority exploration: {} unique concrete states, {} enabled edges; {} persisted grants, {} revocation mutations, {} blocked old grants, {} reinvites, {} ownership adoptions, {} delayed history replays, {} conflicts ({} TLC states, {} TLC edges)",
        keys.len(),
        explored_edges,
        evidence.persisted_grants,
        evidence.revocation_mutations,
        evidence.blocked_grants,
        evidence.reinvites,
        evidence.ownership_adoptions,
        evidence.delayed_history_replays,
        evidence.conflicts,
        graph.states.len(),
        graph.edges.len()
    );
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(canonical_json).collect::<Vec<_>>())
        }
        scalar => scalar,
    }
}

fn concrete_fingerprint(key: &ConcreteAuthorityKey) -> u64 {
    // JSON object member order has no protocol meaning. Canonicalizing only
    // object keys makes the fingerprint stable while preserving array order;
    // structural equality below still resolves any hash collision.
    let canonical = canonical_json(serde_json::to_value(key).unwrap());
    let mut hasher = DefaultHasher::new();
    serde_json::to_string(&canonical).unwrap().hash(&mut hasher);
    hasher.finish()
}

fn normalized_action(label: &str) -> String {
    label.split_whitespace().collect()
}

fn authority_projection(state: &Value) -> Value {
    let mut state = state.clone();
    state
        .as_object_mut()
        .expect("TLC authority state")
        .remove("replayedHistory");
    state
}

fn signed<T>(seed: &[u8; 32], signer_key_id: &str, payload: T) -> SignedEnvelope<T>
where
    T: Clone + Serialize,
{
    let envelope = sign_json_envelope(
        seed,
        serde_json::to_value(&payload).unwrap(),
        signer_key_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    SignedEnvelope {
        payload,
        signer_key_id: envelope.signer_key_id,
        signature: envelope.signature,
    }
}

fn runtime_epoch(model_epoch: u64) -> u64 {
    assert!(model_epoch > 0);
    model_epoch + 1
}

fn model_epoch(runtime_epoch: u64) -> u64 {
    runtime_epoch - 1
}

fn field<'a>(state: &'a Value, name: &str) -> &'a Value {
    state
        .get(name)
        .unwrap_or_else(|| panic!("TLC state is missing {name}"))
}

fn number(state: &Value, name: &str) -> u64 {
    field(state, name).as_u64().unwrap()
}

fn string<'a>(state: &'a Value, name: &str) -> &'a str {
    field(state, name).as_str().unwrap()
}

fn boolean(state: &Value, name: &str) -> bool {
    field(state, name).as_bool().unwrap()
}

fn numbers(state: &Value, name: &str) -> BTreeSet<u64> {
    field(state, name)
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap())
        .collect()
}

fn strings(state: &Value, name: &str) -> BTreeSet<String> {
    field(state, name)
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

fn owner_history(state: &Value) -> BTreeSet<(u64, String, String)> {
    field(state, "ownerHistory")
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            let record = record.as_array().unwrap();
            (
                record[0].as_u64().unwrap(),
                record[1].as_str().unwrap().to_string(),
                record[2].as_str().unwrap().to_string(),
            )
        })
        .collect()
}
