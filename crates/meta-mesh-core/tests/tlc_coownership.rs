#[allow(dead_code)]
#[path = "support/tlc_graph.rs"]
mod tlc_graph;

use meta_mesh_core::coownership::{
    CoownedApproval, CoownedResolution, CoownedTransition, CoownedTransitionPayload,
    CoownerIdentity, CoownerPolicy, CoownershipForkInput, CoownershipGenesisInput,
    CoownershipLedger, CoownershipResolutionInput, CoownershipState, CoownershipStatus,
    CoownershipTransitionInput, ValidatedCoownership, create_coownership_genesis_payload,
    merge_coownership_ledgers, plan_coownership_fork, plan_coownership_resolution,
    plan_coownership_transition, sign_coownership_approval, sign_coownership_genesis,
    validate_coownership_ledger,
};
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, IdentitySecurity, open_identity_seed,
    public_key_from_seed, public_key_id, seal_identity_seed, sign_device_certificate,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
use tlc_graph::{Graph, action};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Person {
    identity: CoownerIdentity,
    recovered_seed: [u8; 32],
    device_seed: [u8; 32],
    device_id: String,
}

impl Person {
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
        let key = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let envelope = seal_identity_seed(
            &root_seed,
            &person_id,
            key,
            IdentitySecurity::Better,
            &[root_byte; 16],
            &[device_byte; 12],
        )
        .unwrap();
        let recovered_seed = open_identity_seed(&envelope, key).unwrap();
        assert_eq!(recovered_seed, root_seed);
        Self {
            identity: CoownerIdentity {
                person_id,
                public_key,
                certificates: vec![certificate],
            },
            recovered_seed,
            device_seed,
            device_id,
        }
    }
}

fn people() -> &'static BTreeMap<&'static str, Person> {
    static PEOPLE: OnceLock<BTreeMap<&'static str, Person>> = OnceLock::new();
    PEOPLE.get_or_init(|| {
        BTreeMap::from([
            ("alice", Person::new(1, 2)),
            ("bob", Person::new(3, 4)),
            ("carol", Person::new(5, 6)),
        ])
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingRecord {
    Transition(CoownedTransition),
    Resolution(CoownedResolution),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    id: String,
    child: String,
    parent: String,
    scope: String,
    kind: String,
    epoch: u64,
    owners: Vec<String>,
    signers: Vec<String>,
    policy: CoownerPolicy,
    refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CoownershipHarness {
    people: &'static BTreeMap<&'static str, Person>,
    main: CoownershipLedger,
    fork: Option<CoownershipLedger>,
    pending: BTreeMap<String, PendingRecord>,
    candidate_data: BTreeMap<String, Candidate>,
    node_hashes: BTreeMap<String, String>,
    node_by_hash: BTreeMap<String, String>,
    epoch_offsets: BTreeMap<String, i64>,
    recovered_identity: Option<String>,
}

impl CoownershipHarness {
    fn new() -> Self {
        let people = people();
        let alice = &people["alice"];
        let genesis_payload = create_coownership_genesis_payload(CoownershipGenesisInput {
            scope_id: "main_scope".into(),
            creator: alice.identity.clone(),
            policy: CoownerPolicy::Majority,
        })
        .unwrap();
        let genesis =
            sign_coownership_genesis(&alice.device_seed, genesis_payload, &alice.device_id)
                .unwrap();
        let mut main = CoownershipLedger {
            genesis,
            transitions: Vec::new(),
            resolutions: Vec::new(),
        };
        // TLA RootMain models an already co-owned scope. Establish that state
        // from the real single-creator genesis through a signed v2 transition.
        let owners = sorted_people(&people, &["alice".into(), "bob".into()]);
        let planned = plan_coownership_transition(CoownershipTransitionInput {
            ledger: main.clone(),
            owners,
            policy: CoownerPolicy::Majority,
        })
        .unwrap();
        let approval =
            sign_coownership_approval(&alice.device_seed, &planned, &alice.device_id).unwrap();
        main.transitions.push(CoownedTransition {
            payload: planned,
            approvals: vec![approval],
        });
        let CoownershipStatus::Authorized(initial_state) =
            validate_coownership_ledger(&main).unwrap().status
        else {
            panic!("co-owned bootstrap must authorize");
        };
        assert_eq!(
            initial_state.epoch, 2,
            "real genesis plus owner addition starts at epoch 2"
        );
        let root_hash = payload_hash(&main.transitions[0].payload);
        Self {
            people,
            main,
            fork: None,
            pending: BTreeMap::new(),
            candidate_data: BTreeMap::new(),
            node_hashes: BTreeMap::from([("root_main".into(), root_hash.clone())]),
            node_by_hash: BTreeMap::from([(root_hash, "root_main".into())]),
            epoch_offsets: BTreeMap::from([("main_scope".into(), 0)]),
            recovered_identity: None,
        }
    }

    fn apply(&mut self, label: &str, model_before: &Value, model_after: &Value) {
        let (name, _) = action(label);
        if name == "RestoreIdentity" {
            let main_before = self.main.clone();
            let fork_before = self.fork.clone();
            self.restore_identity(model_before);
            assert_eq!(self.main, main_before, "recovery changed main authority");
            assert_eq!(self.fork, fork_before, "recovery changed fork authority");
        } else {
            match name {
                "Issue" => self.issue(parse_candidate(label)),
                "Observe" | "Resolve" => self.observe(parse_candidate(label)),
                "Fork" => self.fork_scope(),
                other => panic!("unexpected co-ownership TLC action {other}: {label}"),
            }
        }
        if model_before["heads"]["main_scope"] != model_after["heads"]["main_scope"] {
            self.recovered_identity = None;
        }
    }

    fn issue(&mut self, candidate: Candidate) {
        assert!(!self.pending.contains_key(&candidate.id));
        let parent_hash = self
            .node_hashes
            .get(&candidate.parent)
            .unwrap_or_else(|| panic!("unknown candidate parent: {candidate:?}"))
            .clone();
        let owners = sorted_people(&self.people, &candidate.owners);
        let ledger = self.ledger_for_scope(&candidate.scope).clone();
        let pending = if candidate.kind == "Resolution" {
            let payload = plan_coownership_resolution(CoownershipResolutionInput {
                ledger,
                parent_certificate_hash: parent_hash.clone(),
                owners,
                policy: candidate.policy,
            })
            .unwrap_or_else(|error| {
                panic!("resolution planning failed for {candidate:?}: {error}")
            });
            assert_eq!(
                payload.parent_certificate_hash, parent_hash,
                "{candidate:?}"
            );
            assert_eq!(
                payload.epoch as i64,
                candidate.epoch as i64 + self.epoch_offsets[&candidate.scope],
                "{candidate:?}"
            );
            assert_eq!(
                names_for_hashes(&self.node_by_hash, &payload.conflicting_certificate_hashes),
                candidate.refs.iter().cloned().collect(),
                "resolution planner and TLC evidence differ for {candidate:?}"
            );
            let approvals = approvals_for(&self.people, &candidate.signers, &payload);
            PendingRecord::Resolution(CoownedResolution { payload, approvals })
        } else {
            let payload = plan_coownership_transition(CoownershipTransitionInput {
                ledger,
                owners,
                policy: candidate.policy,
            })
            .unwrap_or_else(|error| {
                panic!("transition planning failed for {candidate:?}: {error}")
            });
            assert_eq!(
                payload.parent_certificate_hash, parent_hash,
                "{candidate:?}"
            );
            assert_eq!(
                payload.epoch as i64,
                candidate.epoch as i64 + self.epoch_offsets[&candidate.scope],
                "{candidate:?}"
            );
            let approvals = approvals_for(&self.people, &candidate.signers, &payload);
            PendingRecord::Transition(CoownedTransition { payload, approvals })
        };
        let payload_hash = pending_hash(&pending);
        assert!(
            self.node_hashes
                .insert(candidate.child.clone(), payload_hash.clone())
                .is_none()
        );
        assert!(
            self.node_by_hash
                .insert(payload_hash, candidate.child.clone())
                .is_none()
        );
        self.candidate_data
            .insert(candidate.id.clone(), candidate.clone());
        self.pending.insert(candidate.id, pending);
    }

    fn observe(&mut self, candidate: Candidate) {
        let pending = self
            .pending
            .remove(&candidate.id)
            .unwrap_or_else(|| panic!("TLC observed unissued candidate: {candidate:?}"));
        match (candidate.kind.as_str(), pending) {
            ("Resolution", PendingRecord::Resolution(record)) => {
                self.merge_record(&candidate.scope, None, Some(record));
            }
            ("Resolution", PendingRecord::Transition(_)) => {
                panic!("resolution action carried transition: {candidate:?}")
            }
            (_, PendingRecord::Transition(record)) => {
                self.merge_record(&candidate.scope, Some(record), None);
            }
            (_, PendingRecord::Resolution(_)) => {
                panic!("observe action carried resolution: {candidate:?}")
            }
        }
    }

    fn merge_record(
        &mut self,
        scope: &str,
        transition: Option<CoownedTransition>,
        resolution: Option<CoownedResolution>,
    ) {
        let current = self.ledger_for_scope(scope).clone();
        let mut incoming = current.clone();
        if let Some(record) = transition {
            incoming.transitions.push(record);
        }
        if let Some(record) = resolution {
            incoming.resolutions.push(record);
        }
        let merged = merge_coownership_ledgers(Some(&current), &incoming).unwrap_or_else(|error| {
            panic!("co-ownership merge rejected valid TLC evidence: {error}")
        });
        if scope == "main_scope" {
            self.main = merged;
        } else {
            self.fork = Some(merged);
        }
    }

    fn fork_scope(&mut self) {
        assert!(self.fork.is_none());
        let carol = &self.people["carol"];
        let payload = plan_coownership_fork(CoownershipForkInput {
            source_ledger: self.main.clone(),
            scope_id: "fork_scope".into(),
            creator: carol.identity.clone(),
            policy: CoownerPolicy::Majority,
        })
        .unwrap();
        let genesis =
            sign_coownership_genesis(&carol.device_seed, payload, &carol.device_id).unwrap();
        let hash = payload_hash(&genesis.payload);
        self.node_hashes.insert("root_fork".into(), hash.clone());
        self.node_by_hash.insert(hash, "root_fork".into());
        self.epoch_offsets.insert("fork_scope".into(), 1);
        self.fork = Some(CoownershipLedger {
            genesis,
            transitions: Vec::new(),
            resolutions: Vec::new(),
        });
    }

    fn restore_identity(&mut self, model: &Value) {
        let head = model["heads"]["main_scope"].as_str().unwrap();
        let name = model["nodes"][head][2].as_str().unwrap();
        let person = &self.people[name];
        let restored_id =
            public_key_id(&public_key_from_seed(&person.recovered_seed).unwrap()).unwrap();
        assert_eq!(restored_id, person.identity.person_id);
        self.recovered_identity = Some(name.to_owned());
    }

    fn ledger_for_scope(&self, scope: &str) -> &CoownershipLedger {
        match scope {
            "main_scope" => &self.main,
            "fork_scope" => self
                .fork
                .as_ref()
                .expect("fork genesis must precede its records"),
            other => panic!("unknown co-ownership scope {other}"),
        }
    }

    fn assert_matches(&self, model: &Value, trace: &[String]) {
        let main = validate_coownership_ledger(&self.main).unwrap();
        assert_scope_matches(self, model, "main_scope", "root_main", &main, trace);
        if model["forkExists"].as_bool().unwrap() {
            let fork = validate_coownership_ledger(
                self.fork
                    .as_ref()
                    .expect("model fork exists without Rust genesis"),
            )
            .unwrap();
            assert_scope_matches(self, model, "fork_scope", "root_fork", &fork, trace);
        } else {
            assert!(
                self.fork.is_none(),
                "Rust fork exists before TLC Fork; trace={trace:?}"
            );
        }

        let model_issued = strings(&model["issued"]);
        let model_observed = strings(&model["observed"]);
        let recovered = model["recoveredIdentity"].as_str().unwrap();
        assert_eq!(
            self.recovered_identity.as_deref().unwrap_or(""),
            recovered,
            "recovered identity projection; trace={trace:?}"
        );
        assert_eq!(
            self.pending.keys().cloned().collect::<BTreeSet<_>>(),
            model_issued.difference(&model_observed).cloned().collect(),
            "pending certificate ids; trace={trace:?}"
        );
        assert_eq!(
            self.candidate_data.keys().cloned().collect::<BTreeSet<_>>(),
            model_issued,
            "issued certificate ids; trace={trace:?}"
        );
        self.assert_retained_evidence(model, &model_observed, trace);
    }

    fn assert_retained_evidence(
        &self,
        model: &Value,
        observed: &BTreeSet<String>,
        trace: &[String],
    ) {
        let mut concrete_children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut concrete_observed = BTreeSet::new();
        for scope in [&self.main, self.fork.as_ref().unwrap_or(&self.main)] {
            for record in &scope.transitions {
                let child = self.node_by_hash.get(&payload_hash(&record.payload));
                let parent = self
                    .node_by_hash
                    .get(&record.payload.parent_certificate_hash);
                if let (Some(child), Some(parent)) = (child, parent) {
                    concrete_children
                        .entry(parent.clone())
                        .or_default()
                        .insert(child.clone());
                    if child != "root_main" && child != "root_fork" {
                        concrete_observed.insert(self.candidate_id_for_child(child));
                    }
                }
            }
            for record in &scope.resolutions {
                let child = self.node_by_hash.get(&payload_hash(&record.payload));
                let parent = self
                    .node_by_hash
                    .get(&record.payload.parent_certificate_hash);
                if let (Some(child), Some(parent)) = (child, parent) {
                    concrete_children
                        .entry(parent.clone())
                        .or_default()
                        .insert(child.clone());
                    concrete_observed.insert(self.candidate_id_for_child(child));
                }
            }
        }
        assert_eq!(
            &concrete_observed, observed,
            "retained observed records; trace={trace:?}"
        );
        let model_children = model["children"].as_object().unwrap();
        for (parent, children) in model_children {
            let expected = strings(children);
            let actual = concrete_children.get(parent).cloned().unwrap_or_default();
            assert_eq!(
                actual, expected,
                "child evidence for {parent}; trace={trace:?}"
            );
        }
    }

    fn candidate_id_for_child(&self, child: &str) -> String {
        self.candidate_data
            .iter()
            .find_map(|(id, candidate)| (candidate.child == child).then(|| id.clone()))
            .unwrap_or_else(|| panic!("observed unknown candidate child {child}"))
    }
}

#[ignore = "requires freshly generated TLC graph; executed by formal/check_coownership.sh"]
#[test]
fn tlc_coownership_graph_refines_signed_rust_transitions() {
    let graph = Graph::load("MESH_TLC_COOWNERSHIP_GRAPH");
    let mut exercised = BTreeSet::new();
    let mut outgoing: BTreeMap<String, Vec<&tlc_graph::Edge>> = BTreeMap::new();
    for edge in &graph.edges {
        outgoing.entry(edge.from.clone()).or_default().push(edge);
    }
    let initial = CoownershipHarness::new();
    initial.assert_matches(&graph.states[&graph.initial], &[]);
    let mut harnesses = BTreeMap::from([(graph.initial.clone(), initial)]);
    let mut traces = BTreeMap::from([(graph.initial.clone(), Vec::<String>::new())]);
    let mut queue = std::collections::VecDeque::from([graph.initial.clone()]);
    let mut edges = 0;
    while let Some(source) = queue.pop_front() {
        let source_harness = harnesses[&source].clone();
        let source_trace = traces[&source].clone();
        for edge in outgoing.get(&source).into_iter().flatten() {
            let mut trace = source_trace.clone();
            trace.push(edge.action.clone());
            let mut target_harness = source_harness.clone();
            target_harness.apply(
                &edge.action,
                &graph.states[&source],
                &graph.states[&edge.to],
            );
            exercised.insert(action(&edge.action).0.to_owned());
            edges += 1;
            if let Some(previous) = harnesses.get(&edge.to) {
                assert_eq!(
                    previous, &target_harness,
                    "one TLC state maps to different concrete signed histories; trace={trace:?}"
                );
            } else {
                target_harness.assert_matches(&graph.states[&edge.to], &trace);
                harnesses.insert(edge.to.clone(), target_harness);
                traces.insert(edge.to.clone(), trace);
                queue.push_back(edge.to.clone());
                if harnesses.len() % 500 == 0 {
                    println!(
                        "Rust co-ownership progress: {} unique TLC states, {edges} edges, {} queued",
                        harnesses.len(),
                        queue.len()
                    );
                }
            }
        }
    }
    assert_eq!(
        harnesses.len(),
        graph.states.len(),
        "unreachable TLC states"
    );
    assert_eq!(edges, graph.edges.len(), "not every TLC edge replayed");
    assert_eq!(
        exercised,
        BTreeSet::from([
            "Fork".into(),
            "Issue".into(),
            "Observe".into(),
            "Resolve".into(),
            "RestoreIdentity".into()
        ])
    );
    println!(
        "Rust co-ownership conformance: replayed {edges} concrete trace edges across {} TLC states and {} TLC edges",
        graph.states.len(),
        graph.edges.len()
    );
}

#[test]
fn coownership_implementation_negative_controls() {
    let mut quorum = CoownershipHarness::new();
    let parent = quorum.node_hashes["root_main"].clone();
    let under_quorum = plan_coownership_transition(CoownershipTransitionInput {
        ledger: quorum.main.clone(),
        owners: sorted_people(
            quorum.people,
            &["alice".into(), "bob".into(), "carol".into()],
        ),
        policy: CoownerPolicy::Majority,
    })
    .unwrap();
    assert_eq!(under_quorum.parent_certificate_hash, parent);
    quorum.main.transitions.push(CoownedTransition {
        approvals: approvals_for(quorum.people, &["alice".into()], &under_quorum),
        payload: under_quorum,
    });
    assert!(
        validate_coownership_ledger(&quorum.main).is_err(),
        "one of two current owners cannot approve a majority transition"
    );

    let stale = CoownershipHarness::new();
    let stale_payload = CoownedTransitionPayload {
        kind: "scope-coownership-transition".into(),
        version: 2,
        scope_id: "main_scope".into(),
        parent_certificate_hash: payload_hash(&stale.main.genesis.payload),
        epoch: 3,
        owners: sorted_people(stale.people, &["alice".into(), "bob".into()]),
        policy: CoownerPolicy::Majority,
    };
    let mut stale_ledger = stale.main.clone();
    stale_ledger.transitions.push(CoownedTransition {
        approvals: approvals_for(stale.people, &["alice".into()], &stale_payload),
        payload: stale_payload,
    });
    assert!(
        validate_coownership_ledger(&stale_ledger).is_err(),
        "transition epoch must match exact parent epoch"
    );

    let current = CoownershipHarness::new();
    let root = current.node_hashes["root_main"].clone();
    let left = signed_conformance_sibling(
        &current,
        &root,
        &["alice", "bob", "carol"],
        CoownerPolicy::Majority,
    );
    let right = signed_conformance_sibling(&current, &root, &["bob"], CoownerPolicy::Majority);
    let mut left_ledger = current.main.clone();
    left_ledger.transitions.push(left);
    let mut right_ledger = current.main.clone();
    right_ledger.transitions.push(right);
    let merged = merge_coownership_ledgers(Some(&left_ledger), &right_ledger).unwrap();
    assert!(
        matches!(
            validate_coownership_ledger(&merged).unwrap().status,
            CoownershipStatus::Ambiguous { .. }
        ),
        "merge must retain both authenticated sibling certificates"
    );
}

fn assert_scope_matches(
    harness: &CoownershipHarness,
    model: &Value,
    scope: &str,
    root_name: &str,
    actual: &ValidatedCoownership,
    trace: &[String],
) {
    let nodes = model["nodes"].as_object().unwrap();
    let head = model["heads"][scope].as_str().unwrap();
    let mut ancestry = Vec::new();
    let mut cursor = head;
    loop {
        ancestry.push(cursor.to_owned());
        let parent = nodes[cursor][4].as_str().unwrap();
        if parent.is_empty() {
            break;
        }
        cursor = parent;
    }
    ancestry.reverse();
    let open = &model["open"];
    let first_conflict = ancestry.iter().find(|node| open[*node].as_bool().unwrap());
    match (&actual.status, first_conflict) {
        (CoownershipStatus::Authorized(state), None) => {
            assert_authorized_state(harness, state, model, scope, head, trace);
        }
        (CoownershipStatus::Ambiguous { conflicts }, Some(parent)) => {
            assert!(
                !conflicts.is_empty(),
                "empty conflict response; trace={trace:?}"
            );
            let conflict = &conflicts[0];
            let parent_name = harness
                .node_by_hash
                .get(&conflict.parent_certificate_hash)
                .unwrap_or_else(|| panic!("unknown conflict parent; trace={trace:?}"));
            assert_eq!(
                parent_name.as_str(),
                parent.as_str(),
                "wrong active conflict; trace={trace:?}"
            );
            let actual_children = names_for_hashes(
                &harness.node_by_hash,
                &conflict.conflicting_certificate_hashes,
            );
            let expected_children = strings(&model["children"][parent.as_str()]);
            assert_eq!(
                actual_children, expected_children,
                "conflict sibling set; trace={trace:?}"
            );
        }
        (CoownershipStatus::Authorized(state), Some(parent)) => panic!(
            "Rust authorized while TLC has active conflict at {parent}; state={state:?}; trace={trace:?}"
        ),
        (CoownershipStatus::Ambiguous { conflicts }, None) => panic!(
            "Rust ambiguous while TLC ancestry clear; conflicts={conflicts:?}; trace={trace:?}"
        ),
    }
    assert_eq!(actual.scope_id, scope, "scope id; trace={trace:?}");
    assert_eq!(root_name == "root_fork", scope == "fork_scope");
}

fn assert_authorized_state(
    harness: &CoownershipHarness,
    actual: &CoownershipState,
    model: &Value,
    scope: &str,
    head: &str,
    trace: &[String],
) {
    let expected_node = &model["nodes"][head];
    let model_epoch = expected_node[0].as_u64().unwrap();
    let root_name = if scope == "fork_scope" {
        "root_fork"
    } else {
        "root_main"
    };
    let root_epoch = model["nodes"][root_name][0].as_u64().unwrap();
    let actual_root_epoch = if scope == "fork_scope" { 1 } else { 2 };
    let offset = actual_root_epoch as i64 - root_epoch as i64;
    assert_eq!(
        actual.epoch as i64,
        model_epoch as i64 + offset,
        "epoch; trace={trace:?}"
    );
    assert_eq!(actual.scope_id, scope, "scope id; trace={trace:?}");
    assert_eq!(
        actual.certificate_hash, harness.node_hashes[head],
        "current certificate hash; trace={trace:?}"
    );
    assert_eq!(
        actual
            .owners
            .iter()
            .map(|owner| owner.person_id.clone())
            .collect::<BTreeSet<_>>(),
        strings(&expected_node[1])
            .iter()
            .map(|name| harness.people[name.as_str()].identity.person_id.clone())
            .collect(),
        "authorized owners; trace={trace:?}"
    );
    assert_eq!(
        actual.policy,
        parse_policy(expected_node[3].as_str().unwrap()),
        "policy; trace={trace:?}"
    );
}

fn parse_candidate(label: &str) -> Candidate {
    let (_, args) = label.split_once('(').expect("TLC candidate action");
    let record = args
        .strip_suffix(')')
        .expect("TLC candidate action argument");
    let fields = parse_record(record);
    Candidate {
        id: unquote(&fields["id"]),
        child: fields["child"].to_owned(),
        parent: fields["parent"].to_owned(),
        scope: fields["scope"].to_owned(),
        kind: unquote(&fields["kind"]),
        epoch: fields["epoch"].parse().unwrap(),
        owners: parse_set(&fields["owners"]),
        signers: parse_set(&fields["signers"]),
        policy: parse_policy(&unquote(&fields["mode"])),
        refs: parse_set(&fields["refs"]),
    }
}

fn parse_record(record: &str) -> BTreeMap<String, String> {
    let record = record.trim();
    let body = record
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .expect("expected TLA record action argument");
    let mut fields = BTreeMap::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in body.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        match ch {
            '"' => quoted = true,
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                insert_record_field(&mut fields, &body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    insert_record_field(&mut fields, &body[start..]);
    fields
}

fn insert_record_field(fields: &mut BTreeMap<String, String>, field: &str) {
    let (name, value) = field.split_once("|->").expect("TLA record field");
    fields.insert(name.trim().to_owned(), value.trim().to_owned());
}

fn parse_set(value: &str) -> Vec<String> {
    let body = value
        .trim()
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .expect("TLA set");
    if body.trim().is_empty() {
        Vec::new()
    } else {
        body.split(',').map(|value| unquote(value.trim())).collect()
    }
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('"') {
        serde_json::from_str(value).unwrap()
    } else {
        value.to_owned()
    }
}

fn parse_policy(value: &str) -> CoownerPolicy {
    match value {
        "Majority" => CoownerPolicy::Majority,
        "Unanimous" => CoownerPolicy::Unanimous,
        other => panic!("unknown TLA co-owner policy {other}"),
    }
}

fn sorted_people(
    people: &BTreeMap<&'static str, Person>,
    names: &[String],
) -> Vec<CoownerIdentity> {
    let mut owners = names
        .iter()
        .map(|name| people[name.as_str()].identity.clone())
        .collect::<Vec<_>>();
    owners.sort_by(|left, right| left.person_id.cmp(&right.person_id));
    owners
}

fn approvals_for<T: serde::Serialize>(
    people: &BTreeMap<&'static str, Person>,
    signers: &[String],
    payload: &T,
) -> Vec<CoownedApproval> {
    signers
        .iter()
        .map(|name| {
            let person = &people[name.as_str()];
            sign_coownership_approval(&person.device_seed, payload, &person.device_id).unwrap()
        })
        .collect()
}

fn names_for_hashes(
    node_by_hash: &BTreeMap<String, String>,
    hashes: &[String],
) -> BTreeSet<String> {
    hashes
        .iter()
        .map(|hash| {
            node_by_hash
                .get(hash)
                .unwrap_or_else(|| {
                    panic!("unknown certificate hash in co-ownership evidence: {hash}")
                })
                .clone()
        })
        .collect()
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("expected TLC set")
        .iter()
        .map(|item| item.as_str().expect("TLC set string").to_owned())
        .collect()
}

fn pending_hash(pending: &PendingRecord) -> String {
    match pending {
        PendingRecord::Transition(record) => payload_hash(&record.payload),
        PendingRecord::Resolution(record) => payload_hash(&record.payload),
    }
}

fn signed_conformance_sibling(
    harness: &CoownershipHarness,
    parent_hash: &str,
    owner_names: &[&str],
    policy: CoownerPolicy,
) -> CoownedTransition {
    let payload = CoownedTransitionPayload {
        kind: "scope-coownership-transition".into(),
        version: 2,
        scope_id: "main_scope".into(),
        parent_certificate_hash: parent_hash.into(),
        epoch: 3,
        owners: sorted_people(
            harness.people,
            &owner_names
                .iter()
                .map(|name| (*name).into())
                .collect::<Vec<_>>(),
        ),
        policy,
    };
    CoownedTransition {
        approvals: approvals_for(harness.people, &["alice".into(), "bob".into()], &payload),
        payload,
    }
}

fn payload_hash<T: serde::Serialize>(payload: &T) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use meta_mesh_core::canonicalize_json;
    use sha2::{Digest, Sha256};

    let value = serde_json::to_value(payload).unwrap();
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        canonicalize_json(&value).unwrap().as_bytes(),
    ))
}
