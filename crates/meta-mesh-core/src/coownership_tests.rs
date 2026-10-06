use super::*;
use crate::{DeviceCertificatePayload, public_key_from_seed, sign_device_certificate};
use serde_json::Value;

struct Person {
    identity: CoownerIdentity,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
    device_id: String,
}

fn person(root_byte: u8, device_byte: u8) -> Person {
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
    Person {
        identity: CoownerIdentity {
            person_id,
            public_key,
            certificates: vec![certificate],
        },
        root_seed,
        device_seed,
        device_id,
    }
}

fn genesis(alice: &Person) -> CoownershipLedger {
    let payload = create_coownership_genesis_payload(CoownershipGenesisInput {
        scope_id: "scope-alpha".into(),
        creator: alice.identity.clone(),
        policy: CoownerPolicy::Majority,
    })
    .unwrap();
    CoownershipLedger {
        genesis: sign_coownership_genesis(&alice.device_seed, payload, &alice.device_id).unwrap(),
        transitions: Vec::new(),
        resolutions: Vec::new(),
    }
}

fn signed_transition(
    parent_hash: &str,
    epoch: u64,
    scope_id: &str,
    owners: Vec<CoownerIdentity>,
    policy: CoownerPolicy,
    approvers: &[&Person],
) -> CoownedTransition {
    let payload = CoownedTransitionPayload {
        kind: "scope-coownership-transition".into(),
        version: COOWNERSHIP_VERSION,
        scope_id: scope_id.into(),
        parent_certificate_hash: parent_hash.into(),
        epoch,
        owners,
        policy,
    };
    let approvals = approvers
        .iter()
        .map(|person| {
            sign_coownership_approval(&person.device_seed, &payload, &person.device_id).unwrap()
        })
        .collect();
    CoownedTransition { payload, approvals }
}

fn signed_resolution(
    payload: CoownedResolutionPayload,
    approvers: &[&Person],
) -> CoownedResolution {
    let approvals = approvers
        .iter()
        .map(|person| {
            sign_coownership_approval(&person.device_seed, &payload, &person.device_id).unwrap()
        })
        .collect();
    CoownedResolution { payload, approvals }
}

fn certificate_hash<T: Serialize>(payload: &T) -> String {
    payload_hash(payload).unwrap()
}

fn add_transition(ledger: &mut CoownershipLedger, transition: CoownedTransition) {
    ledger.transitions.push(transition);
}

#[test]
fn genesis_is_authenticated_and_opt_in_v2() {
    let alice = person(1, 2);
    let ledger = genesis(&alice);
    let validated = validate_coownership_ledger(&ledger).unwrap();
    let CoownershipStatus::Authorized(state) = validated.status else {
        panic!("genesis should authorize creator");
    };
    assert_eq!(state.epoch, 1);
    assert_eq!(state.owners, vec![alice.identity]);
    assert_eq!(ledger.genesis.payload.version, 2);

    let mut forged = ledger;
    forged.genesis.payload.scope_id = "scope-forged".into();
    assert!(validate_coownership_ledger(&forged).is_err());
}

#[test]
fn parent_policy_counts_distinct_people_and_rejects_stale_owner() {
    let alice = person(1, 2);
    let bob = person(3, 4);
    let carol = person(5, 6);
    let mut ledger = genesis(&alice);
    let genesis_hash = certificate_hash(&ledger.genesis.payload);
    let add_bob = signed_transition(
        &genesis_hash,
        2,
        "scope-alpha",
        sorted(&[&alice, &bob]),
        CoownerPolicy::Majority,
        &[&alice],
    );
    add_transition(&mut ledger, add_bob);
    let add_bob_hash = certificate_hash(&ledger.transitions[0].payload);

    let mut stale = signed_transition(
        &add_bob_hash,
        3,
        "scope-alpha",
        sorted(&[&alice, &bob, &carol]),
        CoownerPolicy::Majority,
        &[&alice],
    );
    ledger.transitions.push(stale.clone());
    assert!(validate_coownership_ledger(&ledger).is_err());

    // Alice's root and device signatures still count as one owner.
    let device_signature =
        sign_coownership_approval(&alice.device_seed, &stale.payload, &alice.device_id).unwrap();
    let root_signature =
        sign_coownership_approval(&alice.root_seed, &stale.payload, &alice.identity.person_id)
            .unwrap();
    stale.approvals = vec![device_signature, root_signature];
    ledger.transitions[1] = stale;
    assert!(validate_coownership_ledger(&ledger).is_err());

    let mut forged_signer_id = signed_transition(
        &add_bob_hash,
        3,
        "scope-alpha",
        sorted(&[&alice, &bob, &carol]),
        CoownerPolicy::Majority,
        &[],
    );
    forged_signer_id.approvals.push(
        sign_coownership_approval(
            &alice.root_seed,
            &forged_signer_id.payload,
            "unowned-device-id",
        )
        .unwrap(),
    );
    ledger.transitions[1] = forged_signer_id;
    assert!(validate_coownership_ledger(&ledger).is_err());

    let authorized = signed_transition(
        &add_bob_hash,
        3,
        "scope-alpha",
        sorted(&[&alice, &bob, &carol]),
        CoownerPolicy::Majority,
        &[&alice, &bob],
    );
    ledger.transitions[1] = authorized.clone();
    assert!(matches!(
        validate_coownership_ledger(&ledger).unwrap().status,
        CoownershipStatus::Authorized(_)
    ));

    // Alice can vote to remove herself, then cannot approve a descendant.
    let authorized_hash = certificate_hash(&authorized.payload);
    let remove_alice = signed_transition(
        &authorized_hash,
        4,
        "scope-alpha",
        sorted(&[&bob, &carol]),
        CoownerPolicy::Majority,
        &[&alice, &bob],
    );
    let remove_hash = certificate_hash(&remove_alice.payload);
    ledger.transitions.push(remove_alice);
    ledger.transitions.push(signed_transition(
        &remove_hash,
        5,
        "scope-alpha",
        sorted(&[&alice, &bob, &carol]),
        CoownerPolicy::Majority,
        &[&alice, &bob],
    ));
    assert!(validate_coownership_ledger(&ledger).is_err());
}

#[test]
fn merge_retains_siblings_and_resolution_reopens_on_late_evidence() {
    let alice = person(1, 2);
    let bob = person(3, 4);
    let carol = person(5, 6);
    let mut base = genesis(&alice);
    let parent = certificate_hash(&base.genesis.payload);
    let left = signed_transition(
        &parent,
        2,
        "scope-alpha",
        sorted(&[&alice, &bob]),
        CoownerPolicy::Majority,
        &[&alice],
    );
    let right = signed_transition(
        &parent,
        2,
        "scope-alpha",
        sorted(&[&alice, &carol]),
        CoownerPolicy::Majority,
        &[&alice],
    );
    let mut left_ledger = base.clone();
    left_ledger.transitions.push(left.clone());
    let left_hash = certificate_hash(&left.payload);
    left_ledger.transitions.push(signed_transition(
        &left_hash,
        3,
        "scope-alpha",
        sorted(&[&alice, &bob]),
        CoownerPolicy::Majority,
        &[&alice, &bob],
    ));
    left_ledger.transitions.push(signed_transition(
        &left_hash,
        3,
        "scope-alpha",
        sorted(&[&alice, &bob]),
        CoownerPolicy::Unanimous,
        &[&alice, &bob],
    ));
    let mut right_ledger = base.clone();
    right_ledger.transitions.push(right.clone());
    let merged = merge_coownership_ledgers(Some(&left_ledger), &right_ledger).unwrap();
    let CoownershipStatus::Ambiguous { conflicts } =
        validate_coownership_ledger(&merged).unwrap().status
    else {
        panic!("sibling certificates must pause governance");
    };
    assert_eq!(conflicts[0].conflicting_certificate_hashes.len(), 2);

    let resolution_payload = plan_coownership_resolution(CoownershipResolutionInput {
        ledger: merged.clone(),
        parent_certificate_hash: parent.clone(),
        owners: sorted(&[&alice, &bob]),
        policy: CoownerPolicy::Majority,
    })
    .unwrap();
    let resolution = signed_resolution(resolution_payload, &[&alice]);
    base.resolutions.push(resolution.clone());
    base.transitions = merged.transitions.clone();
    assert!(matches!(
        validate_coownership_ledger(&base).unwrap().status,
        CoownershipStatus::Authorized(_)
    ));

    let late = signed_transition(
        &parent,
        2,
        "scope-alpha",
        sorted(&[&alice, &carol]),
        CoownerPolicy::Unanimous,
        &[&alice],
    );
    // A semantically distinct payload from same branch is a new sibling.
    base.transitions.push(late);
    assert!(matches!(
        validate_coownership_ledger(&base).unwrap().status,
        CoownershipStatus::Ambiguous { .. }
    ));
}

#[test]
fn competing_resolutions_need_later_resolution_covering_both() {
    let alice = person(1, 2);
    let bob = person(3, 4);
    let carol = person(5, 6);
    let mut ledger = genesis(&alice);
    let parent = certificate_hash(&ledger.genesis.payload);
    let a = signed_transition(
        &parent,
        2,
        "scope-alpha",
        sorted(&[&alice, &bob]),
        CoownerPolicy::Majority,
        &[&alice],
    );
    let b = signed_transition(
        &parent,
        2,
        "scope-alpha",
        sorted(&[&alice, &carol]),
        CoownerPolicy::Majority,
        &[&alice],
    );
    let aid = certificate_hash(&a.payload);
    let bid = certificate_hash(&b.payload);
    ledger.transitions = vec![a, b];
    let mut first = plan_coownership_resolution(CoownershipResolutionInput {
        ledger: ledger.clone(),
        parent_certificate_hash: parent.clone(),
        owners: sorted(&[&alice, &bob]),
        policy: CoownerPolicy::Majority,
    })
    .unwrap();
    first.conflicting_certificate_hashes = vec![aid.clone(), bid.clone()];
    first.conflicting_certificate_hashes.sort();
    let mut second = first.clone();
    second.owners = sorted(&[&alice, &carol]);
    let first = signed_resolution(first, &[&alice]);
    let second = signed_resolution(second, &[&alice]);
    ledger.resolutions.extend([first, second]);
    assert!(matches!(
        validate_coownership_ledger(&ledger).unwrap().status,
        CoownershipStatus::Ambiguous { .. }
    ));

    let prior_resolution_ids = ledger
        .resolutions
        .iter()
        .map(|record| certificate_hash(&record.payload))
        .collect::<Vec<_>>();
    let mut covering = plan_coownership_resolution(CoownershipResolutionInput {
        ledger: ledger.clone(),
        parent_certificate_hash: parent,
        owners: sorted(&[&alice, &bob]),
        policy: CoownerPolicy::Majority,
    })
    .unwrap();
    covering
        .conflicting_certificate_hashes
        .extend(prior_resolution_ids);
    covering.conflicting_certificate_hashes.sort();
    covering.conflicting_certificate_hashes.dedup();
    ledger
        .resolutions
        .push(signed_resolution(covering, &[&alice]));
    assert!(matches!(
        validate_coownership_ledger(&ledger).unwrap().status,
        CoownershipStatus::Authorized(_)
    ));
}

#[test]
fn merge_is_idempotent_and_reordering_does_not_change_decision() {
    let alice = person(1, 2);
    let bob = person(3, 4);
    let mut ledger = genesis(&alice);
    let parent = certificate_hash(&ledger.genesis.payload);
    ledger.transitions.push(signed_transition(
        &parent,
        2,
        "scope-alpha",
        sorted(&[&alice, &bob]),
        CoownerPolicy::Majority,
        &[&alice],
    ));
    let twice = merge_coownership_ledgers(Some(&ledger), &ledger).unwrap();
    assert_eq!(twice.transitions.len(), 1);
    assert_eq!(
        validate_coownership_ledger(&twice).unwrap(),
        validate_coownership_ledger(&ledger).unwrap()
    );
    let mut reversed = ledger.clone();
    reversed.transitions.reverse();
    assert_eq!(
        validate_coownership_ledger(&reversed).unwrap(),
        validate_coownership_ledger(&ledger).unwrap()
    );
}

#[test]
fn fork_starts_new_genesis_without_source_authority() {
    let alice = person(1, 2);
    let bob = person(3, 4);
    let fork = plan_coownership_fork(CoownershipForkInput {
        source_ledger: genesis(&alice),
        scope_id: "scope-fork".into(),
        creator: bob.identity.clone(),
        policy: CoownerPolicy::Unanimous,
    })
    .unwrap();
    assert_eq!(fork.scope_id, "scope-fork");
    assert_eq!(fork.creator, bob.identity);
    assert_ne!(fork.scope_id, "scope-alpha");
    assert_ne!(fork.creator.person_id, alice.identity.person_id);
}

#[test]
fn unknown_v2_fields_are_rejected() {
    let alice = person(1, 2);
    let payload = create_coownership_genesis_payload(CoownershipGenesisInput {
        scope_id: "scope-alpha".into(),
        creator: alice.identity,
        policy: CoownerPolicy::Majority,
    })
    .unwrap();
    let mut value = serde_json::to_value(payload).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), Value::Bool(true));
    assert!(serde_json::from_value::<CoownedGenesisPayload>(value).is_err());
}

#[test]
fn signed_records_reject_cross_scope_epoch_or_empty_owners() {
    let alice = person(1, 2);
    let bob = person(3, 4);
    let ledger = genesis(&alice);
    let parent = certificate_hash(&ledger.genesis.payload);
    for (scope, epoch, owners) in [
        ("scope-other", 2, sorted(&[&alice, &bob])),
        ("scope-alpha", 3, sorted(&[&alice, &bob])),
        ("scope-alpha", 2, vec![]),
    ] {
        let record = signed_transition(
            &parent,
            epoch,
            scope,
            owners,
            CoownerPolicy::Majority,
            &[&alice],
        );
        let mut invalid = ledger.clone();
        invalid.transitions.push(record);
        assert!(validate_coownership_ledger(&invalid).is_err());
    }
}

#[test]
fn resource_and_strict_record_limits_reject_before_admission() {
    let alice = person(1, 2);
    assert!(
        create_coownership_genesis_payload(CoownershipGenesisInput {
            scope_id: "x".repeat(MAX_SCOPE_ID_BYTES + 1),
            creator: alice.identity.clone(),
            policy: CoownerPolicy::Majority,
        })
        .is_err()
    );
    assert!(next_epoch(u64::MAX).is_err());
    assert!(validate_payload_size(&"x".repeat(MAX_COOWNERSHIP_PAYLOAD_BYTES + 1)).is_err());
    assert!(validate_owner_set(&vec![alice.identity.clone(); MAX_COOWNERSHIP_OWNERS + 1]).is_err());
    let ledger = genesis(&alice);
    let mut value = serde_json::to_value(&ledger).unwrap();
    value["genesis"]["unexpected"] = Value::Bool(true);
    assert!(serde_json::from_value::<CoownershipLedger>(value).is_err());
    let payload = plan_coownership_transition(CoownershipTransitionInput {
        ledger: ledger.clone(),
        owners: vec![alice.identity.clone()],
        policy: CoownerPolicy::Unanimous,
    })
    .unwrap();
    let approval =
        sign_coownership_approval(&alice.device_seed, &payload, &alice.device_id).unwrap();
    assert!(
        verify_approvals(
            &payload,
            &vec![approval.clone(); MAX_COOWNERSHIP_APPROVALS + 1],
            std::slice::from_ref(&alice.identity),
            CoownerPolicy::Majority
        )
        .is_err()
    );
    let mut value = serde_json::to_value(approval).unwrap();
    value["unexpected"] = Value::Bool(true);
    assert!(serde_json::from_value::<CoownedApproval>(value).is_err());
    let record = CoownedTransition {
        payload,
        approvals: vec![],
    };
    let mut too_many = ledger;
    too_many.transitions = vec![record; MAX_COOWNERSHIP_TRANSITIONS + 1];
    assert!(validate_coownership_ledger(&too_many).is_err());
    let mut oversized_signature = genesis(&alice);
    oversized_signature.genesis.signature = "x".repeat(1_024);
    assert!(
        validate_coownership_ledger(&oversized_signature)
            .unwrap_err()
            .contains("signature length")
    );
    assert!(validate_serialized_limit(&"x".repeat(32), 16).is_err());
    assert!(validate_serialized_limit(&"x", 16).is_ok());
}

#[test]
fn reverse_ordered_deep_history_has_same_projection() {
    let alice = person(1, 2);
    let mut ledger = genesis(&alice);
    let mut parent = certificate_hash(&ledger.genesis.payload);
    for epoch in 2..34 {
        let policy = if epoch % 2 == 0 {
            CoownerPolicy::Unanimous
        } else {
            CoownerPolicy::Majority
        };
        let record = signed_transition(
            &parent,
            epoch,
            "scope-alpha",
            vec![alice.identity.clone()],
            policy,
            &[&alice],
        );
        parent = certificate_hash(&record.payload);
        ledger.transitions.push(record);
    }
    let ordered = validate_coownership_ledger(&ledger).unwrap();
    ledger.transitions.reverse();
    assert_eq!(validate_coownership_ledger(&ledger).unwrap(), ordered);
    ledger.transitions[0].payload.parent_certificate_hash = "x".repeat(43);
    assert!(
        validate_coownership_ledger(&ledger)
            .unwrap_err()
            .contains("orphan or cycle")
    );
}

#[test]
fn two_certified_devices_of_one_person_cannot_supply_two_owner_votes() {
    let mut alice = person(1, 2);
    let alice_second = person(1, 7);
    let bob = person(3, 4);
    alice
        .identity
        .certificates
        .extend(alice_second.identity.certificates.clone());
    let mut ledger = genesis(&alice);
    let payload = plan_coownership_transition(CoownershipTransitionInput {
        ledger: ledger.clone(),
        owners: sorted(&[&alice, &bob]),
        policy: CoownerPolicy::Majority,
    })
    .unwrap();
    let hash = certificate_hash(&payload);
    ledger.transitions.push(CoownedTransition {
        approvals: vec![
            sign_coownership_approval(&alice.device_seed, &payload, &alice.device_id).unwrap(),
        ],
        payload,
    });
    let duplicate_person_votes = signed_transition(
        &hash,
        3,
        "scope-alpha",
        vec![bob.identity.clone()],
        CoownerPolicy::Majority,
        &[&alice, &alice_second],
    );
    ledger.transitions.push(duplicate_person_votes);
    assert!(
        validate_coownership_ledger(&ledger)
            .unwrap_err()
            .contains("Insufficient distinct")
    );
    let bob_approval = sign_coownership_approval(
        &bob.device_seed,
        &ledger.transitions[1].payload,
        &bob.device_id,
    )
    .unwrap();
    ledger.transitions[1].approvals.push(bob_approval);
    assert!(matches!(
        validate_coownership_ledger(&ledger).unwrap().status,
        CoownershipStatus::Authorized(_)
    ));
}

fn sorted(people: &[&Person]) -> Vec<CoownerIdentity> {
    let mut owners = people
        .iter()
        .map(|person| person.identity.clone())
        .collect::<Vec<_>>();
    owners.sort_by(|left, right| left.person_id.cmp(&right.person_id));
    owners
}
