//! Opt-in version 2 shared-owner authority for replicated scopes.
//!
//! This ledger is independent from the version 1 single-controller ledger.

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope, canonicalize_json,
    public_key_id, verify_device_certificate_chain, verify_signed_envelope,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

pub const COOWNERSHIP_VERSION: u8 = 2;
pub const MAX_COOWNERSHIP_OWNERS: usize = 64;
pub const MAX_COOWNERSHIP_TRANSITIONS: usize = 4_096;
pub const MAX_COOWNERSHIP_RESOLUTIONS: usize = 4_096;
pub const MAX_COOWNERSHIP_APPROVALS: usize = MAX_COOWNERSHIP_OWNERS * 32;
pub const MAX_COOWNERSHIP_LEDGER_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCOPE_ID_BYTES: usize = 512;
const MAX_COOWNERSHIP_PAYLOAD_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoownerPolicy {
    Majority,
    Unanimous,
}

impl CoownerPolicy {
    fn quorum(self, owners: usize) -> usize {
        match self {
            Self::Majority => owners / 2 + 1,
            Self::Unanimous => owners,
        }
    }
}

/// Strict v2 signature container. Shared device-certificate values retain
/// their existing v1 serde behavior; all new v2 record fields are strict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownedSignedRecord<T> {
    pub payload: T,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownedApproval {
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownedGenesisPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub creator: CoownerIdentity,
    pub policy: CoownerPolicy,
    pub epoch: u64,
}

/// Public owner identity and its certified signing devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownerIdentity {
    pub person_id: String,
    pub public_key: String,
    pub certificates: Vec<DeviceCertificate>,
}

impl CoownerIdentity {
    fn validate(&self) -> Result<(), String> {
        validate_serialized_limit(self, MAX_COOWNERSHIP_PAYLOAD_BYTES)?;
        if self.person_id.is_empty()
            || self.person_id.len() > MAX_SCOPE_ID_BYTES
            || self.public_key.len() != 43
            || self.certificates.is_empty()
            || self.certificates.len() > crate::MAX_CERTIFICATE_CHAIN_LENGTH
            || public_key_id(&self.public_key)? != self.person_id
        {
            return Err("Invalid co-owner identity".into());
        }
        for certificate in &self.certificates {
            if certificate.signature.len() != 86 {
                return Err("Invalid co-owner certificate signature length".into());
            }
        }
        let identity = PublicIdentity {
            person_id: self.person_id.clone(),
            public_key: self.public_key.clone(),
            display_name: String::new(),
        };
        let device = self.certificates[0].payload.device_id.as_str();
        verify_device_certificate_chain(
            &identity,
            device,
            &self.certificates,
            DEFAULT_SIGNATURE_DOMAIN,
        )?;
        Ok(())
    }
}

pub type SignedCoownedGenesis = CoownedSignedRecord<CoownedGenesisPayload>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownershipGenesisInput {
    pub scope_id: String,
    pub creator: CoownerIdentity,
    pub policy: CoownerPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownedTransitionPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub parent_certificate_hash: String,
    pub epoch: u64,
    pub owners: Vec<CoownerIdentity>,
    pub policy: CoownerPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownedTransition {
    pub payload: CoownedTransitionPayload,
    pub approvals: Vec<CoownedApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownedResolutionPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub parent_certificate_hash: String,
    pub epoch: u64,
    /// Sorted certificate hashes of all known siblings, excluding this resolution.
    pub conflicting_certificate_hashes: Vec<String>,
    pub owners: Vec<CoownerIdentity>,
    pub policy: CoownerPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownedResolution {
    pub payload: CoownedResolutionPayload,
    pub approvals: Vec<CoownedApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownershipLedger {
    pub genesis: SignedCoownedGenesis,
    pub transitions: Vec<CoownedTransition>,
    pub resolutions: Vec<CoownedResolution>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownershipTransitionInput {
    pub ledger: CoownershipLedger,
    pub owners: Vec<CoownerIdentity>,
    pub policy: CoownerPolicy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownershipResolutionInput {
    pub ledger: CoownershipLedger,
    pub parent_certificate_hash: String,
    pub owners: Vec<CoownerIdentity>,
    pub policy: CoownerPolicy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoownershipForkInput {
    pub source_ledger: CoownershipLedger,
    pub scope_id: String,
    pub creator: CoownerIdentity,
    pub policy: CoownerPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoownershipState {
    pub scope_id: String,
    pub certificate_hash: String,
    pub epoch: u64,
    pub owners: Vec<CoownerIdentity>,
    pub policy: CoownerPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoownershipConflict {
    pub parent_certificate_hash: String,
    pub conflicting_certificate_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "camelCase")]
pub enum CoownershipStatus {
    Authorized(CoownershipState),
    Ambiguous { conflicts: Vec<CoownershipConflict> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedCoownership {
    pub scope_id: String,
    pub status: CoownershipStatus,
}

pub fn create_coownership_genesis_payload(
    input: CoownershipGenesisInput,
) -> Result<CoownedGenesisPayload, String> {
    validate_scope_id(&input.scope_id)?;
    input.creator.validate()?;
    let payload = CoownedGenesisPayload {
        kind: "scope-coownership-genesis".into(),
        version: COOWNERSHIP_VERSION,
        scope_id: input.scope_id,
        creator: input.creator,
        policy: input.policy,
        epoch: 1,
    };
    validate_payload_size(&payload)?;
    Ok(payload)
}

pub fn sign_coownership_genesis(
    seed: &[u8; 32],
    payload: CoownedGenesisPayload,
    signer_key_id: impl Into<String>,
) -> Result<SignedCoownedGenesis, String> {
    sign_strict_record(seed, payload, signer_key_id)
}

/// Signs one approval over the exact shared payload. Call once per owner.
pub fn sign_coownership_approval<T: Serialize>(
    seed: &[u8; 32],
    payload: &T,
    signer_key_id: impl Into<String>,
) -> Result<CoownedApproval, String> {
    let record = crate::sign_json_envelope(
        seed,
        serde_json::to_value(payload).map_err(|_| "Co-ownership payload invalid")?,
        signer_key_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    Ok(CoownedApproval {
        signer_key_id: record.signer_key_id,
        signature: record.signature,
    })
}

fn sign_strict_record<T: Serialize>(
    seed: &[u8; 32],
    payload: T,
    signer_key_id: impl Into<String>,
) -> Result<CoownedSignedRecord<T>, String> {
    let record = crate::sign_json_envelope(
        seed,
        serde_json::to_value(&payload).map_err(|_| "Co-ownership payload invalid")?,
        signer_key_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    Ok(CoownedSignedRecord {
        payload,
        signer_key_id: record.signer_key_id,
        signature: record.signature,
    })
}

pub fn plan_coownership_transition(
    input: CoownershipTransitionInput,
) -> Result<CoownedTransitionPayload, String> {
    let validated = validate_coownership_ledger(&input.ledger)?;
    let CoownershipStatus::Authorized(state) = validated.status else {
        return Err("Co-ownership authority is ambiguous".into());
    };
    validate_owner_set(&input.owners)?;
    if input.owners == state.owners && input.policy == state.policy {
        return Err("Co-ownership transition changes no authority".into());
    }
    let payload = CoownedTransitionPayload {
        kind: "scope-coownership-transition".into(),
        version: COOWNERSHIP_VERSION,
        scope_id: state.scope_id,
        parent_certificate_hash: state.certificate_hash,
        epoch: next_epoch(state.epoch)?,
        owners: input.owners,
        policy: input.policy,
    };
    validate_payload_size(&payload)?;
    Ok(payload)
}

pub fn plan_coownership_resolution(
    input: CoownershipResolutionInput,
) -> Result<CoownedResolutionPayload, String> {
    validate_owner_set(&input.owners)?;
    let graph = build_graph(&input.ledger)?;
    let parent = graph
        .nodes
        .get(&input.parent_certificate_hash)
        .ok_or("Unknown co-ownership conflict parent")?;
    let siblings = graph
        .children
        .get(&input.parent_certificate_hash)
        .cloned()
        .unwrap_or_default();
    if siblings.len() < 2 {
        return Err("Co-ownership parent has no conflict".into());
    }
    let mut sibling_ids = siblings.into_iter().collect::<Vec<_>>();
    sibling_ids.sort();
    let ids = sibling_ids.iter().cloned().collect::<BTreeSet<_>>();
    let unique_resolvers = resolver_ids(&graph, &input.parent_certificate_hash, &ids);
    if unique_resolvers.len() == 1 {
        return Err("Co-ownership conflict already has a complete resolution".into());
    }
    let payload = CoownedResolutionPayload {
        kind: "scope-coownership-resolution".into(),
        version: COOWNERSHIP_VERSION,
        scope_id: parent.scope_id.clone(),
        parent_certificate_hash: input.parent_certificate_hash,
        epoch: next_epoch(parent.epoch)?,
        conflicting_certificate_hashes: sibling_ids,
        owners: input.owners,
        policy: input.policy,
    };
    validate_payload_size(&payload)?;
    Ok(payload)
}

pub fn plan_coownership_fork(input: CoownershipForkInput) -> Result<CoownedGenesisPayload, String> {
    // New scope gets only caller's authenticated identity. Source authority is not copied.
    let source = validate_coownership_ledger(&input.source_ledger)?;
    if source.scope_id == input.scope_id {
        return Err("Co-ownership fork requires a new scope id".into());
    }
    create_coownership_genesis_payload(CoownershipGenesisInput {
        scope_id: input.scope_id,
        creator: input.creator,
        policy: input.policy,
    })
}

pub fn validate_coownership_ledger(
    ledger: &CoownershipLedger,
) -> Result<ValidatedCoownership, String> {
    let graph = build_graph(ledger)?;
    let root_id = graph.genesis_hash.clone();
    let mut cursor = root_id;
    loop {
        let node = graph
            .nodes
            .get(&cursor)
            .ok_or("Invalid co-ownership parent")?;
        let siblings = graph.children.get(&cursor).cloned().unwrap_or_default();
        if siblings.is_empty() {
            return Ok(ValidatedCoownership {
                scope_id: node.scope_id.clone(),
                status: CoownershipStatus::Authorized(state(node, &cursor)),
            });
        }
        if siblings.len() == 1 {
            cursor = siblings.into_iter().next().expect("one sibling");
            continue;
        }
        let ids = siblings.iter().cloned().collect::<BTreeSet<_>>();
        let resolvers = resolver_ids(&graph, &cursor, &ids);
        if resolvers.len() != 1 {
            let mut conflicting_certificate_hashes = ids.into_iter().collect::<Vec<_>>();
            conflicting_certificate_hashes.sort();
            return Ok(ValidatedCoownership {
                scope_id: node.scope_id.clone(),
                status: CoownershipStatus::Ambiguous {
                    conflicts: vec![CoownershipConflict {
                        parent_certificate_hash: cursor,
                        conflicting_certificate_hashes,
                    }],
                },
            });
        }
        cursor = resolvers.into_iter().next().expect("one resolver");
    }
}

/// Union validated history. Conflicts are valid states and remain in the result.
pub fn merge_coownership_ledgers(
    current: Option<&CoownershipLedger>,
    incoming: &CoownershipLedger,
) -> Result<CoownershipLedger, String> {
    let mut merged = incoming.clone();
    let Some(current) = current else {
        build_graph(&merged)?;
        sort_ledger(&mut merged);
        return Ok(merged);
    };
    let left = build_graph(current)?;
    let right = build_graph(incoming)?;
    if left.genesis_hash != right.genesis_hash {
        return Err("Co-ownership genesis cannot change".into());
    }
    for record in &current.transitions {
        merge_transition(&mut merged.transitions, record.clone());
    }
    for record in &current.resolutions {
        merge_resolution(&mut merged.resolutions, record.clone());
    }
    sort_ledger(&mut merged);
    build_graph(&merged)?;
    Ok(merged)
}

#[derive(Debug, Clone)]
struct Node {
    scope_id: String,
    epoch: u64,
    owners: Vec<CoownerIdentity>,
    policy: CoownerPolicy,
}

#[derive(Debug)]
struct Graph {
    genesis_hash: String,
    nodes: HashMap<String, Node>,
    children: HashMap<String, BTreeSet<String>>,
    resolutions: HashMap<String, CoownedResolutionPayload>,
}

fn build_graph(ledger: &CoownershipLedger) -> Result<Graph, String> {
    if ledger.transitions.len() > MAX_COOWNERSHIP_TRANSITIONS
        || ledger.resolutions.len() > MAX_COOWNERSHIP_RESOLUTIONS
    {
        return Err("Co-ownership record limit exceeded".into());
    }
    validate_serialized_limit(ledger, MAX_COOWNERSHIP_LEDGER_BYTES)?;
    let genesis = &ledger.genesis.payload;
    validate_genesis(genesis)?;
    genesis.creator.validate()?;
    verify_signed_record(&ledger.genesis, &genesis.creator)?;
    let genesis_hash = payload_hash(genesis)?;
    let mut nodes = HashMap::new();
    nodes.insert(
        genesis_hash.clone(),
        Node {
            scope_id: genesis.scope_id.clone(),
            epoch: genesis.epoch,
            owners: vec![genesis.creator.clone()],
            policy: genesis.policy,
        },
    );
    let mut children: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut resolutions = HashMap::new();
    let mut pending: HashMap<String, Vec<Pending<'_>>> = HashMap::new();
    let mut seen_payloads = HashSet::new();
    for transition in &ledger.transitions {
        let id = payload_hash(&transition.payload)?;
        if !seen_payloads.insert(id.clone()) {
            return Err("Duplicate co-ownership payload record".into());
        }
        pending
            .entry(transition.payload.parent_certificate_hash.clone())
            .or_default()
            .push(Pending::Transition(id, transition));
    }
    for resolution in &ledger.resolutions {
        let id = payload_hash(&resolution.payload)?;
        if !seen_payloads.insert(id.clone()) {
            return Err("Duplicate co-ownership payload record".into());
        }
        pending
            .entry(resolution.payload.parent_certificate_hash.clone())
            .or_default()
            .push(Pending::Resolution(id, resolution));
    }

    // Visit each parent once. Reverse-ordered valid history cannot cause repeated scans.
    let mut ready = VecDeque::from([genesis_hash.clone()]);
    while let Some(parent_hash) = ready.pop_front() {
        let Some(records) = pending.remove(&parent_hash) else {
            continue;
        };
        let parent = nodes
            .get(&parent_hash)
            .ok_or("Invalid co-ownership parent")?
            .clone();
        for record in records {
            let id = record.id_and_parent().0.to_owned();
            let (node, is_resolution) = match &record {
                Pending::Transition(_, transition) => {
                    validate_transition(&transition.payload, &parent)?;
                    verify_approvals(
                        &transition.payload,
                        &transition.approvals,
                        &parent.owners,
                        parent.policy,
                    )?;
                    (node_from_transition(&transition.payload), None)
                }
                Pending::Resolution(_, resolution) => {
                    validate_resolution(&resolution.payload, &parent)?;
                    verify_approvals(
                        &resolution.payload,
                        &resolution.approvals,
                        &parent.owners,
                        parent.policy,
                    )?;
                    (
                        node_from_resolution(&resolution.payload),
                        Some(resolution.payload.clone()),
                    )
                }
            };
            nodes.insert(id.clone(), node);
            children
                .entry(parent_hash.clone())
                .or_default()
                .insert(id.clone());
            if let Some(payload) = is_resolution {
                resolutions.insert(id.clone(), payload);
            }
            ready.push_back(id);
        }
    }
    if !pending.is_empty() {
        return Err("Co-ownership ledger contains an orphan or cycle".into());
    }

    // Resolution references must name sibling evidence retained in this ledger.
    for (resolution_id, resolution) in &resolutions {
        let siblings = children
            .get(&resolution.parent_certificate_hash)
            .ok_or("Co-ownership resolution lacks conflict evidence")?;
        let referenced = resolution
            .conflicting_certificate_hashes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if referenced.len() < 2
            || referenced.contains(resolution_id.as_str())
            || !referenced.is_subset(siblings)
        {
            return Err("Co-ownership resolution references missing evidence".into());
        }
    }
    Ok(Graph {
        genesis_hash,
        nodes,
        children,
        resolutions,
    })
}

enum Pending<'a> {
    Transition(String, &'a CoownedTransition),
    Resolution(String, &'a CoownedResolution),
}

impl Pending<'_> {
    fn id_and_parent(&self) -> (&str, &str) {
        match self {
            Self::Transition(id, record) => (id, &record.payload.parent_certificate_hash),
            Self::Resolution(id, record) => (id, &record.payload.parent_certificate_hash),
        }
    }
}

fn validate_genesis(payload: &CoownedGenesisPayload) -> Result<(), String> {
    validate_scope_id(&payload.scope_id)?;
    if payload.kind != "scope-coownership-genesis"
        || payload.version != COOWNERSHIP_VERSION
        || payload.epoch != 1
    {
        return Err("Invalid co-ownership genesis".into());
    }
    validate_payload_size(payload)
}

fn validate_transition(payload: &CoownedTransitionPayload, parent: &Node) -> Result<(), String> {
    validate_common_payload(
        &payload.kind,
        &payload.version,
        &payload.scope_id,
        &payload.parent_certificate_hash,
        payload.epoch,
        parent,
        "scope-coownership-transition",
    )?;
    validate_owner_set(&payload.owners)?;
    validate_payload_size(payload)
}

fn validate_resolution(payload: &CoownedResolutionPayload, parent: &Node) -> Result<(), String> {
    validate_common_payload(
        &payload.kind,
        &payload.version,
        &payload.scope_id,
        &payload.parent_certificate_hash,
        payload.epoch,
        parent,
        "scope-coownership-resolution",
    )?;
    validate_owner_set(&payload.owners)?;
    if payload.conflicting_certificate_hashes.len() < 2
        || payload.conflicting_certificate_hashes.len()
            > MAX_COOWNERSHIP_TRANSITIONS + MAX_COOWNERSHIP_RESOLUTIONS
        || payload
            .conflicting_certificate_hashes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || payload
            .conflicting_certificate_hashes
            .iter()
            .any(|hash| hash.len() != 43)
    {
        return Err("Invalid co-ownership conflict references".into());
    }
    validate_payload_size(payload)
}

fn validate_common_payload(
    kind: &str,
    version: &u8,
    scope_id: &str,
    parent_hash: &str,
    epoch: u64,
    parent: &Node,
    expected_kind: &str,
) -> Result<(), String> {
    let expected_epoch = next_epoch(parent.epoch)?;
    if kind != expected_kind
        || *version != COOWNERSHIP_VERSION
        || scope_id != parent.scope_id
        || parent_hash.len() != 43
        || epoch != expected_epoch
    {
        return Err("Invalid co-ownership transition parent or epoch".into());
    }
    Ok(())
}

fn validate_owner_set(owners: &[CoownerIdentity]) -> Result<(), String> {
    validate_serialized_limit(&owners, MAX_COOWNERSHIP_PAYLOAD_BYTES)?;
    if owners.is_empty() || owners.len() > MAX_COOWNERSHIP_OWNERS {
        return Err("Invalid co-owner count".into());
    }
    if owners
        .windows(2)
        .any(|pair| pair[0].person_id >= pair[1].person_id)
    {
        return Err("Co-owners must be unique and sorted by person id".into());
    }
    for owner in owners {
        owner.validate()?;
    }
    Ok(())
}

fn verify_signed_record<T: Serialize>(
    record: &CoownedSignedRecord<T>,
    owner: &CoownerIdentity,
) -> Result<(), String> {
    if record.signature.len() != 86 {
        return Err("Invalid co-ownership signature length".into());
    }
    let shared = SignedEnvelope {
        payload: &record.payload,
        signer_key_id: record.signer_key_id.clone(),
        signature: record.signature.clone(),
    };
    verify_for_owner(&shared, owner)
}

fn verify_approvals<T: Serialize + Clone>(
    payload: &T,
    approvals: &[CoownedApproval],
    owners: &[CoownerIdentity],
    policy: CoownerPolicy,
) -> Result<(), String> {
    if approvals.is_empty() || approvals.len() > MAX_COOWNERSHIP_APPROVALS {
        return Err("Invalid co-ownership approval count".into());
    }
    let mut seen_signatures = HashSet::new();
    let mut approved_people = HashSet::new();
    for approval in approvals {
        if approval.signer_key_id.is_empty()
            || approval.signer_key_id.len() > MAX_SCOPE_ID_BYTES
            || approval.signature.len() != 86
            || !seen_signatures
                .insert((approval.signer_key_id.as_str(), approval.signature.as_str()))
        {
            return Err("Invalid duplicate co-ownership approval".into());
        }
        let signed = SignedEnvelope {
            payload: payload.clone(),
            signer_key_id: approval.signer_key_id.clone(),
            signature: approval.signature.clone(),
        };
        let mut matched = None;
        for owner in owners {
            if verify_for_owner(&signed, owner).is_ok() {
                if matched.is_some() {
                    return Err("Ambiguous co-ownership signer".into());
                }
                matched = Some(owner.person_id.as_str());
            }
        }
        let person = matched.ok_or("Invalid co-ownership signer")?;
        approved_people.insert(person.to_owned());
    }
    if approved_people.len() < policy.quorum(owners.len()) {
        return Err("Insufficient distinct co-owner approvals".into());
    }
    Ok(())
}

fn verify_for_owner<T: Serialize>(
    record: &SignedEnvelope<T>,
    owner: &CoownerIdentity,
) -> Result<(), String> {
    if record.signer_key_id == owner.person_id
        && verify_signed_envelope(record, &owner.public_key, DEFAULT_SIGNATURE_DOMAIN)?
    {
        return Ok(());
    }
    let identity = PublicIdentity {
        person_id: owner.person_id.clone(),
        public_key: owner.public_key.clone(),
        display_name: String::new(),
    };
    let device_key = verify_device_certificate_chain(
        &identity,
        &record.signer_key_id,
        &owner.certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    if verify_signed_envelope(record, &device_key, DEFAULT_SIGNATURE_DOMAIN)? {
        Ok(())
    } else {
        Err("Invalid co-ownership signature".into())
    }
}

fn node_from_transition(payload: &CoownedTransitionPayload) -> Node {
    Node {
        scope_id: payload.scope_id.clone(),
        epoch: payload.epoch,
        owners: payload.owners.clone(),
        policy: payload.policy,
    }
}

fn node_from_resolution(payload: &CoownedResolutionPayload) -> Node {
    Node {
        scope_id: payload.scope_id.clone(),
        epoch: payload.epoch,
        owners: payload.owners.clone(),
        policy: payload.policy,
    }
}

fn state(node: &Node, certificate_hash: &str) -> CoownershipState {
    CoownershipState {
        scope_id: node.scope_id.clone(),
        certificate_hash: certificate_hash.to_owned(),
        epoch: node.epoch,
        owners: node.owners.clone(),
        policy: node.policy,
    }
}

fn resolver_ids(graph: &Graph, parent_hash: &str, siblings: &BTreeSet<String>) -> Vec<String> {
    graph
        .resolutions
        .iter()
        .filter(|(id, resolution)| {
            resolution.parent_certificate_hash == parent_hash
                && resolution
                    .conflicting_certificate_hashes
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    == siblings
                        .iter()
                        .filter(|other| *other != *id)
                        .cloned()
                        .collect()
        })
        .map(|(id, _)| id.clone())
        .collect()
}

fn payload_hash<T: Serialize>(payload: &T) -> Result<String, String> {
    let value = serde_json::to_value(payload).map_err(|_| "Co-ownership payload invalid")?;
    let canonical = canonicalize_json(&value)?;
    if canonical.len() > MAX_COOWNERSHIP_PAYLOAD_BYTES {
        return Err("Co-ownership payload limit exceeded".into());
    }
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

// Count serialized bytes without allocating another whole ledger.
fn validate_serialized_limit(value: &impl Serialize, limit: usize) -> Result<(), String> {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::Error::other(
                    "Co-ownership ledger byte limit exceeded",
                ));
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(limit), value)
        .map_err(|_| "Co-ownership ledger byte limit exceeded".into())
}

fn validate_payload_size<T: Serialize>(payload: &T) -> Result<(), String> {
    let value = serde_json::to_value(payload).map_err(|_| "Co-ownership payload invalid")?;
    if canonicalize_json(&value)?.len() > MAX_COOWNERSHIP_PAYLOAD_BYTES {
        return Err("Co-ownership payload limit exceeded".into());
    }
    Ok(())
}

fn validate_scope_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_SCOPE_ID_BYTES {
        return Err("Invalid co-ownership scope id".into());
    }
    Ok(())
}

fn next_epoch(epoch: u64) -> Result<u64, String> {
    epoch
        .checked_add(1)
        .ok_or_else(|| "Co-ownership epoch overflow".into())
}

fn merge_transition(records: &mut Vec<CoownedTransition>, incoming: CoownedTransition) {
    if let Some(existing) = records
        .iter_mut()
        .find(|record| record.payload == incoming.payload)
    {
        merge_approvals(&mut existing.approvals, &incoming.approvals);
    } else {
        records.push(incoming);
    }
}

fn merge_resolution(records: &mut Vec<CoownedResolution>, incoming: CoownedResolution) {
    if let Some(existing) = records
        .iter_mut()
        .find(|record| record.payload == incoming.payload)
    {
        merge_approvals(&mut existing.approvals, &incoming.approvals);
    } else {
        records.push(incoming);
    }
}

fn merge_approvals(current: &mut Vec<CoownedApproval>, incoming: &[CoownedApproval]) {
    for approval in incoming {
        if !current.contains(approval) {
            current.push(approval.clone());
        }
    }
    current.sort_by(|left, right| {
        left.signer_key_id
            .cmp(&right.signer_key_id)
            .then(left.signature.cmp(&right.signature))
    });
}

fn sort_ledger(ledger: &mut CoownershipLedger) {
    for transition in &mut ledger.transitions {
        transition.approvals.sort_by(|left, right| {
            left.signer_key_id
                .cmp(&right.signer_key_id)
                .then(left.signature.cmp(&right.signature))
        });
    }
    for resolution in &mut ledger.resolutions {
        resolution.approvals.sort_by(|left, right| {
            left.signer_key_id
                .cmp(&right.signer_key_id)
                .then(left.signature.cmp(&right.signature))
        });
    }
    ledger
        .transitions
        .sort_by_key(|record| payload_hash(&record.payload).unwrap_or_default());
    ledger
        .resolutions
        .sort_by_key(|record| payload_hash(&record.payload).unwrap_or_default());
}

#[cfg(test)]
#[path = "coownership_tests.rs"]
mod tests;
