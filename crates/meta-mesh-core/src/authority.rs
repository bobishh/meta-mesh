use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope, WorkspaceGrant,
    WorkspaceRole, public_key_id, verify_device_certificate_chain, verify_signed_envelope,
    verify_workspace_grant,
};

pub const MAX_AUTHORITY_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_SUCCESSION_CLAIM_BYTES: usize = 128 * 1024;
pub const MAX_SUCCESSION_EDITORS: usize = 32;
pub const MAX_WORKSPACE_HEADS: usize = 256;
pub const MAX_AUTHORITY_FUTURE_MS: i128 = 5 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAuthority {
    pub person_id: String,
    pub public_key: String,
    pub certificates: Vec<DeviceCertificate>,
}

impl WorkspaceAuthority {
    fn identity(&self) -> PublicIdentity {
        PublicIdentity {
            person_id: self.person_id.clone(),
            public_key: self.public_key.clone(),
            display_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRevocationPayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub owner_person_id: String,
    pub person_id: String,
    pub epoch: u64,
    pub workspace_heads: Vec<String>,
    pub revoked_at: String,
}

pub type WorkspaceRevocation = SignedEnvelope<WorkspaceRevocationPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDeparturePayload {
    pub kind: String, pub version: u8, pub workspace_id: String, pub person_id: String,
    pub access_epoch: u64, pub workspace_heads: Vec<String>, pub left_at: String,
}
pub type WorkspaceDeparture = SignedEnvelope<WorkspaceDeparturePayload>;

pub fn verify_workspace_departure(record: &WorkspaceDeparture, workspace_id: &str,
    authority: &WorkspaceAuthority, now_ms: i128) -> Result<(), String> {
    bounded(record, 32 * 1024, "Workspace departure too large")?;
    let p = &record.payload;
    if p.kind != "workspace-departure" || p.version != 1 || p.workspace_id != workspace_id
        || p.person_id != authority.person_id || p.access_epoch < 1
        || !valid_heads(&p.workspace_heads)
        || public_key_id(&authority.public_key)? != authority.person_id || !valid_time(&p.left_at, now_ms)? {
        return Err("Invalid workspace departure".into());
    }
    verify_owner_envelope(record, authority, "workspace departure")
}

/// A device removal is scoped to one workspace and preserves person membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDeviceRevocationPayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub person_id: String,
    pub device_id: String,
    pub workspace_heads: Vec<String>,
    pub revoked_at: String,
}
pub type WorkspaceDeviceRevocation = SignedEnvelope<WorkspaceDeviceRevocationPayload>;

pub fn verify_workspace_device_revocation(record: &WorkspaceDeviceRevocation, workspace_id: &str,
    owner_person_id: &str, authority: &WorkspaceAuthority, now_ms: i128) -> Result<(), String> {
    bounded(record, 32 * 1024, "Device revocation too large")?;
    let p = &record.payload;
    if p.kind != "workspace-device-revocation" || p.version != 1 || p.workspace_id != workspace_id
        || p.person_id.is_empty() || p.device_id.is_empty()
        || !valid_heads(&p.workspace_heads)
        || (authority.person_id != owner_person_id && authority.person_id != p.person_id)
        || public_key_id(&authority.public_key)? != authority.person_id
        || !valid_time(&p.revoked_at, now_ms)? {
        return Err("Invalid workspace device revocation".into());
    }
    verify_owner_envelope(record, authority, "workspace device revocation")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceOwnershipTransferPayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub from_owner_person_id: String,
    pub to_owner_person_id: String,
    pub to_owner_public_key: String,
    pub to_owner_certificates: Vec<DeviceCertificate>,
    pub to_owner_grant: WorkspaceGrant,
    pub former_owner_grant: WorkspaceGrant,
    pub workspace_heads: Vec<String>,
    pub epoch: u64,
    pub transferred_at: String,
}

pub type WorkspaceOwnershipTransfer = SignedEnvelope<WorkspaceOwnershipTransferPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSuccessionPolicyPayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub owner_person_id: String,
    pub successor_person_id: Option<String>,
    pub eligible_editor_person_ids: Vec<String>,
    pub epoch: u64,
    pub updated_at: String,
}

pub type WorkspaceSuccessionPolicy = SignedEnvelope<WorkspaceSuccessionPolicyPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSuccessionVotePayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub owner_person_id: String,
    pub voter_person_id: String,
    pub candidate_person_id: String,
    pub policy_signature: String,
    pub voted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSuccessionVote {
    pub signed: SignedEnvelope<WorkspaceSuccessionVotePayload>,
    pub voter_public_key: String,
    pub voter_certificates: Vec<DeviceCertificate>,
    pub voter_grant: WorkspaceGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSuccessionClaimPayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub from_owner_person_id: String,
    pub to_owner_person_id: String,
    pub to_owner_public_key: String,
    pub to_owner_certificates: Vec<DeviceCertificate>,
    pub candidate_grant: WorkspaceGrant,
    pub former_owner_grant: WorkspaceGrant,
    pub policy: WorkspaceSuccessionPolicy,
    pub votes: Vec<WorkspaceSuccessionVote>,
    pub workspace_heads: Vec<String>,
    pub epoch: u64,
    pub claimed_at: String,
}

pub type WorkspaceSuccessionClaim = SignedEnvelope<WorkspaceSuccessionClaimPayload>;

pub fn has_conflicting_ownership_transfers(records: &[Value]) -> bool {
    let mut successors: HashMap<(u64, &str), HashSet<&str>> = HashMap::new();
    for record in records {
        let Some(payload) = record.get("payload") else {
            continue;
        };
        let Some(epoch) = payload.get("epoch").and_then(Value::as_u64) else {
            continue;
        };
        let Some(from_owner) = payload
            .get("fromOwnerPersonId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(to_owner) = payload
            .get("toOwnerPersonId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if epoch > 9_007_199_254_740_991 {
            continue;
        }
        successors
            .entry((epoch, from_owner))
            .or_default()
            .insert(to_owner);
    }
    successors.values().any(|values| values.len() > 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipTransitionPlan {
    pub records: Vec<Value>,
    pub conflicted: bool,
}

/// Select the deterministic ownership chain from already verified authority
/// records.  A conflicting successor stalls the chain instead of letting a
/// host adapter adopt whichever packet it happened to see first.
pub fn plan_ownership_transitions(
    records: &[Value],
    initial_owner_person_id: &str,
    initial_epoch: u64,
) -> OwnershipTransitionPlan {
    let mut owner_person_id = initial_owner_person_id;
    let mut epoch = initial_epoch;
    let mut planned = Vec::new();

    loop {
        let Some(next_epoch) = records.iter().filter(|record|
            record.pointer("/payload/fromOwnerPersonId").and_then(Value::as_str) == Some(owner_person_id))
            .filter_map(|record| record.pointer("/payload/epoch").and_then(Value::as_u64))
            .filter(|candidate| *candidate > epoch).min() else {
            return OwnershipTransitionPlan { records: planned, conflicted: false };
        };
        let mut candidates = records
            .iter()
            .filter(|record| {
                record.pointer("/payload/epoch").and_then(Value::as_u64) == Some(next_epoch)
                    && record.pointer("/payload/fromOwnerPersonId").and_then(Value::as_str)
                        == Some(owner_person_id)
                    && record.pointer("/payload/toOwnerPersonId").and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && record.get("signature").and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return OwnershipTransitionPlan { records: planned, conflicted: false };
        }
        let successors = candidates.iter()
            .filter_map(|record| record.pointer("/payload/toOwnerPersonId").and_then(Value::as_str))
            .collect::<HashSet<_>>();
        if successors.len() > 1 {
            return OwnershipTransitionPlan { records: planned, conflicted: true };
        }
        candidates.sort_by_key(|record| record.get("signature").and_then(Value::as_str).unwrap_or_default());
        let selected = candidates[0];
        owner_person_id = selected.pointer("/payload/toOwnerPersonId").and_then(Value::as_str).unwrap_or_default();
        epoch = next_epoch;
        planned.push(selected.clone());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedOwnershipTransition {
    pub candidates: Vec<WorkspaceOwnershipTransfer>,
    pub selected: Option<WorkspaceOwnershipTransfer>,
    pub conflicted: bool,
}

/// Verify every proposal at the next ownership epoch before selecting a
/// successor. The host persists the selected credential; the decision and
/// signature checks stay identical for browser, native, and mobile clients.
pub fn next_verified_ownership_transition(
    records: &[Value],
    workspace_id: &str,
    current_owner: &WorkspaceAuthority,
    current_epoch: u64,
    revoked_people: &HashSet<String>,
    now_ms: i128,
) -> Result<VerifiedOwnershipTransition, String> {
    if records.len() > 512 || workspace_id.is_empty() {
        return Err("Invalid workspace ownership transition catalog".into());
    }
    let next_epoch = records.iter()
        .filter(|record| record.pointer("/payload/fromOwnerPersonId").and_then(Value::as_str) == Some(current_owner.person_id.as_str()))
        .filter_map(|record| record.pointer("/payload/epoch").and_then(Value::as_u64))
        .filter(|epoch| *epoch > current_epoch)
        .min();
    let Some(next_epoch) = next_epoch else {
        return Ok(VerifiedOwnershipTransition { candidates: vec![], selected: None, conflicted: false });
    };
    let mut candidates = records.iter()
        .filter(|record| record.pointer("/payload/fromOwnerPersonId").and_then(Value::as_str) == Some(current_owner.person_id.as_str())
            && record.pointer("/payload/epoch").and_then(Value::as_u64) == Some(next_epoch))
        .cloned()
        .map(|record| serde_json::from_value::<WorkspaceOwnershipTransfer>(record)
            .map_err(|_| "Invalid workspace ownership transfer".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort_by(|left, right| left.signature.cmp(&right.signature));
    let mut successors = HashSet::new();
    for record in &candidates {
        verify_workspace_ownership_transfer(record, workspace_id, current_owner, current_epoch, now_ms)?;
        if revoked_people.contains(&record.payload.to_owner_person_id) {
            return Err("New owner access is revoked".into());
        }
        successors.insert(record.payload.to_owner_person_id.as_str());
    }
    let conflicted = successors.len() > 1;
    let selected = if conflicted { None } else { candidates.first().cloned() };
    Ok(VerifiedOwnershipTransition { candidates, selected, conflicted })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionSummary {
    pub successor_person_id: Option<String>,
    pub eligible_editor_person_ids: Vec<String>,
    pub votes: Vec<SuccessionVoteSummary>,
    pub quorum: usize,
    pub conflicted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionVoteSummary {
    pub voter_person_id: String,
    pub candidate_person_id: String,
}

/// Produces the user-visible recovery state from records that have already
/// crossed their signature-verification boundary. Keeping this reduction in
/// Rust prevents browser, desktop and mobile hosts from deriving a different
/// quorum or conflict state for the same catalog.
pub fn summarize_succession(
    policy: Option<&Value>,
    claims: &[Value],
    votes: &[Value],
    transfers: &[Value],
    revocations: &[Value],
    epoch: u64,
) -> Result<Option<SuccessionSummary>, String> {
    let revoked: HashSet<&str> = revocations.iter()
        .filter_map(|record| record.pointer("/payload/personId").and_then(Value::as_str))
        .collect();
    let conflicted = has_conflicting_ownership_transfers(transfers)
        || claims.iter()
            .filter(|claim| claim.pointer("/payload/epoch").and_then(Value::as_u64) == Some(epoch))
            .filter_map(|claim| claim.pointer("/payload/toOwnerPersonId").and_then(Value::as_str))
            .collect::<HashSet<_>>().len() > 1;
    let policy = policy
        .filter(|policy| policy.pointer("/payload/epoch").and_then(Value::as_u64) == Some(epoch))
        .or_else(|| claims.iter()
            .find(|claim| claim.pointer("/payload/epoch").and_then(Value::as_u64) == Some(epoch + 1))
            .and_then(|claim| claim.pointer("/payload/policy")));
    let Some(policy) = policy else {
        return if conflicted {
            Ok(Some(SuccessionSummary { successor_person_id: None, eligible_editor_person_ids: vec![], votes: vec![], quorum: 0, conflicted }))
        } else { Ok(None) };
    };
    let payload = policy.get("payload").and_then(Value::as_object)
        .ok_or_else(|| "Invalid workspace succession policy".to_string())?;
    let eligible = payload.get("eligibleEditorPersonIds").and_then(Value::as_array)
        .ok_or_else(|| "Invalid workspace succession policy".to_string())?
        .iter().map(|value| value.as_str().map(str::to_owned)
            .ok_or_else(|| "Invalid workspace succession policy".to_string()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter().filter(|person_id| !revoked.contains(person_id.as_str())).collect::<Vec<_>>();
    let successor_person_id = match payload.get("successorPersonId") {
        None | Some(Value::Null) => None,
        Some(Value::String(person_id)) if !revoked.contains(person_id.as_str()) => Some(person_id.clone()),
        Some(Value::String(_)) => None,
        _ => return Err("Invalid workspace succession policy".to_string()),
    };
    let votes = votes.iter().filter_map(|vote| {
        let payload = vote.pointer("/signed/payload")?.as_object()?;
        Some(SuccessionVoteSummary {
            voter_person_id: payload.get("voterPersonId")?.as_str()?.to_owned(),
            candidate_person_id: payload.get("candidatePersonId")?.as_str()?.to_owned(),
        })
    }).collect();
    Ok(Some(SuccessionSummary { successor_person_id, eligible_editor_person_ids: eligible.clone(),
        votes, quorum: eligible.len() / 2 + 1, conflicted }))
}

pub fn eligible_editor_person_ids(peers: &[Value]) -> Vec<String> {
    let mut people = peers.iter().filter_map(|peer| {
        let role = peer.get("role").and_then(Value::as_str)?;
        let person_id = peer.get("personId").and_then(Value::as_str)?;
        let revoked = peer.get("revokedAt").is_some_and(|value| !value.is_null());
        (role == "editor" && !revoked && !person_id.is_empty()).then(|| person_id.to_owned())
    }).collect::<Vec<_>>();
    people.sort();
    people.dedup();
    people
}

pub fn canonical_revocations(records: &[Value]) -> Vec<Value> {
    let mut unique: HashMap<String, Value> = HashMap::new();
    for record in records {
        let Some(_) = record.pointer("/payload/personId").and_then(Value::as_str).filter(|value| !value.is_empty()) else { continue; };
        if record.pointer("/payload/epoch").and_then(Value::as_u64).is_none() { continue; }
        unique.insert(serde_json::to_string(record).expect("JSON value serializes"), record.clone());
    }
    let mut result = unique.into_values().collect::<Vec<_>>();
    result.sort_by(|left, right| {
        left.pointer("/payload/personId").and_then(Value::as_str)
            .cmp(&right.pointer("/payload/personId").and_then(Value::as_str))
            .then_with(|| left.pointer("/payload/epoch").and_then(Value::as_u64)
                .cmp(&right.pointer("/payload/epoch").and_then(Value::as_u64)))
            .then_with(|| serde_json::to_string(left).ok().cmp(&serde_json::to_string(right).ok()))
    });
    result
}

pub fn verify_workspace_revocation(
    record: &WorkspaceRevocation,
    workspace_id: &str,
    authority: &WorkspaceAuthority,
    now_ms: i128,
) -> Result<(), String> {
    bounded(record, 32 * 1024, "Workspace revocation too large")?;
    let payload = &record.payload;
    if payload.kind != "workspace-revocation"
        || payload.version != 1
        || payload.workspace_id != workspace_id
        || payload.owner_person_id != authority.person_id
        || payload.person_id.is_empty()
        || payload.person_id == authority.person_id
        || payload.epoch < 2
        || !valid_heads(&payload.workspace_heads)
        || !valid_time(&payload.revoked_at, now_ms)?
        || public_key_id(&authority.public_key)? != authority.person_id
    {
        return Err("Invalid workspace revocation".to_string());
    }
    verify_owner_envelope(record, authority, "workspace revocation")
}

pub fn verify_workspace_ownership_transfer(
    record: &WorkspaceOwnershipTransfer,
    workspace_id: &str,
    authority: &WorkspaceAuthority,
    minimum_epoch: u64,
    now_ms: i128,
) -> Result<(), String> {
    bounded(
        record,
        MAX_AUTHORITY_RECORD_BYTES,
        "Workspace ownership transfer too large",
    )?;
    let payload = &record.payload;
    if payload.kind != "workspace-ownership-transfer"
        || payload.version != 1
        || payload.workspace_id != workspace_id
        || payload.from_owner_person_id != authority.person_id
        || payload.to_owner_person_id.is_empty()
        || payload.to_owner_person_id == payload.from_owner_person_id
        || payload.to_owner_public_key.is_empty()
        || payload.to_owner_certificates.is_empty()
        || !valid_heads(&payload.workspace_heads)
        || payload.epoch <= minimum_epoch
        || !valid_time(&payload.transferred_at, now_ms)?
        || public_key_id(&authority.public_key)? != authority.person_id
        || public_key_id(&payload.to_owner_public_key)? != payload.to_owner_person_id
    {
        return Err("Invalid workspace ownership transfer".to_string());
    }
    let target = PublicIdentity {
        person_id: payload.to_owner_person_id.clone(),
        public_key: payload.to_owner_public_key.clone(),
        display_name: String::new(),
    };
    verify_device_certificate_chain(
        &target,
        &payload.to_owner_certificates[0].payload.device_id,
        &payload.to_owner_certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .map_err(|_| "Invalid workspace ownership transfer".to_string())?;
    verify_owner_envelope(record, authority, "ownership transfer")?;
    if verify_workspace_grant(
        &payload.to_owner_grant,
        workspace_id,
        &payload.to_owner_person_id,
        &authority.identity(),
        &authority.certificates,
    )? != WorkspaceRole::Owner
        || verify_workspace_grant(
            &payload.former_owner_grant,
            workspace_id,
            &payload.from_owner_person_id,
            &authority.identity(),
            &authority.certificates,
        )? != WorkspaceRole::Editor
    {
        return Err("Invalid ownership transfer roles".to_string());
    }
    Ok(())
}


pub fn verify_workspace_succession_policy(
    policy: &WorkspaceSuccessionPolicy,
    workspace_id: &str,
    authority: &WorkspaceAuthority,
    now_ms: i128,
) -> Result<(), String> {
    bounded(
        policy,
        MAX_AUTHORITY_RECORD_BYTES,
        "Workspace succession policy too large",
    )?;
    let payload = &policy.payload;
    let eligible = &payload.eligible_editor_person_ids;
    let mut sorted = eligible.clone();
    sorted.sort();
    let unique = eligible.iter().collect::<HashSet<_>>().len() == eligible.len();
    if payload.kind != "workspace-succession-policy"
        || payload.version != 1
        || payload.workspace_id != workspace_id
        || payload.owner_person_id != authority.person_id
        || payload.epoch < 1
        || !valid_time(&payload.updated_at, now_ms)?
        || eligible.len() > MAX_SUCCESSION_EDITORS
        || !unique
        || eligible
            .iter()
            .any(|id| id.is_empty() || id == &authority.person_id)
        || sorted != *eligible
        || payload
            .successor_person_id
            .as_ref()
            .is_some_and(|id| !eligible.contains(id))
    {
        return Err("Invalid workspace succession policy".to_string());
    }
    verify_owner_envelope(policy, authority, "workspace-succession-policy")
}

pub fn verify_workspace_succession_vote(
    vote: &WorkspaceSuccessionVote,
    policy: &WorkspaceSuccessionPolicy,
    candidate_person_id: &str,
    authority: &WorkspaceAuthority,
    revoked: &HashSet<String>,
    now_ms: i128,
) -> Result<(), String> {
    bounded(
        vote,
        MAX_AUTHORITY_RECORD_BYTES,
        "Workspace succession vote too large",
    )?;
    let payload = &vote.signed.payload;
    let eligible = &policy.payload.eligible_editor_person_ids;
    if payload.kind != "workspace-succession-vote"
        || payload.version != 1
        || payload.workspace_id != policy.payload.workspace_id
        || payload.owner_person_id != authority.person_id
        || payload.policy_signature != policy.signature
        || payload.candidate_person_id != candidate_person_id
        || !eligible.contains(&payload.voter_person_id)
        || !eligible.contains(&payload.candidate_person_id)
        || revoked.contains(&payload.voter_person_id)
        || !valid_time(&payload.voted_at, now_ms)?
        || vote.voter_public_key.is_empty()
    {
        return Err("Invalid workspace succession vote".to_string());
    }
    if public_key_id(&vote.voter_public_key)? != payload.voter_person_id {
        return Err("Invalid succession voter identity".to_string());
    }
    let voter = PublicIdentity {
        person_id: payload.voter_person_id.clone(),
        public_key: vote.voter_public_key.clone(),
        display_name: String::new(),
    };
    let signer_key = verify_device_certificate_chain(
        &voter,
        &vote.signed.signer_key_id,
        &vote.voter_certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .map_err(|_| "Invalid workspace succession vote signature".to_string())?;
    if !verify_signed_envelope(&vote.signed, &signer_key, DEFAULT_SIGNATURE_DOMAIN)? {
        return Err("Invalid workspace succession vote signature".to_string());
    }
    if verify_workspace_grant(
        &vote.voter_grant,
        &payload.workspace_id,
        &payload.voter_person_id,
        &authority.identity(),
        &authority.certificates,
    )? != WorkspaceRole::Editor
    {
        return Err("Succession voter is not an editor".to_string());
    }
    Ok(())
}

pub fn verify_workspace_succession_claim(
    claim: &WorkspaceSuccessionClaim,
    workspace_id: &str,
    authority: &WorkspaceAuthority,
    minimum_epoch: u64,
    revoked: &HashSet<String>,
    now_ms: i128,
) -> Result<(), String> {
    bounded(
        claim,
        MAX_SUCCESSION_CLAIM_BYTES,
        "Workspace succession claim too large",
    )?;
    let payload = &claim.payload;
    if payload.kind != "workspace-succession-claim"
        || payload.version != 1
        || payload.workspace_id != workspace_id
        || payload.from_owner_person_id != authority.person_id
        || payload.to_owner_person_id.is_empty()
        || payload.to_owner_person_id == authority.person_id
        || revoked.contains(&payload.to_owner_person_id)
        || public_key_id(&payload.to_owner_public_key)? != payload.to_owner_person_id
        || payload.to_owner_certificates.is_empty()
        || !valid_heads(&payload.workspace_heads)
        || payload.epoch
            != minimum_epoch
                .checked_add(1)
                .ok_or_else(|| "Invalid workspace succession claim".to_string())?
        || !valid_time(&payload.claimed_at, now_ms)?
        || payload.votes.len() > MAX_SUCCESSION_EDITORS
    {
        return Err("Invalid workspace succession claim".to_string());
    }
    verify_workspace_succession_policy(&payload.policy, workspace_id, authority, now_ms)?;
    if payload.policy.payload.epoch != minimum_epoch {
        return Err("Succession policy epoch is stale".to_string());
    }
    if verify_workspace_grant(
        &payload.candidate_grant,
        workspace_id,
        &payload.to_owner_person_id,
        &authority.identity(),
        &authority.certificates,
    )? != WorkspaceRole::Editor
    {
        return Err("Successor is not an editor".to_string());
    }
    let next_identity = PublicIdentity {
        person_id: payload.to_owner_person_id.clone(),
        public_key: payload.to_owner_public_key.clone(),
        display_name: String::new(),
    };
    let candidate_key = verify_device_certificate_chain(
        &next_identity,
        &claim.signer_key_id,
        &payload.to_owner_certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .map_err(|_| "Invalid workspace succession claim signature".to_string())?;
    if !verify_signed_envelope(claim, &candidate_key, DEFAULT_SIGNATURE_DOMAIN)? {
        return Err("Invalid workspace succession claim signature".to_string());
    }

    let named = payload.policy.payload.successor_person_id.as_ref();
    if named.is_none_or(|id| revoked.contains(id)) {
        if !payload
            .policy
            .payload
            .eligible_editor_person_ids
            .contains(&payload.to_owner_person_id)
        {
            return Err("Candidate is not an eligible editor".to_string());
        }
        let active = payload
            .policy
            .payload
            .eligible_editor_person_ids
            .iter()
            .filter(|id| !revoked.contains(*id))
            .count();
        let quorum = active / 2 + 1;
        let mut voters = HashSet::new();
        for vote in &payload.votes {
            verify_workspace_succession_vote(
                vote,
                &payload.policy,
                &payload.to_owner_person_id,
                authority,
                revoked,
                now_ms,
            )?;
            if !voters.insert(&vote.signed.payload.voter_person_id) {
                return Err("Duplicate succession voter".to_string());
            }
        }
        if voters.len() < quorum {
            return Err(format!("Editor quorum requires {quorum} votes"));
        }
    } else if named != Some(&payload.to_owner_person_id) {
        return Err("Named successor has priority".to_string());
    }

    let next_authority = WorkspaceAuthority {
        person_id: payload.to_owner_person_id.clone(),
        public_key: payload.to_owner_public_key.clone(),
        certificates: payload.to_owner_certificates.clone(),
    };
    if verify_workspace_grant(
        &payload.former_owner_grant,
        workspace_id,
        &authority.person_id,
        &next_authority.identity(),
        &next_authority.certificates,
    )? != WorkspaceRole::Editor
    {
        return Err("Former owner grant is invalid".to_string());
    }
    Ok(())
}

fn verify_owner_envelope<T: Serialize>(
    envelope: &SignedEnvelope<T>,
    authority: &WorkspaceAuthority,
    label: &str,
) -> Result<(), String> {
    let key = if envelope.signer_key_id == authority.person_id {
        authority.public_key.clone()
    } else {
        verify_device_certificate_chain(
            &authority.identity(),
            &envelope.signer_key_id,
            &authority.certificates,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .map_err(|_| format!("Invalid {label} signature"))?
    };
    if verify_signed_envelope(envelope, &key, DEFAULT_SIGNATURE_DOMAIN)? {
        Ok(())
    } else {
        Err(format!("Invalid {label} signature"))
    }
}

fn valid_heads(heads: &[String]) -> bool {
    !heads.is_empty()
        && heads.len() <= MAX_WORKSPACE_HEADS
        && heads.iter().all(|head| !head.is_empty())
}

fn valid_time(value: &str, now_ms: i128) -> Result<bool, String> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| "Invalid authority timestamp".to_string())?;
    let timestamp_ms = parsed.unix_timestamp_nanos() / 1_000_000;
    Ok(value.len() == 24
        && value.ends_with('Z')
        && timestamp_ms <= now_ms + MAX_AUTHORITY_FUTURE_MS)
}

fn bounded(value: &impl Serialize, maximum: usize, message: &str) -> Result<(), String> {
    if serde_json::to_vec(value)
        .map_err(|_| message.to_string())?
        .len()
        > maximum
    {
        Err(message.to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::summarize_succession;

    #[test]
    fn succession_summary_excludes_revoked_editors_and_reports_quorum() {
        let policy = json!({ "payload": {
            "epoch": 4, "successorPersonId": null, "eligibleEditorPersonIds": ["alice", "bob", "carol"]
        }});
        let votes = vec![json!({ "signed": { "payload": { "voterPersonId": "alice", "candidatePersonId": "bob" } } })];
        let revocations = vec![json!({ "payload": { "personId": "carol" } })];
        let summary = summarize_succession(Some(&policy), &[], &votes, &[], &revocations, 4).unwrap().unwrap();
        assert_eq!(summary.eligible_editor_person_ids, vec!["alice", "bob"]);
        assert_eq!(summary.quorum, 2);
        assert_eq!(summary.votes.len(), 1);
    }

    #[test]
    fn eligible_editors_are_unique_sorted_and_active() {
        let peers = vec![
            json!({ "role": "editor", "personId": "bob", "revokedAt": null }),
            json!({ "role": "editor", "personId": "alice" }),
            json!({ "role": "editor", "personId": "bob" }),
            json!({ "role": "editor", "personId": "carol", "revokedAt": "2026-09-21T00:00:00.000Z" }),
            json!({ "role": "visitor", "personId": "dave" }),
        ];
        assert_eq!(super::eligible_editor_person_ids(&peers), vec!["alice", "bob"]);
    }

    #[test]
    fn canonical_revocations_preserve_distinct_boundaries_per_person() {
        let records = vec![
            json!({ "payload": { "personId": "bob", "epoch": 2 } }),
            json!({ "payload": { "personId": "alice", "epoch": 4 } }),
            json!({ "payload": { "personId": "bob", "epoch": 3 } }),
        ];
        let canonical = super::canonical_revocations(&records);
        assert_eq!(canonical.len(), 3);
        assert_eq!(canonical[0].pointer("/payload/personId").unwrap(), "alice");
        assert_eq!(canonical[1].pointer("/payload/epoch").unwrap(), 2);
        assert_eq!(canonical[2].pointer("/payload/epoch").unwrap(), 3);
    }

    #[test]
    fn ownership_transition_plan_stops_on_conflicting_successors() {
        let records = vec![
            json!({ "signature": "b", "payload": { "epoch": 2, "fromOwnerPersonId": "alice", "toOwnerPersonId": "bob" } }),
            json!({ "signature": "a", "payload": { "epoch": 2, "fromOwnerPersonId": "alice", "toOwnerPersonId": "carol" } }),
        ];
        let plan = super::plan_ownership_transitions(&records, "alice", 1);
        assert!(plan.conflicted);
        assert!(plan.records.is_empty());
    }

    #[test]
    fn ownership_transition_plan_selects_a_deterministic_chain() {
        let records = vec![
            json!({ "signature": "z", "payload": { "epoch": 2, "fromOwnerPersonId": "alice", "toOwnerPersonId": "bob" } }),
            json!({ "signature": "a", "payload": { "epoch": 2, "fromOwnerPersonId": "alice", "toOwnerPersonId": "bob" } }),
            json!({ "signature": "c", "payload": { "epoch": 3, "fromOwnerPersonId": "bob", "toOwnerPersonId": "carol" } }),
        ];
        let plan = super::plan_ownership_transitions(&records, "alice", 1);
        assert!(!plan.conflicted);
        assert_eq!(plan.records.len(), 2);
        assert_eq!(plan.records[0].get("signature").unwrap(), "a");
        assert_eq!(plan.records[1].get("signature").unwrap(), "c");
    }

    #[test]
    fn ownership_transition_plan_allows_access_epoch_gaps() {
        let records = vec![json!({ "signature": "a", "payload": {
            "epoch": 4, "fromOwnerPersonId": "alice", "toOwnerPersonId": "bob" } })];
        let plan = super::plan_ownership_transitions(&records, "alice", 1);
        assert!(!plan.conflicted);
        assert_eq!(plan.records, records);
    }
}
