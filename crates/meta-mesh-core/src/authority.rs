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
    pub revoked_at: String,
}

pub type WorkspaceRevocation = SignedEnvelope<WorkspaceRevocationPayload>;

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

/// A recovery claim may only advance a specific owner/epoch to one successor.
/// Keep this decision in the protocol core so replicas cannot disagree over a
/// catalog merely because their host adapter observed records in a different order.
pub fn has_conflicting_break_glass_claims(records: &[Value]) -> bool {
    let mut successors: HashMap<(u64, &str), HashSet<&str>> = HashMap::new();
    for record in records {
        let Some(payload) = record.get("payload") else { continue; };
        let Some(epoch) = payload.get("epoch").and_then(Value::as_u64) else { continue; };
        let Some(from_owner) = payload
            .get("fromOwnerPersonId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else { continue; };
        let Some(to_owner) = payload
            .get("toOwnerPersonId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else { continue; };
        if epoch > 9_007_199_254_740_991 { continue; }
        successors.entry((epoch, from_owner)).or_default().insert(to_owner);
    }
    successors.values().any(|values| values.len() > 1)
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
    break_glass_claims: &[Value],
    revocations: &[Value],
    epoch: u64,
) -> Result<Option<SuccessionSummary>, String> {
    let revoked: HashSet<&str> = revocations.iter()
        .filter_map(|record| record.pointer("/payload/personId").and_then(Value::as_str))
        .collect();
    let conflicted = has_conflicting_ownership_transfers(transfers)
        || has_conflicting_break_glass_claims(break_glass_claims)
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

    use super::{has_conflicting_break_glass_claims, summarize_succession};

    #[test]
    fn break_glass_conflicts_are_scoped_to_the_owner_and_epoch() {
        let same_transition = vec![
            json!({ "payload": { "fromOwnerPersonId": "owner", "toOwnerPersonId": "alice", "epoch": 2 } }),
            json!({ "payload": { "fromOwnerPersonId": "owner", "toOwnerPersonId": "bob", "epoch": 2 } }),
        ];
        assert!(has_conflicting_break_glass_claims(&same_transition));

        let independent_transitions = vec![
            json!({ "payload": { "fromOwnerPersonId": "owner", "toOwnerPersonId": "alice", "epoch": 2 } }),
            json!({ "payload": { "fromOwnerPersonId": "owner", "toOwnerPersonId": "bob", "epoch": 3 } }),
        ];
        assert!(!has_conflicting_break_glass_claims(&independent_transitions));
    }

    #[test]
    fn succession_summary_excludes_revoked_editors_and_reports_quorum() {
        let policy = json!({ "payload": {
            "epoch": 4, "successorPersonId": null, "eligibleEditorPersonIds": ["alice", "bob", "carol"]
        }});
        let votes = vec![json!({ "signed": { "payload": { "voterPersonId": "alice", "candidatePersonId": "bob" } } })];
        let revocations = vec![json!({ "payload": { "personId": "carol" } })];
        let summary = summarize_succession(Some(&policy), &[], &votes, &[], &[], &revocations, 4).unwrap().unwrap();
        assert_eq!(summary.eligible_editor_person_ids, vec!["alice", "bob"]);
        assert_eq!(summary.quorum, 2);
        assert_eq!(summary.votes.len(), 1);
    }
}
