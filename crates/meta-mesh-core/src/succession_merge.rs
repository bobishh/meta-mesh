use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    WorkspaceAuthority, WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy,
    WorkspaceSuccessionVote, plan_ownership_transitions, verify_workspace_succession_claim,
    verify_workspace_succession_policy, verify_workspace_succession_vote,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionMergeInput {
    pub workspace_id: String,
    pub owner: WorkspaceAuthority,
    pub owner_history: Vec<WorkspaceAuthority>,
    pub epoch: u64,
    pub current_policy: Option<WorkspaceSuccessionPolicy>,
    pub current_votes: Vec<WorkspaceSuccessionVote>,
    pub current_claims: Vec<WorkspaceSuccessionClaim>,
    pub incoming_policy: Option<WorkspaceSuccessionPolicy>,
    pub incoming_votes: Vec<WorkspaceSuccessionVote>,
    pub incoming_claims: Vec<WorkspaceSuccessionClaim>,
    pub revoked_people: HashSet<String>,
    pub revoked_before_epoch: HashSet<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionMergePlan {
    pub noop: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<WorkspaceSuccessionPolicy>,
    pub votes: Vec<WorkspaceSuccessionVote>,
    pub claims: Vec<WorkspaceSuccessionClaim>,
    pub transitions: Vec<WorkspaceSuccessionClaim>,
    pub conflicted: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionPolicyRefresh {
    pub changed: bool,
    pub successor_person_id: Option<String>,
}

pub fn plan_succession_policy_refresh(
    current: &WorkspaceSuccessionPolicy,
    eligible_editor_person_ids: &[String],
    epoch: u64,
) -> SuccessionPolicyRefresh {
    let successor = current
        .payload
        .successor_person_id
        .as_ref()
        .filter(|person_id| eligible_editor_person_ids.contains(person_id))
        .cloned();
    SuccessionPolicyRefresh {
        changed: current.payload.eligible_editor_person_ids.as_slice()
            != eligible_editor_person_ids
            || current.payload.successor_person_id != successor
            || current.payload.epoch != epoch,
        successor_person_id: successor,
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionCatalogInput {
    pub original_catalog: Value,
    pub original_owner_person_id: String,
    pub credential: Value,
    pub policy: Option<WorkspaceSuccessionPolicy>,
    pub votes: Vec<WorkspaceSuccessionVote>,
    pub claims: Vec<WorkspaceSuccessionClaim>,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessionCatalogPlan {
    pub credential: Value,
    pub persist: bool,
    pub publish: bool,
}

pub fn plan_succession_catalog(
    mut input: SuccessionCatalogInput,
) -> Result<SuccessionCatalogPlan, String> {
    let original = fields(&input.original_catalog);
    let credential = input
        .credential
        .as_object_mut()
        .ok_or("Invalid workspace credential")?;
    let same_owner = credential.get("ownerPersonId").and_then(Value::as_str)
        == Some(&input.original_owner_person_id);
    let mut persist = false;
    if same_owner {
        let catalog = credential.entry("catalog").or_insert_with(|| json!({}));
        if !catalog.is_object() {
            *catalog = json!({});
        }
        let catalog = catalog.as_object_mut().ok_or("Invalid workspace catalog")?;
        let before = fields(&Value::Object(catalog.clone()));
        if let Some(policy) = input.policy {
            catalog.insert("successionPolicy".into(), json!(policy));
        } else {
            catalog.remove("successionPolicy");
        }
        catalog.insert("successionVotes".into(), json!(input.votes));
        catalog.insert("successionClaims".into(), json!(input.claims));
        persist = fields(&Value::Object(catalog.clone())) != before;
        if persist {
            credential.insert("updatedAt".into(), json!(input.updated_at));
        }
    }
    let publish = credential
        .get("catalog")
        .is_some_and(|catalog| fields(catalog) != original);
    Ok(SuccessionCatalogPlan {
        credential: input.credential,
        persist,
        publish,
    })
}

fn fields(catalog: &Value) -> (Option<Value>, Value, Value) {
    (
        catalog
            .get("successionPolicy")
            .filter(|value| !value.is_null())
            .cloned(),
        catalog
            .get("successionVotes")
            .cloned()
            .unwrap_or_else(|| json!([])),
        catalog
            .get("successionClaims")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
}

pub fn plan_succession_merge(
    input: SuccessionMergeInput,
    now_ms: i128,
) -> Result<SuccessionMergePlan, String> {
    if input.current_policy.is_none()
        && input.current_votes.is_empty()
        && input.current_claims.is_empty()
        && input.incoming_policy.is_none()
        && input.incoming_votes.is_empty()
        && input.incoming_claims.is_empty()
    {
        return Ok(SuccessionMergePlan {
            noop: true,
            policy: None,
            votes: vec![],
            claims: vec![],
            transitions: vec![],
            conflicted: false,
        });
    }
    let mut policy = input.current_policy;
    if let Some(incoming) = input.incoming_policy {
        if incoming.payload.owner_person_id == input.owner.person_id
            && incoming.payload.epoch == input.epoch
        {
            verify_workspace_succession_policy(
                &incoming,
                &input.workspace_id,
                &input.owner,
                now_ms,
            )?;
            if policy.as_ref().is_none_or(|current| {
                incoming.payload.updated_at > current.payload.updated_at
                    || (incoming.payload.updated_at == current.payload.updated_at
                        && incoming.signature > current.signature)
            }) {
                policy = Some(incoming);
            }
        }
    }
    policy = match policy {
        Some(current)
            if current.payload.owner_person_id == input.owner.person_id
                && current.payload.epoch == input.epoch =>
        {
            verify_workspace_succession_policy(
                &current,
                &input.workspace_id,
                &input.owner,
                now_ms,
            )?;
            Some(current)
        }
        _ => None,
    };

    let mut by_voter = HashMap::<String, WorkspaceSuccessionVote>::new();
    if let Some(policy) = &policy {
        for vote in input.current_votes.into_iter().chain(input.incoming_votes) {
            if vote.signed.payload.policy_signature != policy.signature {
                continue;
            }
            verify_workspace_succession_vote(
                &vote,
                policy,
                &vote.signed.payload.candidate_person_id,
                &input.owner,
                &input.revoked_people,
                now_ms,
            )?;
            let voter = vote.signed.payload.voter_person_id.clone();
            if by_voter
                .get(&voter)
                .is_none_or(|prior| vote.signed.signature < prior.signed.signature)
            {
                by_voter.insert(voter, vote);
            }
        }
    }
    let mut votes = by_voter.into_values().collect::<Vec<_>>();
    votes.sort_by(|left, right| {
        left.signed
            .payload
            .voter_person_id
            .cmp(&right.signed.payload.voter_person_id)
    });

    let mut claims = HashMap::<String, WorkspaceSuccessionClaim>::new();
    for claim in input.current_claims {
        if !claim.signature.is_empty() {
            claims.insert(claim.signature.clone(), claim);
        }
    }
    for claim in input.incoming_claims {
        if claim.signature.is_empty() {
            continue;
        }
        if claim.payload.epoch == input.epoch + 1
            && claim.payload.from_owner_person_id == input.owner.person_id
        {
            verify_workspace_succession_claim(
                &claim,
                &input.workspace_id,
                &input.owner,
                input.epoch,
                &input.revoked_people,
                now_ms,
            )?;
            claims.insert(claim.signature.clone(), claim);
        } else if claim.payload.epoch == input.epoch {
            if let Some(previous_owner) = input
                .owner_history
                .iter()
                .find(|owner| owner.person_id == claim.payload.from_owner_person_id)
            {
                verify_workspace_succession_claim(
                    &claim,
                    &input.workspace_id,
                    previous_owner,
                    claim.payload.epoch.saturating_sub(1),
                    &input.revoked_before_epoch,
                    now_ms,
                )?;
                claims.insert(claim.signature.clone(), claim);
            }
        }
    }
    let mut claims = claims.into_values().collect::<Vec<_>>();
    claims.sort_by(|left, right| {
        left.payload
            .epoch
            .cmp(&right.payload.epoch)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let values = claims
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid workspace succession claim".to_string())?;
    let transitions = plan_ownership_transitions(&values, &input.owner.person_id, input.epoch);
    let selected = transitions
        .records
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid workspace succession claim".to_string())?;
    let mut current_owner = input.owner;
    let mut current_epoch = input.epoch;
    for claim in &selected {
        verify_workspace_succession_claim(
            claim,
            &input.workspace_id,
            &current_owner,
            current_epoch,
            &input.revoked_people,
            now_ms,
        )?;
        current_owner = WorkspaceAuthority {
            person_id: claim.payload.to_owner_person_id.clone(),
            public_key: claim.payload.to_owner_public_key.clone(),
            certificates: claim.payload.to_owner_certificates.clone(),
        };
        current_epoch = claim.payload.epoch;
    }
    Ok(SuccessionMergePlan {
        noop: false,
        policy,
        votes,
        claims,
        transitions: selected,
        conflicted: transitions.conflicted,
    })
}
