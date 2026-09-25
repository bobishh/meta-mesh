use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    WorkspaceAuthority, WorkspaceOwnershipTransfer, has_conflicting_ownership_transfers,
    next_verified_ownership_transition, verify_workspace_ownership_transfer,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipMergeInput {
    pub workspace_id: String,
    pub current_owner: WorkspaceAuthority,
    pub owner_history: Vec<WorkspaceAuthority>,
    pub owner_epoch: u64,
    pub current: Vec<WorkspaceOwnershipTransfer>,
    pub incoming: Vec<Value>,
    pub revoked_people: HashSet<String>,
    pub now_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipMergeStep {
    pub record: WorkspaceOwnershipTransfer,
    pub accepted: Vec<WorkspaceOwnershipTransfer>,
    pub previous_owner_epoch: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipMergePlan {
    pub accepted: Vec<WorkspaceOwnershipTransfer>,
    pub steps: Vec<OwnershipMergeStep>,
    pub conflicted: bool,
    pub persist_catalog: bool,
}

pub fn plan_ownership_merge(input: OwnershipMergeInput) -> Result<OwnershipMergePlan, String> {
    let mut known = BTreeMap::<String, Value>::new();
    let mut accepted = BTreeMap::<String, WorkspaceOwnershipTransfer>::new();
    for record in &input.current {
        known.insert(
            record.signature.clone(),
            serde_json::to_value(record).map_err(|_| "Invalid workspace ownership transfer")?,
        );
        accepted.insert(record.signature.clone(), record.clone());
    }
    for raw in input.incoming {
        if let Some(signature) = raw.get("signature").and_then(Value::as_str) {
            if !signature.is_empty() {
                known.insert(signature.to_string(), raw);
            }
        }
    }
    let authorities = std::iter::once(&input.current_owner).chain(input.owner_history.iter());
    for raw in known.values() {
        let signature = raw
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if accepted.contains_key(signature) {
            continue;
        }
        let epoch = raw
            .pointer("/payload/epoch")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if epoch > input.owner_epoch {
            continue;
        }
        let from = raw
            .pointer("/payload/fromOwnerPersonId")
            .and_then(Value::as_str);
        let Some(authority) = authorities
            .clone()
            .find(|authority| Some(authority.person_id.as_str()) == from)
        else {
            continue;
        };
        let record: WorkspaceOwnershipTransfer = serde_json::from_value(raw.clone())
            .map_err(|_| "Invalid workspace ownership transfer")?;
        verify_workspace_ownership_transfer(
            &record,
            &input.workspace_id,
            authority,
            epoch.saturating_sub(1),
            i128::from(input.now_ms),
        )?;
        accepted.insert(record.signature.clone(), record);
    }
    let mut steps = Vec::new();
    let mut owner = input.current_owner;
    let mut owner_epoch = input.owner_epoch;
    let mut conflicted = has_conflicting_ownership_transfers(&to_values(&accepted)?);
    while !conflicted {
        let transition = next_verified_ownership_transition(
            &known.values().cloned().collect::<Vec<_>>(),
            &input.workspace_id,
            &owner,
            owner_epoch,
            &input.revoked_people,
            i128::from(input.now_ms),
        )?;
        for record in transition.candidates {
            accepted.insert(record.signature.clone(), record);
        }
        if transition.conflicted {
            conflicted = true;
            break;
        }
        let Some(record) = transition.selected else {
            break;
        };
        steps.push(OwnershipMergeStep {
            record: record.clone(),
            accepted: ordered(&accepted),
            previous_owner_epoch: owner_epoch,
        });
        owner = WorkspaceAuthority {
            person_id: record.payload.to_owner_person_id.clone(),
            public_key: record.payload.to_owner_public_key.clone(),
            certificates: record.payload.to_owner_certificates.clone(),
        };
        owner_epoch = record.payload.epoch;
    }
    let persist_catalog = conflicted || (steps.is_empty() && accepted.len() > input.current.len());
    Ok(OwnershipMergePlan {
        accepted: ordered(&accepted),
        steps,
        conflicted,
        persist_catalog,
    })
}

fn ordered(
    records: &BTreeMap<String, WorkspaceOwnershipTransfer>,
) -> Vec<WorkspaceOwnershipTransfer> {
    let mut records = records.values().cloned().collect::<Vec<_>>();
    records.sort_by(|a, b| {
        a.payload
            .epoch
            .cmp(&b.payload.epoch)
            .then_with(|| a.signature.cmp(&b.signature))
    });
    records
}

fn to_values(records: &BTreeMap<String, WorkspaceOwnershipTransfer>) -> Result<Vec<Value>, String> {
    records
        .values()
        .map(|record| {
            serde_json::to_value(record).map_err(|_| "Invalid workspace ownership transfer".into())
        })
        .collect()
}
