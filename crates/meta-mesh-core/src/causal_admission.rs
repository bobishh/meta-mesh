use std::collections::{HashMap, HashSet};

use automerge::{AutoCommit, Change};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    IncomingWorkspaceChangeAuthorization, WorkspaceRole, WorkspaceWriteAuthorizationSnapshot,
};

/// Full raw Automerge history and its signed write proofs.
///
/// `snapshot.document` must contain the raw union of changes. The evaluator reads
/// hashes and dependencies from those signed Automerge changes; it does not trust
/// a host-provided graph or known-hash list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalAdmissionInput {
    pub records: Vec<IncomingWorkspaceChangeAuthorization>,
    pub snapshot: WorkspaceWriteAuthorizationSnapshot,
    /// Automerge Change bytes not yet integrated into `snapshot.document`.
    /// Parseable changes with missing dependencies stay visible as pending.
    #[serde(default)]
    pub pending_change_bytes: Vec<Vec<u8>>,
    /// Legacy receiver-time metadata only. Causal permission ignores it.
    pub now_ms: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalAdmissionPlan {
    pub decisions: Vec<CausalAdmissionDecision>,
    /// Signed proof records verified against this complete history and authority
    /// snapshot. Host can persist these as projection metadata.
    pub verified_authorizations: Vec<IncomingWorkspaceChangeAuthorization>,
    /// Valid Automerge save containing only admitted changes and their admitted
    /// dependency closure. Raw signed history remains host-owned evidence.
    pub authorized_document: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalAdmissionDecision {
    pub hash: String,
    pub status: CausalAdmissionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum CausalAdmissionStatus {
    Admitted { role: WorkspaceRole },
    Quarantined { reason: String },
    Pending { reason: String },
}

#[derive(Debug, Clone)]
struct ChangeNode {
    change: Change,
    hash: String,
    dependencies: Vec<String>,
    authority: Option<ChangeAuthorityMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeAuthorityMetadata {
    #[serde(default)]
    kind: Option<String>,
    version: u8,
    #[serde(default)]
    authority_grant_hash: Option<String>,
    #[serde(default)]
    person_id: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    transaction_id: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    entity_ids: Option<Vec<String>>,
}

const MAX_CAUSAL_ADMISSION_BYTES: usize = 256 * 1024 * 1024;

/// Re-evaluate the complete Automerge history against verified signed authority.
/// Every change is reclassified, including hashes a caller already knew.
pub fn evaluate_causal_admission(
    input: CausalAdmissionInput,
) -> Result<CausalAdmissionPlan, String> {
    if input.records.len() > 20_000 {
        return Err("Too many workspace change authorizations".into());
    }
    if input.snapshot.document.len() > MAX_CAUSAL_ADMISSION_BYTES {
        return Err("Workspace causal evidence exceeds size limit".into());
    }
    let pending_bytes = input
        .pending_change_bytes
        .iter()
        .try_fold(0usize, |total, change| total.checked_add(change.len()))
        .ok_or_else(|| "Workspace causal evidence exceeds size limit".to_string())?;
    if input.snapshot.document.len().saturating_add(pending_bytes) > MAX_CAUSAL_ADMISSION_BYTES {
        return Err("Workspace causal evidence exceeds size limit".into());
    }
    let record_bytes = input.records.iter().try_fold(0usize, |total, record| {
        let bytes = serde_json::to_vec(record).ok()?.len();
        total.checked_add(bytes)
    });
    if record_bytes.is_none_or(|bytes| bytes > 64 * 1024 * 1024) {
        return Err("Workspace causal authorization evidence exceeds size limit".into());
    }
    let mut raw = AutoCommit::load(&input.snapshot.document)
        .map_err(|_| "Invalid workspace authority document".to_string())?;
    let mut changes = raw.get_changes(&[]);
    let mut seen = changes
        .iter()
        .map(|change| change.hash().to_string())
        .collect::<HashSet<_>>();
    for bytes in input.pending_change_bytes {
        let change = Change::from_bytes(bytes)
            .map_err(|_| "Invalid pending Automerge change".to_string())?;
        if seen.insert(change.hash().to_string()) {
            changes.push(change);
        }
    }
    if changes.len() > 1_000_000 {
        return Err("Workspace change history exceeds size limit".into());
    }
    let nodes = changes
        .into_iter()
        .map(|change| {
            let hash = change.hash().to_string();
            let dependencies = change.deps().iter().map(ToString::to_string).collect();
            let authority = parse_change_authority_metadata(change.message());
            ChangeNode {
                change,
                hash,
                dependencies,
                authority,
            }
        })
        .collect::<Vec<_>>();
    let by_hash = nodes
        .iter()
        .map(|node| (node.hash.as_str(), node))
        .collect::<HashMap<_, _>>();
    let all_hashes = nodes
        .iter()
        .map(|node| node.hash.clone())
        .collect::<Vec<_>>();
    let _receiver_clock_metadata = input.now_ms;
    let context =
        crate::authorization::ValidatedWorkspaceWriteAuthorizationContext::from_snapshot_causal(
            &input.snapshot,
        )?;
    let needed = all_hashes.iter().collect::<HashSet<_>>();
    let mut roles = HashMap::<String, WorkspaceRole>::new();
    let mut provenance_errors = HashMap::<String, String>::new();
    let mut verified_authorizations = Vec::new();

    for record in &input.records {
        let covered = record
            .signed
            .payload
            .hashes
            .iter()
            .filter(|hash| by_hash.contains_key(hash.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if covered.is_empty() {
            continue;
        }
        let admitted = crate::authorization::admit_with_needed(record, &context, &needed)?;
        verified_authorizations.push(record.clone());
        for proof in admitted {
            let node = by_hash[proof.hash.as_str()];
            let identityless_legacy_owner_rebind = proof.role == WorkspaceRole::Owner
                && node.dependencies.len() > 0
                && node.authority.as_ref().is_none_or(|metadata| {
                    metadata.person_id.is_none() && metadata.device_id.is_none()
                })
                && !context.inside_all_signed_frontiers(&node.hash);
            if !metadata_identity_matches(record, node) || identityless_legacy_owner_rebind {
                provenance_errors.insert(
                    proof.hash,
                    "Change identity metadata does not match its signed authorization".into(),
                );
                continue;
            }
            if proof.role == WorkspaceRole::Editor
                && !editor_provenance_matches(record, node, &input.snapshot, &context)
            {
                provenance_errors.insert(
                    proof.hash,
                    "Editor change grant provenance does not match its signed change metadata"
                        .into(),
                );
                continue;
            }
            // Match's established duplicate-proof rule: owner evidence wins.
            if roles.get(&proof.hash) != Some(&WorkspaceRole::Owner) {
                roles.insert(proof.hash, proof.role);
            }
        }
    }

    let mut statuses = nodes
        .iter()
        .map(|node| {
            (
                node.hash.clone(),
                CausalAdmissionStatus::Pending {
                    reason: "Change dependencies are unresolved".into(),
                },
            )
        })
        .collect::<HashMap<_, _>>();

    // Resolve repeatedly; serialized arrival order cannot decide whether a
    // dependency was classified before its child.
    loop {
        let mut changed = false;
        for node in &nodes {
            if !matches!(
                statuses.get(&node.hash),
                Some(CausalAdmissionStatus::Pending { reason })
                    if reason == "Change dependencies are unresolved"
            ) {
                continue;
            }
            if node
                .dependencies
                .iter()
                .any(|dependency| !by_hash.contains_key(dependency.as_str()))
            {
                statuses.insert(
                    node.hash.clone(),
                    CausalAdmissionStatus::Pending {
                        reason: "Change dependency is missing".into(),
                    },
                );
                changed = true;
            } else if node.dependencies.iter().any(|dependency| {
                matches!(
                    statuses.get(dependency),
                    Some(CausalAdmissionStatus::Quarantined { .. })
                ) || matches!(
                    statuses.get(dependency),
                    Some(CausalAdmissionStatus::Pending { reason })
                        if reason != "Change dependencies are unresolved"
                )
            }) {
                statuses.insert(
                    node.hash.clone(),
                    CausalAdmissionStatus::Pending {
                        reason: "Change depends on a change outside the authorized projection"
                            .into(),
                    },
                );
                changed = true;
            } else if node.dependencies.iter().any(|dependency| {
                matches!(
                    statuses.get(dependency),
                    Some(CausalAdmissionStatus::Pending { reason })
                        if reason == "Change dependencies are unresolved"
                )
            }) {
                continue;
            } else if node.dependencies.iter().all(|dependency| {
                matches!(
                    statuses.get(dependency),
                    Some(CausalAdmissionStatus::Admitted { .. })
                )
            }) {
                let own_status = if let Some(role) = roles.get(&node.hash).copied() {
                    if role == WorkspaceRole::Editor && node.dependencies.is_empty() {
                        CausalAdmissionStatus::Quarantined {
                            reason: "Editors cannot create the initial workspace change".into(),
                        }
                    } else {
                        CausalAdmissionStatus::Admitted { role }
                    }
                } else if let Some(reason) = provenance_errors.get(&node.hash) {
                    CausalAdmissionStatus::Quarantined {
                        reason: reason.clone(),
                    }
                } else {
                    CausalAdmissionStatus::Quarantined {
                        reason: "No verified signed authorization covers this change".into(),
                    }
                };
                statuses.insert(node.hash.clone(), own_status);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for status in statuses.values_mut() {
        if matches!(
            status,
            CausalAdmissionStatus::Pending { reason }
                if reason == "Change dependencies are unresolved"
        ) {
            *status = CausalAdmissionStatus::Pending {
                reason: "Change dependency chain is unresolved".into(),
            };
        }
    }

    let mut remaining = nodes
        .iter()
        .filter(|node| {
            matches!(
                statuses.get(&node.hash),
                Some(CausalAdmissionStatus::Admitted { .. })
            )
        })
        .map(|node| node.hash.clone())
        .collect::<HashSet<_>>();
    let node_by_hash = nodes
        .iter()
        .map(|node| (node.hash.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut ordered_changes = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let mut ready = remaining
            .iter()
            .filter(|hash| {
                node_by_hash[hash.as_str()]
                    .dependencies
                    .iter()
                    .all(|dependency| !remaining.contains(dependency))
            })
            .cloned()
            .collect::<Vec<_>>();
        ready.sort();
        if ready.is_empty() {
            return Err("Authorized workspace change dependencies are cyclic".into());
        }
        for hash in ready {
            remaining.remove(&hash);
            ordered_changes.push(node_by_hash[hash.as_str()].change.clone());
        }
    }
    let mut authorized = AutoCommit::new();
    authorized
        .apply_changes(ordered_changes)
        .map_err(|_| "Unable to rebuild authorized workspace projection".to_string())?;

    Ok(CausalAdmissionPlan {
        decisions: {
            let mut decisions = nodes
                .iter()
                .map(|node| CausalAdmissionDecision {
                    hash: node.hash.clone(),
                    status: statuses
                        .remove(&node.hash)
                        .expect("status for every change"),
                })
                .collect::<Vec<_>>();
            decisions.sort_by(|left, right| left.hash.cmp(&right.hash));
            decisions
        },
        verified_authorizations,
        authorized_document: authorized.save(),
    })
}

fn parse_change_authority_metadata(message: Option<&str>) -> Option<ChangeAuthorityMetadata> {
    let value = serde_json::from_str::<serde_json::Value>(message?).ok()?;
    let metadata = serde_json::from_value::<ChangeAuthorityMetadata>(value).ok()?;
    let recognized = metadata.kind.as_deref() == Some("workspace-change-metadata")
        || metadata.transaction_id.is_some()
        || metadata.action.is_some()
        || metadata.entity_ids.is_some();
    (recognized && metadata.version == 1).then_some(metadata)
}

fn metadata_identity_matches(
    record: &IncomingWorkspaceChangeAuthorization,
    node: &ChangeNode,
) -> bool {
    node.authority.as_ref().is_none_or(|metadata| {
        match (metadata.person_id.as_deref(), metadata.device_id.as_deref()) {
            (Some(person_id), Some(device_id)) => {
                person_id == record.signed.payload.person_id
                    && device_id == record.signed.payload.device_id
            }
            (None, None) => true,
            _ => false,
        }
    })
}

fn editor_provenance_matches(
    record: &IncomingWorkspaceChangeAuthorization,
    node: &ChangeNode,
    snapshot: &WorkspaceWriteAuthorizationSnapshot,
    context: &crate::authorization::ValidatedWorkspaceWriteAuthorizationContext,
) -> bool {
    let Some(grant) = record.grant.as_ref() else {
        return false;
    };
    let metadata = node.authority.as_ref();
    let has_immutable_binding = metadata
        .and_then(|metadata| metadata.authority_grant_hash.as_deref())
        .is_some();
    if !has_immutable_binding {
        // Version 1 history predates immutable grant binding. Keep it only when
        // the actual signed frontiers prove the change was already present and
        // no signed boundary makes the attached grant a newer regrant.
        let epoch = grant.payload.effective_access_epoch();
        let has_newer_boundary = snapshot
            .revocations
            .iter()
            .filter(|boundary| boundary.payload.person_id == record.signed.payload.person_id)
            .any(|boundary| epoch > boundary.payload.epoch)
            || snapshot
                .departures
                .iter()
                .filter(|boundary| {
                    boundary.record.payload.person_id == record.signed.payload.person_id
                })
                .any(|boundary| epoch > boundary.record.payload.access_epoch);
        return !has_newer_boundary
            && context.inside_signed_frontiers(
                &record.signed.payload.person_id,
                &record.signed.payload.device_id,
                &node.hash,
            );
    }
    let Some(metadata) = metadata else {
        return false;
    };
    let Ok(value) = serde_json::to_value(grant) else {
        return false;
    };
    let Ok(canonical) = crate::identity::canonicalize_json(&value) else {
        return false;
    };
    let grant_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    metadata.authority_grant_hash.as_deref() == Some(grant_hash.as_str())
        && metadata.person_id.as_deref() == Some(record.signed.payload.person_id.as_str())
        && metadata.device_id.as_deref() == Some(record.signed.payload.device_id.as_str())
}

#[cfg(test)]
mod tests;
