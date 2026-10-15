use std::collections::{BTreeSet, HashMap, HashSet};

use automerge::{
    AutoCommit, Change, ObjId, Prop, ROOT, ReadDoc, ScalarValue, hydrate::Value as HydratedValue,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AutomationGrantScope, IncomingWorkspaceChangeAuthorization, WorkspaceRole,
    WorkspaceWriteAuthorizationSnapshot,
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
    /// Legacy receiver-time metadata. Historical causal admission does not use
    /// author timestamps to prove when an automation change was created.
    pub now_ms: i128,
}

/// Retained archive observations name these rules explicitly. Changes to causal
/// admission semantics require a new policy ID and reader compatibility review.
pub const CAUSAL_ADMISSION_POLICY_ID: &str = "mesh-causal-admission@3";

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

#[derive(Debug, Clone)]
struct AutomationEffect {
    item_id: String,
    moved: bool,
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
    evaluate_causal_admission_inner(input, None)
}

/// Admit only changes causally descended from a Native-verified compact
/// history basis. The basis hash is supplied only by the opaque receiver
/// handle; ordinary callers must use full-history admission.
pub(crate) fn evaluate_causal_admission_from_history_basis(
    input: CausalAdmissionInput,
    trusted_basis_hash: &str,
) -> Result<CausalAdmissionPlan, String> {
    if trusted_basis_hash.is_empty() {
        return Err("History basis admission requires a verified basis hash".into());
    }
    evaluate_causal_admission_inner(input, Some(trusted_basis_hash))
}

fn evaluate_causal_admission_inner(
    input: CausalAdmissionInput,
    trusted_basis_hash: Option<&str>,
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
    // Loaded history is large even when its serialized snapshot is tiny.
    // Release it before authority verification loads the same snapshot.
    drop(raw);
    let mut raw = None;
    let mut seen = changes
        .iter()
        .map(|change| change.hash().to_string())
        .collect::<HashSet<_>>();
    let has_pending_bytes = !input.pending_change_bytes.is_empty();
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
    let needed = all_hashes.iter().filter(|hash| Some(hash.as_str()) != trusted_basis_hash).collect::<HashSet<_>>();
    let mut roles = HashMap::<String, WorkspaceRole>::new();
    let mut automation_scopes = HashMap::<String, AutomationGrantScope>::new();
    let mut automation_effects = HashMap::<String, AutomationEffect>::new();
    let mut provenance_errors = HashMap::<String, String>::new();
    let mut verified_authorizations = Vec::new();

    for record in &input.records {
        let covered = record
            .signed
            .payload
            .hashes
            .iter()
            .filter(|hash| by_hash.contains_key(hash.as_str()) && Some(hash.as_str()) != trusted_basis_hash)
            .cloned()
            .collect::<Vec<_>>();
        if covered.is_empty() {
            continue;
        }
        let admitted =
            crate::authorization::admit_with_needed_for_causal(record, &context, &needed, true)?;
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
            if proof.role == WorkspaceRole::Automation
                && !automation_provenance_matches(record, node)
            {
                provenance_errors.insert(
                    proof.hash,
                    "Automation grant provenance does not match its signed change metadata".into(),
                );
                continue;
            }
            if proof.role == WorkspaceRole::Visitor {
                if let Err(reason) = visitor_profile_change_only(
                    admission_document(&mut raw, &input.snapshot.document)?,
                    node,
                    &record.signed.payload.person_id,
                ) {
                    provenance_errors.insert(
                        proof.hash,
                        format!("Visitors may change only their own avatar profile ({reason})"),
                    );
                    continue;
                }
            }
            if proof.role == WorkspaceRole::Automation {
                let Some(scope) = record
                    .grant
                    .as_ref()
                    .and_then(|grant| grant.payload.automation.clone())
                else {
                    provenance_errors
                        .insert(proof.hash, "Automation grant scope is missing".into());
                    continue;
                };
                if automation_scopes
                    .get(&proof.hash)
                    .is_some_and(|existing| existing != &scope)
                {
                    provenance_errors
                        .insert(proof.hash, "Conflicting automation grant scopes".into());
                    continue;
                }
                automation_scopes.insert(proof.hash.clone(), scope);
            }
            // Match's established duplicate-proof rule: owner evidence wins.
            if roles.get(&proof.hash) != Some(&WorkspaceRole::Owner) {
                roles.insert(proof.hash, proof.role);
            }
        }
    }

    if let Some(basis_hash) = trusted_basis_hash {
        let basis = nodes.iter().find(|node| node.hash == basis_hash)
            .ok_or("Verified history basis is absent from the admitted document")?;
        if !basis.dependencies.is_empty() || nodes.iter().filter(|node| node.dependencies.is_empty()).count() != 1 {
            return Err("History basis must be the single root of the compact active history".into());
        }
    }
    let mut statuses = nodes
        .iter()
        .map(|node| {
            (
                node.hash.clone(),
                if Some(node.hash.as_str()) == trusted_basis_hash {
                    CausalAdmissionStatus::Admitted { role: WorkspaceRole::Owner }
                } else { CausalAdmissionStatus::Pending { reason: "Change dependencies are unresolved".into() } },
            )
        })
        .collect::<HashMap<_, _>>();
    let mut application_source_creations = HashMap::<String, (Vec<String>, Option<ObjId>)>::new();
    let mut entities_map_rebindings = HashMap::<String, ObjId>::new();

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
                    if let Some(previous_entities_id) = workspace_entities_map_rebound(
                        admission_document(&mut raw, &input.snapshot.document)?,
                        node,
                    ) {
                        entities_map_rebindings.insert(node.hash.clone(), previous_entities_id);
                    }
                    let source_result = {
                        let raw_document = admission_document(&mut raw, &input.snapshot.document)?;
                        if application_source_change_may_touch(raw_document, node) {
                            application_source_change_allowed(
                                raw_document,
                                node,
                                role,
                                &input.snapshot.workspace_id,
                                automation_scopes.get(&node.hash),
                            )
                        } else {
                            Ok(Vec::new())
                        }
                    };
                    if let Ok(created_ids) = &source_result {
                        if !created_ids.is_empty() {
                            let entities_id = workspace_entities_object_at_frontier(
                                admission_document(&mut raw, &input.snapshot.document)?,
                                std::slice::from_ref(&node.hash),
                            );
                            application_source_creations
                                .insert(node.hash.clone(), (created_ids.clone(), entities_id));
                        }
                    }
                    if let Err(reason) = source_result {
                        CausalAdmissionStatus::Quarantined {
                            reason: reason.into(),
                        }
                    } else if role == WorkspaceRole::Editor && node.dependencies.is_empty() {
                        CausalAdmissionStatus::Quarantined {
                            reason: "Editors cannot create the initial workspace change".into(),
                        }
                    } else if role == WorkspaceRole::Automation {
                        match automation_scopes.get(&node.hash) {
                            Some(scope) => match automation_change_allowed(
                                admission_document(&mut raw, &input.snapshot.document)?,
                                node,
                                scope,
                            ) {
                                Ok(effect) => {
                                    automation_effects.insert(node.hash.clone(), effect);
                                    CausalAdmissionStatus::Admitted { role }
                                }
                                Err(reason) => CausalAdmissionStatus::Quarantined {
                                    reason: reason.into(),
                                },
                            },
                            None => CausalAdmissionStatus::Quarantined {
                                reason: "Automation grant scope is missing".into(),
                            },
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

    let conflicted_sources = if application_source_creations.is_empty() {
        BTreeSet::new()
    } else {
        raw.as_mut()
            .map(application_source_conflicts)
            .unwrap_or_default()
    };
    for (hash, (created_ids, _)) in &application_source_creations {
        if created_ids.iter().any(|id| conflicted_sources.contains(id)) {
            statuses.insert(
                hash.clone(),
                CausalAdmissionStatus::Quarantined {
                    reason:
                        "Concurrent application source creation conflicts on the same record id"
                            .into(),
                },
            );
        }
    }
    for (hash, previous_entities_id) in entities_map_rebindings {
        let rebind_conflicts_with_source = application_source_creations
            .values()
            .any(|(_, source_base_id)| source_base_id.as_ref() == Some(&previous_entities_id));
        if rebind_conflicts_with_source {
            statuses.insert(
                hash,
                CausalAdmissionStatus::Quarantined {
                    reason: "Workspace entities map rebind conflicts with an application source created from that map".into(),
                },
            );
        }
    }

    // Scoped checks need history, but projection construction does not.
    drop(raw);
    // A verified snapshot already contains the exact authorized projection.
    // Replay is required only for excluded/pending changes or move conflicts.
    if !has_pending_bytes
        && statuses
            .values()
            .all(|status| matches!(status, CausalAdmissionStatus::Admitted { .. }))
        && automation_effects.values().all(|effect| !effect.moved)
    {
        return Ok(admission_plan(
            &nodes,
            statuses,
            verified_authorizations,
            input.snapshot.document,
        ));
    }
    let mut authorized = if !has_pending_bytes
        && statuses
            .values()
            .all(|status| matches!(status, CausalAdmissionStatus::Admitted { .. }))
    {
        AutoCommit::load(&input.snapshot.document)
            .map_err(|_| "Invalid workspace authority document".to_string())?
    } else {
        build_authorized_projection(&nodes, &statuses)?
    };
    let conflicting_automation = automation_effects
        .iter()
        .filter_map(|(hash, effect)| {
            (effect.moved
                && matches!(
                    statuses.get(hash),
                    Some(CausalAdmissionStatus::Admitted { .. })
                )
                && projected_item_has_parent_conflict(&mut authorized, &effect.item_id))
            .then_some(hash.clone())
        })
        .collect::<Vec<_>>();
    for hash in conflicting_automation {
        statuses.insert(
            hash,
            CausalAdmissionStatus::Quarantined {
                reason: "Automation move conflicts with a concurrent authorized status change"
                    .into(),
            },
        );
    }
    loop {
        let mut changed = false;
        for node in &nodes {
            if !matches!(
                statuses.get(&node.hash),
                Some(CausalAdmissionStatus::Admitted { .. })
            ) {
                continue;
            }
            if node.dependencies.iter().any(|dependency| {
                matches!(
                    statuses.get(dependency),
                    Some(CausalAdmissionStatus::Quarantined { .. })
                ) || matches!(
                    statuses.get(dependency),
                    Some(CausalAdmissionStatus::Pending { .. })
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
            }
        }
        if !changed {
            break;
        }
    }
    if statuses
        .values()
        .any(|status| !matches!(status, CausalAdmissionStatus::Admitted { .. }))
    {
        authorized = build_authorized_projection(&nodes, &statuses)?;
    }

    Ok(admission_plan(
        &nodes,
        statuses,
        verified_authorizations,
        authorized.save(),
    ))
}

fn admission_plan(
    nodes: &[ChangeNode],
    mut statuses: HashMap<String, CausalAdmissionStatus>,
    verified_authorizations: Vec<IncomingWorkspaceChangeAuthorization>,
    authorized_document: Vec<u8>,
) -> CausalAdmissionPlan {
    CausalAdmissionPlan {
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
        authorized_document,
    }
}

/// Orders admitted changes in deterministic dependency layers. Building each
/// frontier by rescanning all remaining changes is quadratic for long histories.
fn ordered_admitted_hashes<'a>(
    nodes: impl IntoIterator<Item = (&'a str, &'a [String])>,
    admitted: &HashSet<String>,
) -> Result<Vec<String>, String> {
    let mut indegrees = HashMap::<String, usize>::with_capacity(admitted.len());
    let mut children = HashMap::<String, Vec<String>>::with_capacity(admitted.len());
    for (hash, dependencies) in nodes {
        if !admitted.contains(hash) {
            continue;
        }
        let mut unique_dependencies = HashSet::new();
        for dependency in dependencies {
            if admitted.contains(dependency) && unique_dependencies.insert(dependency.clone()) {
                children
                    .entry(dependency.clone())
                    .or_default()
                    .push(hash.to_string());
            }
        }
        indegrees.insert(hash.to_string(), unique_dependencies.len());
    }

    let mut frontier = indegrees
        .iter()
        .filter_map(|(hash, degree)| (*degree == 0).then_some(hash.clone()))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(admitted.len());
    while !frontier.is_empty() {
        let current = std::mem::take(&mut frontier);
        let mut next = BTreeSet::new();
        for hash in current {
            ordered.push(hash.clone());
            for child in children.get(&hash).into_iter().flatten() {
                let degree = indegrees.get_mut(child).expect("child has an indegree");
                *degree -= 1;
                if *degree == 0 {
                    next.insert(child.clone());
                }
            }
        }
        frontier = next;
    }

    if ordered.len() != admitted.len() {
        return Err("Authorized workspace change dependencies are cyclic".into());
    }
    Ok(ordered)
}

fn build_authorized_projection(
    nodes: &[ChangeNode],
    statuses: &HashMap<String, CausalAdmissionStatus>,
) -> Result<AutoCommit, String> {
    let remaining = nodes
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
    let ordered_hashes = ordered_admitted_hashes(
        nodes
            .iter()
            .map(|node| (node.hash.as_str(), node.dependencies.as_slice())),
        &remaining,
    )?;
    let ordered_changes = ordered_hashes
        .iter()
        .map(|hash| node_by_hash[hash.as_str()].change.clone())
        .collect::<Vec<_>>();
    let mut authorized = AutoCommit::new();
    authorized
        .apply_changes(ordered_changes)
        .map_err(|_| "Unable to rebuild authorized workspace projection".to_string())?;
    Ok(authorized)
}

fn projected_item_has_parent_conflict(doc: &mut AutoCommit, item_id: &str) -> bool {
    let Ok(HydratedValue::Map(root)) = doc.hydrate(&ROOT, None) else {
        return false;
    };
    let Some(HydratedValue::Map(entities)) = root.get("entities") else {
        return false;
    };
    let Some(HydratedValue::Map(item)) = entities.get(item_id) else {
        return false;
    };
    let Some(HydratedValue::Map(placement)) = item.get("placement") else {
        return false;
    };
    placement
        .iter()
        .any(|(key, value)| key == "parentId" && value.conflict)
}

fn admission_document<'a>(
    document: &'a mut Option<AutoCommit>,
    bytes: &[u8],
) -> Result<&'a mut AutoCommit, String> {
    if document.is_none() {
        *document = Some(
            AutoCommit::load(bytes)
                .map_err(|_| "Invalid workspace authority document".to_string())?,
        );
    }
    Ok(document.as_mut().expect("loaded admission document"))
}

/// Read causal views without cloning the full operation history for each scope check.
fn change_root_views(
    raw: &mut AutoCommit,
    node: &ChangeNode,
) -> Result<(HydratedValue, HydratedValue), &'static str> {
    if node
        .change
        .deps()
        .iter()
        .any(|hash| raw.get_change_by_hash(hash).is_none())
    {
        return Err("dependency view unavailable");
    }
    let before = raw
        .hydrate(&ROOT, Some(node.change.deps()))
        .map_err(|_| "dependency root unavailable")?;
    let after = if raw.get_change_by_hash(&node.change.hash()).is_some() {
        raw.hydrate(&ROOT, Some(&[node.change.hash()]))
            .map_err(|_| "result root unavailable")?
    } else {
        // Pending change bytes have no historical view in the retained snapshot.
        let mut after = raw
            .fork_at(node.change.deps())
            .map_err(|_| "dependency view unavailable")?;
        after
            .apply_changes(vec![node.change.clone()])
            .map_err(|_| "change could not be replayed")?;
        after
            .hydrate(&ROOT, None)
            .map_err(|_| "result root unavailable")?
    };
    Ok((before, after))
}

const MAX_APPLICATION_SOURCE_RECORDS: usize = 20_000;
const MAX_APPLICATION_SOURCE_BYTES: usize = 65_536;

/// Admit immutable source observations at the signed change boundary. The
/// materialized root is read at this change's causal frontier, so concurrent
/// independent records remain independent while edits cannot masquerade as
/// creation on a later branch.
fn application_source_change_allowed(
    raw: &mut AutoCommit,
    node: &ChangeNode,
    role: WorkspaceRole,
    workspace_id: &str,
    automation_scope: Option<&AutomationGrantScope>,
) -> Result<Vec<String>, &'static str> {
    let (before, after) = change_root_views(raw, node)
        .map_err(|_| "Application source change views are unavailable")?;
    let (HydratedValue::Map(mut before_root), HydratedValue::Map(mut after_root)) = (before, after)
    else {
        return Err("Application source workspace root is not a map");
    };
    let before_entities = before_root
        .remove("entities")
        .and_then(|value| match value.value {
            HydratedValue::Map(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    let after_entities = after_root
        .remove("entities")
        .and_then(|value| match value.value {
            HydratedValue::Map(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();

    let candidates = before_entities
        .keys()
        .chain(after_entities.keys())
        .filter(|id| {
            id.starts_with("application-source:")
                || before_entities
                    .get(*id)
                    .and_then(map_value)
                    .and_then(|map| scalar_string(map.get("kind")))
                    .as_deref()
                    == Some("application_source")
                || after_entities
                    .get(*id)
                    .and_then(map_value)
                    .and_then(|map| scalar_string(map.get("kind")))
                    .as_deref()
                    == Some("application_source")
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if candidates.len() > MAX_APPLICATION_SOURCE_RECORDS {
        return Err("Application source record limit exceeded");
    }

    let mut created_ids = Vec::new();
    for id in candidates {
        let before_value = before_entities.get(&id);
        let after_value = after_entities.get(&id);
        let protected = id.starts_with("application-source:")
            || before_value
                .and_then(map_value)
                .and_then(|map| scalar_string(map.get("kind")))
                .as_deref()
                == Some("application_source")
            || after_value
                .and_then(map_value)
                .and_then(|map| scalar_string(map.get("kind")))
                .as_deref()
                == Some("application_source");
        let before_conflict = map_entry_conflict(&before_entities, &id);
        let after_conflict = map_entry_conflict(&after_entities, &id);
        if !protected && !before_conflict && !after_conflict {
            continue;
        }
        if before_value == after_value && before_conflict == after_conflict {
            continue;
        }
        if before_value.is_some() {
            return Err("Application source records cannot be edited, deleted, moved, or archived");
        }
        if !matches!(role, WorkspaceRole::Owner | WorkspaceRole::Editor)
            && !(role == WorkspaceRole::Automation
                && automation_scope.is_some_and(|scope| scope.version == 2))
        {
            return Err("This workspace role cannot create application source records");
        }
        let Some(entity) = after_value else {
            continue;
        };
        if after_conflict {
            return Err("Application source record creation has a same-id conflict");
        }
        validate_application_source_entity(&id, entity, &after_entities, workspace_id)?;
        created_ids.push(id);
    }
    Ok(created_ids)
}

/// Inspect this signed change's operations and their historical parent paths.
/// Never expand recursive document patches: an unrelated title edit must not
/// decode the card's unchanged narrative or other visible board content.
fn application_source_change_may_touch(raw: &mut AutoCommit, node: &ChangeNode) -> bool {
    use automerge::legacy::{Key, ObjectId, OpType};
    let hash = node.change.hash();
    if raw.get_change_by_hash(&hash).is_none() {
        return true;
    }
    // Expanded legacy operations allocate per-character structs for browser
    // Text. Large changes use the complete source transition check directly,
    // which reads materialized text rather than expanding its operation log.
    if node.change.len() > 32_768 {
        return true;
    }
    let expanded = node.change.decode();
    let safe_created_objects = safe_created_root_path_objects(&expanded);
    let mut checked_objects = HashSet::new();
    for operation in &expanded.operations {
        if matches!(&operation.key, Key::Map(key) if key.starts_with("application-source:"))
            || matches!(&operation.action, OpType::Put(ScalarValue::Str(text)) if text == "application_source")
        {
            return true;
        }
        let ObjectId::Id(id) = &operation.obj else {
            continue;
        };
        if safe_created_objects.contains(&operation.obj) {
            continue;
        }
        if !checked_objects.insert(operation.obj.clone()) {
            continue;
        }
        let Ok(object) = raw.import_obj(&format!("{}@{}", id.counter(), id.actor())) else {
            return true;
        };
        let created_here = id.actor() == &expanded.actor_id
            && id.counter() >= expanded.start_op.get()
            && id.counter()
                < expanded
                    .start_op
                    .get()
                    .saturating_add(expanded.operations.len() as u64);
        let after_heads = [hash];
        if matches!(&operation.key, Key::Map(key) if key == "kind")
            && application_source_kind_at(raw, &object, &after_heads)
        {
            return true;
        }
        let frontiers: &[&[automerge::ChangeHash]] = if created_here {
            &[&after_heads]
        } else {
            &[node.change.deps(), &after_heads]
        };
        for heads in frontiers {
            let Ok(mut parents) = raw.parents_at(&object, heads) else {
                return true;
            };
            if parents.any(|parent| match parent.prop {
                Prop::Map(key) => {
                    key.starts_with("application-source:")
                        || key == "kind"
                            && application_source_kind_at(raw, &parent.obj, &after_heads)
                }
                _ => false,
            }) {
                return true;
            }
        }
    }
    false
}

fn safe_created_root_path_objects(change: &automerge::ExpandedChange) -> HashSet<automerge::legacy::ObjectId> {
    use automerge::legacy::{Key, ObjectId, OpId, OpType};

    let mut safe = HashSet::new();
    for (index, operation) in change.operations.iter().enumerate() {
        if !matches!(operation.action, OpType::Make(_)) {
            continue;
        }
        let Some(counter) = change.start_op.get().checked_add(index as u64) else {
            continue;
        };
        let safe_parent = match &operation.obj {
            ObjectId::Root => matches!(&operation.key, Key::Map(key)
                if key != "entities" && key != "kind" && !key.starts_with("application-source:")),
            ObjectId::Id(parent) => safe.contains(&ObjectId::Id(parent.clone()))
                && !matches!(&operation.key, Key::Map(key)
                    if key == "kind" || key.starts_with("application-source:")),
        };
        if safe_parent {
            safe.insert(ObjectId::Id(OpId::new(counter, &change.actor_id)));
        }
    }
    safe
}

fn application_source_kind_at(
    raw: &AutoCommit,
    object: &ObjId,
    heads: &[automerge::ChangeHash],
) -> bool {
    match raw.get_at(object, "kind", heads) {
        Ok(Some((automerge::Value::Scalar(value), _))) => {
            matches!(value.as_ref(), ScalarValue::Str(text) if text == "application_source")
        }
        Ok(Some((automerge::Value::Object(automerge::ObjType::Text), id))) => {
            raw.length_at(&id, heads) == 18
                && raw
                    .text_at(&id, heads)
                    .is_ok_and(|text| text == "application_source")
        }
        _ => false,
    }
}

fn map_entry_conflict(map: &automerge::hydrate::Map, id: &str) -> bool {
    map.iter().any(|(key, value)| key == id && value.conflict)
}

fn application_source_conflicts(raw: &mut AutoCommit) -> BTreeSet<String> {
    let Ok(HydratedValue::Map(root)) = raw.hydrate(&ROOT, None) else {
        return BTreeSet::new();
    };
    let Some(HydratedValue::Map(entities)) = root.get("entities") else {
        return BTreeSet::new();
    };
    entities
        .iter()
        .filter_map(|(id, value)| {
            let source_candidate = id.starts_with("application-source:")
                || map_value(&value.value)
                    .and_then(|map| scalar_string(map.get("kind")))
                    .as_deref()
                    == Some("application_source");
            (source_candidate && (value.conflict || hydrated_map_has_conflict(&value.value)))
                .then(|| id.clone())
        })
        .collect()
}

fn workspace_entities_map_rebound(raw: &mut AutoCommit, node: &ChangeNode) -> Option<ObjId> {
    if !change_may_rebind_workspace_entities(node) {
        return None;
    }
    let Ok(Some((before_value, before_id))) = raw.get_at(ROOT, "entities", node.change.deps())
    else {
        return None;
    };
    if !matches!(
        before_value,
        automerge::Value::Object(automerge::ObjType::Map)
    ) {
        return None;
    }
    let hash = node.change.hash();
    match raw.get_at(ROOT, "entities", &[hash]) {
        Ok(Some((automerge::Value::Object(automerge::ObjType::Map), after_id)))
            if before_id == after_id =>
        {
            None
        }
        Ok(_) => Some(before_id),
        Err(_) => None,
    }
}

fn change_may_rebind_workspace_entities(node: &ChangeNode) -> bool {
    use automerge::legacy::{Key, ObjectId};

    // Small changes can prove that the root binding was untouched from their
    // operation targets. Large changes retain the conservative frontier check.
    if node.change.len() > 32_768 {
        return true;
    }
    node.change.decode().operations.iter().any(|operation| {
        matches!(operation.obj, ObjectId::Root)
            && matches!(&operation.key, Key::Map(key) if key == "entities")
    })
}

fn workspace_entities_object_at_frontier(raw: &mut AutoCommit, heads: &[String]) -> Option<ObjId> {
    let hashes = heads
        .iter()
        .map(|hash| hash.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    let (value, id) = raw.get_at(ROOT, "entities", &hashes).ok()??;
    matches!(value, automerge::Value::Object(automerge::ObjType::Map)).then_some(id)
}

fn hydrated_map_has_conflict(value: &HydratedValue) -> bool {
    match value {
        HydratedValue::Map(map) => map
            .iter()
            .any(|(_, entry)| entry.conflict || hydrated_map_has_conflict(&entry.value)),
        _ => false,
    }
}

fn validate_application_source_entity(
    entity_id: &str,
    value: &HydratedValue,
    entities: &automerge::hydrate::Map,
    workspace_id: &str,
) -> Result<(), &'static str> {
    let Some(entity) = map_value(value) else {
        return Err("Application source entity is malformed");
    };
    let Some(record_id) = entity_id.strip_prefix("application-source:") else {
        return Err("Application source id must use its reserved prefix");
    };
    if record_id.is_empty()
        || record_id.len() > 128
        || !record_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("Application source id is malformed");
    }
    if entity.len() != 8
        || scalar_string(entity.get("id")).as_deref() != Some(entity_id)
        || scalar_string(entity.get("kind")).as_deref() != Some("application_source")
        || scalar_string(entity.get("title")).as_deref() != Some("Application source")
        || !matches!(
            entity.get("archivedAt"),
            Some(HydratedValue::Scalar(ScalarValue::Null))
        )
    {
        return Err("Application source entity fields are malformed");
    }
    let created_at = scalar_string(entity.get("createdAt"))
        .ok_or("Application source creation time is missing")?;
    let updated_at = scalar_string(entity.get("updatedAt"))
        .ok_or("Application source update time is missing")?;
    if created_at != updated_at || !canonical_rfc3339(&created_at) {
        return Err("Application source timestamps must be equal canonical ISO values");
    }
    let placement = entity
        .get("placement")
        .and_then(map_value)
        .ok_or("Application source placement is missing")?;
    if placement.len() != 2 || scalar_string(placement.get("rank")).as_deref() != Some("0/1") {
        return Err("Application source placement is malformed");
    }
    let card_id = scalar_string(placement.get("parentId"))
        .ok_or("Application source parent card is missing")?;
    if !valid_js_identifier(&card_id) {
        return Err("Application source parent card id is outside bounds");
    }
    let Some(card) = entities.get(&card_id).and_then(map_value) else {
        return Err("Application source parent card does not exist");
    };
    if scalar_string(card.get("id")).as_deref() != Some(card_id.as_str())
        || card.get("kind").is_some()
        || !is_item_map(card)
    {
        return Err("Application source parent must be a kindless item card");
    }
    let data = scalar_string(entity.get("data")).ok_or("Application source data is missing")?;
    if data.len() > MAX_APPLICATION_SOURCE_BYTES {
        return Err("Application source data exceeds size limit");
    }
    let parsed: serde_json::Value =
        serde_json::from_str(&data).map_err(|_| "Application source data is not valid JSON")?;
    if crate::identity::canonicalize_json(&parsed).as_deref() != Ok(data.as_str()) {
        return Err("Application source data must use canonical JSON encoding");
    }
    let object = parsed
        .as_object()
        .ok_or("Application source data must be a JSON object")?;
    const REQUIRED_SOURCE_FIELDS: &[&str] = &[
        "kind",
        "version",
        "recordId",
        "workspaceId",
        "cardId",
        "applicationId",
        "observation",
    ];
    const ALLOWED_SOURCE_FIELDS: &[&str] = &[
        "kind",
        "version",
        "recordId",
        "workspaceId",
        "cardId",
        "applicationId",
        "messageIds",
        "atsId",
        "observation",
    ];
    let version = object.get("version").and_then(serde_json::Value::as_u64);
    let refs_valid = match version {
        Some(1) => !object.contains_key("messageIds") && !object.contains_key("atsId"),
        Some(2) => {
            let message_ids_valid = object.get("messageIds").is_none_or(|value| {
                value.as_array().is_some_and(|ids| {
                    !ids.is_empty()
                        && ids.len() <= 40
                        && ids.iter().all(|id| {
                            id.as_str().is_some_and(|text| {
                                !text.trim().is_empty() && js_units(text) <= 500
                            })
                        })
                })
            });
            let ats_id_valid = object.get("atsId").is_none_or(|value| {
                value.as_str().is_some_and(|text| {
                    !text.trim().is_empty() && js_units(text) <= 256
                })
            });
            let has_reference = object
                .get("messageIds")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|ids| !ids.is_empty())
                || object
                    .get("atsId")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty());
            message_ids_valid && ats_id_valid && has_reference
        }
        _ => false,
    };
    if REQUIRED_SOURCE_FIELDS.iter().any(|key| !object.contains_key(*key))
        || object.keys().any(|key| !ALLOWED_SOURCE_FIELDS.contains(&key.as_str()))
        || !refs_valid
        || object.get("kind").and_then(serde_json::Value::as_str)
        != Some("application-source-observation")
        || object.get("recordId").and_then(serde_json::Value::as_str) != Some(record_id)
        || object
            .get("workspaceId")
            .and_then(serde_json::Value::as_str)
            != Some(workspace_id)
        || object.get("cardId").and_then(serde_json::Value::as_str) != Some(card_id.as_str())
        || !valid_js_identifier(workspace_id)
        || !valid_js_identifier(card_id.as_str())
        || !object
            .get("applicationId")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|application_id| js_units(application_id) <= 513)
        || object
            .get("applicationId")
            .and_then(serde_json::Value::as_str)
            != Some(format!("{workspace_id}:{card_id}").as_str())
    {
        return Err("Application source data scope or schema is invalid");
    }
    validate_application_source_observation(
        object
            .get("observation")
            .and_then(serde_json::Value::as_object)
            .ok_or("Application source observation is missing")?,
        record_id,
        workspace_id,
        &card_id,
        &format!("{workspace_id}:{card_id}"),
        entities,
    )
}

fn validate_application_source_observation(
    observation: &serde_json::Map<String, serde_json::Value>,
    record_id: &str,
    workspace_id: &str,
    card_id: &str,
    application_id: &str,
    entities: &automerge::hydrate::Map,
) -> Result<(), &'static str> {
    const FIELDS: &[&str] = &[
        "phase",
        "origin",
        "status",
        "observedAt",
        "jobUrl",
        "originalRecordId",
        "company",
        "title",
        "text",
        "extractorVersion",
        "contentDigest",
        "reason",
    ];
    if observation
        .keys()
        .any(|key| !FIELDS.contains(&key.as_str()))
    {
        return Err("Application source observation has unknown fields");
    }
    let phase = json_string(observation, "phase")?;
    let origin = json_string(observation, "origin")?;
    let status = json_string(observation, "status")?;
    if !matches!(phase, "original" | "refresh" | "legacy")
        || !matches!(origin, "website" | "email" | "manual" | "legacy")
        || !matches!(
            status,
            "available" | "pending" | "not-found" | "unavailable" | "missing-evidence"
        )
    {
        return Err("Application source observation enum is invalid");
    }
    let observed_at = json_string(observation, "observedAt")?;
    if !canonical_rfc3339(observed_at) {
        return Err("Application source observation time is not canonical ISO");
    }
    if let Some(url) = observation.get("jobUrl") {
        let raw = url.as_str().ok_or("Application source URL must be text")?;
        let parsed = url::Url::parse(raw).map_err(|_| "Application source URL is invalid")?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || js_units(raw) > 4096
        {
            return Err("Application source URL must use HTTPS without credentials");
        }
    }
    let available_fields = [
        "company",
        "title",
        "text",
        "extractorVersion",
        "contentDigest",
    ];
    if status == "available" {
        if observation.contains_key("reason") {
            return Err("Available application source cannot contain a reason");
        }
        let company = json_string(observation, "company")?;
        let title = json_string(observation, "title")?;
        let text = json_string(observation, "text")?;
        let extractor = json_string(observation, "extractorVersion")?;
        let digest = json_string(observation, "contentDigest")?;
        if company.trim().is_empty()
            || js_units(company) > 512
            || title.trim().is_empty()
            || js_units(title) > 2048
            || text.trim().is_empty()
            || js_units(text) > 48_000
            || extractor.trim().is_empty()
            || js_units(extractor) > 128
        {
            return Err("Available application source content is outside bounds");
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(digest)
            .map_err(|_| "Application source digest is malformed")?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes())) != digest
        {
            return Err("Application source digest does not match its text");
        }
    } else if available_fields
        .iter()
        .any(|field| observation.contains_key(*field))
    {
        return Err("Non-available application source cannot contain extracted content");
    }
    if let Some(reason) = observation.get("reason") {
        let reason = reason
            .as_str()
            .ok_or("Application source reason must be text")?;
        if js_units(reason) > 2048 {
            return Err("Application source reason exceeds size limit");
        }
    }
    match phase {
        "refresh" => {
            let original_id = json_string(observation, "originalRecordId")?;
            if original_id == record_id || !valid_source_record_id(original_id) {
                return Err("Application refresh source reference is invalid");
            }
            let key = format!("application-source:{original_id}");
            let Some(original) = entities.get(&key).and_then(map_value) else {
                return Err("Application refresh source record is missing");
            };
            let source_data = scalar_string(original.get("data"))
                .ok_or("Application refresh source record is malformed")?;
            let source: serde_json::Value = serde_json::from_str(&source_data)
                .map_err(|_| "Application refresh source record is malformed")?;
            if source
                .get("applicationId")
                .and_then(serde_json::Value::as_str)
                != Some(application_id)
                || source
                    .get("workspaceId")
                    .and_then(serde_json::Value::as_str)
                    != Some(workspace_id)
                || source.get("cardId").and_then(serde_json::Value::as_str) != Some(card_id)
                || source.get("recordId").and_then(serde_json::Value::as_str) != Some(original_id)
                || source
                    .pointer("/observation/phase")
                    .and_then(serde_json::Value::as_str)
                    != Some("original")
            {
                return Err(
                    "Application refresh reference must name an original from the same application",
                );
            }
            // Check the target phase before full validation: validating another refresh
            // recursively follows its reference and would permit a cyclic chain to exhaust
            // the stack on hostile input.
            validate_application_source_entity(
                &key,
                &HydratedValue::Map(original.clone()),
                entities,
                workspace_id,
            )?;
        }
        "original" | "legacy" if observation.contains_key("originalRecordId") => {
            return Err("Only refresh observations can reference an original record");
        }
        _ => {}
    }
    if phase == "legacy" {
        if origin != "legacy" || status != "missing-evidence" {
            return Err("Legacy application source must be marked missing-evidence");
        }
    } else if origin == "legacy" || status == "missing-evidence" {
        return Err("Non-legacy application source cannot use legacy markers");
    }
    Ok(())
}

fn valid_source_record_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn js_units(value: &str) -> usize {
    value.encode_utf16().count()
}

fn valid_js_identifier(value: &str) -> bool {
    !value.is_empty() && js_units(value) <= 256
}

fn exact_keys(map: &serde_json::Map<String, serde_json::Value>, expected: &[&str]) -> bool {
    map.len() == expected.len() && expected.iter().all(|key| map.contains_key(*key))
}

fn json_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, &'static str> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or("Application source observation field is missing or malformed")
}

fn canonical_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return false;
    }
    let Ok(parsed) =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
    else {
        return false;
    };
    parsed.offset() == time::UtcOffset::UTC && parsed.nanosecond() % 1_000_000 == 0
}

fn visitor_profile_change_only(
    raw: &mut AutoCommit,
    node: &ChangeNode,
    person_id: &str,
) -> Result<(), &'static str> {
    let (before_value, after_value) = change_root_views(raw, node)?;
    let (HydratedValue::Map(mut before_root), HydratedValue::Map(mut after_root)) =
        (before_value, after_value)
    else {
        return Err("root is not a map");
    };
    let (
        Some(HydratedValue::Map(mut before_entities)),
        Some(HydratedValue::Map(mut after_entities)),
    ) = (
        before_root.remove("entities").map(|value| value.value),
        after_root.remove("entities").map(|value| value.value),
    )
    else {
        return Err("entity map is missing");
    };
    if before_root != after_root {
        return Err("workspace root changed");
    }
    let profile_id = format!("member-profile:{person_id}");
    let before_profile = before_entities.remove(&profile_id).map(|value| value.value);
    let after_profile = after_entities.remove(&profile_id).map(|value| value.value);
    if before_entities != after_entities {
        return Err("another entity changed");
    }
    if let Some(reason) =
        profile_delta_rejection(before_profile.as_ref(), after_profile.as_ref(), person_id)
    {
        return Err(reason);
    }
    Ok(())
}

fn automation_change_allowed(
    raw: &mut AutoCommit,
    node: &ChangeNode,
    scope: &AutomationGrantScope,
) -> Result<AutomationEffect, &'static str> {
    let (before_value, after_value) =
        change_root_views(raw, node).map_err(|_| "Automation change views are unavailable")?;
    let (HydratedValue::Map(mut left_root), HydratedValue::Map(mut right_root)) =
        (before_value, after_value)
    else {
        return Err("Automation workspace root is invalid");
    };
    let (Some(HydratedValue::Map(left_entities)), Some(HydratedValue::Map(right_entities))) = (
        left_root.remove("entities").map(|value| value.value),
        right_root.remove("entities").map(|value| value.value),
    ) else {
        return Err("Automation entity map is missing");
    };
    if left_root != right_root {
        return Err("Automation cannot change workspace settings or schema");
    }
    let board = right_entities
        .get(&scope.board_id)
        .ok_or("Automation board is missing")?;
    let board_map = map_value(board).ok_or("Automation board is invalid")?;
    if scalar_string(board_map.get("kind")).as_deref() != Some("board")
        || is_archived(board_map.get("archivedAt"))
    {
        return Err("Automation board is invalid");
    }
    let archive_id = scalar_string(board_map.get("archiveColumnId"));
    let mut approved_columns = vec![
        scope.columns.lead.as_str(),
        scope.columns.interview.as_str(),
        scope.columns.rejected.as_str(),
    ];
    if let Some(applied) = &scope.columns.applied {
        approved_columns.push(applied.as_str());
    }
    let mut board_columns = std::collections::HashSet::new();
    for (id, entity) in right_entities.iter() {
        let Some(map) = map_value(&entity.value) else {
            continue;
        };
        if scalar_string(map.get("kind")).as_deref() != Some("column") {
            continue;
        }
        let Some(placement) = map.get("placement").and_then(map_value) else {
            continue;
        };
        if scalar_string(placement.get("parentId")).as_deref() == Some(scope.board_id.as_str())
            && archive_id.as_deref() != Some(id.as_str())
            && !is_archived(map.get("archivedAt"))
        {
            board_columns.insert(id.clone());
        }
    }
    for id in approved_columns {
        let Some(column) = right_entities.get(id) else {
            return Err("Automation column binding is missing");
        };
        let Some(map) = map_value(column) else {
            return Err("Automation column binding is invalid");
        };
        let Some(placement) = map.get("placement").and_then(map_value) else {
            return Err("Automation column placement is invalid");
        };
        if !board_columns.contains(id)
            || archive_id.as_deref() == Some(id)
            || is_archived(map.get("archivedAt"))
            || scalar_string(map.get("kind")).as_deref() != Some("column")
            || scalar_string(placement.get("parentId")).as_deref() != Some(scope.board_id.as_str())
        {
            return Err("Automation column is outside the approved board");
        }
    }
    for field_id in &scope.field_ids {
        let Some(field) = right_entities.get(field_id) else {
            return Err("Automation field binding is missing");
        };
        let Some(field_map) = map_value(field) else {
            return Err("Automation field binding is invalid");
        };
        let Some(placement) = field_map.get("placement").and_then(map_value) else {
            return Err("Automation field placement is invalid");
        };
        if scalar_string(field_map.get("kind")).as_deref() != Some("field")
            || scalar_string(placement.get("parentId")).as_deref() != Some(scope.board_id.as_str())
        {
            return Err("Automation field is outside the approved board");
        }
    }
    let ids = left_entities
        .keys()
        .chain(right_entities.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut changed_items = Vec::new();
    let mut rank_siblings = Vec::new();
    let mut source_append = None;
    for id in ids {
        let left = left_entities.get(&id);
        let right = right_entities.get(&id);
        if left == right {
            continue;
        }
        if id.starts_with("application-source:") {
            if scope.version != 2 || left.is_some() || source_append.is_some() {
                return Err("Automation source append requires v2 and one new immutable record");
            }
            source_append = Some(right.ok_or("Automation cannot delete application sources")?);
            continue;
        }
        if let (Some(left), Some(right)) = (left, right) {
            if rank_only_item(left, right) {
                rank_siblings.push((left, right));
                continue;
            }
        }
        changed_items.push((id, left, right));
    }
    // A source-only refresh still has exactly one bound card. This does not
    // permit an original to be retroactively invented for an existing card.
    if changed_items.is_empty() {
        if let Some(source) = source_append {
            let card_id = map_value(source)
                .and_then(placement_parent)
                .ok_or("Automation source card is missing")?;
            changed_items.push((
                card_id.clone(),
                left_entities.get(&card_id),
                right_entities.get(&card_id),
            ));
        }
    }
    if changed_items.len() != 1 {
        return Err("Automation change must affect one job card");
    }
    let (item_id, before_item, after_item) = changed_items.pop().unwrap();
    let after_item = after_item.ok_or("Automation cannot delete job cards")?;
    let after_map = map_value(after_item).ok_or("Automation item is invalid")?;
    if !is_item_map(after_map) || entity_has_child(&right_entities, &item_id) {
        return Err("Automation can change only leaf job cards");
    }
    if scalar_string(after_map.get("id")).as_deref() != Some(item_id.as_str()) {
        return Err("Automation item ID does not match its entity key");
    }
    if let Some(source) = source_append {
        check_automation_source_append(source, &item_id, before_item.is_some(), &left_entities)?;
    }
    let after_parent = placement_parent(after_map).ok_or("Automation item placement is invalid")?;
    let source_parent;
    if let Some(before_item) = before_item {
        let before_map = map_value(before_item).ok_or("Automation item base is invalid")?;
        let old_parent =
            placement_parent(before_map).ok_or("Automation item base placement is invalid")?;
        if !is_item_map(before_map)
            || entity_has_child(&left_entities, &item_id)
            || is_archived(before_map.get("archivedAt"))
            || is_archived(after_map.get("archivedAt"))
            || archive_id.as_deref() == Some(old_parent.as_str())
            || !board_columns.contains(&old_parent)
        {
            return Err("Automation can change only active leaf cards on the approved board");
        }
        if old_parent != after_parent
            && after_parent != scope.columns.interview
            && after_parent != scope.columns.rejected
            && scope.columns.applied.as_deref() != Some(after_parent.as_str())
        {
            return Err("Automation can move cards only to approved application columns");
        }
        check_item_delta(before_map, after_map, &scope.field_ids)?;
        if old_parent == after_parent
            && before_map.get("values") == after_map.get("values")
            && source_append.is_none()
        {
            return Err("Automation change has no approved card effect");
        }
        if before_map.get("workflow") != after_map.get("workflow") {
            if old_parent == after_parent {
                return Err("Automation cannot change workflow without moving the card");
            }
            if let Some(workflow) = after_map.get("workflow") {
                let (column_id, changed_at) =
                    automation_workflow_fields(workflow).ok_or("Automation workflow is invalid")?;
                if column_id != after_parent || changed_at.is_empty() {
                    return Err("Automation workflow does not match card placement");
                }
            }
        }
        source_parent = old_parent;
    } else {
        if after_parent != scope.columns.lead
            && scope.columns.applied.as_deref() != Some(after_parent.as_str())
        {
            return Err(
                "Automation can create cards only in Lead or an explicitly approved Applied column",
            );
        }
        if is_archived(after_map.get("archivedAt")) {
            return Err("Automation can create only active cards");
        }
        let permitted_keys = [
            "id",
            "title",
            "body",
            "values",
            "placement",
            "archivedAt",
            "createdAt",
            "updatedAt",
            "lastActivityAt",
            "workflow",
            "lifecycle",
        ];
        if after_map
            .keys()
            .any(|key| !permitted_keys.contains(&key.as_str()))
        {
            return Err("Automation item contains unexpected properties");
        }
        let values = map_value(
            after_map
                .get("values")
                .ok_or("Automation item values are missing")?,
        )
        .ok_or("Automation item values are invalid")?;
        if values.keys().any(|field| !scope.field_ids.contains(field)) {
            return Err("Automation item uses an unapproved field");
        }
        if let Some(workflow) = after_map.get("workflow") {
            let (column_id, changed_at) =
                automation_workflow_fields(workflow).ok_or("Automation workflow is invalid")?;
            if column_id != after_parent || changed_at.is_empty() {
                return Err("Automation workflow does not match card placement");
            }
        }
        source_parent = scope.columns.lead.clone();
    }
    for (left, _) in rank_siblings {
        let sibling_parent = map_value(left)
            .and_then(placement_parent)
            .ok_or("Automation sibling placement is invalid")?;
        if (sibling_parent != source_parent && sibling_parent != after_parent)
            || !board_columns.contains(&sibling_parent)
        {
            return Err("Automation rank changes exceed the affected board columns");
        }
    }
    Ok(AutomationEffect {
        item_id,
        moved: before_item.is_some() && source_parent != after_parent,
    })
}

fn check_automation_source_append(
    source: &HydratedValue,
    card_id: &str,
    existing_card: bool,
    before_entities: &automerge::hydrate::Map,
) -> Result<(), &'static str> {
    let source = map_value(source).ok_or("Automation source is invalid")?;
    if placement_parent(source).as_deref() != Some(card_id) {
        return Err("Automation source must belong to its one affected card");
    }
    let encoded = scalar_string(source.get("data")).ok_or("Automation source data is missing")?;
    let data: serde_json::Value =
        serde_json::from_str(&encoded).map_err(|_| "Automation source data is invalid")?;
    let observation = data
        .get("observation")
        .ok_or("Automation source observation is missing")?;
    let phase = observation.get("phase").and_then(serde_json::Value::as_str);
    if !existing_card && phase == Some("original") {
        return Ok(());
    }
    if existing_card && phase == Some("refresh") {
        let original = observation
            .get("originalRecordId")
            .and_then(serde_json::Value::as_str)
            .ok_or("Automation refresh reference is missing")?;
        if before_entities.contains_key(&format!("application-source:{original}")) {
            return Ok(());
        }
    }
    Err("Automation requires an original with a new card or a refresh of a prior original")
}

fn is_archived(value: Option<&HydratedValue>) -> bool {
    scalar_string(value).is_some()
}

fn map_value(value: &HydratedValue) -> Option<&automerge::hydrate::Map> {
    if let HydratedValue::Map(map) = value {
        Some(map)
    } else {
        None
    }
}

/// Item workflow transitions use JSON.stringify in the TypeScript domain layer.
/// Accept that canonical scalar form and historical Automerge maps while keeping
/// the two-field workflow record closed to additional authority-bearing data.
fn automation_workflow_fields(value: &HydratedValue) -> Option<(String, String)> {
    let fields = if let Some(map) = map_value(value) {
        if map.len() != 2 {
            return None;
        }
        (
            scalar_string(map.get("columnId"))?,
            scalar_string(map.get("changedAt"))?,
        )
    } else {
        let encoded = scalar_string(Some(value))?;
        let parsed: serde_json::Value = serde_json::from_str(&encoded).ok()?;
        let object = parsed.as_object()?;
        if object.len() != 2 {
            return None;
        }
        (
            object.get("columnId")?.as_str()?.to_string(),
            object.get("changedAt")?.as_str()?.to_string(),
        )
    };
    if fields.0.is_empty() || fields.1.is_empty() {
        return None;
    }
    Some(fields)
}

fn is_item_map(map: &automerge::hydrate::Map) -> bool {
    matches!(
        map.get("body"),
        Some(HydratedValue::Text(_) | HydratedValue::Scalar(ScalarValue::Str(_)))
    ) && matches!(map.get("values"), Some(HydratedValue::Map(_)))
}

fn placement_parent(map: &automerge::hydrate::Map) -> Option<String> {
    scalar_string(map.get("placement").and_then(map_value)?.get("parentId"))
}

fn entity_has_child(entities: &automerge::hydrate::Map, id: &str) -> bool {
    entities.values().any(|entity| {
        map_value(&entity.value).is_some_and(|map| {
            scalar_string(map.get("kind")).as_deref() != Some("application_source")
                && placement_parent(map).as_deref() == Some(id)
        })
    })
}

fn rank_only_item(before: &HydratedValue, after: &HydratedValue) -> bool {
    let (Some(before), Some(after)) = (map_value(before), map_value(after)) else {
        return false;
    };
    if !is_item_map(before)
        || !is_item_map(after)
        || placement_parent(before) != placement_parent(after)
    {
        return false;
    }
    let mut left = before.clone();
    let mut right = after.clone();
    let (
        Some(HydratedValue::Map(mut left_placement)),
        Some(HydratedValue::Map(mut right_placement)),
    ) = (
        left.remove("placement").map(|value| value.value),
        right.remove("placement").map(|value| value.value),
    )
    else {
        return false;
    };
    let left_rank = left_placement.remove("rank");
    let right_rank = right_placement.remove("rank");
    left == right && left_placement == right_placement && left_rank != right_rank
}

fn check_item_delta(
    before: &automerge::hydrate::Map,
    after: &automerge::hydrate::Map,
    allowed_fields: &[String],
) -> Result<(), &'static str> {
    let mut left = before.clone();
    let mut right = after.clone();
    for key in ["updatedAt", "lastActivityAt", "workflow"] {
        left.remove(key);
        right.remove(key);
    }
    let left_values = left.remove("values");
    let right_values = right.remove("values");
    let left_placement = left.remove("placement");
    let right_placement = right.remove("placement");
    if left != right {
        return Err("Automation changed job card content outside approved fields");
    }
    if let (Some(HydratedValue::Map(mut left_values)), Some(HydratedValue::Map(mut right_values))) = (
        left_values.as_ref().map(|value| &value.value).cloned(),
        right_values.as_ref().map(|value| &value.value).cloned(),
    ) {
        let keys = left_values
            .keys()
            .chain(right_values.keys())
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        for key in keys {
            if left_values.get(&key) != right_values.get(&key) && !allowed_fields.contains(&key) {
                return Err("Automation changed an unapproved item field");
            }
            left_values.remove(&key);
            right_values.remove(&key);
        }
        if left_values != right_values {
            return Err("Automation changed an unapproved item field");
        }
    } else if left_values.as_ref().map(|value| &value.value)
        != right_values.as_ref().map(|value| &value.value)
    {
        return Err("Automation item values are invalid");
    }
    if let (Some(HydratedValue::Map(mut left)), Some(HydratedValue::Map(mut right))) = (
        left_placement.as_ref().map(|value| &value.value).cloned(),
        right_placement.as_ref().map(|value| &value.value).cloned(),
    ) {
        left.remove("rank");
        right.remove("rank");
        left.remove("parentId");
        right.remove("parentId");
        if left != right {
            return Err("Automation changed item placement metadata");
        }
    } else if left_placement.as_ref().map(|value| &value.value)
        != right_placement.as_ref().map(|value| &value.value)
    {
        return Err("Automation item placement is invalid");
    }
    Ok(())
}

fn profile_delta_rejection(
    before: Option<&HydratedValue>,
    after: Option<&HydratedValue>,
    person_id: &str,
) -> Option<&'static str> {
    match (before, after) {
        (None, Some(value)) | (Some(value), None) => {
            avatar_profile_invalid_reason(value, person_id)
        }
        (Some(before), Some(after)) => {
            if let Some(reason) = avatar_profile_invalid_reason(before, person_id) {
                return Some(reason);
            }
            if let Some(reason) = avatar_profile_invalid_reason(after, person_id) {
                return Some(reason);
            }
            let (HydratedValue::Map(mut left), HydratedValue::Map(mut right)) =
                (before.clone(), after.clone())
            else {
                return Some("profile record is not a map");
            };
            let previous_data = left.remove("data").map(|value| value.value);
            let next_data = right.remove("data").map(|value| value.value);
            left.remove("updatedAt");
            right.remove("updatedAt");
            (previous_data == next_data || left != right)
                .then_some("profile update changed fields beyond avatar data")
        }
        (None, None) => Some("profile record was not changed"),
    }
}

fn avatar_profile_invalid_reason(value: &HydratedValue, person_id: &str) -> Option<&'static str> {
    let HydratedValue::Map(profile) = value else {
        return Some("profile record is not a map");
    };
    let expected_keys = [
        "id",
        "kind",
        "personId",
        "data",
        "title",
        "placement",
        "archivedAt",
        "createdAt",
        "updatedAt",
    ];
    if profile.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !profile.contains_key(*key))
    {
        return Some("profile fields are missing or unexpected");
    }
    let expected_id = format!("member-profile:{person_id}");
    if scalar_string(profile.get("id")).as_deref() != Some(expected_id.as_str()) {
        return Some("profile id differs from signed actor");
    }
    if scalar_string(profile.get("kind")).as_deref() != Some("member_profile") {
        return Some("profile kind is invalid");
    }
    if scalar_string(profile.get("personId")).as_deref() != Some(person_id) {
        return Some("profile person differs from signed actor");
    }
    if scalar_string(profile.get("title")).as_deref() != Some("Member profile") {
        return Some("profile title is invalid");
    }
    if !matches!(
        profile.get("archivedAt"),
        Some(HydratedValue::Scalar(ScalarValue::Null))
    ) {
        return Some("profile archive marker is invalid");
    }
    if !is_rfc3339(profile.get("createdAt")) {
        return Some("profile creation time is invalid");
    }
    if !is_rfc3339(profile.get("updatedAt")) {
        return Some("profile update time is invalid");
    }
    let Some(HydratedValue::Map(placement)) = profile.get("placement") else {
        return Some("profile placement is invalid");
    };
    if placement.len() != 2
        || !matches!(
            placement.get("parentId"),
            Some(HydratedValue::Scalar(ScalarValue::Null))
        )
        || scalar_string(placement.get("rank")).as_deref() != Some("0/1")
    {
        return Some("profile placement is invalid");
    }
    let Some(data) = scalar_string(profile.get("data")) else {
        return Some("avatar data is missing");
    };
    if !valid_avatar_data(&data) {
        return Some("avatar data is malformed or outside bounds");
    }
    None
}

fn scalar_string(value: Option<&HydratedValue>) -> Option<String> {
    match value? {
        HydratedValue::Scalar(ScalarValue::Str(value)) => Some(value.to_string()),
        HydratedValue::Text(value) => Some(value.to_string()),
        _ => None,
    }
}

fn is_rfc3339(value: Option<&HydratedValue>) -> bool {
    scalar_string(value).is_some_and(|value| {
        time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339).is_ok()
    })
}

fn valid_avatar_data(value: &str) -> bool {
    let Ok(record) = serde_json::from_str::<serde_json::Value>(value) else {
        return false;
    };
    let Some(object) = record.as_object() else {
        return false;
    };
    if object.len() != 2 {
        return false;
    }
    let Some(changed_at) = object.get("changedAt").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if time::OffsetDateTime::parse(changed_at, &time::format_description::well_known::Rfc3339)
        .is_err()
    {
        return false;
    }
    if object
        .get("avatarData")
        .is_some_and(serde_json::Value::is_null)
    {
        return true;
    }
    let Some(avatar) = object.get("avatarData").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let (encoded, webp) = if let Some(encoded) = avatar.strip_prefix("data:image/webp;base64,") {
        (encoded, true)
    } else if let Some(encoded) = avatar.strip_prefix("data:image/jpeg;base64,") {
        (encoded, false)
    } else {
        return false;
    };
    if encoded.len() > 22_000 || encoded.len() % 4 != 0 {
        return false;
    }
    BASE64.decode(encoded).is_ok_and(|bytes| {
        !bytes.is_empty() && bytes.len() <= 16 * 1024 && avatar_dimensions(&bytes, webp)
    })
}

fn avatar_dimensions(bytes: &[u8], webp: bool) -> bool {
    if webp {
        if bytes.len() < 30 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
            return false;
        }
        if &bytes[12..16] == b"VP8X" {
            return bytes[24..30] == [127, 0, 0, 127, 0, 0];
        }
        if &bytes[12..16] == b"VP8 " {
            let width = u16::from_le_bytes([bytes[26], bytes[27]]) & 0x3fff;
            let height = u16::from_le_bytes([bytes[28], bytes[29]]) & 0x3fff;
            return bytes[23..26] == [0x9d, 0x01, 0x2a] && width == 128 && height == 128;
        }
        if &bytes[12..16] == b"VP8L" && bytes.len() >= 25 && bytes[20] == 0x2f {
            let width = 1 + bytes[21] as u32 + (((bytes[22] & 0x3f) as u32) << 8);
            let height = 1
                + (((bytes[22] & 0xc0) as u32) >> 6)
                + ((bytes[23] as u32) << 2)
                + (((bytes[24] & 0x0f) as u32) << 10);
            return width == 128 && height == 128;
        }
        false
    } else {
        jpeg_dimensions(bytes)
    }
}

fn jpeg_dimensions(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes[0..2] != [0xff, 0xd8] {
        return false;
    }
    let mut offset = 2;
    while offset + 3 < bytes.len() {
        if bytes[offset] != 0xff {
            return false;
        }
        let marker = bytes[offset + 1];
        offset += 2;
        if marker == 0xd8 || marker == 0xd9 || (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            continue;
        }
        let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        if length < 2 || offset + length > bytes.len() {
            return false;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            if length < 7 {
                return false;
            }
            let height = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]);
            let width = u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]);
            return width == 128 && height == 128;
        }
        offset += length;
    }
    false
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

fn automation_provenance_matches(
    record: &IncomingWorkspaceChangeAuthorization,
    node: &ChangeNode,
) -> bool {
    let Some(grant) = record.grant.as_ref() else {
        return false;
    };
    let Some(metadata) = node.authority.as_ref() else {
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
