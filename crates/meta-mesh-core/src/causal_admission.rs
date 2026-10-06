use std::collections::{HashMap, HashSet};

use automerge::{AutoCommit, Change, ReadDoc, ScalarValue, hydrate::Value as HydratedValue, ROOT};
use base64::{Engine, engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD}};
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
        let admitted = crate::authorization::admit_with_needed_for_causal(record, &context, &needed, true)?;
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
            if proof.role == WorkspaceRole::Visitor {
                if let Err(reason) = visitor_profile_change_only(&mut raw, node, &record.signed.payload.person_id) {
                provenance_errors.insert(
                    proof.hash,
                    format!("Visitors may change only their own avatar profile ({reason})"),
                );
                continue;
                }
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

fn visitor_profile_change_only(raw: &mut AutoCommit, node: &ChangeNode, person_id: &str) -> Result<(), &'static str> {
    let Ok(mut before) = raw.fork_at(node.change.deps()) else { return Err("dependency view unavailable") };
    let before_value = match before.hydrate(&ROOT, None) {
        Ok(value) => value,
        Err(_) => return Err("dependency root unavailable"),
    };
    let mut after = before.fork();
    if after.apply_changes(vec![node.change.clone()]).is_err() { return Err("change could not be replayed") }
    let after_value = match after.hydrate(&ROOT, None) {
        Ok(value) => value,
        Err(_) => return Err("result root unavailable"),
    };
    let (HydratedValue::Map(mut before_root), HydratedValue::Map(mut after_root)) = (before_value, after_value) else { return Err("root is not a map") };
    let (Some(HydratedValue::Map(mut before_entities)), Some(HydratedValue::Map(mut after_entities))) =
        (before_root.remove("entities").map(|value| value.value), after_root.remove("entities").map(|value| value.value)) else { return Err("entity map is missing") };
    if before_root != after_root { return Err("workspace root changed") }
    let profile_id = format!("member-profile:{person_id}");
    let before_profile = before_entities.remove(&profile_id).map(|value| value.value);
    let after_profile = after_entities.remove(&profile_id).map(|value| value.value);
    if before_entities != after_entities { return Err("another entity changed") }
    if let Some(reason) = profile_delta_rejection(before_profile.as_ref(), after_profile.as_ref(), person_id) { return Err(reason) }
    Ok(())
}

fn profile_delta_rejection(before: Option<&HydratedValue>, after: Option<&HydratedValue>, person_id: &str) -> Option<&'static str> {
    match (before, after) {
        (None, Some(value)) | (Some(value), None) => avatar_profile_invalid_reason(value, person_id),
        (Some(before), Some(after)) => {
            if let Some(reason) = avatar_profile_invalid_reason(before, person_id) { return Some(reason) }
            if let Some(reason) = avatar_profile_invalid_reason(after, person_id) { return Some(reason) }
            let (HydratedValue::Map(mut left), HydratedValue::Map(mut right)) = (before.clone(), after.clone()) else { return Some("profile record is not a map") };
            let previous_data = left.remove("data").map(|value| value.value);
            let next_data = right.remove("data").map(|value| value.value);
            left.remove("updatedAt");
            right.remove("updatedAt");
            (previous_data == next_data || left != right).then_some("profile update changed fields beyond avatar data")
        }
        (None, None) => Some("profile record was not changed"),
    }
}

fn avatar_profile_invalid_reason(value: &HydratedValue, person_id: &str) -> Option<&'static str> {
    let HydratedValue::Map(profile) = value else { return Some("profile record is not a map") };
    let expected_keys = ["id", "kind", "personId", "data", "title", "placement", "archivedAt", "createdAt", "updatedAt"];
    if profile.len() != expected_keys.len() || expected_keys.iter().any(|key| !profile.contains_key(*key)) { return Some("profile fields are missing or unexpected") }
    let expected_id = format!("member-profile:{person_id}");
    if scalar_string(profile.get("id")).as_deref() != Some(expected_id.as_str()) { return Some("profile id differs from signed actor") }
    if scalar_string(profile.get("kind")).as_deref() != Some("member_profile") { return Some("profile kind is invalid") }
    if scalar_string(profile.get("personId")).as_deref() != Some(person_id) { return Some("profile person differs from signed actor") }
    if scalar_string(profile.get("title")).as_deref() != Some("Member profile") { return Some("profile title is invalid") }
    if !matches!(profile.get("archivedAt"), Some(HydratedValue::Scalar(ScalarValue::Null))) { return Some("profile archive marker is invalid") }
    if !is_rfc3339(profile.get("createdAt")) { return Some("profile creation time is invalid") }
    if !is_rfc3339(profile.get("updatedAt")) { return Some("profile update time is invalid") }
    let Some(HydratedValue::Map(placement)) = profile.get("placement") else { return Some("profile placement is invalid") };
    if placement.len() != 2
        || !matches!(placement.get("parentId"), Some(HydratedValue::Scalar(ScalarValue::Null)))
        || scalar_string(placement.get("rank")).as_deref() != Some("0/1")
    { return Some("profile placement is invalid") }
    let Some(data) = scalar_string(profile.get("data")) else { return Some("avatar data is missing") };
    if !valid_avatar_data(&data) { return Some("avatar data is malformed or outside bounds") }
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
    scalar_string(value).is_some_and(|value| time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339).is_ok())
}

fn valid_avatar_data(value: &str) -> bool {
    let Ok(record) = serde_json::from_str::<serde_json::Value>(value) else { return false };
    let Some(object) = record.as_object() else { return false };
    if object.len() != 2 { return false }
    let Some(avatar) = object.get("avatarData").and_then(serde_json::Value::as_str) else { return false };
    let Some(changed_at) = object.get("changedAt").and_then(serde_json::Value::as_str) else { return false };
    if time::OffsetDateTime::parse(changed_at, &time::format_description::well_known::Rfc3339).is_err() { return false }
    let (encoded, webp) = if let Some(encoded) = avatar.strip_prefix("data:image/webp;base64,") {
        (encoded, true)
    } else if let Some(encoded) = avatar.strip_prefix("data:image/jpeg;base64,") {
        (encoded, false)
    } else { return false };
    if encoded.len() > 22_000 || encoded.len() % 4 != 0 { return false }
    BASE64.decode(encoded).is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= 16 * 1024 && avatar_dimensions(&bytes, webp))
}

fn avatar_dimensions(bytes: &[u8], webp: bool) -> bool {
    if webp {
        if bytes.len() < 30 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" { return false }
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
            let height = 1 + (((bytes[22] & 0xc0) as u32) >> 6) + ((bytes[23] as u32) << 2) + (((bytes[24] & 0x0f) as u32) << 10);
            return width == 128 && height == 128;
        }
        false
    } else {
        jpeg_dimensions(bytes)
    }
}

fn jpeg_dimensions(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes[0..2] != [0xff, 0xd8] { return false }
    let mut offset = 2;
    while offset + 3 < bytes.len() {
        if bytes[offset] != 0xff { return false }
        let marker = bytes[offset + 1];
        offset += 2;
        if marker == 0xd8 || marker == 0xd9 || (0xd0..=0xd7).contains(&marker) || marker == 0x01 { continue }
        let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        if length < 2 || offset + length > bytes.len() { return false }
        if matches!(marker, 0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc5 | 0xc6 | 0xc7 | 0xc9 | 0xca | 0xcb | 0xcd | 0xce | 0xcf) {
            if length < 7 { return false }
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

#[cfg(test)]
mod tests;
