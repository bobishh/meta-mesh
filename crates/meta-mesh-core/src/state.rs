use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{WorkspaceRole, canonicalize_json};

pub const MAX_STATE_STRING: usize = 256;
pub const MAX_ENDPOINT_LENGTH: usize = 2_048;
pub const MAX_SECRET_LENGTH: usize = 4_096;
pub const MAX_AUTH_BUNDLE_LENGTH: usize = 131_072;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerTransportInstance {
    pub instance_id: String,
    pub endpoint: String,
    pub last_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertisement: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePeerRecord {
    pub workspace_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    pub person_id: String,
    pub endpoint: String,
    pub transport_secret: Value,
    pub role: WorkspaceRole,
    pub last_seen: String,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_at: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertisement: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instances: Option<Vec<PeerTransportInstance>>,
}

pub fn validate_peer_record(peer: &WorkspacePeerRecord) -> Result<(), String> {
    required_bounded(&peer.workspace_id, MAX_STATE_STRING, "workspaceId")?;
    required_bounded(&peer.device_id, MAX_STATE_STRING, "deviceId")?;
    required_bounded(&peer.person_id, MAX_STATE_STRING, "personId")?;
    required_bounded(&peer.endpoint, MAX_ENDPOINT_LENGTH, "endpoint")?;
    if let Some(instance_id) = &peer.instance_id {
        required_bounded(instance_id, MAX_STATE_STRING, "instanceId")?;
    }
    validate_secret(&peer.transport_secret)?;
    timestamp_ms(&peer.last_seen)?;
    if let Some(Some(revoked_at)) = &peer.revoked_at {
        timestamp_ms(revoked_at)?;
    }
    if let Some(advertisement) = &peer.advertisement {
        let bytes = serde_json::to_vec(advertisement).map_err(|_| "Invalid peer advertisement")?;
        if bytes.len() > MAX_AUTH_BUNDLE_LENGTH {
            return Err("Invalid peer record: advertisement is too large".to_string());
        }
    }
    if let Some(instances) = &peer.instances {
        if instances.len() > 32 {
            return Err("Invalid peer record transport instances".to_string());
        }
        for instance in instances {
            required_bounded(&instance.instance_id, MAX_STATE_STRING, "instanceId")?;
            required_bounded(&instance.endpoint, MAX_ENDPOINT_LENGTH, "endpoint")?;
            timestamp_ms(&instance.last_seen)?;
        }
    }
    Ok(())
}

pub fn merge_peer_records(
    existing: &WorkspacePeerRecord,
    incoming: &WorkspacePeerRecord,
) -> Result<WorkspacePeerRecord, String> {
    validate_peer_record(existing)?;
    validate_peer_record(incoming)?;
    if existing.workspace_id != incoming.workspace_id {
        return Err("Cannot merge peer records from different workspaces".to_string());
    }
    if existing.device_id != incoming.device_id {
        return Err("Cannot merge peer records with different deviceIds".to_string());
    }

    let existing_time = timestamp_ms(&existing.last_seen)?;
    let incoming_time = timestamp_ms(&incoming.last_seen)?;
    let incoming_newer = incoming_time > existing_time;
    let incoming_tie = canonical_record(incoming)? > canonical_record(existing)?;
    let incoming_dominates = incoming_newer || (incoming_time == existing_time && incoming_tie);
    let dominant = if incoming_dominates {
        incoming
    } else {
        existing
    };
    let mut role = if incoming_newer {
        incoming.role
    } else if existing_time > incoming_time {
        existing.role
    } else if existing.role == WorkspaceRole::Owner || incoming.role == WorkspaceRole::Owner {
        WorkspaceRole::Owner
    } else if existing.role == WorkspaceRole::Visitor || incoming.role == WorkspaceRole::Visitor {
        WorkspaceRole::Visitor
    } else {
        WorkspaceRole::Editor
    };
    let revoked_at = merge_revocation(existing, incoming, incoming_dominates)?;

    let mut instances = BTreeMap::<String, PeerTransportInstance>::new();
    collect_instances(&mut instances, existing, false, incoming_dominates)?;
    collect_instances(&mut instances, incoming, true, incoming_dominates)?;

    // Routes advance independently of owner-issued permissions. Both records
    // must already have passed member verification before entering this store.
    let mut advertisement = dominant.advertisement.clone();
    if let Some(authorized) = newer_grant_record(existing, incoming) {
        role = authorized.role;
        if let (Some(target), Some(source)) =
            (advertisement.as_mut(), authorized.advertisement.as_ref())
        {
            copy_grant(target, source);
            for instance in instances.values_mut() {
                if let Some(bundle) = instance.advertisement.as_mut() {
                    copy_grant(bundle, source);
                }
            }
        }
    }

    Ok(WorkspacePeerRecord {
        workspace_id: existing.workspace_id.clone(),
        device_id: existing.device_id.clone(),
        instance_id: dominant.instance_id.clone(),
        person_id: if incoming_newer {
            incoming.person_id.clone()
        } else if existing_time > incoming_time {
            existing.person_id.clone()
        } else {
            incoming.person_id.clone().max(existing.person_id.clone())
        },
        endpoint: dominant.endpoint.clone(),
        transport_secret: dominant.transport_secret.clone(),
        role,
        last_seen: if incoming_time >= existing_time {
            incoming.last_seen.clone()
        } else {
            existing.last_seen.clone()
        },
        revoked_at,
        advertisement,
        instances: (!instances.is_empty()).then(|| instances.into_values().take(32).collect()),
    })
}

fn newer_grant_record<'a>(
    left: &'a WorkspacePeerRecord,
    right: &'a WorkspacePeerRecord,
) -> Option<&'a WorkspacePeerRecord> {
    if left.person_id != right.person_id {
        return None;
    }
    let a = left.advertisement.as_ref()?;
    let b = right.advertisement.as_ref()?;
    if a.get("ownerPublicKey")?.as_str()? != b.get("ownerPublicKey")?.as_str()? {
        return None;
    }
    let epoch = |bundle: &Value| -> Option<u64> {
        let payload = bundle.get("grant")?.get("payload")?;
        if payload.get("workspaceId")?.as_str()? != left.workspace_id
            || payload.get("personId")?.as_str()? != left.person_id
        {
            return None;
        }
        Some(
            payload
                .get("accessEpoch")
                .and_then(Value::as_u64)
                .unwrap_or(1),
        )
    };
    match epoch(a)?.cmp(&epoch(b)?) {
        std::cmp::Ordering::Greater => Some(left),
        std::cmp::Ordering::Less => Some(right),
        std::cmp::Ordering::Equal => None,
    }
}

fn copy_grant(target: &mut Value, source: &Value) {
    if let Some(object) = target.as_object_mut() {
        for key in ["grant", "ownerPublicKey", "ownerCertificates"] {
            if let Some(value) = source.get(key) {
                object.insert(key.to_string(), value.clone());
            }
        }
    }
}

fn collect_instances(
    instances: &mut BTreeMap<String, PeerTransportInstance>,
    peer: &WorkspacePeerRecord,
    replace_endpoint_alias: bool,
    incoming_dominates: bool,
) -> Result<(), String> {
    let mut candidates = peer.instances.clone().unwrap_or_default();
    if let Some(instance_id) = &peer.instance_id {
        candidates.push(PeerTransportInstance {
            instance_id: instance_id.clone(),
            endpoint: peer.endpoint.clone(),
            last_seen: peer.last_seen.clone(),
            advertisement: peer.advertisement.clone(),
        });
    }
    for candidate in candidates {
        let selected = match instances.get(&candidate.instance_id) {
            Some(current) if !prefer_instance(current, &candidate)? => continue,
            _ => candidate,
        };
        if replace_endpoint_alias && (route_sequence(&selected).is_some() || incoming_dominates) {
            instances.retain(|id, value| {
                id == &selected.instance_id
                    || value.endpoint != selected.endpoint
                    || route_sequence(value).is_some()
            });
        }
        instances.insert(selected.instance_id.clone(), selected);
    }
    Ok(())
}

fn prefer_instance(
    current: &PeerTransportInstance,
    candidate: &PeerTransportInstance,
) -> Result<bool, String> {
    match (route_sequence(current), route_sequence(candidate)) {
        (None, Some(_)) => Ok(true),
        (Some(_), None) => Ok(false),
        (Some(left), Some(right)) if left != right => Ok(right > left),
        _ => Ok(instance_tie(candidate)? > instance_tie(current)?),
    }
}

fn route_sequence(instance: &PeerTransportInstance) -> Option<i64> {
    let advertisement = instance.advertisement.as_ref()?;
    [
        advertisement.get("sequence"),
        advertisement.pointer("/payload/sequence"),
        advertisement.pointer("/payload/routeSequence"),
        advertisement.pointer("/advertisement/payload/sequence"),
        advertisement.pointer("/advertisement/payload/routeSequence"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_i64)
}

fn instance_tie(instance: &PeerTransportInstance) -> Result<String, String> {
    canonicalize_json(&serde_json::json!({
        "instanceId": instance.instance_id,
        "endpoint": instance.endpoint,
        "advertisement": instance.advertisement,
    }))
}

fn canonical_record(record: &WorkspacePeerRecord) -> Result<String, String> {
    canonicalize_json(&serde_json::to_value(record).map_err(|_| "Invalid peer record")?)
}

fn merge_revocation(
    existing: &WorkspacePeerRecord,
    incoming: &WorkspacePeerRecord,
    incoming_dominates: bool,
) -> Result<Option<Option<String>>, String> {
    if incoming.revoked_at == Some(None) && incoming_dominates {
        return Ok(Some(None));
    }
    match (&existing.revoked_at, &incoming.revoked_at) {
        (Some(Some(left)), Some(Some(right))) => {
            Ok(Some(Some(if timestamp_ms(right)? <= timestamp_ms(left)? {
                right.clone()
            } else {
                left.clone()
            })))
        }
        (Some(Some(value)), _) => Ok(Some(Some(value.clone()))),
        (_, Some(Some(value))) => Ok(Some(Some(value.clone()))),
        _ => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaRecord {
    pub id: String,
    pub updated_at: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaTombstone {
    pub id: String,
    pub deleted_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicaSet {
    pub records: Vec<ReplicaRecord>,
    pub tombstones: Vec<ReplicaTombstone>,
}

pub fn reconcile_replica_sets(left: &ReplicaSet, right: &ReplicaSet) -> Result<ReplicaSet, String> {
    let mut tombstones = BTreeMap::<String, ReplicaTombstone>::new();
    for candidate in left.tombstones.iter().chain(&right.tombstones) {
        required_bounded(&candidate.id, MAX_STATE_STRING, "replica tombstone")?;
        let replace = prefer_timestamped(tombstones.get(&candidate.id), candidate, |value| {
            &value.deleted_at
        })?;
        if replace {
            tombstones.insert(candidate.id.clone(), candidate.clone());
        }
    }
    let mut records = BTreeMap::<String, ReplicaRecord>::new();
    for candidate in left.records.iter().chain(&right.records) {
        required_bounded(&candidate.id, MAX_STATE_STRING, "replica record")?;
        if let Some(deleted) = tombstones.get(&candidate.id) {
            if timestamp_ms(&deleted.deleted_at)? >= timestamp_ms(&candidate.updated_at)? {
                continue;
            }
        }
        let replace = prefer_timestamped(records.get(&candidate.id), candidate, |value| {
            &value.updated_at
        })?;
        if replace {
            records.insert(candidate.id.clone(), candidate.clone());
        }
    }
    Ok(ReplicaSet {
        records: records.into_values().collect(),
        tombstones: tombstones.into_values().collect(),
    })
}

fn prefer_timestamped<T: Serialize>(
    current: Option<&T>,
    candidate: &T,
    date: impl Fn(&T) -> &str,
) -> Result<bool, String> {
    let candidate_time = timestamp_ms(date(candidate))?;
    let Some(current) = current else {
        return Ok(true);
    };
    let current_time = timestamp_ms(date(current))?;
    if candidate_time != current_time {
        return Ok(candidate_time > current_time);
    }
    let candidate = serde_json::to_value(candidate).map_err(|_| "Invalid replica value")?;
    let current = serde_json::to_value(current).map_err(|_| "Invalid replica value")?;
    Ok(canonicalize_json(&candidate)? > canonicalize_json(&current)?)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipBounds {
    pub low: usize,
    pub target: usize,
    pub high: usize,
    pub eager_fanout: usize,
    pub maximum_offer_hashes: usize,
    pub maximum_wants: usize,
    pub maximum_changes: usize,
    pub maximum_frame_bytes: usize,
    pub seen_capacity: usize,
    pub base_backoff_ms: u64,
}

impl Default for GossipBounds {
    fn default() -> Self {
        Self {
            low: 2,
            target: 4,
            high: 6,
            eager_fanout: 3,
            maximum_offer_hashes: 64,
            maximum_wants: 64,
            maximum_changes: 32,
            maximum_frame_bytes: 256 * 1024,
            seen_capacity: 2_048,
            base_backoff_ms: 1_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipCandidate {
    pub device_id: String,
    #[serde(default)]
    pub health: i64,
    #[serde(default)]
    pub backed_off_until: i64,
}

pub fn select_scoped_neighbors(
    local_device_id: &str,
    candidates: &[GossipCandidate],
    bounds: &GossipBounds,
    now: i64,
    rotation: u32,
) -> Result<Vec<String>, String> {
    validate_gossip_bounds(bounds)?;
    let mut by_device = HashMap::<String, GossipCandidate>::new();
    for candidate in candidates {
        if candidate.device_id.is_empty()
            || candidate.device_id == local_device_id
            || candidate.backed_off_until > now
        {
            continue;
        }
        if by_device
            .get(&candidate.device_id)
            .is_none_or(|current| candidate.health > current.health)
        {
            by_device.insert(candidate.device_id.clone(), candidate.clone());
        }
    }
    let mut eligible = by_device.into_values().collect::<Vec<_>>();
    let mut ring = eligible
        .iter()
        .map(|value| value.device_id.clone())
        .collect::<Vec<_>>();
    ring.push(local_device_id.to_string());
    ring.sort();
    let local_index = ring
        .iter()
        .position(|value| value == local_device_id)
        .unwrap_or(0);
    let mut mandatory = Vec::<String>::new();
    if ring.len() > 1 && bounds.target > 0 {
        mandatory.push(ring[(local_index + 1) % ring.len()].clone());
    }
    if ring.len() > 2 && bounds.target > 1 {
        let candidate = ring[(local_index + ring.len() - 1) % ring.len()].clone();
        if !mandatory.contains(&candidate) {
            mandatory.push(candidate);
        }
    }
    eligible.retain(|candidate| !mandatory.contains(&candidate.device_id));
    eligible.sort_by(|left, right| {
        right
            .health
            .cmp(&left.health)
            .then_with(|| {
                stable_score(local_device_id, &left.device_id, rotation).cmp(&stable_score(
                    local_device_id,
                    &right.device_id,
                    rotation,
                ))
            })
            .then_with(|| left.device_id.cmp(&right.device_id))
    });
    mandatory.extend(eligible.into_iter().map(|value| value.device_id));
    mandatory.truncate(bounds.target.min(bounds.high));
    Ok(mandatory)
}

fn validate_gossip_bounds(bounds: &GossipBounds) -> Result<(), String> {
    if bounds.low > bounds.target
        || bounds.target > bounds.high
        || bounds.eager_fanout > bounds.high
        || bounds.maximum_offer_hashes == 0
        || bounds.maximum_wants == 0
        || bounds.maximum_changes == 0
        || bounds.maximum_frame_bytes == 0
        || bounds.seen_capacity == 0
        || bounds.base_backoff_ms == 0
    {
        return Err("Invalid gossip bounds".to_string());
    }
    Ok(())
}

fn stable_score(local_device_id: &str, candidate: &str, rotation: u32) -> u32 {
    let value = format!("{local_device_id}\0{candidate}\0{rotation}");
    value.encode_utf16().fold(0x811c9dc5_u32, |hash, unit| {
        (hash ^ u32::from(unit)).wrapping_mul(0x01000193)
    })
}

fn validate_secret(value: &Value) -> Result<(), String> {
    let valid = match value {
        Value::String(value) => !value.is_empty() && value.len() <= MAX_SECRET_LENGTH,
        Value::Array(values) => {
            !values.is_empty()
                && values.len() <= MAX_SECRET_LENGTH
                && values
                    .iter()
                    .all(|value| value.as_u64().is_some_and(|byte| byte <= 255))
        }
        _ => false,
    };
    valid.then_some(()).ok_or_else(|| {
        "Invalid peer record: transportSecret must be a non-empty string or byte array".to_string()
    })
}

fn required_bounded(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum {
        Err(format!("Invalid {label}"))
    } else {
        Ok(())
    }
}

fn timestamp_ms(value: &str) -> Result<i128, String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|value| value.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "Invalid replica timestamp".to_string())
}

fn deserialize_nullable<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(endpoint: &str, seen: &str) -> WorkspacePeerRecord {
        WorkspacePeerRecord {
            workspace_id: "workspace-1".to_string(),
            device_id: "device-1".to_string(),
            instance_id: Some("instance-1".to_string()),
            person_id: "person-1".to_string(),
            endpoint: endpoint.to_string(),
            transport_secret: Value::String("secret".to_string()),
            role: WorkspaceRole::Editor,
            last_seen: seen.to_string(),
            revoked_at: None,
            advertisement: None,
            instances: None,
        }
    }

    #[test]
    fn peer_merge_is_monotonic_and_deterministic() {
        let old = peer("old", "2026-09-20T10:00:00.000Z");
        let mut new = peer("new", "2026-09-20T10:01:00.000Z");
        new.role = WorkspaceRole::Visitor;
        let merged = merge_peer_records(&old, &new).unwrap();
        assert_eq!(merged.endpoint, "new");
        assert_eq!(merged.role, WorkspaceRole::Visitor);
        assert_eq!(merge_peer_records(&new, &old).unwrap(), merged);
    }

    #[test]
    fn newer_grant_survives_a_newer_route_with_old_permissions() {
        let mut promoted = peer("old", "2026-09-20T10:00:00.000Z");
        promoted.advertisement = Some(serde_json::json!({"ownerPublicKey":"owner", "grant": {
            "payload":{"workspaceId":"workspace-1","personId":"person-1","accessEpoch":3,"role":"editor"}
        }}));
        let mut stale = peer("new", "2026-09-20T10:01:00.000Z");
        stale.role = WorkspaceRole::Visitor;
        stale.advertisement = Some(serde_json::json!({"ownerPublicKey":"owner", "grant": {
            "payload":{"workspaceId":"workspace-1","personId":"person-1","accessEpoch":1,"role":"visitor"}
        }}));
        let merged = merge_peer_records(&promoted, &stale).unwrap();
        assert_eq!(merged.endpoint, "new");
        assert_eq!(merged.role, WorkspaceRole::Editor);
        assert_eq!(
            merged.advertisement.as_ref().unwrap()["grant"],
            promoted.advertisement.as_ref().unwrap()["grant"]
        );
        assert_eq!(merge_peer_records(&stale, &promoted).unwrap(), merged);
    }

    #[test]
    fn replica_reconcile_keeps_newer_tombstone() {
        let left = ReplicaSet {
            records: vec![ReplicaRecord {
                id: "a".into(),
                updated_at: "2026-09-20T10:00:00.000Z".into(),
                value: serde_json::json!(1),
            }],
            tombstones: vec![],
        };
        let right = ReplicaSet {
            records: vec![],
            tombstones: vec![ReplicaTombstone {
                id: "a".into(),
                deleted_at: "2026-09-20T10:01:00.000Z".into(),
            }],
        };
        let merged = reconcile_replica_sets(&left, &right).unwrap();
        assert!(merged.records.is_empty());
        assert_eq!(merged.tombstones.len(), 1);
    }

    #[test]
    fn neighbor_selection_preserves_ring_bridges() {
        let candidates = (1..=8)
            .map(|index| GossipCandidate {
                device_id: format!("device-{index}"),
                health: index,
                backed_off_until: 0,
            })
            .collect::<Vec<_>>();
        let neighbors =
            select_scoped_neighbors("device-4", &candidates, &GossipBounds::default(), 0, 0)
                .unwrap();
        assert_eq!(neighbors.len(), 4);
        assert!(neighbors.contains(&"device-3".to_string()));
        assert!(neighbors.contains(&"device-5".to_string()));
    }
}
