use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{SignedEnvelope, sign_json_envelope, verify_signed_envelope};

pub const ROUTE_SIGNATURE_DOMAIN: &str = "META-MESH-ROUTE/1";
pub const REPLICATION_SIGNATURE_DOMAIN: &str = "META-MESH-REPLICATION/1";
pub const MAX_DEVICE_ROUTE_BYTES: usize = 8 * 1024;
pub const MAX_DEVICE_ROUTE_STRING: usize = 2 * 1024;
pub const MAX_DEVICE_ROUTE_LIFETIME_MS: i128 = 10 * 60 * 1_000;
pub const MAX_DEVICE_ROUTE_FUTURE_MS: i128 = 5 * 60 * 1_000;
pub const MAX_ACK_HASHES: usize = 256;
pub const MAX_ACK_HEADS: usize = 64;
pub const MAX_DURABLE_ACK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRoutePayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub person_id: String,
    pub device_id: String,
    pub instance_id: String,
    pub endpoint: String,
    pub sequence: u64,
    pub issued_at: String,
    pub expires_at: String,
}

pub type SignedDeviceRoute = SignedEnvelope<DeviceRoutePayload>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRoute {
    #[serde(flatten)]
    pub payload: DeviceRoutePayload,
    pub signer_key_id: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_evidence: Option<serde_json::Value>,
}

pub fn sign_device_route(
    seed: &[u8; 32],
    signer_key_id: &str,
    payload: DeviceRoutePayload,
) -> Result<SignedDeviceRoute, String> {
    validate_device_route_payload(&payload)?;
    if signer_key_id != payload.device_id {
        return Err("Device route signer does not match device".to_string());
    }
    let signed = sign_json_envelope(
        seed,
        serde_json::to_value(&payload).map_err(|_| "Invalid device route")?,
        signer_key_id,
        ROUTE_SIGNATURE_DOMAIN,
    )?;
    Ok(SignedEnvelope {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    })
}

pub fn verify_device_route(
    envelope: &SignedDeviceRoute,
    device_public_key: &str,
    now_ms: i128,
    allow_expired: bool,
) -> Result<DeviceRoute, String> {
    validate_device_route_payload(&envelope.payload)?;
    if envelope.signer_key_id != envelope.payload.device_id {
        return Err("Device route signer does not match device".to_string());
    }
    required_bounded(
        &envelope.signature,
        MAX_DEVICE_ROUTE_STRING,
        "device route signature",
    )?;
    let bytes = serde_json::to_vec(envelope).map_err(|_| "Invalid signed device route")?;
    if bytes.len() > MAX_DEVICE_ROUTE_BYTES {
        return Err("Device route exceeds size limit".to_string());
    }
    let issued_at = timestamp_ms(&envelope.payload.issued_at)?;
    let expires_at = timestamp_ms(&envelope.payload.expires_at)?;
    if issued_at > now_ms + MAX_DEVICE_ROUTE_FUTURE_MS {
        return Err("Device route issued too far in future".to_string());
    }
    if !allow_expired && expires_at <= now_ms {
        return Err("Device route expired".to_string());
    }
    if !verify_signed_envelope(envelope, device_public_key, ROUTE_SIGNATURE_DOMAIN)? {
        return Err("Invalid device route signature".to_string());
    }
    Ok(DeviceRoute {
        payload: envelope.payload.clone(),
        signer_key_id: envelope.signer_key_id.clone(),
        signature: envelope.signature.clone(),
        legacy_evidence: None,
    })
}

pub fn validate_device_route(route: &DeviceRoute) -> Result<(), String> {
    validate_device_route_payload(&route.payload)?;
    if route.signer_key_id != route.payload.device_id {
        return Err("Device route signer does not match device".to_string());
    }
    required_bounded(&route.signature, MAX_DEVICE_ROUTE_STRING, "route signature")
}

pub fn validate_device_route_payload(route: &DeviceRoutePayload) -> Result<(), String> {
    if route.kind != "mesh-device-route" || route.version != 1 {
        return Err("Unsupported device route version".to_string());
    }
    for (value, label) in [
        (&route.scope_id, "route scope"),
        (&route.person_id, "route person"),
        (&route.device_id, "route device"),
        (&route.instance_id, "route instance"),
        (&route.endpoint, "route endpoint"),
    ] {
        required_bounded(value, MAX_DEVICE_ROUTE_STRING, label)?;
    }
    if route.sequence == 0 {
        return Err("Invalid route sequence".to_string());
    }
    let issued_at = timestamp_ms(&route.issued_at)?;
    let expires_at = timestamp_ms(&route.expires_at)?;
    if expires_at <= issued_at || expires_at - issued_at > MAX_DEVICE_ROUTE_LIFETIME_MS {
        return Err("Invalid route lifetime".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceChange {
    pub hash: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceBatch {
    pub protocol_version: u8,
    pub scope_id: String,
    pub document_id: String,
    pub batch_id: String,
    pub changes: Vec<DeviceChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableBatchAckPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub document_id: String,
    pub batch_id: String,
    pub receiver_device_id: String,
    pub accepted_hashes: Vec<String>,
    pub accepted_heads: Vec<String>,
    pub committed_at: String,
}

pub type SignedDurableBatchAck = SignedEnvelope<DurableBatchAckPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableBatchAck {
    #[serde(flatten)]
    pub payload: DurableBatchAckPayload,
    pub signer_key_id: String,
    pub signature: String,
}

pub fn sign_durable_batch_ack(
    seed: &[u8; 32],
    signer_key_id: &str,
    payload: DurableBatchAckPayload,
) -> Result<SignedDurableBatchAck, String> {
    validate_durable_ack_payload(&payload)?;
    if signer_key_id != payload.receiver_device_id {
        return Err("Durable acknowledgement signer mismatch".to_string());
    }
    let signed = sign_json_envelope(
        seed,
        serde_json::to_value(&payload).map_err(|_| "Invalid durable acknowledgement")?,
        signer_key_id,
        REPLICATION_SIGNATURE_DOMAIN,
    )?;
    Ok(SignedEnvelope {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    })
}

pub fn verify_durable_batch_ack(
    envelope: &SignedDurableBatchAck,
    device_public_key: &str,
) -> Result<DurableBatchAck, String> {
    validate_durable_ack_payload(&envelope.payload)?;
    if envelope.signer_key_id != envelope.payload.receiver_device_id {
        return Err("Durable acknowledgement signer mismatch".to_string());
    }
    let bytes = serde_json::to_vec(envelope).map_err(|_| "Invalid durable acknowledgement")?;
    if envelope.signature.is_empty() || bytes.len() > MAX_DURABLE_ACK_BYTES {
        return Err("Invalid durable acknowledgement envelope".to_string());
    }
    if !verify_signed_envelope(envelope, device_public_key, REPLICATION_SIGNATURE_DOMAIN)? {
        return Err("Invalid durable acknowledgement signature".to_string());
    }
    Ok(DurableBatchAck {
        payload: envelope.payload.clone(),
        signer_key_id: envelope.signer_key_id.clone(),
        signature: envelope.signature.clone(),
    })
}

pub fn validate_durable_ack_payload(payload: &DurableBatchAckPayload) -> Result<(), String> {
    if payload.kind != "mesh-durable-batch-ack" || payload.version != 1 {
        return Err("Unsupported durable acknowledgement".to_string());
    }
    for value in [
        &payload.scope_id,
        &payload.document_id,
        &payload.batch_id,
        &payload.receiver_device_id,
    ] {
        required_bounded(
            value,
            MAX_DEVICE_ROUTE_STRING,
            "durable acknowledgement field",
        )?;
    }
    validate_string_list(
        &payload.accepted_hashes,
        MAX_ACK_HASHES,
        "durable acknowledgement hashes",
    )?;
    validate_string_list(
        &payload.accepted_heads,
        MAX_ACK_HEADS,
        "durable acknowledgement heads",
    )?;
    timestamp_ms(&payload.committed_at)
        .map(|_| ())
        .map_err(|_| "Invalid durable acknowledgement commit time".to_string())
}

pub fn durable_ack_matches(
    ack: &DurableBatchAck,
    batch: &DeviceBatch,
    target_device_id: &str,
) -> bool {
    if ack.payload.kind != "mesh-durable-batch-ack"
        || ack.payload.version != 1
        || ack.payload.scope_id != batch.scope_id
        || ack.payload.document_id != batch.document_id
        || ack.payload.batch_id != batch.batch_id
        || ack.payload.receiver_device_id != target_device_id
        || ack.signature.is_empty()
    {
        return false;
    }
    let expected = batch
        .changes
        .iter()
        .map(|change| change.hash.as_str())
        .collect::<std::collections::HashSet<_>>();
    let accepted = ack
        .payload
        .accepted_hashes
        .iter()
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>();
    accepted.len() == ack.payload.accepted_hashes.len() && accepted == expected
}

#[derive(Debug, Default)]
pub struct DeviceRouteCatalog {
    routes: BTreeMap<String, DeviceRoute>,
}

impl DeviceRouteCatalog {
    pub fn admit(&mut self, route: DeviceRoute) -> Result<DeviceRoute, String> {
        validate_device_route(&route)?;
        let key = format!(
            "{}\0{}\0{}",
            route.payload.scope_id, route.payload.device_id, route.payload.instance_id
        );
        let selected = match self.routes.get(&key) {
            Some(current) if !prefer_route(current, &route) => current.clone(),
            _ => route,
        };
        self.routes.insert(key, selected.clone());
        Ok(selected)
    }

    pub fn routes_for(&self, scope_id: &str, device_id: &str) -> Vec<DeviceRoute> {
        self.routes
            .values()
            .filter(|route| {
                route.payload.scope_id == scope_id && route.payload.device_id == device_id
            })
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteHealth {
    pub route: DeviceRoute,
    pub health: i64,
}

pub fn order_delivery_routes(
    target_device_id: &str,
    routes: &[RouteHealth],
) -> Result<Vec<DeviceRoute>, String> {
    let mut indexed = routes
        .iter()
        .enumerate()
        .filter(|(_, value)| value.route.payload.device_id == target_device_id)
        .collect::<Vec<_>>();
    if indexed.is_empty() {
        return Err(format!("No routes for device {target_device_id}"));
    }
    indexed.sort_by(|(left_index, left), (right_index, right)| {
        right
            .health
            .cmp(&left.health)
            .then_with(|| left_index.cmp(right_index))
    });
    Ok(indexed
        .into_iter()
        .map(|(_, value)| value.route.clone())
        .collect())
}

fn prefer_route(current: &DeviceRoute, candidate: &DeviceRoute) -> bool {
    if candidate.payload.sequence != current.payload.sequence {
        return candidate.payload.sequence > current.payload.sequence;
    }
    route_tie(candidate) > route_tie(current)
}

fn route_tie(route: &DeviceRoute) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        route.payload.endpoint, route.payload.issued_at, route.payload.expires_at, route.signature
    )
}

fn validate_string_list(values: &[String], maximum: usize, label: &str) -> Result<(), String> {
    if values.len() > maximum
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > MAX_DEVICE_ROUTE_STRING)
    {
        Err(format!("Invalid {label}"))
    } else {
        Ok(())
    }
}

fn required_bounded(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum {
        Err(format!("Invalid {label}"))
    } else {
        Ok(())
    }
}

fn timestamp_ms(value: &str) -> Result<i128, String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|value| value.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "Invalid timestamp".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{public_key_from_seed, public_key_id};

    fn payload(sequence: u64, endpoint: &str) -> DeviceRoutePayload {
        DeviceRoutePayload {
            kind: "mesh-device-route".into(),
            version: 1,
            scope_id: "scope-1".into(),
            person_id: "person-1".into(),
            device_id: "device-1".into(),
            instance_id: "instance-1".into(),
            endpoint: endpoint.into(),
            sequence,
            issued_at: "2026-09-20T10:00:00.000Z".into(),
            expires_at: "2026-09-20T10:10:00.000Z".into(),
        }
    }

    #[test]
    fn route_signature_and_expiry_are_verified() {
        let seed = [11; 32];
        let public_key = public_key_from_seed(&seed).unwrap();
        let device_id = public_key_id(&public_key).unwrap();
        let mut route = payload(1, "endpoint-a");
        route.device_id = device_id.clone();
        let signed = sign_device_route(&seed, &device_id, route).unwrap();
        assert!(
            verify_device_route(
                &signed,
                &public_key,
                timestamp_ms("2026-09-20T10:05:00.000Z").unwrap(),
                false,
            )
            .is_ok()
        );
        assert!(
            verify_device_route(
                &signed,
                &public_key,
                timestamp_ms("2026-09-20T10:11:00.000Z").unwrap(),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_retains_highest_route_sequence() {
        let mut catalog = DeviceRouteCatalog::default();
        let route = |sequence, endpoint: &str| DeviceRoute {
            payload: payload(sequence, endpoint),
            signer_key_id: "device-1".into(),
            signature: "signature".into(),
            legacy_evidence: None,
        };
        catalog.admit(route(2, "new")).unwrap();
        assert_eq!(
            catalog.admit(route(1, "old")).unwrap().payload.endpoint,
            "new"
        );
    }

    #[test]
    fn durable_ack_must_confirm_the_complete_batch() {
        let batch = DeviceBatch {
            protocol_version: 1,
            scope_id: "s".into(),
            document_id: "d".into(),
            batch_id: "b".into(),
            changes: vec![DeviceChange {
                hash: "h".into(),
                bytes: vec![1],
            }],
        };
        let ack = DurableBatchAck {
            payload: DurableBatchAckPayload {
                kind: "mesh-durable-batch-ack".into(),
                version: 1,
                scope_id: "s".into(),
                document_id: "d".into(),
                batch_id: "b".into(),
                receiver_device_id: "target".into(),
                accepted_hashes: vec!["h".into()],
                accepted_heads: vec![],
                committed_at: "2026-09-20T10:00:00.000Z".into(),
            },
            signer_key_id: "target".into(),
            signature: "signature".into(),
        };
        assert!(durable_ack_matches(&ack, &batch, "target"));
        let empty = DurableBatchAck {
            payload: DurableBatchAckPayload {
                accepted_hashes: vec![],
                ..ack.payload.clone()
            },
            ..ack.clone()
        };
        assert!(!durable_ack_matches(&empty, &batch, "target"));
        let partial_batch = DeviceBatch {
            changes: vec![
                DeviceChange { hash: "h".into(), bytes: vec![1] },
                DeviceChange { hash: "second".into(), bytes: vec![2] },
            ],
            ..batch.clone()
        };
        assert!(!durable_ack_matches(&ack, &partial_batch, "target"));
        let mut forged = ack;
        forged.payload.accepted_hashes.push("other".into());
        assert!(!durable_ack_matches(&forged, &batch, "target"));
    }
}
