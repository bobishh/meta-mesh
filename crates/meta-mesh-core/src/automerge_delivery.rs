//! Platform-neutral round state for durable Automerge device sync.
//! Hosts perform transport, route attempts, signature checks, and document I/O.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AutomergeSyncFrame, DeviceBatch, DeviceChange};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSyncWireFrame {
    pub version: u8,
    pub scope_id: String,
    pub document_id: String,
    pub from_device_id: String,
    pub to_device_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSyncRequest {
    pub kind: &'static str,
    pub version: u8,
    pub batch_id: String,
    pub frame: DeviceSyncWireFrame,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSyncRound {
    pub round: u32,
    pub batch: DeviceBatch,
    pub request: DeviceSyncRequest,
    pub selected_route_instance_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSyncConverged {
    pub rounds: u32,
    pub route_instance_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
pub enum DeviceSyncStep {
    Round(DeviceSyncRound),
    Converged(DeviceSyncConverged),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncomingWireFrame {
    version: u8,
    scope_id: String,
    document_id: String,
    from_device_id: String,
    to_device_id: String,
    message: String,
    #[serde(default)]
    proof: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncomingDeviceSyncRequest {
    kind: String,
    version: u8,
    batch_id: String,
    frame: IncomingWireFrame,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSyncInbound {
    pub frame: AutomergeSyncFrame,
    pub batch: DeviceBatch,
}

pub fn decode_device_sync_request(raw: Value, expected_remote_device_id: &str) -> Result<DeviceSyncInbound, String> {
    let request: IncomingDeviceSyncRequest = serde_json::from_value(raw)
        .map_err(|_| "Invalid Automerge device sync request".to_string())?;
    if request.kind != "mesh-automerge-device-sync" || request.version != 1 || request.batch_id.is_empty() {
        return Err("Invalid Automerge device sync request".into());
    }
    let frame = request.frame.decode()?;
    if frame.version != 1 || frame.scope_id.is_empty() || frame.document_id.is_empty() ||
        frame.from_device_id.is_empty() || frame.to_device_id.is_empty() {
        return Err("Invalid Automerge device sync frame".into());
    }
    if frame.from_device_id != expected_remote_device_id {
        return Err("Automerge sync sender does not match remote device".into());
    }
    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(&frame.message));
    if request.batch_id != hash { return Err("Automerge sync batch does not match frame".into()); }
    Ok(DeviceSyncInbound { batch: DeviceBatch { protocol_version: 1,
        scope_id: frame.scope_id.clone(), document_id: frame.document_id.clone(),
        batch_id: hash.clone(), changes: vec![DeviceChange { hash, bytes: frame.message.clone() }] }, frame })
}

pub fn encode_device_sync_response(batch_id: String, ack: Value,
    frame: Option<AutomergeSyncFrame>) -> Result<Value, String> {
    if batch_id.is_empty() || ack.is_null() { return Err("Invalid Automerge device sync response".into()); }
    let frame = frame.map(|frame| DeviceSyncWireFrame { version: frame.version,
        scope_id: frame.scope_id, document_id: frame.document_id,
        from_device_id: frame.from_device_id, to_device_id: frame.to_device_id,
        message: URL_SAFE_NO_PAD.encode(frame.message), proof: frame.proof });
    let mut response = serde_json::json!({ "kind": "mesh-automerge-device-sync-response",
        "version": 1, "batchId": batch_id, "ack": ack });
    if let Some(frame) = frame {
        response["frame"] = serde_json::to_value(frame).map_err(|_| "Invalid Automerge device sync frame".to_string())?;
    }
    Ok(response)
}

impl IncomingWireFrame {
    fn decode(self) -> Result<AutomergeSyncFrame, String> {
        let message = URL_SAFE_NO_PAD.decode(self.message.as_bytes())
            .map_err(|_| "Invalid Automerge device sync frame".to_string())?;
        Ok(AutomergeSyncFrame { version: self.version, scope_id: self.scope_id,
            document_id: self.document_id, from_device_id: self.from_device_id,
            to_device_id: self.to_device_id, message, proof: self.proof })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncomingDeviceSyncResponse {
    kind: String,
    version: u8,
    batch_id: String,
    ack: Value,
    #[serde(default)]
    frame: Option<IncomingWireFrame>,
}

pub struct AutomergeDeviceSyncFlow {
    target_device_id: String,
    document_id: String,
    maximum_rounds: u32,
    rounds: u32,
    selected_route_instance_id: Option<String>,
    route_instance_ids: Vec<String>,
    pending_batch_id: Option<String>,
    pending_scope_id: Option<String>,
    local_device_id: Option<String>,
}

impl AutomergeDeviceSyncFlow {
    pub fn new(target_device_id: String, document_id: String, maximum_rounds: u32) -> Result<Self, String> {
        if target_device_id.is_empty() || document_id.is_empty() {
            return Err("Invalid Automerge device sync identity".into());
        }
        if maximum_rounds == 0 || maximum_rounds > 1_000_000 {
            return Err("Invalid Automerge sync round limit".into());
        }
        Ok(Self { target_device_id, document_id, maximum_rounds, rounds: 0,
            selected_route_instance_id: None, route_instance_ids: Vec::new(), pending_batch_id: None,
            pending_scope_id: None, local_device_id: None })
    }

    pub fn next(&mut self, frame: Option<AutomergeSyncFrame>) -> Result<DeviceSyncStep, String> {
        if self.pending_batch_id.is_some() {
            return Err("Automerge sync round is still pending".into());
        }
        let Some(frame) = frame else {
            return Ok(DeviceSyncStep::Converged(DeviceSyncConverged {
                rounds: self.rounds, route_instance_ids: self.route_instance_ids.clone(),
            }));
        };
        if self.rounds >= self.maximum_rounds {
            return Err("Automerge device sync exceeded round limit".into());
        }
        if frame.version != 1 || frame.document_id != self.document_id ||
            frame.to_device_id != self.target_device_id || frame.scope_id.is_empty() || frame.from_device_id.is_empty() {
            return Err("Invalid Automerge device sync frame".into());
        }
        let batch_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&frame.message));
        let batch = DeviceBatch { protocol_version: 1, scope_id: frame.scope_id.clone(),
            document_id: frame.document_id.clone(), batch_id: batch_id.clone(),
            changes: vec![DeviceChange { hash: batch_id.clone(), bytes: frame.message.clone() }] };
        self.pending_scope_id = Some(frame.scope_id.clone());
        self.local_device_id = Some(frame.from_device_id.clone());
        let request = DeviceSyncRequest { kind: "mesh-automerge-device-sync", version: 1,
            batch_id: batch_id.clone(), frame: DeviceSyncWireFrame { version: frame.version,
                scope_id: frame.scope_id, document_id: frame.document_id,
                from_device_id: frame.from_device_id, to_device_id: frame.to_device_id,
                message: URL_SAFE_NO_PAD.encode(frame.message), proof: frame.proof } };
        self.pending_batch_id = Some(batch_id);
        Ok(DeviceSyncStep::Round(DeviceSyncRound { round: self.rounds + 1, batch, request,
            selected_route_instance_id: self.selected_route_instance_id.clone() }))
    }

    /// Validate every racing route's response before its acknowledgement can win.
    pub fn validate_response(&self, raw: Value) -> Result<(), String> {
        let response: IncomingDeviceSyncResponse = serde_json::from_value(raw)
            .map_err(|_| "Invalid Automerge device sync response".to_string())?;
        self.check_response(&response)
    }

    pub fn complete_round(&mut self, route_instance_id: String, raw: Value) -> Result<Option<AutomergeSyncFrame>, String> {
        if route_instance_id.is_empty() { return Err("Invalid Automerge sync route".into()); }
        let response: IncomingDeviceSyncResponse = serde_json::from_value(raw)
            .map_err(|_| "Invalid Automerge device sync response".to_string())?;
        self.check_response(&response)?;
        let frame = response.frame.map(IncomingWireFrame::decode).transpose()?;
        self.rounds += 1;
        self.route_instance_ids.push(route_instance_id.clone());
        self.selected_route_instance_id = Some(route_instance_id);
        self.pending_batch_id = None;
        self.pending_scope_id = None;
        Ok(frame)
    }

    fn check_response(&self, response: &IncomingDeviceSyncResponse) -> Result<(), String> {
        if response.kind != "mesh-automerge-device-sync-response" || response.version != 1 ||
            self.pending_batch_id.as_deref() != Some(response.batch_id.as_str()) || response.ack.is_null() {
            return Err("Invalid Automerge device sync response".into());
        }
        if let Some(frame) = &response.frame {
            if frame.version != 1 || frame.scope_id != self.pending_scope_id.as_deref().unwrap_or_default() ||
                frame.document_id != self.document_id || frame.from_device_id != self.target_device_id ||
                frame.to_device_id != self.local_device_id.as_deref().unwrap_or_default() ||
                URL_SAFE_NO_PAD.decode(frame.message.as_bytes()).is_err() {
                return Err("Invalid Automerge device sync frame".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_route_cannot_advance_round_and_success_reuses_route_until_convergence() {
        let mut flow = AutomergeDeviceSyncFlow::new("bob".into(), "chat".into(), 2).unwrap();
        let frame = AutomergeSyncFrame { version: 1, scope_id: "chat".into(), document_id: "chat".into(),
            from_device_id: "alice".into(), to_device_id: "bob".into(), message: vec![1, 2], proof: None };
        let DeviceSyncStep::Round(first) = flow.next(Some(frame.clone())).unwrap() else { panic!() };
        assert!(first.selected_route_instance_id.is_none());
        let wrong = serde_json::json!({"kind":"mesh-automerge-device-sync-response","version":1,"batchId":"wrong","ack":{}});
        assert!(flow.validate_response(wrong).is_err());
        let accepted = serde_json::json!({"kind":"mesh-automerge-device-sync-response","version":1,"batchId":first.batch.batch_id,"ack":{}});
        assert!(flow.complete_round("route-a".into(), accepted).unwrap().is_none());
        let DeviceSyncStep::Round(second) = flow.next(Some(frame)).unwrap() else { panic!() };
        assert_eq!(second.selected_route_instance_id.as_deref(), Some("route-a"));
        let accepted = serde_json::json!({"kind":"mesh-automerge-device-sync-response","version":1,"batchId":second.batch.batch_id,"ack":{}});
        flow.complete_round("route-a".into(), accepted).unwrap();
        assert!(flow.next(Some(AutomergeSyncFrame {version:1, scope_id:"chat".into(), document_id:"chat".into(),
            from_device_id:"alice".into(), to_device_id:"bob".into(), message:vec![3], proof:None})).is_err());
        let DeviceSyncStep::Converged(done) = flow.next(None).unwrap() else { panic!() };
        assert_eq!(done.rounds, 2);
        assert_eq!(done.route_instance_ids, ["route-a", "route-a"]);
    }
}
