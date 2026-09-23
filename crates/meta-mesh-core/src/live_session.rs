use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    control_frames, AutomergeSyncEngine, AutomergeSyncFrame, ControlFrameReceiver, PairingCodec,
};
use serde_json::Value;

const MAX_OWNER_OFFER_BYTES: usize = 24 * 1024 * 1024;
const MAX_GOSSIP_PACKET_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "camelCase")]
pub enum LiveSessionAction {
    DurableBatch(Vec<u8>),
    Heartbeat,
    Control(Vec<u8>),
    OwnerWorkspaceOffer(Vec<u8>),
    Gossip(Vec<u8>),
    BlobRequest(Vec<u8>),
    HandoffRequest(Vec<u8>),
    AutomergeSync(Vec<u8>),
    Snapshot(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LiveSessionEffect {
    MergeDurableBatch,
    MergeWorkspaceSnapshot,
    SendSavedAcknowledgement,
    SendHeartbeatAcknowledgement,
    MergeAuthorization,
    MergeChat,
    MergeMesh,
    HandleOwnerWorkspaceOffer,
    HandleGossip,
    HandleBlobRequest,
    HandleHandoffRequest,
    ReadDocument,
    ReadAuthorization,
    PrepareDocument,
    PersistDocument,
    CommitDocument,
    SendSyncResponse,
    CloseSend,
    UnsupportedControl,
    UnsupportedSnapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSessionReceivePlan {
    pub effects: Vec<LiveSessionEffect>,
    pub serialize_document: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<WorkspaceControlSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedLiveDocument {
    pub document: Vec<u8>,
    pub accepted_changes: usize,
    pub should_persist: bool,
    pub accepted_hashes: Vec<String>,
    pub heads: Vec<String>,
    pub response: Option<Vec<u8>>,
    pub proof: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSessionPublishPlan {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_frame: Option<Vec<u8>>,
    pub control_snapshot: Vec<u8>,
    pub control_frames: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSessionSnapshotPlan {
    pub snapshot: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceControlSnapshot {
    pub version: u8,
    pub workspace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh: Option<Value>,
}

struct LiveDocumentSync {
    engine: AutomergeSyncEngine,
    remote_device_id: String,
}

/// Transport-independent protocol for one authenticated live workspace stream.
/// The host performs storage and I/O; acknowledgements are created only after
/// its durable write succeeds.
pub struct LiveWorkspaceSession {
    workspace_id: String,
    secret: String,
    control_receiver: ControlFrameReceiver,
    transfer_sequence: u64,
    last_control_sent: Option<Vec<u8>>,
    document_sync: Option<LiveDocumentSync>,
}

impl LiveWorkspaceSession {
    pub fn new(workspace_id: impl Into<String>, secret: impl Into<String>) -> Result<Self, String> {
        let workspace_id = workspace_id.into();
        let secret = secret.into();
        if workspace_id.is_empty() || secret.is_empty() {
            return Err("Invalid live workspace session".to_string());
        }
        Ok(Self {
            control_receiver: ControlFrameReceiver::new(&workspace_id),
            workspace_id,
            secret,
            transfer_sequence: 0,
            last_control_sent: None,
            document_sync: None,
        })
    }

    pub fn receive(&mut self, frame: &[u8]) -> Result<Option<LiveSessionAction>, String> {
        let header = PairingCodec::inspect(frame)?;
        let payload = PairingCodec::decode(frame, &header.frame_type, &self.secret)?;
        let action = match header.frame_type.as_str() {
            "mesh-durable-batch" => LiveSessionAction::DurableBatch(payload),
            "sync-heartbeat" => {
                if !payload.is_empty() {
                    return Err("Invalid mesh heartbeat".to_string());
                }
                LiveSessionAction::Heartbeat
            }
            "mesh-control-sync" => match self.control_receiver.receive(&payload)? {
                Some(bytes) => LiveSessionAction::Control(bytes),
                None => return Ok(None),
            },
            "mesh-owner-workspace-offer" => {
                if payload.len() > MAX_OWNER_OFFER_BYTES {
                    return Err("Owner workspace offer exceeds size limit".to_string());
                }
                LiveSessionAction::OwnerWorkspaceOffer(payload)
            }
            "mesh-iroh-gossip" => {
                if payload.len() > MAX_GOSSIP_PACKET_BYTES {
                    return Err("Gossip packet exceeds size limit".to_string());
                }
                LiveSessionAction::Gossip(payload)
            }
            "mesh-blob-request-v1" => LiveSessionAction::BlobRequest(payload),
            "mesh-handoff-request" => LiveSessionAction::HandoffRequest(payload),
            "mesh-automerge-sync" => LiveSessionAction::AutomergeSync(payload),
            "sync-update" => LiveSessionAction::Snapshot(payload),
            _ => {
                return Err(format!(
                    "Unsupported live workspace frame: {}",
                    header.frame_type
                ))
            }
        };
        Ok(Some(action))
    }

    /// Selects host effects and their order for one authenticated incoming frame.
    /// Storage, callbacks, and transport remain host operations.
    pub fn receive_plan(
        &self,
        action: &LiveSessionAction,
    ) -> Result<LiveSessionReceivePlan, String> {
        use LiveSessionAction as A;
        use LiveSessionEffect as E;
        let effects = match action {
            A::DurableBatch(_) => vec![
                E::MergeDurableBatch,
                E::SendSavedAcknowledgement,
                E::CloseSend,
            ],
            A::Heartbeat => vec![E::SendHeartbeatAcknowledgement, E::CloseSend],
            A::Control(_) if self.workspace_id == "workspace-set" => {
                vec![E::UnsupportedControl]
            }
            A::Control(payload) => {
                let control = self.decode_control(payload)?;
                let mut effects = Vec::new();
                if control.authorization.is_some() {
                    effects.push(E::MergeAuthorization);
                }
                if control.chat.is_some() {
                    effects.push(E::MergeChat);
                }
                if control.mesh.is_some() {
                    effects.push(E::MergeMesh);
                }
                effects.push(E::CloseSend);
                return Ok(LiveSessionReceivePlan {
                    effects,
                    serialize_document: true,
                    control: Some(control),
                });
            }
            A::OwnerWorkspaceOffer(_) => vec![
                E::HandleOwnerWorkspaceOffer,
                E::SendSavedAcknowledgement,
                E::CloseSend,
            ],
            A::Gossip(_) => vec![E::HandleGossip, E::CloseSend],
            A::BlobRequest(_) => vec![E::HandleBlobRequest],
            A::HandoffRequest(_) => vec![E::HandleHandoffRequest],
            A::AutomergeSync(_) => vec![
                E::ReadDocument,
                E::ReadAuthorization,
                E::PrepareDocument,
                E::PersistDocument,
                E::CommitDocument,
                E::SendSyncResponse,
                E::CloseSend,
            ],
            A::Snapshot(_) if self.workspace_id == "workspace-set" => {
                vec![E::MergeWorkspaceSnapshot, E::CloseSend]
            }
            A::Snapshot(_) => vec![E::UnsupportedSnapshot],
        };
        Ok(LiveSessionReceivePlan {
            effects,
            serialize_document: matches!(action, A::AutomergeSync(_)),
            control: None,
        })
    }

    pub fn encode(&self, frame_type: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        match frame_type {
            "mesh-owner-workspace-offer" if payload.len() > MAX_OWNER_OFFER_BYTES => {
                Err("Owner workspace offer exceeds size limit".to_string())
            }
            "mesh-iroh-gossip" if payload.len() > MAX_GOSSIP_PACKET_BYTES => {
                Err("Gossip packet exceeds size limit".to_string())
            }
            "mesh-durable-batch"
            | "sync-heartbeat"
            | "sync-heartbeat-ack"
            | "mesh-control-sync"
            | "mesh-owner-workspace-offer"
            | "mesh-iroh-gossip"
            | "mesh-automerge-sync"
            | "sync-update" => PairingCodec::encode(frame_type, &self.secret, payload),
            _ => Err("Unsupported outgoing live workspace frame".to_string()),
        }
    }

    pub fn encode_automerge_frame(&self, frame: &AutomergeSyncFrame) -> Result<Vec<u8>, String> {
        let mut value =
            serde_json::to_value(frame).map_err(|_| "Invalid Automerge sync frame".to_string())?;
        value
            .as_object_mut()
            .ok_or_else(|| "Invalid Automerge sync frame".to_string())?
            .insert(
                "message".to_string(),
                URL_SAFE_NO_PAD.encode(&frame.message).into(),
            );
        let payload =
            serde_json::to_vec(&value).map_err(|_| "Invalid Automerge sync frame".to_string())?;
        self.encode("mesh-automerge-sync", &payload)
    }

    pub fn decode_automerge_payload(&self, payload: &[u8]) -> Result<AutomergeSyncFrame, String> {
        let mut value: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|_| "Invalid Automerge sync frame".to_string())?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "Invalid Automerge sync frame".to_string())?;
        let message = object
            .get("message")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "Invalid Automerge sync frame".to_string())?;
        let bytes = URL_SAFE_NO_PAD
            .decode(message)
            .map_err(|_| "Invalid Automerge sync frame".to_string())?;
        object.insert(
            "message".to_string(),
            serde_json::to_value(bytes).map_err(|_| "Invalid Automerge sync frame".to_string())?,
        );
        serde_json::from_value(value).map_err(|_| "Invalid Automerge sync frame".to_string())
    }

    pub fn start_document_sync(
        &mut self,
        local_device_id: &str,
        remote_device_id: &str,
    ) -> Result<(), String> {
        if remote_device_id.is_empty() {
            return Err("Invalid remote device ID".to_string());
        }
        self.document_sync = Some(LiveDocumentSync {
            engine: AutomergeSyncEngine::new(local_device_id, None)?,
            remote_device_id: remote_device_id.to_string(),
        });
        Ok(())
    }

    pub fn generate_document(
        &mut self,
        document: &[u8],
        proof: Option<Value>,
    ) -> Result<Option<Vec<u8>>, String> {
        let workspace_id = self.workspace_id.clone();
        let sync = self
            .document_sync
            .as_mut()
            .ok_or_else(|| "Document sync is not started".to_string())?;
        sync.engine
            .load_document(&workspace_id, &workspace_id, document)?;
        let frame = sync
            .engine
            .generate(&workspace_id, &sync.remote_device_id, true, proof)?;
        frame
            .map(|frame| self.encode_automerge_frame(&frame))
            .transpose()
    }

    pub fn prepare_document(
        &mut self,
        payload: &[u8],
        document: &[u8],
        response_proof: Option<Value>,
    ) -> Result<PreparedLiveDocument, String> {
        let frame = self.decode_automerge_payload(payload)?;
        if frame.document_id != self.workspace_id || frame.scope_id != self.workspace_id {
            return Err("Invalid Automerge sync frame".to_string());
        }
        let workspace_id = self.workspace_id.clone();
        let sync = self
            .document_sync
            .as_mut()
            .ok_or_else(|| "Document sync is not started".to_string())?;
        sync.engine
            .load_document(&workspace_id, &workspace_id, document)?;
        let proof = frame.proof.clone();
        let result =
            sync.engine
                .prepare_receive(&sync.remote_device_id, frame, true, response_proof)?;
        Ok(PreparedLiveDocument {
            document: result.document,
            accepted_changes: result.accepted_changes,
            should_persist: result.accepted_changes > 0 || proof.is_some(),
            accepted_hashes: result.accepted_hashes,
            heads: result.heads,
            response: result
                .response
                .map(|frame| self.encode_automerge_frame(&frame))
                .transpose()?,
            proof,
        })
    }

    pub fn commit_document(&mut self) -> Result<(), String> {
        let sync = self
            .document_sync
            .as_mut()
            .ok_or_else(|| "Document sync is not started".to_string())?;
        sync.engine
            .commit_prepared_receive(&self.workspace_id, &sync.remote_device_id)
    }

    pub fn abort_document(&mut self) {
        if let Some(sync) = self.document_sync.as_mut() {
            sync.engine
                .abort_prepared_receive(&self.workspace_id, &sync.remote_device_id);
        }
    }

    pub fn reset_document(&mut self) {
        if let Some(sync) = self.document_sync.as_mut() {
            sync.engine
                .reset(&self.workspace_id, &sync.remote_device_id);
        }
    }

    pub fn control_changed(&self, snapshot: &[u8]) -> bool {
        self.last_control_sent.as_deref() != Some(snapshot)
    }

    pub fn encode_control(
        &self,
        authorization: Option<Value>,
        chat: Option<Value>,
        mesh: Option<Value>,
    ) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&WorkspaceControlSnapshot {
            version: 1,
            workspace_id: self.workspace_id.clone(),
            authorization,
            chat,
            mesh,
        })
        .map_err(|_| "Invalid mesh control frame".to_string())
    }

    pub fn decode_control(&self, bytes: &[u8]) -> Result<WorkspaceControlSnapshot, String> {
        let snapshot: WorkspaceControlSnapshot =
            serde_json::from_slice(bytes).map_err(|_| "Invalid mesh control frame".to_string())?;
        if snapshot.version != 1 || snapshot.workspace_id != self.workspace_id {
            return Err("Invalid mesh control frame".to_string());
        }
        Ok(snapshot)
    }

    pub fn control_frames(&mut self, snapshot: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.transfer_sequence = self.transfer_sequence.saturating_add(1);
        control_frames(
            &self.workspace_id,
            &format!("live-{}", self.transfer_sequence),
            snapshot,
        )?
        .into_iter()
        .map(|part| self.encode("mesh-control-sync", &part))
        .collect()
    }

    pub fn mark_control_sent(&mut self, snapshot: Vec<u8>) {
        self.last_control_sent = Some(snapshot);
    }

    /// Builds the outgoing document/control work in protocol order without
    /// marking control state delivered; the host commits only after sends.
    pub fn prepare_publish(
        &mut self,
        document: &[u8],
        proof: Option<Value>,
        authorization: Option<Value>,
        chat: Option<Value>,
        mesh: Option<Value>,
    ) -> Result<LiveSessionPublishPlan, String> {
        let document_frame = self.generate_document(document, proof)?;
        let control = self.prepare_control_publish(authorization, chat, mesh)?;
        let control_snapshot = control.control_snapshot;
        let control_frames = control.control_frames;
        Ok(LiveSessionPublishPlan {
            document_frame,
            control_snapshot,
            control_frames,
        })
    }

    pub fn prepare_control_publish(
        &mut self,
        authorization: Option<Value>,
        chat: Option<Value>,
        mesh: Option<Value>,
    ) -> Result<LiveSessionPublishPlan, String> {
        let control_snapshot = self.encode_control(authorization, chat, mesh)?;
        let control_frames = if self.control_changed(&control_snapshot) {
            self.control_frames(&control_snapshot)?
        } else {
            Vec::new()
        };
        Ok(LiveSessionPublishPlan {
            document_frame: None,
            control_snapshot,
            control_frames,
        })
    }

    pub fn prepare_snapshot_publish(
        &self,
        snapshot: &[u8],
    ) -> Result<LiveSessionSnapshotPlan, String> {
        Ok(LiveSessionSnapshotPlan {
            snapshot: snapshot.to_vec(),
            frame: self
                .control_changed(snapshot)
                .then(|| self.encode("sync-update", snapshot))
                .transpose()?,
        })
    }

    pub fn finish_publish(&mut self, control_snapshot: &[u8], all_frames_sent: bool) {
        if all_frames_sent {
            self.mark_control_sent(control_snapshot.to_vec());
        }
    }

    pub fn acknowledge_saved(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
        PairingCodec::encode("mesh-durable-ack", &self.secret, digest.as_bytes())
    }

    pub fn verify_saved_receipt(&self, frame: &[u8], bytes: &[u8]) -> Result<(), String> {
        let receipt = PairingCodec::decode(frame, "mesh-durable-ack", &self.secret)?;
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
        if receipt != expected.as_bytes() {
            return Err("Ownership receipt does not match the saved data".to_string());
        }
        Ok(())
    }

    pub fn verify_heartbeat_ack(&self, frame: &[u8]) -> Result<(), String> {
        let payload = PairingCodec::decode(frame, "sync-heartbeat-ack", &self.secret)?;
        if !payload.is_empty() {
            return Err("Invalid mesh heartbeat acknowledgement".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automerge::{transaction::Transactable, AutoCommit, ROOT};

    #[test]
    fn confirmed_delivery_requires_exact_saved_bytes() {
        let mut session = LiveWorkspaceSession::new("board", "secret").unwrap();
        let bytes = b"document and authority";
        let frame = session.encode("mesh-durable-batch", bytes).unwrap();
        assert_eq!(
            session.receive(&frame).unwrap(),
            Some(LiveSessionAction::DurableBatch(bytes.to_vec()))
        );
        let ack = session.acknowledge_saved(bytes).unwrap();
        session.verify_saved_receipt(&ack, bytes).unwrap();
        assert!(session
            .verify_saved_receipt(&ack, b"different authority")
            .is_err());
        assert!(LiveWorkspaceSession::new("board", "another secret")
            .unwrap()
            .receive(&frame)
            .is_err());
    }

    #[test]
    fn control_reassembles_and_only_marks_after_send() {
        let mut sender = LiveWorkspaceSession::new("board", "secret").unwrap();
        let mut receiver = LiveWorkspaceSession::new("board", "secret").unwrap();
        let snapshot = vec![42; 300_000];
        assert!(sender.control_changed(&snapshot));
        let parts = sender.control_frames(&snapshot).unwrap();
        assert!(parts.len() > 1);
        for part in parts.iter().take(parts.len() - 1) {
            assert_eq!(receiver.receive(part).unwrap(), None);
        }
        assert_eq!(
            receiver.receive(parts.last().unwrap()).unwrap(),
            Some(LiveSessionAction::Control(snapshot.clone()))
        );
        assert!(sender.control_changed(&snapshot));
        sender.mark_control_sent(snapshot.clone());
        assert!(!sender.control_changed(&snapshot));
    }

    #[test]
    fn receive_plan_owns_dispatch_and_control_merge_order() {
        let mut sender = LiveWorkspaceSession::new("board", "secret").unwrap();
        let mut receiver = LiveWorkspaceSession::new("board", "secret").unwrap();
        let control = sender
            .encode_control(
                Some(serde_json::json!({ "proof": true })),
                Some(serde_json::json!([])),
                None,
            )
            .unwrap();
        let frames = sender.control_frames(&control).unwrap();
        let mut action = None;
        for frame in frames {
            action = receiver.receive(&frame).unwrap().or(action);
        }
        let plan = receiver.receive_plan(action.as_ref().unwrap()).unwrap();
        assert!(plan.serialize_document);
        assert_eq!(
            plan.effects,
            vec![
                LiveSessionEffect::MergeAuthorization,
                LiveSessionEffect::MergeChat,
                LiveSessionEffect::CloseSend,
            ]
        );
        assert_eq!(plan.control.unwrap().version, 1);

        let gossip = sender.encode("mesh-iroh-gossip", b"packet").unwrap();
        let action = receiver.receive(&gossip).unwrap().unwrap();
        let plan = receiver.receive_plan(&action).unwrap();
        assert!(!plan.serialize_document);
        assert_eq!(
            plan.effects,
            vec![
                LiveSessionEffect::HandleGossip,
                LiveSessionEffect::CloseSend
            ]
        );

        let batch = sender.encode("mesh-durable-batch", b"document").unwrap();
        let action = receiver.receive(&batch).unwrap().unwrap();
        assert_eq!(
            receiver.receive_plan(&action).unwrap().effects,
            vec![
                LiveSessionEffect::MergeDurableBatch,
                LiveSessionEffect::SendSavedAcknowledgement,
                LiveSessionEffect::CloseSend,
            ]
        );
    }

    #[test]
    fn failed_control_send_is_not_committed_and_publish_retry_resends() {
        let mut doc = AutoCommit::new();
        doc.put(ROOT, "id", "board").unwrap();
        let bytes = doc.save();
        let mut sender = LiveWorkspaceSession::new("board", "secret").unwrap();
        sender.start_document_sync("local", "remote").unwrap();

        let first = sender
            .prepare_publish(&bytes, None, None, Some(serde_json::json!(["chat"])), None)
            .unwrap();
        assert!(!first.control_frames.is_empty());
        sender.finish_publish(&first.control_snapshot, false);

        let retry = sender
            .prepare_publish(&bytes, None, None, Some(serde_json::json!(["chat"])), None)
            .unwrap();
        assert!(!retry.control_frames.is_empty());
        sender.finish_publish(&retry.control_snapshot, true);

        let unchanged = sender
            .prepare_publish(&bytes, None, None, Some(serde_json::json!(["chat"])), None)
            .unwrap();
        assert!(unchanged.control_frames.is_empty());
    }

    #[test]
    fn workspace_set_snapshot_receive_and_publish_are_rust_planned() {
        let mut sender = LiveWorkspaceSession::new("workspace-set", "secret").unwrap();
        let mut receiver = LiveWorkspaceSession::new("workspace-set", "secret").unwrap();
        let first = sender.prepare_snapshot_publish(b"snapshot").unwrap();
        assert_eq!(
            first.frame.as_deref(),
            Some(&sender.encode("sync-update", b"snapshot").unwrap()[..])
        );
        sender.finish_publish(&first.snapshot, false);
        assert!(sender
            .prepare_snapshot_publish(b"snapshot")
            .unwrap()
            .frame
            .is_some());
        sender.finish_publish(&first.snapshot, true);
        assert!(sender
            .prepare_snapshot_publish(b"snapshot")
            .unwrap()
            .frame
            .is_none());

        let action = receiver
            .receive(first.frame.as_ref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            receiver.receive_plan(&action).unwrap().effects,
            vec![
                LiveSessionEffect::MergeWorkspaceSnapshot,
                LiveSessionEffect::CloseSend
            ]
        );

        let mut control_sender = LiveWorkspaceSession::new("workspace-set", "secret").unwrap();
        let mut control_receiver = LiveWorkspaceSession::new("workspace-set", "secret").unwrap();
        let control = control_sender
            .encode_control(Some(serde_json::json!({ "proof": true })), None, None)
            .unwrap();
        let frames = control_sender.control_frames(&control).unwrap();
        let mut control_action = None;
        for frame in frames {
            control_action = control_receiver.receive(&frame).unwrap().or(control_action);
        }
        assert_eq!(
            control_receiver
                .receive_plan(control_action.as_ref().unwrap())
                .unwrap()
                .effects,
            vec![LiveSessionEffect::UnsupportedControl]
        );
    }

    #[test]
    fn heartbeat_and_gossip_are_authenticated_and_bounded() {
        let mut session = LiveWorkspaceSession::new("board", "secret").unwrap();
        let heartbeat = session.encode("sync-heartbeat", &[]).unwrap();
        assert_eq!(
            session.receive(&heartbeat).unwrap(),
            Some(LiveSessionAction::Heartbeat)
        );
        let ack = session.encode("sync-heartbeat-ack", &[]).unwrap();
        session.verify_heartbeat_ack(&ack).unwrap();
        assert!(session
            .encode("mesh-iroh-gossip", &vec![0; MAX_GOSSIP_PACKET_BYTES + 1])
            .is_err());
        let oversized = PairingCodec::encode(
            "mesh-iroh-gossip",
            "secret",
            &vec![0; MAX_GOSSIP_PACKET_BYTES + 1],
        )
        .unwrap();
        assert!(session.receive(&oversized).is_err());
    }

    #[test]
    fn automerge_wire_format_round_trips_through_live_session() {
        let mut session = LiveWorkspaceSession::new("board", "secret").unwrap();
        let frame = AutomergeSyncFrame {
            version: 1,
            scope_id: "board".to_string(),
            document_id: "board".to_string(),
            from_device_id: "left".to_string(),
            to_device_id: "right".to_string(),
            message: vec![1, 2, 255],
            proof: None,
        };
        let encoded = session.encode_automerge_frame(&frame).unwrap();
        let Some(LiveSessionAction::AutomergeSync(payload)) = session.receive(&encoded).unwrap()
        else {
            panic!("expected Automerge sync");
        };
        let wire: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(wire["message"], "AQL_");
        assert_eq!(session.decode_automerge_payload(&payload).unwrap(), frame);
    }

    #[test]
    fn document_sync_can_abort_and_retry_prepared_receive() {
        let mut source_document = AutoCommit::new();
        source_document.put(ROOT, "id", "board").unwrap();
        let baseline = source_document.save();
        source_document.put(ROOT, "title", "new title").unwrap();
        let changed = source_document.save();

        let mut source = LiveWorkspaceSession::new("board", "secret").unwrap();
        source.start_document_sync("source", "receiver").unwrap();
        let outbound = source.generate_document(&changed, None).unwrap().unwrap();
        let mut receiver = LiveWorkspaceSession::new("board", "secret").unwrap();
        receiver.start_document_sync("receiver", "source").unwrap();
        let Some(LiveSessionAction::AutomergeSync(payload)) = receiver.receive(&outbound).unwrap()
        else {
            panic!("expected document frame");
        };
        let first = receiver
            .prepare_document(&payload, &baseline, None)
            .unwrap();
        assert!(receiver.generate_document(&baseline, None).is_err());
        receiver.abort_document();
        let second = receiver
            .prepare_document(&payload, &baseline, None)
            .unwrap();
        assert_eq!(second.accepted_hashes, first.accepted_hashes);
        receiver.commit_document().unwrap();
        AutoCommit::load(&second.document).unwrap();
    }
}
