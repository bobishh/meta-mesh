use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    LiveSessionAction, LiveSessionEffect, LiveSessionPublishPlan, LiveWorkspaceSession,
    WorkspaceControlSnapshot,
};

struct PendingDocumentReceive {
    payload: Vec<u8>,
    prepared: Option<PreparedDocumentReceive>,
}

struct PreparedDocumentReceive {
    engine_prepared: bool,
    should_persist: bool,
    response: Option<Vec<u8>>,
    effect: MeshScopeFrameEffect,
    proofs: Option<crate::AuthorizationPageReceiver>,
}

struct PendingSavedReceive {
    payload: Vec<u8>,
}

/// One authenticated scope stream. Hosts supply stored document bytes and
/// perform persistence or transport effects; this runtime owns frame order,
/// Automerge preparation, and commit-or-abort state.
pub struct MeshScopeRuntime {
    live: LiveWorkspaceSession,
    pending_document_receive: Option<PendingDocumentReceive>,
    pending_saved_receive: Option<PendingSavedReceive>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum MeshScopeFrameEffect {
    NeedDocument,
    ProofRequest {
        frame: Vec<u8>,
        cache_key: String,
    },
    ProofSource {
        payload: Vec<u8>,
    },
    ProofPageReceived {
        cache_key: String,
        payload: Vec<u8>,
    },
    DocumentReceive {
        document: Vec<u8>,
        proof: Option<Value>,
        should_persist: bool,
        accepted_changes: usize,
        accepted_hashes: Vec<String>,
        heads: Vec<String>,
    },
    Control {
        control: WorkspaceControlSnapshot,
        effects: Vec<LiveSessionEffect>,
        close_send: bool,
    },
    Gossip {
        payload: Vec<u8>,
        close_send: bool,
    },
    Heartbeat {
        acknowledgement: Vec<u8>,
        close_send: bool,
    },
    DurableBatch {
        payload: Vec<u8>,
    },
    OwnerWorkspaceOffer {
        payload: Vec<u8>,
    },
    BlobRequest {
        payload: Vec<u8>,
    },
    HandoffRequest {
        payload: Vec<u8>,
    },
    WorkspaceSnapshot {
        payload: Vec<u8>,
        close_send: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshScopeDocumentCompletion {
    pub response: Option<Vec<u8>>,
    pub close_send: bool,
}

impl MeshScopeRuntime {
    pub fn new(workspace_id: impl Into<String>, secret: impl Into<String>) -> Result<Self, String> {
        Ok(Self {
            live: LiveWorkspaceSession::new(workspace_id, secret)?,
            pending_document_receive: None,
            pending_saved_receive: None,
        })
    }

    pub fn start_document_sync(
        &mut self,
        local_device_id: &str,
        remote_device_id: &str,
    ) -> Result<(), String> {
        self.live
            .start_document_sync(local_device_id, remote_device_id)
    }

    /// Decode one authenticated frame and return the next host operation.
    /// Document bytes are requested only after the authenticated frame says
    /// they are needed, so gossip and control handlers never read storage.
    pub fn receive_frame(&mut self, frame: &[u8]) -> Result<Option<MeshScopeFrameEffect>, String> {
        let Some(action) = self.live.receive(frame)? else {
            return Ok(None);
        };
        match action {
            LiveSessionAction::ProofRequest(payload) => {
                Ok(Some(MeshScopeFrameEffect::ProofSource { payload }))
            }
            LiveSessionAction::ProofPage(payload) => self.accept_proof_page(&payload).map(Some),
            LiveSessionAction::AutomergeSync(payload) => {
                if self.pending_document_receive.is_some() {
                    return Err("Mesh document receive is pending persistence".into());
                }
                self.pending_document_receive = Some(PendingDocumentReceive {
                    payload,
                    prepared: None,
                });
                Ok(Some(MeshScopeFrameEffect::NeedDocument))
            }
            LiveSessionAction::Control(payload) => {
                let plan = self
                    .live
                    .receive_plan(&LiveSessionAction::Control(payload))?;
                let control = plan.control.ok_or("Invalid mesh control plan")?;
                Ok(Some(MeshScopeFrameEffect::Control {
                    control,
                    effects: plan.effects,
                    close_send: true,
                }))
            }
            LiveSessionAction::Gossip(payload) => Ok(Some(MeshScopeFrameEffect::Gossip {
                payload,
                close_send: true,
            })),
            LiveSessionAction::Heartbeat => Ok(Some(MeshScopeFrameEffect::Heartbeat {
                acknowledgement: self.live.encode("sync-heartbeat-ack", &[])?,
                close_send: true,
            })),
            LiveSessionAction::DurableBatch(payload) => self.begin_saved_receive(payload, true),
            LiveSessionAction::OwnerWorkspaceOffer(payload) => {
                self.begin_saved_receive(payload, false)
            }
            LiveSessionAction::BlobRequest(payload) => {
                Ok(Some(MeshScopeFrameEffect::BlobRequest { payload }))
            }
            LiveSessionAction::HandoffRequest(payload) => {
                Ok(Some(MeshScopeFrameEffect::HandoffRequest { payload }))
            }
            LiveSessionAction::Snapshot(payload) => {
                let plan = self
                    .live
                    .receive_plan(&LiveSessionAction::Snapshot(payload.clone()))?;
                if !matches!(
                    plan.effects.as_slice(),
                    [
                        LiveSessionEffect::MergeWorkspaceSnapshot,
                        LiveSessionEffect::CloseSend
                    ]
                ) {
                    return Err("Workspace snapshots are only valid for workspace-set".into());
                }
                Ok(Some(MeshScopeFrameEffect::WorkspaceSnapshot {
                    payload,
                    close_send: true,
                }))
            }
        }
    }

    /// Prepare the pending authenticated Automerge payload against host storage.
    /// The prepared engine state is still abortable until durable persistence
    /// finishes through `complete_document_receive`.
    pub fn provide_document(
        &mut self,
        document: &[u8],
        response_proof: Option<Value>,
    ) -> Result<MeshScopeFrameEffect, String> {
        let mut pending = self
            .pending_document_receive
            .take()
            .ok_or("Mesh document receive is not pending")?;
        if pending.prepared.is_some() {
            self.pending_document_receive = Some(pending);
            return Err("Mesh document receive is ready for persistence".into());
        }
        let prepared = match self
            .live
            .prepare_document(&pending.payload, document, response_proof)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                self.pending_document_receive = Some(pending);
                return Err(error);
            }
        };
        let proofs = if prepared
            .proof
            .as_ref()
            .and_then(|p| p.get("kind"))
            .and_then(Value::as_str)
            == Some("workspace-authorization-manifest")
        {
            let result = serde_json::from_value(prepared.proof.clone().unwrap())
                .map_err(|_| "Invalid authorization manifest".to_string())
                .and_then(|manifest| {
                    crate::AuthorizationPageReceiver::new(manifest, &prepared.document, document)
                });
            match result {
                Ok(receiver) => Some(receiver),
                Err(error) => {
                    self.pending_document_receive = Some(pending);
                    return Err(error);
                }
            }
        } else {
            None
        };
        let effect = MeshScopeFrameEffect::DocumentReceive {
            document: prepared.document,
            proof: prepared.proof,
            should_persist: prepared.should_persist,
            accepted_changes: prepared.accepted_changes,
            accepted_hashes: prepared.accepted_hashes,
            heads: prepared.heads,
        };
        pending.prepared = Some(PreparedDocumentReceive {
            engine_prepared: true,
            should_persist: prepared.should_persist,
            response: prepared.response,
            proofs,
            effect: effect.clone(),
        });
        self.pending_document_receive = Some(pending);
        self.continue_proof_receive()
    }

    /// Initial snapshots use the same proof exchange before invitation
    /// admission. No Automerge sync state or durable receipt is advanced.
    pub fn begin_authorization_transfer(
        &mut self,
        candidate: &[u8],
        local: &[u8],
        manifest: Value,
    ) -> Result<MeshScopeFrameEffect, String> {
        if self.pending_document_receive.is_some() {
            return Err("Document receive already pending".into());
        }
        let receiver = crate::AuthorizationPageReceiver::new(
            serde_json::from_value(manifest).map_err(|_| "Invalid authorization manifest")?,
            candidate,
            local,
        )?;
        let effect = MeshScopeFrameEffect::DocumentReceive {
            document: candidate.to_vec(),
            proof: None,
            should_persist: true,
            accepted_changes: 0,
            accepted_hashes: vec![],
            heads: vec![],
        };
        self.pending_document_receive = Some(PendingDocumentReceive {
            payload: vec![],
            prepared: Some(PreparedDocumentReceive {
                engine_prepared: false,
                should_persist: true,
                response: None,
                effect,
                proofs: Some(receiver),
            }),
        });
        self.continue_proof_receive()
    }

    pub fn provide_proof_page(
        &self,
        payload: &[u8],
        document: &[u8],
        authorization: Value,
    ) -> Result<Vec<u8>, String> {
        let request =
            serde_json::from_slice(payload).map_err(|_| "Invalid authorization page request")?;
        let page = crate::authorization_page(document, &authorization, request)?;
        self.live.encode(
            "mesh-proof-page-v1",
            &serde_json::to_vec(&page).map_err(|e| e.to_string())?,
        )
    }

    pub fn accept_proof_page(&mut self, payload: &[u8]) -> Result<MeshScopeFrameEffect, String> {
        if payload.len() > crate::proof_transfer::MAX_PROOF_PAGE_BYTES {
            return Err("Authorization page exceeds payload limit".into());
        }
        let prepared = self
            .pending_document_receive
            .as_mut()
            .and_then(|p| p.prepared.as_mut())
            .ok_or("No document awaiting authorization pages")?;
        let receiver = prepared
            .proofs
            .as_mut()
            .ok_or("No authorization transfer pending")?;
        let request = receiver.request()?.ok_or("Unexpected authorization page")?;
        let cache_key = format!("{}:{}", request.request_id, request.after);
        let page = serde_json::from_slice(payload).map_err(|_| "Invalid authorization page")?;
        if receiver.is_replay(&page)? {
            return self.continue_proof_receive();
        }
        receiver.accept(page)?;
        Ok(MeshScopeFrameEffect::ProofPageReceived {
            cache_key,
            payload: payload.to_vec(),
        })
    }

    pub fn continue_proof_receive(&mut self) -> Result<MeshScopeFrameEffect, String> {
        let prepared = self
            .pending_document_receive
            .as_mut()
            .and_then(|p| p.prepared.as_mut())
            .ok_or("No document awaiting authorization pages")?;
        if let Some(receiver) = &prepared.proofs {
            if let Some(request) = receiver.request()? {
                let cache_key = format!("{}:{}", request.request_id, request.after);
                let frame = self.live.encode(
                    "mesh-proof-request-v1",
                    &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
                )?;
                return Ok(MeshScopeFrameEffect::ProofRequest { frame, cache_key });
            }
            if let MeshScopeFrameEffect::DocumentReceive { proof, .. } = &mut prepared.effect {
                *proof = Some(receiver.bundle()?);
            }
            prepared.proofs = None;
        }
        Ok(prepared.effect.clone())
    }

    /// Complete the durable side of a prepared Automerge receive. A failed
    /// persistence cannot advance sync state or emit its response frame.
    pub fn complete_document_receive(
        &mut self,
        persisted: bool,
    ) -> Result<MeshScopeDocumentCompletion, String> {
        if self
            .pending_document_receive
            .as_ref()
            .and_then(|p| p.prepared.as_ref())
            .is_some_and(|p| p.proofs.is_some())
        {
            return Err("Document authorization transfer is incomplete".into());
        }
        if self
            .pending_document_receive
            .as_ref()
            .ok_or("Mesh document receive is not pending")?
            .prepared
            .is_none()
        {
            return Err("Mesh document receive needs a document".into());
        }
        let pending = self
            .pending_document_receive
            .take()
            .ok_or("Mesh document receive is not pending")?;
        let prepared = pending.prepared.expect("checked above");
        if prepared.should_persist && !persisted {
            self.live.abort_document();
            self.live.reset_document();
            return Err("Mesh document persistence failed".into());
        }
        if prepared.engine_prepared {
            self.live.commit_document()?;
        }
        Ok(MeshScopeDocumentCompletion {
            response: prepared.response,
            close_send: true,
        })
    }

    /// A host rejected the prepared change after authorization validation.
    /// Resetting the sync engine preserves the existing retry-convergence path.
    pub fn reject_document_receive(&mut self) -> Result<(), String> {
        if self.pending_document_receive.take().is_none() {
            return Err("Mesh document receive is not pending".into());
        }
        self.live.abort_document();
        self.live.reset_document();
        Ok(())
    }

    pub fn reset_document(&mut self) {
        self.live.reset_document();
    }

    /// Acknowledge durable frames only after the host completed their storage
    /// or authority import work. This preserves the pre-existing send order.
    pub fn complete_saved_receive(
        &mut self,
        persisted: bool,
    ) -> Result<MeshScopeDocumentCompletion, String> {
        let pending = self
            .pending_saved_receive
            .take()
            .ok_or("Mesh durable receive is not pending")?;
        if !persisted {
            return Err("Mesh durable receive was not persisted".into());
        }
        Ok(MeshScopeDocumentCompletion {
            response: Some(self.live.acknowledge_saved(&pending.payload)?),
            close_send: true,
        })
    }

    /// Build the next authenticated Automerge frame from the host's current
    /// document. The caller performs the returned transport send.
    pub fn publish_frame(
        &mut self,
        document: &[u8],
        proof: Option<Value>,
    ) -> Result<Option<Vec<u8>>, String> {
        if self.pending_document_receive.is_some() {
            return Ok(None);
        }
        self.live.generate_document(document, proof)
    }

    /// Build the complete publish transaction in wire order. Hosts send the
    /// document frame then each control frame, then report whether all sends
    /// succeeded so duplicate control state is not suppressed prematurely.
    pub fn prepare_publish(
        &mut self,
        document: &[u8],
        proof: Option<Value>,
        authorization: Option<Value>,
        chat: Option<Value>,
        mesh: Option<Value>,
    ) -> Result<LiveSessionPublishPlan, String> {
        if self.pending_document_receive.is_some() {
            return self.live.prepare_control_publish(None, chat, mesh);
        }
        self.live
            .prepare_publish(document, proof, authorization, chat, mesh)
    }

    pub fn finish_publish(&mut self, control_snapshot: &[u8], all_frames_sent: bool) {
        self.live.finish_publish(control_snapshot, all_frames_sent);
    }

    fn begin_saved_receive(
        &mut self,
        payload: Vec<u8>,
        durable_batch: bool,
    ) -> Result<Option<MeshScopeFrameEffect>, String> {
        if self.pending_saved_receive.is_some() {
            return Err("Mesh durable receive is pending persistence".into());
        }
        self.pending_saved_receive = Some(PendingSavedReceive {
            payload: payload.clone(),
        });
        Ok(Some(if durable_batch {
            MeshScopeFrameEffect::DurableBatch { payload }
        } else {
            MeshScopeFrameEffect::OwnerWorkspaceOffer { payload }
        }))
    }
}

#[cfg(test)]
mod tests {
    use automerge::{AutoCommit, ROOT, transaction::Transactable};

    use super::*;

    #[test]
    fn document_receive_requires_persistence_before_committing_and_replying() {
        let mut source_document = AutoCommit::new();
        source_document.put(ROOT, "id", "board").unwrap();
        let baseline = source_document.save();
        source_document.put(ROOT, "title", "new title").unwrap();
        let changed = source_document.save();

        let mut source = MeshScopeRuntime::new("board", "secret").unwrap();
        source.start_document_sync("source", "receiver").unwrap();
        let frame = source
            .publish_frame(&changed, Some(serde_json::json!({ "proof": "signed" })))
            .unwrap()
            .unwrap();

        let mut receiver = MeshScopeRuntime::new("board", "secret").unwrap();
        receiver.start_document_sync("receiver", "source").unwrap();
        assert!(matches!(
            receiver.receive_frame(&frame).unwrap(),
            Some(MeshScopeFrameEffect::NeedDocument)
        ));
        let effect = receiver.provide_document(&baseline, None).unwrap();
        let MeshScopeFrameEffect::DocumentReceive {
            document: _,
            should_persist,
            ..
        } = effect
        else {
            panic!("expected document receive");
        };
        assert!(should_persist);
        assert!(receiver.complete_document_receive(false).is_err());
        assert!(matches!(
            receiver.receive_frame(&frame).unwrap(),
            Some(MeshScopeFrameEffect::NeedDocument)
        ));
        let effect = receiver.provide_document(&baseline, None).unwrap();
        let MeshScopeFrameEffect::DocumentReceive { document, .. } = effect else {
            panic!("expected document receive retry");
        };
        AutoCommit::load(&document).unwrap();
        let completion = receiver.complete_document_receive(true).unwrap();
        assert!(completion.close_send);
    }

    #[test]
    fn heartbeat_and_gossip_return_authenticated_host_effects() {
        let mut runtime = MeshScopeRuntime::new("board", "secret").unwrap();
        let heartbeat = LiveWorkspaceSession::new("board", "secret")
            .unwrap()
            .encode("sync-heartbeat", &[])
            .unwrap();
        assert!(matches!(
            runtime.receive_frame(&heartbeat).unwrap(),
            Some(MeshScopeFrameEffect::Heartbeat {
                close_send: true,
                ..
            })
        ));
        let gossip = LiveWorkspaceSession::new("board", "secret")
            .unwrap()
            .encode("mesh-iroh-gossip", b"packet")
            .unwrap();
        assert!(matches!(
            runtime.receive_frame(&gossip).unwrap(),
            Some(MeshScopeFrameEffect::Gossip { payload, close_send: true }) if payload == b"packet"
        ));
    }

    #[test]
    fn durable_ack_waits_for_host_completion_and_snapshots_are_scope_bound() {
        let sender = LiveWorkspaceSession::new("board", "secret").unwrap();
        let durable = sender.encode("mesh-durable-batch", b"batch").unwrap();
        let mut runtime = MeshScopeRuntime::new("board", "secret").unwrap();
        assert!(matches!(
            runtime.receive_frame(&durable).unwrap(),
            Some(MeshScopeFrameEffect::DurableBatch { payload }) if payload == b"batch"
        ));
        assert!(runtime.complete_saved_receive(false).is_err());
        assert!(matches!(
            runtime.receive_frame(&durable).unwrap(),
            Some(MeshScopeFrameEffect::DurableBatch { .. })
        ));
        assert!(
            runtime
                .complete_saved_receive(true)
                .unwrap()
                .response
                .is_some()
        );

        let snapshot = sender.encode("sync-update", b"snapshot").unwrap();
        assert!(runtime.receive_frame(&snapshot).is_err());
    }
}
