use meta_mesh_core::{
    LiveSessionEffect, LiveSessionPublishPlan, MeshScopeFrameEffect, MeshScopeRuntime,
};
use serde_json::Value;

/// Durable product state supplied by a native consumer such as lighthouse.
pub struct NativeScopeSnapshot {
    pub document: Vec<u8>,
    pub authorization: Option<Value>,
    pub chat: Option<Value>,
    pub mesh: Option<Value>,
}

/// Product validation and persistence stay outside the mesh protocol.
pub trait NativeScopeHost {
    fn snapshot(&mut self) -> Result<NativeScopeSnapshot, String>;
    fn persist_document(
        &mut self,
        document: &[u8],
        proof: Option<&Value>,
        accepted_hashes: &[String],
    ) -> Result<(), String>;
    fn merge_authorization(&mut self, value: &Value) -> Result<(), String>;
    fn merge_chat(&mut self, value: &Value) -> Result<(), String>;
    fn merge_mesh(&mut self, value: &Value) -> Result<(), String>;
    fn merge_durable_batch(&mut self, bytes: &[u8]) -> Result<(), String>;
    fn merge_owner_offer(&mut self, bytes: &[u8]) -> Result<(), String>;
    fn receive_gossip(&mut self, bytes: &[u8]) -> Result<(), String>;
    fn receive_blob_request(&mut self, _: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Err("Unsupported blob request".into())
    }
    fn receive_handoff_request(&mut self, _: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Err("Unsupported handoff request".into())
    }
    fn merge_workspace_snapshot(&mut self, _: &[u8]) -> Result<(), String> {
        Err("Unsupported workspace snapshot".into())
    }
}

/// Native I/O adapter for the same Rust scope runtime used by Match's browser.
/// One instance belongs to one authenticated remote device session.
pub struct NativeScopePeer<H: NativeScopeHost> {
    runtime: MeshScopeRuntime,
    host: H,
}

impl<H: NativeScopeHost> NativeScopePeer<H> {
    pub fn new(
        scope_id: &str,
        secret: &str,
        local_device_id: &str,
        remote_device_id: &str,
        host: H,
    ) -> Result<Self, String> {
        let mut runtime = MeshScopeRuntime::new(scope_id, secret)?;
        runtime.start_document_sync(local_device_id, remote_device_id)?;
        Ok(Self { runtime, host })
    }

    pub fn host(&self) -> &H {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Return the reply frame only after product storage has accepted the change.
    pub fn receive(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let Some(effect) = self.runtime.receive_frame(frame)? else {
            return Ok(None);
        };
        match effect {
            MeshScopeFrameEffect::NeedDocument => {
                let snapshot = match self.host.snapshot() {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        let _ = self.runtime.reject_document_receive();
                        return Err(error);
                    }
                };
                let prepared = match self
                    .runtime
                    .provide_document(&snapshot.document, snapshot.authorization)
                {
                    Ok(MeshScopeFrameEffect::DocumentReceive {
                        document,
                        proof,
                        should_persist,
                        accepted_hashes,
                        ..
                    }) => (document, proof, should_persist, accepted_hashes),
                    Ok(_) => {
                        self.runtime.reject_document_receive()?;
                        return Err("Invalid document receive plan".into());
                    }
                    Err(error) => {
                        self.runtime.reject_document_receive()?;
                        return Err(error);
                    }
                };
                if prepared.2 {
                    if let Err(error) =
                        self.host
                            .persist_document(&prepared.0, prepared.1.as_ref(), &prepared.3)
                    {
                        self.runtime.reject_document_receive()?;
                        return Err(error);
                    }
                }
                Ok(self.runtime.complete_document_receive(true)?.response)
            }
            MeshScopeFrameEffect::Control {
                control, effects, ..
            } => {
                for effect in effects {
                    match effect {
                        LiveSessionEffect::MergeAuthorization => {
                            self.host.merge_authorization(
                                control
                                    .authorization
                                    .as_ref()
                                    .ok_or("Missing authorization control")?,
                            )?;
                            self.runtime.reset_document();
                        }
                        LiveSessionEffect::MergeChat => self
                            .host
                            .merge_chat(control.chat.as_ref().ok_or("Missing chat control")?)?,
                        LiveSessionEffect::MergeMesh => self
                            .host
                            .merge_mesh(control.mesh.as_ref().ok_or("Missing mesh control")?)?,
                        LiveSessionEffect::CloseSend => (),
                        _ => return Err("Unsupported native control effect".into()),
                    }
                }
                Ok(None)
            }
            MeshScopeFrameEffect::Gossip { payload, .. } => {
                self.host.receive_gossip(&payload)?;
                Ok(None)
            }
            MeshScopeFrameEffect::Heartbeat {
                acknowledgement, ..
            } => Ok(Some(acknowledgement)),
            MeshScopeFrameEffect::DurableBatch { payload } => {
                self.saved(payload, |host, bytes| host.merge_durable_batch(bytes))
            }
            MeshScopeFrameEffect::OwnerWorkspaceOffer { payload } => {
                self.saved(payload, |host, bytes| host.merge_owner_offer(bytes))
            }
            MeshScopeFrameEffect::BlobRequest { payload } => {
                self.host.receive_blob_request(&payload)
            }
            MeshScopeFrameEffect::HandoffRequest { payload } => {
                self.host.receive_handoff_request(&payload)
            }
            MeshScopeFrameEffect::WorkspaceSnapshot { payload, .. } => {
                self.host.merge_workspace_snapshot(&payload)?;
                Ok(None)
            }
            MeshScopeFrameEffect::DocumentReceive { .. } => {
                Err("Invalid native document receive state".into())
            }
        }
    }

    pub fn prepare_publish(&mut self) -> Result<LiveSessionPublishPlan, String> {
        let snapshot = self.host.snapshot()?;
        self.runtime.prepare_publish(
            &snapshot.document,
            snapshot.authorization.clone(),
            snapshot.authorization,
            snapshot.chat,
            snapshot.mesh,
        )
    }

    pub fn finish_publish(&mut self, snapshot: &[u8], all_frames_sent: bool) {
        self.runtime.finish_publish(snapshot, all_frames_sent);
    }

    fn saved(
        &mut self,
        payload: Vec<u8>,
        persist: impl FnOnce(&mut H, &[u8]) -> Result<(), String>,
    ) -> Result<Option<Vec<u8>>, String> {
        if let Err(error) = persist(&mut self.host, &payload) {
            let _ = self.runtime.complete_saved_receive(false);
            return Err(error);
        }
        Ok(self.runtime.complete_saved_receive(true)?.response)
    }
}

#[cfg(test)]
mod tests {
    use automerge::{AutoCommit, ROOT, transaction::Transactable};

    use super::*;

    struct Host {
        document: Vec<u8>,
        fail_persist: bool,
        persisted: usize,
    }

    impl NativeScopeHost for Host {
        fn snapshot(&mut self) -> Result<NativeScopeSnapshot, String> {
            Ok(NativeScopeSnapshot {
                document: self.document.clone(),
                authorization: None,
                chat: None,
                mesh: None,
            })
        }

        fn persist_document(
            &mut self,
            document: &[u8],
            _: Option<&Value>,
            _: &[String],
        ) -> Result<(), String> {
            if self.fail_persist {
                return Err("disk unavailable".into());
            }
            self.document = document.to_vec();
            self.persisted += 1;
            Ok(())
        }

        fn merge_authorization(&mut self, _: &Value) -> Result<(), String> {
            Ok(())
        }
        fn merge_chat(&mut self, _: &Value) -> Result<(), String> {
            Ok(())
        }
        fn merge_mesh(&mut self, _: &Value) -> Result<(), String> {
            Ok(())
        }
        fn merge_durable_batch(&mut self, _: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn merge_owner_offer(&mut self, _: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn receive_gossip(&mut self, _: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn rejected_disk_write_does_not_acknowledge_document() {
        let mut document = AutoCommit::new();
        document.put(ROOT, "id", "board").unwrap();
        let baseline = document.save();
        document.put(ROOT, "title", "updated").unwrap();

        let mut source = MeshScopeRuntime::new("board", "secret").unwrap();
        source.start_document_sync("source", "receiver").unwrap();
        let frame = source
            .publish_frame(
                &document.save(),
                Some(serde_json::json!({"proof": "signed"})),
            )
            .unwrap()
            .unwrap();
        let mut receiver = NativeScopePeer::new(
            "board",
            "secret",
            "receiver",
            "source",
            Host {
                document: baseline.clone(),
                fail_persist: true,
                persisted: 0,
            },
        )
        .unwrap();

        assert_eq!(receiver.receive(&frame).unwrap_err(), "disk unavailable");
        assert_eq!(receiver.host().document, baseline);

        receiver.host_mut().fail_persist = false;
        let response = receiver.receive(&frame).unwrap();
        assert!(response.is_some());
        assert_eq!(receiver.host().persisted, 1);
        AutoCommit::load(&receiver.host().document).unwrap();
    }
}
