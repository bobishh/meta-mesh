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

/// Product-authorized new workspace. Preparing this value must verify the
/// authenticated owner/controller and signed invitation without mutating
/// durable storage. Final merge still validates all resolved change proofs.
pub struct NativeOwnerOfferSnapshot {
    pub workspace_id: String,
    pub candidate: Vec<u8>,
    pub local: Vec<u8>,
    pub manifest: Value,
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
    fn prepare_owner_offer(
        &mut self,
        _: &[u8],
    ) -> Result<Option<NativeOwnerOfferSnapshot>, String> {
        Ok(None)
    }
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
    /// Untrusted staging cache; callers must revalidate pages and signatures
    /// after restart. These writes never publish or acknowledge a document.
    fn read_proof_page(&mut self, _: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn write_proof_page(&mut self, _: &str, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn clear_proof_pages(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Native I/O adapter for the same Rust scope runtime used by Match's browser.
/// One instance belongs to one authenticated remote device session.
pub struct NativeScopePeer<H: NativeScopeHost> {
    runtime: MeshScopeRuntime,
    host: H,
    secret: String,
    owner_offer: Option<PendingOwnerOffer>,
    proof_paging_supported: bool,
}

struct PendingOwnerOffer {
    runtime: MeshScopeRuntime,
    payload: Vec<u8>,
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
        Ok(Self {
            runtime,
            host,
            secret: secret.into(),
            owner_offer: None,
            proof_paging_supported: true,
        })
    }

    pub fn host(&self) -> &H {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }
    pub fn set_proof_paging_supported(&mut self, supported: bool) {
        self.proof_paging_supported = supported;
        self.runtime.set_proof_paging_supported(supported);
    }

    /// Abort an incomplete document/proof receive after its RPC exchange is
    /// lost. No product storage was committed while this receive was pending;
    /// the next publish restarts Automerge sync and revalidates staged pages.
    pub fn abort_incomplete_document_receive(&mut self) -> bool {
        if self.owner_offer.take().is_some() {
            let _ = self.runtime.complete_saved_receive(false);
            return true;
        }
        self.runtime.reject_document_receive().is_ok()
    }

    /// Return the reply frame only after product storage has accepted the change.
    pub fn receive(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if self.owner_offer.is_some()
            && meta_mesh_core::PairingCodec::inspect(frame)?.frame_type == "mesh-proof-page-v1"
        {
            let result = self.receive_owner_page(frame);
            if result.is_err() {
                self.owner_offer = None;
                let _ = self.runtime.complete_saved_receive(false);
            }
            return result;
        }
        let Some(mut effect) = self.runtime.receive_frame(frame)? else {
            return Ok(None);
        };
        loop {
            let result = match effect {
                MeshScopeFrameEffect::ProofSource { payload } => {
                    if let Some(frame) = self.runtime.provide_cached_proof_page(&payload)? {
                        return Ok(Some(frame));
                    }
                    let snapshot = self.host.snapshot()?;
                    return Ok(Some(
                        self.runtime.provide_proof_page(
                            &payload,
                            &snapshot.document,
                            snapshot
                                .authorization
                                .ok_or("Missing authorization proof history")?,
                        )?,
                    ));
                }
                MeshScopeFrameEffect::ProofRequest { frame, cache_key } => {
                    // Staging is an optimization only. A cache outage must not
                    // strand this authenticated transfer; cached bytes still
                    // pass the normal receiver checks before they can advance it.
                    if let Some(cached) = self.host.read_proof_page(&cache_key).unwrap_or(None) {
                        match self.runtime.accept_proof_page(&cached) {
                            Ok(next) => {
                                effect = next;
                                continue;
                            }
                            Err(_) => return Ok(Some(frame)),
                        }
                    }
                    return Ok(Some(frame));
                }
                MeshScopeFrameEffect::ProofPageReceived { cache_key, payload } => {
                    // The receiver has validated and retained this page in
                    // memory. Failure to persist its untrusted cache copy must
                    // not block complete authorization admission.
                    let _ = self.host.write_proof_page(&cache_key, &payload);
                    effect = self.runtime.continue_proof_receive()?;
                    continue;
                }
                MeshScopeFrameEffect::NeedDocument => {
                    let snapshot = match self.host.snapshot() {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            let _ = self.runtime.reject_document_receive();
                            return Err(error);
                        }
                    };
                    effect = match self
                        .runtime
                        .provide_document(&snapshot.document, snapshot.authorization)
                    {
                        Ok(effect) => effect,
                        Err(error) => {
                            self.runtime.reject_document_receive()?;
                            return Err(error);
                        }
                    };
                    continue;
                }
                MeshScopeFrameEffect::DocumentReceive {
                    document,
                    proof,
                    should_persist,
                    accepted_hashes,
                    ..
                } => {
                    if should_persist {
                        if let Err(error) =
                            self.host
                                .persist_document(&document, proof.as_ref(), &accepted_hashes)
                        {
                            self.runtime.reject_document_receive()?;
                            let _ = self.host.clear_proof_pages();
                            return Err(error);
                        }
                    }
                    return Ok(self.runtime.complete_document_receive(true)?.response);
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
                    self.begin_owner_offer(payload)
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
            };
            return result;
        }
    }

    fn begin_owner_offer(&mut self, payload: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        let result = (|| {
            let Some(snapshot) = self.host.prepare_owner_offer(&payload)? else {
                return self.saved(payload, |host, bytes| host.merge_owner_offer(bytes));
            };
            if !self.proof_paging_supported {
                return Err("Peer did not negotiate proof paging; update the app".into());
            }
            let mut runtime = MeshScopeRuntime::new(&snapshot.workspace_id, &self.secret)?;
            let effect = runtime.begin_authorization_transfer(
                &snapshot.candidate,
                &snapshot.local,
                snapshot.manifest,
            )?;
            self.owner_offer = Some(PendingOwnerOffer { runtime, payload });
            self.advance_owner_offer(effect)
        })();
        if result.is_err() {
            self.owner_offer = None;
            let _ = self.runtime.complete_saved_receive(false);
        }
        result
    }

    fn receive_owner_page(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let effect = self
            .owner_offer
            .as_mut()
            .ok_or("Owner offer is not pending")?
            .runtime
            .receive_frame(frame)?
            .ok_or("Missing owner proof page")?;
        self.advance_owner_offer(effect)
    }

    fn advance_owner_offer(
        &mut self,
        mut effect: MeshScopeFrameEffect,
    ) -> Result<Option<Vec<u8>>, String> {
        loop {
            let pending = self
                .owner_offer
                .as_mut()
                .ok_or("Owner offer is not pending")?;
            match effect {
                MeshScopeFrameEffect::ProofRequest { frame, cache_key } => {
                    if let Some(cached) = self.host.read_proof_page(&cache_key).unwrap_or(None) {
                        if let Ok(next) = pending.runtime.accept_proof_page(&cached) {
                            effect = next;
                            continue;
                        }
                    }
                    return Ok(Some(frame));
                }
                MeshScopeFrameEffect::ProofPageReceived { cache_key, payload } => {
                    let _ = self.host.write_proof_page(&cache_key, &payload);
                    effect = pending.runtime.continue_proof_receive()?;
                }
                MeshScopeFrameEffect::DocumentReceive { proof, .. } => {
                    let mut value: Value = serde_json::from_slice(&pending.payload)
                        .map_err(|_| "Invalid owner offer")?;
                    let workspace = value
                        .get_mut("workspace")
                        .and_then(Value::as_object_mut)
                        .ok_or("Invalid owner offer workspace")?;
                    workspace.insert(
                        "authorization".into(),
                        proof.ok_or("Missing owner offer proofs")?,
                    );
                    let payload = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
                    self.owner_offer = None;
                    // The outer runtime still binds its receipt to the exact
                    // original offer, while product admission sees full proofs.
                    return self.saved(payload, |host, bytes| host.merge_owner_offer(bytes));
                }
                _ => return Err("Unexpected owner proof transfer state".into()),
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
    use std::collections::HashMap;

    use automerge::{AutoCommit, ROOT, transaction::Transactable};
    use meta_mesh_core::{
        ChangeAdmissionChange, ChangeAdmissionFlowInput, DEFAULT_SIGNATURE_DOMAIN,
        DeviceCertificatePayload, LiveWorkspaceSession, PairingCodec, WorkspaceAuthority,
        WorkspaceWriteAuthorizationSnapshot, authorization_record_pages,
        plan_change_admission_flow, public_key_from_seed, public_key_id, sign_device_certificate,
        sign_json_envelope,
    };

    use super::*;

    struct Host {
        document: Vec<u8>,
        fail_persist: bool,
        persisted: usize,
        accepted_changes: usize,
        fail_saved: bool,
        saved: usize,
        fail_cache_read: bool,
        fail_cache_write: bool,
        proof_pages: HashMap<String, Vec<u8>>,
        admission_snapshot: Option<WorkspaceWriteAuthorizationSnapshot>,
        approve_owner_offer: bool,
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
            proof: Option<&Value>,
            accepted_hashes: &[String],
        ) -> Result<(), String> {
            if self.fail_persist {
                return Err("disk unavailable".into());
            }
            if let Some(snapshot) = &self.admission_snapshot {
                let proof = proof.ok_or("missing authorization bundle")?;
                let pages = authorization_record_pages(proof)?;
                let mut incoming = AutoCommit::load(document).map_err(|error| error.to_string())?;
                let changes = incoming
                    .get_changes(&[])
                    .iter()
                    .filter(|change| accepted_hashes.contains(&change.hash().to_string()))
                    .map(|change| ChangeAdmissionChange {
                        hash: change.hash().to_string(),
                        dependencies: change.deps().iter().map(ToString::to_string).collect(),
                        actor: change.actor_id().to_hex_string(),
                        message: change.message().unwrap_or_default().to_string(),
                    })
                    .collect::<Vec<_>>();
                let plan = plan_change_admission_flow(
                    ChangeAdmissionFlowInput {
                        records: vec![],
                        record_pages: Some(pages),
                        known_hashes: vec![],
                        changes: changes.clone(),
                        snapshot: WorkspaceWriteAuthorizationSnapshot {
                            document: document.to_vec(),
                            ..snapshot.clone()
                        },
                    },
                    0,
                )?;
                if plan.unsigned_error.is_some() || plan.incoming_changes.len() != changes.len() {
                    return Err("workspace change authorization rejected".into());
                }
            }
            self.document = document.to_vec();
            self.persisted += 1;
            self.accepted_changes += accepted_hashes.len();
            Ok(())
        }

        fn read_proof_page(&mut self, key: &str) -> Result<Option<Vec<u8>>, String> {
            if self.fail_cache_read {
                Err("staging read failed".into())
            } else {
                Ok(self.proof_pages.get(key).cloned())
            }
        }

        fn write_proof_page(&mut self, key: &str, payload: &[u8]) -> Result<(), String> {
            if self.fail_cache_write {
                Err("staging write failed".into())
            } else {
                self.proof_pages.insert(key.into(), payload.into());
                Ok(())
            }
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
            if self.fail_saved {
                return Err("durable store unavailable".into());
            }
            self.saved += 1;
            Ok(())
        }
        fn prepare_owner_offer(
            &mut self,
            bytes: &[u8],
        ) -> Result<Option<NativeOwnerOfferSnapshot>, String> {
            let value: Value = serde_json::from_slice(bytes).map_err(|_| "Invalid owner offer")?;
            let snapshot = self
                .admission_snapshot
                .as_ref()
                .ok_or("Missing owner authority")?;
            if !self.approve_owner_offer
                || value["controllerPersonId"] != snapshot.genesis_owner.person_id
                || value["workspace"]["id"] != snapshot.workspace_id
            {
                return Err("Unapproved owner offer".into());
            }
            Ok(Some(NativeOwnerOfferSnapshot {
                workspace_id: snapshot.workspace_id.clone(),
                candidate: snapshot.document.clone(),
                local: self.document.clone(),
                manifest: value["workspace"]["authorization"].clone(),
            }))
        }
        fn merge_owner_offer(&mut self, bytes: &[u8]) -> Result<(), String> {
            if self.fail_saved {
                return Err("durable store unavailable".into());
            }
            let value: Value = serde_json::from_slice(bytes).map_err(|_| "Invalid owner offer")?;
            let candidate = self
                .admission_snapshot
                .as_ref()
                .ok_or("Missing owner authority")?
                .document
                .clone();
            let mut local = AutoCommit::load(&self.document).map_err(|e| e.to_string())?;
            let heads = local.get_heads();
            let mut remote = AutoCommit::load(&candidate).map_err(|e| e.to_string())?;
            let hashes = remote
                .get_changes(&heads)
                .iter()
                .map(|change| change.hash().to_string())
                .collect::<Vec<_>>();
            self.persist_document(
                &candidate,
                value.pointer("/workspace/authorization"),
                &hashes,
            )?;
            self.saved += 1;
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
                accepted_changes: 0,
                fail_saved: false,
                saved: 0,
                fail_cache_read: false,
                fail_cache_write: false,
                proof_pages: HashMap::new(),
                admission_snapshot: None,
                approve_owner_offer: false,
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

    #[test]
    fn durable_batch_ack_is_emitted_only_after_storage_succeeds() {
        let payload = b"durable batch";
        let sender = LiveWorkspaceSession::new("board", "secret").unwrap();
        let frame = sender.encode("mesh-durable-batch", payload).unwrap();
        let mut receiver = NativeScopePeer::new(
            "board",
            "secret",
            "receiver",
            "source",
            Host {
                document: AutoCommit::new().save(),
                fail_persist: false,
                persisted: 0,
                accepted_changes: 0,
                fail_saved: true,
                saved: 0,
                fail_cache_read: false,
                fail_cache_write: false,
                proof_pages: HashMap::new(),
                admission_snapshot: None,
                approve_owner_offer: false,
            },
        )
        .unwrap();

        assert_eq!(
            receiver.receive(&frame),
            Err("durable store unavailable".into())
        );
        assert_eq!(receiver.host().saved, 0);

        receiver.host_mut().fail_saved = false;
        let acknowledgement = receiver
            .receive(&frame)
            .unwrap()
            .expect("ACK after durable storage");
        assert_eq!(receiver.host().saved, 1);
        sender
            .verify_saved_receipt(&acknowledgement, payload)
            .unwrap();
    }

    fn signed_proof_fixture_with_pages(
        multi_page: bool,
    ) -> (Vec<u8>, Vec<u8>, Value, WorkspaceWriteAuthorizationSnapshot) {
        let owner_seed = [41u8; 32];
        let device_seed = [42u8; 32];
        let owner_public_key = public_key_from_seed(&owner_seed).unwrap();
        let person_id = public_key_id(&owner_public_key).unwrap();
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &owner_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let owner = WorkspaceAuthority {
            person_id: person_id.clone(),
            public_key: owner_public_key.clone(),
            certificates: vec![certificate.clone()],
        };
        let mut baseline_doc = AutoCommit::new();
        baseline_doc.put(ROOT, "id", "board").unwrap();
        let baseline = baseline_doc.save();
        let mut candidate_doc = AutoCommit::load(&baseline).unwrap();
        candidate_doc.put(ROOT, "title", "signed update").unwrap();
        let candidate = candidate_doc.save();
        let hash = candidate_doc.get_heads()[0].to_string();
        let sign_record = |hashes: Vec<String>| {
            let signed = sign_json_envelope(
                &device_seed,
                serde_json::json!({
                    "kind": "workspace-changes",
                    "version": 1,
                    "workspaceId": "board",
                    "hashes": hashes,
                    "personId": person_id,
                    "deviceId": device_id,
                }),
                &device_id,
                DEFAULT_SIGNATURE_DOMAIN,
            )
            .unwrap();
            serde_json::json!({
                "signed": signed,
                "publicKey": owner_public_key,
                "certificates": [certificate],
            })
        };
        let records = if multi_page {
            (0..15)
                .map(|record_index| {
                    let mut hashes = vec![hash.clone()];
                    hashes.extend(
                        (0..255).map(|item| format!("{:064x}", 10_000 + record_index * 255 + item)),
                    );
                    sign_record(hashes)
                })
                .collect::<Vec<_>>()
        } else {
            // Repeated identical evidence forces the manifest/page path while
            // remaining valid under the same signer identity.
            vec![sign_record(vec![hash]); 1_000]
        };
        let proof = serde_json::json!({
            "version": 1,
            "authority": {"genesisOwner": owner},
            "records": records,
        });
        let snapshot = WorkspaceWriteAuthorizationSnapshot {
            workspace_id: "board".into(),
            genesis_owner: owner.clone(),
            genesis_epoch: 1,
            expected_current_owner: owner,
            document: candidate.clone(),
            ownership_transfers: vec![],
            succession_claims: vec![],
            revocations: vec![],
            device_revocations: vec![],
            departures: vec![],
        };
        (baseline, candidate, proof, snapshot)
    }

    fn proof_host(
        baseline: Vec<u8>,
        snapshot: WorkspaceWriteAuthorizationSnapshot,
        fail_cache_read: bool,
        fail_cache_write: bool,
    ) -> Host {
        Host {
            document: baseline,
            fail_persist: false,
            persisted: 0,
            accepted_changes: 0,
            fail_saved: false,
            saved: 0,
            fail_cache_read,
            fail_cache_write,
            proof_pages: HashMap::new(),
            admission_snapshot: Some(snapshot),
            approve_owner_offer: false,
        }
    }

    fn proof_page(
        source: &mut MeshScopeRuntime,
        frame: &[u8],
        candidate: &[u8],
        proof: &Value,
    ) -> Vec<u8> {
        let Some(MeshScopeFrameEffect::ProofSource { payload }) =
            source.receive_frame(frame).unwrap()
        else {
            panic!("receiver did not request a proof page")
        };
        source
            .provide_proof_page(&payload, candidate, proof.clone())
            .unwrap()
    }

    fn signed_transfer(
        fail_cache_read: bool,
        fail_cache_write: bool,
    ) -> (
        NativeScopePeer<Host>,
        MeshScopeRuntime,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Value,
    ) {
        signed_transfer_with_pages(fail_cache_read, fail_cache_write, false)
    }

    fn signed_transfer_with_pages(
        fail_cache_read: bool,
        fail_cache_write: bool,
        multi_page: bool,
    ) -> (
        NativeScopePeer<Host>,
        MeshScopeRuntime,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Value,
    ) {
        let (baseline, candidate, proof, snapshot) = signed_proof_fixture_with_pages(multi_page);
        let mut source = MeshScopeRuntime::new("board", "secret").unwrap();
        source.start_document_sync("source", "receiver").unwrap();
        let document_frame = source
            .publish_frame(&candidate, Some(proof.clone()))
            .unwrap()
            .unwrap();
        let receiver = NativeScopePeer::new(
            "board",
            "secret",
            "receiver",
            "source",
            proof_host(
                baseline.clone(),
                snapshot,
                fail_cache_read,
                fail_cache_write,
            ),
        )
        .unwrap();
        (receiver, source, document_frame, baseline, candidate, proof)
    }

    fn request_for_proof(
        receiver: &mut NativeScopePeer<Host>,
        source: &mut MeshScopeRuntime,
        mut incoming: Vec<u8>,
        candidate: &[u8],
        proof: &Value,
    ) -> Vec<u8> {
        for _ in 0..4 {
            let reply = receiver.receive(&incoming).unwrap().expect("sync reply");
            if PairingCodec::inspect(&reply).unwrap().frame_type == "mesh-proof-request-v1" {
                return reply;
            }
            let Some(MeshScopeFrameEffect::NeedDocument) = source.receive_frame(&reply).unwrap()
            else {
                panic!("source expected sync document")
            };
            let effect = source
                .provide_document(candidate, Some(proof.clone()))
                .unwrap();
            assert!(matches!(
                effect,
                MeshScopeFrameEffect::DocumentReceive { .. }
            ));
            incoming = source
                .complete_document_receive(true)
                .unwrap()
                .response
                .expect("source sync response");
        }
        panic!("sync did not reach authorization page request")
    }

    fn owner_offer_fixture() -> (
        NativeScopePeer<Host>,
        MeshScopeRuntime,
        LiveWorkspaceSession,
        Vec<u8>,
        Vec<u8>,
        Value,
    ) {
        let (baseline, candidate, proof, snapshot) = signed_proof_fixture_with_pages(true);
        let manifest = meta_mesh_core::authorization_export(&candidate, &proof).unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "controllerPersonId": snapshot.genesis_owner.person_id,
            "workspaceId": "board", "workspace": {"id": "board", "authorization": manifest},
        }))
        .unwrap();
        let mut host = proof_host(baseline, snapshot, false, false);
        host.approve_owner_offer = true;
        let receiver =
            NativeScopePeer::new("existing-board", "secret", "receiver", "source", host).unwrap();
        let source = MeshScopeRuntime::new("board", "secret").unwrap();
        let sender = LiveWorkspaceSession::new("existing-board", "secret").unwrap();
        let frame = sender
            .encode("mesh-owner-workspace-offer", &payload)
            .unwrap();
        (receiver, source, sender, frame, candidate, proof)
    }

    #[test]
    fn owner_offer_pages_commit_before_original_offer_receipt_and_replay_after_timeout() {
        let (mut receiver, mut source, sender, frame, candidate, proof) = owner_offer_fixture();
        let first = receiver.receive(&frame).unwrap().unwrap();
        assert_eq!(receiver.host().saved, 0);
        let page = proof_page(&mut source, &first, &candidate, &proof);
        let second = receiver.receive(&page).unwrap().unwrap();
        assert_eq!(
            PairingCodec::inspect(&second).unwrap().frame_type,
            "mesh-proof-request-v1"
        );
        assert_eq!(receiver.host().saved, 0);
        assert!(receiver.abort_incomplete_document_receive());
        let replay = receiver.receive(&frame).unwrap().unwrap();
        let after: Value = serde_json::from_slice(
            &PairingCodec::decode(&replay, "mesh-proof-request-v1", "secret").unwrap(),
        )
        .unwrap();
        assert!(!after["after"].as_str().unwrap().is_empty());
        let final_page = proof_page(&mut source, &replay, &candidate, &proof);
        let receipt = receiver.receive(&final_page).unwrap().unwrap();
        assert_eq!(receiver.host().saved, 1);
        assert_eq!(receiver.host().document, candidate);
        let original =
            PairingCodec::decode(&frame, "mesh-owner-workspace-offer", "secret").unwrap();
        sender.verify_saved_receipt(&receipt, &original).unwrap();
        assert!(receipt.len() < 256);
    }

    #[test]
    fn unapproved_owner_offer_and_forged_or_missing_pages_never_ack_or_persist() {
        let (mut receiver, _, _, frame, _, _) = owner_offer_fixture();
        receiver.host_mut().approve_owner_offer = false;
        assert!(receiver.receive(&frame).is_err());
        assert_eq!(receiver.host().saved, 0);
        for corruption in ["missing", "forged"] {
            let (mut receiver, mut source, _, frame, candidate, proof) = owner_offer_fixture();
            let baseline = receiver.host().document.clone();
            let mut request = receiver.receive(&frame).unwrap().unwrap();
            loop {
                let page = proof_page(&mut source, &request, &candidate, &proof);
                let mut value: Value = serde_json::from_slice(
                    &PairingCodec::decode(&page, "mesh-proof-page-v1", "secret").unwrap(),
                )
                .unwrap();
                if corruption == "forged" {
                    value["records"][0]["signed"]["signature"] = serde_json::json!("forged");
                } else {
                    value["records"] = serde_json::json!([]);
                }
                let forged = PairingCodec::encode(
                    "mesh-proof-page-v1",
                    "secret",
                    &serde_json::to_vec(&value).unwrap(),
                )
                .unwrap();
                match receiver.receive(&forged) {
                    Err(_) => break,
                    Ok(Some(next))
                        if PairingCodec::inspect(&next).unwrap().frame_type
                            == "mesh-proof-request-v1" =>
                    {
                        request = next
                    }
                    _ => panic!("Invalid owner proofs were acknowledged"),
                }
            }
            assert_eq!(receiver.host().document, baseline);
            assert_eq!(receiver.host().saved, 0);
            assert_eq!(receiver.host().persisted, 0);
        }
    }

    #[test]
    fn staging_cache_failures_do_not_block_signed_proof_admission_or_ack() {
        let (mut receiver, mut source, document_frame, _, candidate, proof) =
            signed_transfer(true, true);
        let request = request_for_proof(
            &mut receiver,
            &mut source,
            document_frame,
            &candidate,
            &proof,
        );
        let response_page = proof_page(&mut source, &request, &candidate, &proof);
        let acknowledgement = receiver
            .receive(&response_page)
            .unwrap()
            .expect("valid page is durably admitted and acknowledged");
        assert_eq!(receiver.host().accepted_changes, 1);
        assert_eq!(
            receiver.host().document,
            receiver
                .host()
                .admission_snapshot
                .as_ref()
                .unwrap()
                .document
        );
        assert_eq!(
            PairingCodec::inspect(&acknowledgement).unwrap().frame_type,
            "mesh-automerge-sync"
        );
    }

    #[test]
    fn lost_page_response_aborts_only_incomplete_receive_and_replays_cached_page() {
        let (mut receiver, mut source, document_frame, baseline, candidate, proof) =
            signed_transfer_with_pages(false, false, true);
        let first_request = request_for_proof(
            &mut receiver,
            &mut source,
            document_frame,
            &candidate,
            &proof,
        );
        let first_page = proof_page(&mut source, &first_request, &candidate, &proof);
        let second_request = receiver
            .receive(&first_page)
            .unwrap()
            .expect("first proof page asks for the rest");
        assert_eq!(
            PairingCodec::inspect(&second_request).unwrap().frame_type,
            "mesh-proof-request-v1"
        );
        assert_eq!(receiver.host().accepted_changes, 0);
        assert_eq!(receiver.host().document, baseline);
        assert_eq!(receiver.host().proof_pages.len(), 1);

        // The request's response is lost at the RPC deadline. Abort only the
        // in-memory, uncommitted receive; retain the durable document and page cache.
        assert!(receiver.abort_incomplete_document_receive());
        assert!(!receiver.abort_incomplete_document_receive());
        assert_eq!(receiver.host().accepted_changes, 0);
        assert_eq!(receiver.host().document, baseline);
        assert_eq!(receiver.host().proof_pages.len(), 1);

        source.reset_document();
        let replay = source
            .publish_frame(&candidate, Some(proof.clone()))
            .unwrap()
            .unwrap();
        let replay_request =
            request_for_proof(&mut receiver, &mut source, replay, &candidate, &proof);
        let request_payload =
            PairingCodec::decode(&replay_request, "mesh-proof-request-v1", "secret").unwrap();
        let request_value: Value = serde_json::from_slice(&request_payload).unwrap();
        assert!(!request_value["after"].as_str().unwrap().is_empty());
        let final_page = proof_page(&mut source, &replay_request, &candidate, &proof);
        let acknowledgement = receiver
            .receive(&final_page)
            .unwrap()
            .expect("complete validated replay is acknowledged");

        assert_eq!(receiver.host().accepted_changes, 1);
        assert_eq!(receiver.host().document, candidate);
        assert_eq!(
            PairingCodec::inspect(&acknowledgement).unwrap().frame_type,
            "mesh-automerge-sync"
        );
    }

    #[test]
    fn forged_signed_page_is_rejected_without_document_commit_or_ack() {
        let (mut receiver, mut source, document_frame, baseline, candidate, proof) =
            signed_transfer(false, false);
        let request = request_for_proof(
            &mut receiver,
            &mut source,
            document_frame,
            &candidate,
            &proof,
        );
        let mut page = proof_page(&mut source, &request, &candidate, &proof);
        let payload = PairingCodec::decode(&page, "mesh-proof-page-v1", "secret").unwrap();
        let mut value: Value = serde_json::from_slice(&payload).unwrap();
        value["records"][0]["signed"]["signature"] = serde_json::json!("forged-signature");
        page = PairingCodec::encode(
            "mesh-proof-page-v1",
            "secret",
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();

        assert!(receiver.receive(&page).is_err());
        assert_eq!(receiver.host().accepted_changes, 0);
        assert_eq!(receiver.host().document, baseline);
    }
}
