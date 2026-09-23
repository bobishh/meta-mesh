use std::collections::BTreeMap;

use meta_mesh_core::{
    control_frames, encode_workspace_update, is_workspace_update, AutomergeSyncFrame,
    ControlFrameReceiver, DialMode, GossipLifecycleState, GossipRebuildInput, LiveWorkspaceSession,
    MeshScopeRuntime,
    MeshBatchDeliveryFlow, MeshHandshakeFlow, MeshLifecycleState, MeshRuntimeState,
    RelayDialPolicy, SessionCandidate, SessionDirection, SessionKey,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LiveReceiveWithPlan {
    action: meta_mesh_core::LiveSessionAction,
    plan: meta_mesh_core::LiveSessionReceivePlan,
}

#[wasm_bindgen]
pub struct WasmLiveWorkspaceSession {
    inner: LiveWorkspaceSession,
}

#[wasm_bindgen]
impl WasmLiveWorkspaceSession {
    #[wasm_bindgen(constructor)]
    pub fn new(workspace_id: &str, secret: &str) -> Result<Self, JsValue> {
        Ok(Self {
            inner: LiveWorkspaceSession::new(workspace_id, secret).map_err(js_error)?,
        })
    }

    pub fn receive(&mut self, frame: &[u8]) -> Result<JsValue, JsValue> {
        to_value(&self.inner.receive(frame).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = receiveWithPlan)]
    pub fn receive_with_plan(&mut self, frame: &[u8]) -> Result<JsValue, JsValue> {
        let Some(action) = self.inner.receive(frame).map_err(js_error)? else {
            return to_value(&Option::<()>::None);
        };
        let plan = self.inner.receive_plan(&action).map_err(js_error)?;
        to_value(&Some(LiveReceiveWithPlan { action, plan }))
    }

    pub fn encode(&self, frame_type: &str, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.encode(frame_type, payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = encodeAutomergeFrame)]
    pub fn encode_automerge_frame(&self, frame: JsValue) -> Result<Vec<u8>, JsValue> {
        let frame: AutomergeSyncFrame = from_value(frame)?;
        self.inner.encode_automerge_frame(&frame).map_err(js_error)
    }

    #[wasm_bindgen(js_name = decodeAutomergePayload)]
    pub fn decode_automerge_payload(&self, payload: &[u8]) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .decode_automerge_payload(payload)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = startDocumentSync)]
    pub fn start_document_sync(
        &mut self,
        local_device_id: &str,
        remote_device_id: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .start_document_sync(local_device_id, remote_device_id)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = generateDocument)]
    pub fn generate_document(
        &mut self,
        document: &[u8],
        proof: JsValue,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        self.inner
            .generate_document(document, optional_value(proof)?)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = preparePublish)]
    pub fn prepare_publish(
        &mut self,
        document: &[u8],
        proof: JsValue,
        authorization: JsValue,
        chat: JsValue,
        mesh: JsValue,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .prepare_publish(
                    document,
                    optional_value(proof)?,
                    optional_value(authorization)?,
                    optional_value(chat)?,
                    optional_value(mesh)?,
                )
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = prepareControlPublish)]
    pub fn prepare_control_publish(
        &mut self,
        authorization: JsValue,
        chat: JsValue,
        mesh: JsValue,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .prepare_control_publish(
                    optional_value(authorization)?,
                    optional_value(chat)?,
                    optional_value(mesh)?,
                )
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = prepareSnapshotPublish)]
    pub fn prepare_snapshot_publish(&self, snapshot: &[u8]) -> Result<JsValue, JsValue> {
        to_value(&self.inner.prepare_snapshot_publish(snapshot).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = finishPublish)]
    pub fn finish_publish(&mut self, control_snapshot: &[u8], all_frames_sent: bool) {
        self.inner.finish_publish(control_snapshot, all_frames_sent);
    }

    #[wasm_bindgen(js_name = prepareDocument)]
    pub fn prepare_document(
        &mut self,
        payload: &[u8],
        document: &[u8],
        response_proof: JsValue,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .prepare_document(payload, document, optional_value(response_proof)?)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = commitDocument)]
    pub fn commit_document(&mut self) -> Result<(), JsValue> {
        self.inner.commit_document().map_err(js_error)
    }

    #[wasm_bindgen(js_name = abortDocument)]
    pub fn abort_document(&mut self) {
        self.inner.abort_document();
    }

    #[wasm_bindgen(js_name = resetDocument)]
    pub fn reset_document(&mut self) {
        self.inner.reset_document();
    }

    #[wasm_bindgen(js_name = controlChanged)]
    pub fn control_changed(&self, snapshot: &[u8]) -> bool {
        self.inner.control_changed(snapshot)
    }

    #[wasm_bindgen(js_name = encodeControl)]
    pub fn encode_control(
        &self,
        authorization: JsValue,
        chat: JsValue,
        mesh: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        self.inner
            .encode_control(
                optional_value(authorization)?,
                optional_value(chat)?,
                optional_value(mesh)?,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decodeControl)]
    pub fn decode_control(&self, bytes: &[u8]) -> Result<JsValue, JsValue> {
        to_value(&self.inner.decode_control(bytes).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = controlFrames)]
    pub fn control_frames(&mut self, snapshot: &[u8]) -> Result<JsValue, JsValue> {
        to_value(&self.inner.control_frames(snapshot).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = markControlSent)]
    pub fn mark_control_sent(&mut self, snapshot: &[u8]) {
        self.inner.mark_control_sent(snapshot.to_vec());
    }

    #[wasm_bindgen(js_name = acknowledgeSaved)]
    pub fn acknowledge_saved(&self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.acknowledge_saved(bytes).map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifySavedReceipt)]
    pub fn verify_saved_receipt(&self, frame: &[u8], bytes: &[u8]) -> Result<(), JsValue> {
        self.inner
            .verify_saved_receipt(frame, bytes)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifyHeartbeatAck)]
    pub fn verify_heartbeat_ack(&self, frame: &[u8]) -> Result<(), JsValue> {
        self.inner.verify_heartbeat_ack(frame).map_err(js_error)
    }
}

/// WASM host boundary for one authenticated workspace scope stream.
#[wasm_bindgen]
pub struct WasmMeshScopeRuntime {
    inner: MeshScopeRuntime,
}

#[wasm_bindgen]
impl WasmMeshScopeRuntime {
    #[wasm_bindgen(constructor)]
    pub fn new(workspace_id: &str, secret: &str) -> Result<Self, JsValue> {
        Ok(Self {
            inner: MeshScopeRuntime::new(workspace_id, secret).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = startDocumentSync)]
    pub fn start_document_sync(
        &mut self,
        local_device_id: &str,
        remote_device_id: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .start_document_sync(local_device_id, remote_device_id)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = receiveFrame)]
    pub fn receive_frame(&mut self, frame: &[u8]) -> Result<JsValue, JsValue> {
        to_value(&self.inner.receive_frame(frame).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = provideDocument)]
    pub fn provide_document(
        &mut self,
        document: &[u8],
        response_proof: JsValue,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .provide_document(document, optional_value(response_proof)?)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = completeDocumentReceive)]
    pub fn complete_document_receive(&mut self, persisted: bool) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .complete_document_receive(persisted)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = rejectDocumentReceive)]
    pub fn reject_document_receive(&mut self) -> Result<(), JsValue> {
        self.inner.reject_document_receive().map_err(js_error)
    }

    #[wasm_bindgen(js_name = resetDocument)]
    pub fn reset_document(&mut self) {
        self.inner.reset_document();
    }

    #[wasm_bindgen(js_name = completeSavedReceive)]
    pub fn complete_saved_receive(&mut self, persisted: bool) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .complete_saved_receive(persisted)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = publishFrame)]
    pub fn publish_frame(
        &mut self,
        document: &[u8],
        proof: JsValue,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        self.inner
            .publish_frame(document, optional_value(proof)?)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = preparePublish)]
    pub fn prepare_publish(
        &mut self,
        document: &[u8],
        proof: JsValue,
        authorization: JsValue,
        chat: JsValue,
        mesh: JsValue,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .prepare_publish(
                    document,
                    optional_value(proof)?,
                    optional_value(authorization)?,
                    optional_value(chat)?,
                    optional_value(mesh)?,
                )
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = finishPublish)]
    pub fn finish_publish(&mut self, control_snapshot: &[u8], all_frames_sent: bool) {
        self.inner.finish_publish(control_snapshot, all_frames_sent);
    }
}

#[wasm_bindgen]
pub struct WasmMeshBatchDeliveryFlow {
    inner: MeshBatchDeliveryFlow,
}

#[wasm_bindgen]
impl WasmMeshBatchDeliveryFlow {
    #[wasm_bindgen(constructor)]
    pub fn new(target_device_id: &str, route_ids: JsValue, fallback_delay_ms: f64,
        retry_delays_ms: JsValue) -> Result<Self, JsValue> {
        let route_ids: Vec<String> = from_value(route_ids)?;
        let retry_delays_ms: Vec<f64> = from_value(retry_delays_ms)?;
        Ok(Self { inner: MeshBatchDeliveryFlow::new(target_device_id.to_string(), route_ids,
            fallback_delay_ms, retry_delays_ms).map_err(js_error)? })
    }

    pub fn start(&mut self) -> Result<JsValue, JsValue> {
        to_value(&self.inner.start().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = routeResult)]
    pub fn route_result(&mut self, round: u32, route_index: u32, accepted: bool,
        failure: &str) -> Result<JsValue, JsValue> {
        to_value(&self.inner.route_result(round, route_index, accepted, failure.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackElapsed)]
    pub fn fallback_elapsed(&mut self, round: u32) -> Result<JsValue, JsValue> {
        to_value(&self.inner.fallback_elapsed(round))
    }

    #[wasm_bindgen(js_name = retryElapsed)]
    pub fn retry_elapsed(&mut self, round: u32) -> Result<JsValue, JsValue> {
        to_value(&self.inner.retry_elapsed(round))
    }

    pub fn abort(&mut self) -> Result<JsValue, JsValue> {
        to_value(&self.inner.abort())
    }
}

#[wasm_bindgen]
pub struct WasmMeshHandshakeFlow {
    inner: MeshHandshakeFlow,
}

#[wasm_bindgen]
impl WasmMeshHandshakeFlow {
    #[wasm_bindgen(constructor)]
    pub fn new(direction_name: &str) -> Result<Self, JsValue> {
        Ok(Self {
            inner: MeshHandshakeFlow::new(direction(direction_name)?),
        })
    }

    pub fn step(&self) -> String {
        self.inner.step().as_str().to_string()
    }

    #[wasm_bindgen(js_name = isPeerRevoked)]
    pub fn is_peer_revoked(
        &self,
        credential: JsValue,
        person_id: &str,
        grant: JsValue,
        device_id: &str,
    ) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        let grant: Option<serde_json::Value> = optional_value(grant)?;
        Ok(MeshHandshakeFlow::is_peer_revoked(
            &credential,
            person_id,
            grant.as_ref(),
            device_id,
        ))
    }

    #[wasm_bindgen(js_name = matchesExpectedPeer)]
    pub fn matches_expected_peer(
        &self,
        expected_device_id: &str,
        verified_device_id: &str,
    ) -> bool {
        MeshHandshakeFlow::matches_expected_peer(expected_device_id, verified_device_id)
    }

    #[wasm_bindgen(js_name = matchesAdmittedPeer)]
    pub fn matches_admitted_peer(
        &self,
        verified_device_id: &str,
        verified_person_id: &str,
        verified_endpoint: &str,
        admitted_device_id: &str,
        admitted_person_id: &str,
        admitted_endpoint: &str,
    ) -> bool {
        MeshHandshakeFlow::matches_admitted_peer(
            verified_device_id,
            verified_person_id,
            verified_endpoint,
            admitted_device_id,
            admitted_person_id,
            admitted_endpoint,
        )
    }

    pub fn advance(&mut self, completed: &str, decision: Option<bool>) -> Result<String, JsValue> {
        self.inner
            .advance(completed, decision)
            .map(|step| step.as_str().to_string())
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct WasmMeshLifecycleState {
    inner: MeshLifecycleState,
}

#[wasm_bindgen]
impl WasmMeshLifecycleState {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: MeshLifecycleState::default(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn stopped(&self) -> bool {
        self.inner.stopped()
    }

    #[wasm_bindgen(getter, js_name = externallyPaused)]
    pub fn externally_paused(&self) -> bool {
        self.inner.externally_paused()
    }

    #[wasm_bindgen(getter)]
    pub fn disposed(&self) -> bool {
        self.inner.disposed()
    }

    #[wasm_bindgen(js_name = beginStart)]
    pub fn begin_start(&mut self) -> bool {
        self.inner.begin_start()
    }

    #[wasm_bindgen(js_name = canContinueStart)]
    pub fn can_continue_start(&self) -> bool {
        self.inner.can_continue_start()
    }

    #[wasm_bindgen(js_name = completeStart)]
    pub fn complete_start(&mut self) -> bool {
        self.inner.complete_start()
    }

    #[wasm_bindgen(js_name = cancelStart)]
    pub fn cancel_start(&mut self) {
        self.inner.cancel_start();
    }

    pub fn stop(&mut self) -> bool {
        self.inner.stop()
    }
    #[wasm_bindgen(js_name = finishStop)]
    pub fn finish_stop(&mut self) {
        self.inner.finish_stop();
    }
    pub fn pause(&mut self) {
        self.inner.pause();
    }
    pub fn resume(&mut self) -> bool {
        self.inner.resume()
    }
    pub fn dispose(&mut self) {
        self.inner.dispose();
    }
}

#[wasm_bindgen]
pub struct WasmGossipLifecycleState {
    inner: GossipLifecycleState,
}

#[wasm_bindgen]
impl WasmGossipLifecycleState {
    #[wasm_bindgen(constructor)]
    pub fn new(topic_prefix: Option<String>) -> Result<Self, JsValue> {
        Ok(Self {
            inner: GossipLifecycleState::new(
                topic_prefix.unwrap_or_else(|| meta_mesh_core::DEFAULT_GOSSIP_TOPIC_PREFIX.into()),
            )
            .map_err(js_error)?,
        })
    }

    pub fn topic(&self, workspace_id: &str) -> Result<String, JsValue> {
        self.inner.topic(workspace_id).map_err(js_error)
    }

    #[wasm_bindgen(js_name = planRebuild)]
    pub fn plan_rebuild(&mut self, raw: JsValue) -> Result<JsValue, JsValue> {
        let input: GossipRebuildInput = from_value(raw)?;
        to_value(&self.inner.plan_rebuild(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = startFailed)]
    pub fn start_failed(&mut self, workspace_id: &str) -> Result<(), JsValue> {
        self.inner.start_failed(workspace_id).map_err(js_error)
    }
    pub fn started(&mut self, workspace_id: &str) -> Result<(), JsValue> {
        self.inner.started(workspace_id).map_err(js_error)
    }
    pub fn close(&mut self, workspace_id: &str) -> Result<(), JsValue> {
        self.inner.close(workspace_id).map_err(js_error)
    }
    #[wasm_bindgen(js_name = closeAll)]
    pub fn close_all(&mut self) {
        self.inner.close_all();
    }

    #[wasm_bindgen(js_name = receiveAction)]
    pub fn receive_action(
        &self,
        workspace_id: &str,
        driver_available: bool,
        session_available: bool,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .receive_action(workspace_id, driver_available, session_available)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = deliveryAction)]
    pub fn delivery_action(
        &self,
        workspace_id: &str,
        topic: &str,
        session_available: bool,
        packet_valid: bool,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .delivery_action(workspace_id, topic, session_available, packet_valid)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = observeNeighbors)]
    pub fn observe_neighbors(
        &mut self,
        workspace_id: &str,
        count: u32,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .observe_neighbors(workspace_id, count as usize)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = broadcastPlan)]
    pub fn broadcast_plan(
        &self,
        workspace_id: &str,
        driver_available: bool,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .broadcast_plan(workspace_id, driver_available)
                .map_err(js_error)?,
        )
    }
}

#[wasm_bindgen]
pub struct WasmMeshRuntimeState {
    inner: MeshRuntimeState,
    control_receivers: BTreeMap<String, ControlFrameReceiver>,
    transfer_sequence: u64,
    relay_policy: RelayDialPolicy,
}

#[wasm_bindgen]
impl WasmMeshRuntimeState {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: MeshRuntimeState::default(),
            control_receivers: BTreeMap::new(),
            transfer_sequence: 0,
            relay_policy: RelayDialPolicy::default(),
        }
    }

    pub fn start(&mut self) {
        self.inner.start();
    }

    pub fn stop(&mut self) -> Result<JsValue, JsValue> {
        to_value(&self.inner.stop())
    }

    #[wasm_bindgen(getter, js_name = running)]
    pub fn running(&self) -> bool {
        self.inner.is_running()
    }

    #[wasm_bindgen(js_name = sessions)]
    pub fn sessions(&self) -> Result<JsValue, JsValue> {
        to_value(&self.inner.sessions().collect::<Vec<_>>())
    }

    #[wasm_bindgen(js_name = beginRouteAttempt)]
    pub fn begin_route_attempt(
        &mut self,
        route_key: String,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let now_ms = unsigned_integer(now_ms, "Invalid route attempt timestamp")?;
        to_value(&self.inner.begin_route_attempt(route_key, now_ms))
    }

    #[wasm_bindgen(js_name = routeAttemptActive)]
    pub fn route_attempt_active(&self, route_key: &str) -> bool {
        self.inner.route_attempt_active(route_key)
    }

    #[wasm_bindgen(js_name = clearRouteAttempt)]
    pub fn clear_route_attempt(&mut self, route_key: &str) {
        self.inner.clear_route_attempt(route_key);
    }

    #[wasm_bindgen(js_name = finishRouteAttempt)]
    pub fn finish_route_attempt(&mut self, route_key: &str, token: f64) -> Result<bool, JsValue> {
        Ok(self.inner.finish_route_attempt(
            route_key,
            unsigned_integer(token, "Invalid route attempt token")?,
        ))
    }

    #[wasm_bindgen(js_name = scheduleReconnect)]
    pub fn schedule_reconnect(
        &mut self,
        route_key: String,
        now_ms: f64,
        base_delay_ms: f64,
        maximum_delay_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let state = self.inner.schedule_reconnect(
            route_key,
            unsigned_integer(now_ms, "Invalid reconnect timestamp")?,
            unsigned_integer(base_delay_ms, "Invalid reconnect base delay")?,
            unsigned_integer(maximum_delay_ms, "Invalid reconnect maximum delay")?,
        );
        to_value(&state)
    }

    #[wasm_bindgen(js_name = clearReconnect)]
    pub fn clear_reconnect(&mut self, route_key: &str) {
        self.inner.clear_reconnect(route_key);
    }

    #[wasm_bindgen(js_name = reconnectState)]
    pub fn reconnect_state(&self, route_key: &str) -> Result<JsValue, JsValue> {
        to_value(&self.inner.reconnect_state(route_key))
    }

    #[wasm_bindgen(js_name = clearReconnectsWithPrefix)]
    pub fn clear_reconnects_with_prefix(&mut self, prefix: &str) {
        self.inner.clear_reconnects_with_prefix(prefix);
    }

    #[wasm_bindgen(js_name = dueReconnects)]
    pub fn due_reconnects(&self, now_ms: f64) -> Result<JsValue, JsValue> {
        to_value(
            &self
                .inner
                .due_reconnects(unsigned_integer(now_ms, "Invalid reconnect timestamp")?),
        )
    }

    #[wasm_bindgen(js_name = admitSession)]
    pub fn admit_session(
        &mut self,
        candidate: JsValue,
        preferred_direction: &str,
    ) -> Result<JsValue, JsValue> {
        let candidate: SessionCandidate = from_value(candidate)?;
        let preferred = direction(preferred_direction)?;
        to_value(&self.inner.admit_session(candidate, preferred))
    }

    #[wasm_bindgen(js_name = removeSession)]
    pub fn remove_session(&mut self, key: JsValue, generation: f64) -> Result<JsValue, JsValue> {
        let key: SessionKey = from_value(key)?;
        to_value(&self.inner.remove_session(
            &key,
            unsigned_integer(generation, "Invalid session generation")?,
        ))
    }

    #[wasm_bindgen(js_name = connectedDevices)]
    pub fn connected_devices(&self, workspace_id: &str) -> Result<JsValue, JsValue> {
        to_value(&self.inner.connected_devices(workspace_id))
    }

    #[wasm_bindgen(js_name = encodeWorkspaceUpdate)]
    pub fn encode_workspace_update(&self, workspace_id: &str, nonce: &str) -> Vec<u8> {
        encode_workspace_update(workspace_id, nonce)
    }

    #[wasm_bindgen(js_name = isWorkspaceUpdate)]
    pub fn is_workspace_update(&self, payload: &[u8], workspace_id: &str) -> bool {
        is_workspace_update(payload, workspace_id)
    }

    #[wasm_bindgen(js_name = controlFrames)]
    pub fn control_frames(&mut self, workspace_id: &str, bytes: &[u8]) -> Result<JsValue, JsValue> {
        self.transfer_sequence = self.transfer_sequence.saturating_add(1);
        let transfer_id = format!("wasm-{}", self.transfer_sequence);
        to_value(&control_frames(workspace_id, &transfer_id, bytes).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = receiveControlFrame)]
    pub fn receive_control_frame(
        &mut self,
        workspace_id: &str,
        frame: &[u8],
    ) -> Result<Option<Vec<u8>>, JsValue> {
        self.control_receivers
            .entry(workspace_id.to_string())
            .or_insert_with(|| ControlFrameReceiver::new(workspace_id))
            .receive(frame)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = planDial)]
    pub fn plan_dial(
        &mut self,
        peer_key: &str,
        relay_available: bool,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        to_value(&self.relay_policy.plan(
            peer_key,
            relay_available,
            unsigned_integer(now_ms, "Invalid dial timestamp")?,
        ))
    }

    #[wasm_bindgen(js_name = recordNetworkFailure)]
    pub fn record_network_failure(&mut self, peer_key: String, now_ms: f64) -> Result<(), JsValue> {
        self.relay_policy.record_network_failure(
            peer_key,
            unsigned_integer(now_ms, "Invalid dial timestamp")?,
        );
        Ok(())
    }

    #[wasm_bindgen(js_name = recordDialSuccess)]
    pub fn record_dial_success(
        &mut self,
        peer_key: &str,
        mode: &str,
        now_ms: f64,
    ) -> Result<(), JsValue> {
        let mode = match mode {
            "direct" => DialMode::Direct,
            "relay" => DialMode::Relay,
            _ => return Err(js_error("Invalid dial mode")),
        };
        self.relay_policy.record_success(
            peer_key,
            mode,
            unsigned_integer(now_ms, "Invalid dial timestamp")?,
        );
        Ok(())
    }
}

impl Default for WasmMeshRuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

fn direction(value: &str) -> Result<SessionDirection, JsValue> {
    match value {
        "incoming" => Ok(SessionDirection::Incoming),
        "outgoing" => Ok(SessionDirection::Outgoing),
        _ => Err(js_error("Invalid session direction")),
    }
}

fn from_value<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(js_error)
}

fn optional_value(value: JsValue) -> Result<Option<serde_json::Value>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        from_value(value).map(Some)
    }
}

fn to_value(value: &impl Serialize) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_maps_as_objects(true)
                .serialize_missing_as_null(true),
        )
        .map_err(js_error)
}

fn unsigned_integer(value: f64, message: &str) -> Result<u64, JsValue> {
    if value.is_finite() && value.fract() == 0.0 && value >= 0.0 && value <= u64::MAX as f64 {
        Ok(value as u64)
    } else {
        Err(js_error(message))
    }
}

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}
