use std::collections::BTreeMap;

use meta_mesh_core::{
    ControlFrameReceiver, MeshRuntimeState, SessionCandidate, SessionDirection, SessionKey,
    control_frames,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmMeshRuntimeState {
    inner: MeshRuntimeState,
    control_receivers: BTreeMap<String, ControlFrameReceiver>,
    transfer_sequence: u64,
}

#[wasm_bindgen]
impl WasmMeshRuntimeState {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: MeshRuntimeState::default(),
            control_receivers: BTreeMap::new(),
            transfer_sequence: 0,
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
