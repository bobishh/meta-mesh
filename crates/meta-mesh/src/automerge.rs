use meta_mesh_core::{AutomergeDeviceSyncFlow, AutomergeSyncEngine, AutomergeSyncFrame};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmAutomergeSyncEngine {
    inner: AutomergeSyncEngine,
}

#[wasm_bindgen]
impl WasmAutomergeSyncEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(local_device_id: &str, maximum_frame_bytes: Option<usize>) -> Result<Self, JsValue> {
        Ok(Self {
            inner: AutomergeSyncEngine::new(local_device_id, maximum_frame_bytes)
                .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = loadDocument)]
    pub fn load_document(
        &mut self,
        scope_id: &str,
        document_id: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        self.inner
            .load_document(scope_id, document_id, bytes)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = saveDocument)]
    pub fn save_document(&mut self, document_id: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.save_document(document_id).map_err(js_error)
    }

    pub fn heads(&mut self, document_id: &str) -> Result<Vec<String>, JsValue> {
        self.inner.heads(document_id).map_err(js_error)
    }

    pub fn reset(&mut self, document_id: &str, remote_device_id: &str) {
        self.inner.reset(document_id, remote_device_id)
    }

    pub fn generate(
        &mut self,
        document_id: &str,
        remote_device_id: &str,
        authorized: bool,
        proof: JsValue,
    ) -> Result<JsValue, JsValue> {
        let proof = optional_value(proof)?;
        let frame = self
            .inner
            .generate(document_id, remote_device_id, authorized, proof)
            .map_err(js_error)?;
        to_value(&frame)
    }

    pub fn receive(
        &mut self,
        remote_device_id: &str,
        frame: JsValue,
        authorized: bool,
        response_proof: JsValue,
    ) -> Result<JsValue, JsValue> {
        let frame: AutomergeSyncFrame = serde_wasm_bindgen::from_value(frame).map_err(js_error)?;
        let response_proof = optional_value(response_proof)?;
        let result = self
            .inner
            .receive(remote_device_id, frame, authorized, response_proof)
            .map_err(js_error)?;
        to_value(&result)
    }

    #[wasm_bindgen(js_name = prepareReceive)]
    pub fn prepare_receive(
        &mut self,
        remote_device_id: &str,
        frame: JsValue,
        authorized: bool,
        response_proof: JsValue,
    ) -> Result<JsValue, JsValue> {
        let frame: AutomergeSyncFrame = serde_wasm_bindgen::from_value(frame).map_err(js_error)?;
        let response_proof = optional_value(response_proof)?;
        let result = self
            .inner
            .prepare_receive(remote_device_id, frame, authorized, response_proof)
            .map_err(js_error)?;
        to_value(&result)
    }

    #[wasm_bindgen(js_name = commitPreparedReceive)]
    pub fn commit_prepared_receive(
        &mut self,
        document_id: &str,
        remote_device_id: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .commit_prepared_receive(document_id, remote_device_id)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = abortPreparedReceive)]
    pub fn abort_prepared_receive(&mut self, document_id: &str, remote_device_id: &str) {
        self.inner
            .abort_prepared_receive(document_id, remote_device_id)
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

fn optional_value(value: JsValue) -> Result<Option<serde_json::Value>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        serde_wasm_bindgen::from_value(value)
            .map(Some)
            .map_err(js_error)
    }
}

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}

#[wasm_bindgen]
pub struct WasmAutomergeDeviceSyncFlow {
    inner: AutomergeDeviceSyncFlow,
}

#[wasm_bindgen]
impl WasmAutomergeDeviceSyncFlow {
    #[wasm_bindgen(js_name = decodeIncomingRequest)]
    pub fn decode_incoming_request(
        request: JsValue,
        expected_remote_device_id: &str,
    ) -> Result<JsValue, JsValue> {
        let request: serde_json::Value =
            serde_wasm_bindgen::from_value(request).map_err(js_error)?;
        to_value(
            &meta_mesh_core::decode_device_sync_request(request, expected_remote_device_id)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = encodeResponse)]
    pub fn encode_response(
        batch_id: String,
        ack: JsValue,
        frame: JsValue,
    ) -> Result<JsValue, JsValue> {
        let ack: serde_json::Value = serde_wasm_bindgen::from_value(ack).map_err(js_error)?;
        let frame: Option<AutomergeSyncFrame> =
            serde_wasm_bindgen::from_value(frame).map_err(js_error)?;
        to_value(
            &meta_mesh_core::encode_device_sync_response(batch_id, ack, frame).map_err(js_error)?,
        )
    }

    #[wasm_bindgen(constructor)]
    pub fn new(
        target_device_id: String,
        document_id: String,
        maximum_rounds: f64,
    ) -> Result<Self, JsValue> {
        if !maximum_rounds.is_finite()
            || maximum_rounds.fract() != 0.0
            || maximum_rounds < 1.0
            || maximum_rounds > 1_000_000.0
        {
            return Err(js_error("Invalid Automerge sync round limit"));
        }
        Ok(Self {
            inner: AutomergeDeviceSyncFlow::new(
                target_device_id,
                document_id,
                maximum_rounds as u32,
            )
            .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = nextRound)]
    pub fn next_round(&mut self, frame: JsValue) -> Result<JsValue, JsValue> {
        let frame: Option<AutomergeSyncFrame> =
            serde_wasm_bindgen::from_value(frame).map_err(js_error)?;
        to_value(&self.inner.next(frame).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = validateResponse)]
    pub fn validate_response(&self, response: JsValue) -> Result<(), JsValue> {
        let response: serde_json::Value =
            serde_wasm_bindgen::from_value(response).map_err(js_error)?;
        self.inner.validate_response(response).map_err(js_error)
    }

    #[wasm_bindgen(js_name = completeRound)]
    pub fn complete_round(
        &mut self,
        route_instance_id: String,
        response: JsValue,
    ) -> Result<JsValue, JsValue> {
        let response: serde_json::Value =
            serde_wasm_bindgen::from_value(response).map_err(js_error)?;
        to_value(
            &self
                .inner
                .complete_round(route_instance_id, response)
                .map_err(js_error)?,
        )
    }
}
