use meta_mesh_core::{AutomergeSyncEngine, AutomergeSyncFrame};
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
