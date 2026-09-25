use meta_mesh_core::{MeshSessionLifecycleState, SessionCallbackEvent, SessionKey};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmMeshSessionLifecycle {
    inner: MeshSessionLifecycleState,
}

#[wasm_bindgen]
impl WasmMeshSessionLifecycle {
    #[wasm_bindgen(constructor)]
    pub fn new(stable_after_ms: Option<f64>) -> Result<Self, JsValue> {
        let delay = stable_after_ms
            .map(number)
            .transpose()?
            .unwrap_or(meta_mesh_core::DEFAULT_SESSION_STABLE_AFTER_MS);
        Ok(Self {
            inner: MeshSessionLifecycleState::new(delay),
        })
    }
    pub fn register(
        &mut self,
        key: JsValue,
        connection_id: String,
        generation: f64,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let key: SessionKey = from_value(key)?;
        to_value(
            &self
                .inner
                .register(key, connection_id, number(generation)?, number(now_ms)?)
                .map_err(error)?,
        )
        .map_err(|value| error(value.to_string()))
    }
    #[wasm_bindgen(js_name = markStable)]
    pub fn mark_stable(
        &mut self,
        key: JsValue,
        generation: f64,
        now_ms: f64,
    ) -> Result<bool, JsValue> {
        Ok(self
            .inner
            .mark_stable(&from_value(key)?, number(generation)?, number(now_ms)?))
    }
    #[wasm_bindgen(js_name = reportFailure)]
    pub fn report_failure(&mut self, key: JsValue, generation: f64) -> Result<bool, JsValue> {
        Ok(self
            .inner
            .report_failure(&from_value(key)?, number(generation)?))
    }
    #[wasm_bindgen(js_name = publishRecovery)]
    pub fn publish_recovery(&mut self, key: JsValue, generation: f64) -> Result<bool, JsValue> {
        Ok(self
            .inner
            .publish_recovery(&from_value(key)?, number(generation)?))
    }
    #[wasm_bindgen(js_name = callbackPlan)]
    pub fn callback_plan(
        &mut self,
        key: JsValue,
        generation: f64,
        event: &str,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let event = match event {
            "recovery" => SessionCallbackEvent::Recovery,
            "stable" => SessionCallbackEvent::Stable,
            "heartbeatFailed" => SessionCallbackEvent::HeartbeatFailed,
            "receiveSucceeded" => SessionCallbackEvent::ReceiveSucceeded,
            "receiveFailed" => SessionCallbackEvent::ReceiveFailed,
            _ => return Err(error("Invalid session callback event")),
        };
        to_value(&self.inner.callback_plan(
            &from_value(key)?,
            number(generation)?,
            event,
            number(now_ms)?,
        ))
        .map_err(|value| error(value.to_string()))
    }
    #[wasm_bindgen(js_name = publishPlan)]
    pub fn publish_plan(&self) -> Result<JsValue, JsValue> {
        to_value(&self.inner.publish_plan()).map_err(|value| error(value.to_string()))
    }
    pub fn evict(&mut self, key: JsValue, generation: f64) -> Result<JsValue, JsValue> {
        to_value(&self.inner.evict(&from_value(key)?, number(generation)?))
            .map_err(|value| error(value.to_string()))
    }
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

fn number(value: f64) -> Result<u64, JsValue> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > u64::MAX as f64 {
        Err(error("Invalid session lifecycle number"))
    } else {
        Ok(value as u64)
    }
}
fn error(value: impl Into<String>) -> JsValue {
    JsValue::from_str(&value.into())
}
