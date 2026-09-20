use meta_mesh_core::{
    DeviceRoute, DeviceRouteCatalog, DeviceRoutePayload, DurableBatchAck, DurableBatchAckPayload,
    GossipBounds, GossipCandidate, ReplicaSet, RouteHealth, SignedDeviceRoute,
    SignedDurableBatchAck, WorkspacePeerRecord,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmStateCore;

#[wasm_bindgen]
impl WasmStateCore {
    #[wasm_bindgen(js_name = mergePeerRecords)]
    pub fn merge_peer_records(existing: JsValue, incoming: JsValue) -> Result<JsValue, JsValue> {
        let existing: WorkspacePeerRecord = from_value(existing)?;
        let incoming: WorkspacePeerRecord = from_value(incoming)?;
        let merged = meta_mesh_core::merge_peer_records(&existing, &incoming).map_err(js_error)?;
        to_value(&merged)
    }

    #[wasm_bindgen(js_name = reconcileReplicaSets)]
    pub fn reconcile_replica_sets(left: JsValue, right: JsValue) -> Result<JsValue, JsValue> {
        let left: ReplicaSet = from_value(left)?;
        let right: ReplicaSet = from_value(right)?;
        let merged = meta_mesh_core::reconcile_replica_sets(&left, &right).map_err(js_error)?;
        to_value(&merged)
    }

    #[wasm_bindgen(js_name = selectScopedNeighbors)]
    pub fn select_scoped_neighbors(
        local_device_id: &str,
        candidates: JsValue,
        bounds: JsValue,
        now_ms: f64,
        rotation: u32,
    ) -> Result<Vec<String>, JsValue> {
        let candidates: Vec<GossipCandidate> = from_value(candidates)?;
        let bounds: GossipBounds = from_value(bounds)?;
        meta_mesh_core::select_scoped_neighbors(
            local_device_id,
            &candidates,
            &bounds,
            integer(now_ms, "Invalid gossip timestamp")?,
            rotation,
        )
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = validateDeviceRoute)]
    pub fn validate_device_route(route: JsValue) -> Result<(), JsValue> {
        let route: DeviceRoute = from_value(route)?;
        meta_mesh_core::validate_device_route(&route).map_err(js_error)
    }

    #[wasm_bindgen(js_name = signDeviceRoute)]
    pub fn sign_device_route(
        seed: &[u8],
        signer_key_id: &str,
        payload: JsValue,
    ) -> Result<JsValue, JsValue> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| js_error("Private key seed must contain 32 bytes"))?;
        let payload: DeviceRoutePayload = from_value(payload)?;
        let signed =
            meta_mesh_core::sign_device_route(&seed, signer_key_id, payload).map_err(js_error)?;
        to_value(&signed)
    }

    #[wasm_bindgen(js_name = verifyDeviceRoute)]
    pub fn verify_device_route(
        envelope: JsValue,
        public_key: &str,
        now_ms: f64,
        allow_expired: bool,
    ) -> Result<JsValue, JsValue> {
        let envelope: SignedDeviceRoute = from_value(envelope)?;
        let route = meta_mesh_core::verify_device_route(
            &envelope,
            public_key,
            i128::from(integer(now_ms, "Invalid route timestamp")?),
            allow_expired,
        )
        .map_err(js_error)?;
        to_value(&route)
    }

    #[wasm_bindgen(js_name = signDurableAck)]
    pub fn sign_durable_ack(
        seed: &[u8],
        signer_key_id: &str,
        payload: JsValue,
    ) -> Result<JsValue, JsValue> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| js_error("Private key seed must contain 32 bytes"))?;
        let payload: DurableBatchAckPayload = from_value(payload)?;
        let signed = meta_mesh_core::sign_durable_batch_ack(&seed, signer_key_id, payload)
            .map_err(js_error)?;
        to_value(&signed)
    }

    #[wasm_bindgen(js_name = verifyDurableAck)]
    pub fn verify_durable_ack(envelope: JsValue, public_key: &str) -> Result<JsValue, JsValue> {
        let envelope: SignedDurableBatchAck = from_value(envelope)?;
        let ack =
            meta_mesh_core::verify_durable_batch_ack(&envelope, public_key).map_err(js_error)?;
        to_value(&ack)
    }

    #[wasm_bindgen(js_name = durableAckMatches)]
    pub fn durable_ack_matches(
        ack: JsValue,
        batch: JsValue,
        target_device_id: &str,
    ) -> Result<bool, JsValue> {
        let ack: DurableBatchAck = from_value(ack)?;
        let batch = from_value(batch)?;
        Ok(meta_mesh_core::durable_ack_matches(
            &ack,
            &batch,
            target_device_id,
        ))
    }

    #[wasm_bindgen(js_name = orderDeliveryRoutes)]
    pub fn order_delivery_routes(
        target_device_id: &str,
        routes: JsValue,
    ) -> Result<JsValue, JsValue> {
        let routes: Vec<RouteHealth> = from_value(routes)?;
        let ordered =
            meta_mesh_core::order_delivery_routes(target_device_id, &routes).map_err(js_error)?;
        to_value(&ordered)
    }
}

#[wasm_bindgen]
pub struct WasmDeviceRouteCatalog {
    inner: DeviceRouteCatalog,
}

#[wasm_bindgen]
impl WasmDeviceRouteCatalog {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: DeviceRouteCatalog::default(),
        }
    }

    pub fn admit(&mut self, route: JsValue) -> Result<JsValue, JsValue> {
        let route: DeviceRoute = from_value(route)?;
        let admitted = self.inner.admit(route).map_err(js_error)?;
        to_value(&admitted)
    }

    #[wasm_bindgen(js_name = routesFor)]
    pub fn routes_for(&self, scope_id: &str, device_id: &str) -> Result<JsValue, JsValue> {
        to_value(&self.inner.routes_for(scope_id, device_id))
    }
}

impl Default for WasmDeviceRouteCatalog {
    fn default() -> Self {
        Self::new()
    }
}

fn from_value<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(js_error)
}

fn to_value(value: &impl serde::Serialize) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_maps_as_objects(true)
                .serialize_missing_as_null(true),
        )
        .map_err(js_error)
}

fn integer(value: f64, message: &str) -> Result<i64, JsValue> {
    if value.is_finite()
        && value.fract() == 0.0
        && value >= i64::MIN as f64
        && value <= i64::MAX as f64
    {
        Ok(value as i64)
    } else {
        Err(js_error(message))
    }
}

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}
