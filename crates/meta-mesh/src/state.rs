use meta_mesh_core::{
    DeviceRoute, DeviceRouteCatalog, DeviceRoutePayload, DurableBatchAck, DurableBatchAckPayload,
    GossipBounds, GossipCandidate, IncomingDocumentChange, OutboxClaim, OutboxClaimInput,
    ReplicaSet, RouteHealth, SignedDeviceRoute, SignedDurableBatchAck, WorkspaceAuthority,
    WorkspaceGrant, WorkspaceOwnershipTransfer, WorkspacePeerRecord, WorkspaceRevocation,
    WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy, WorkspaceSuccessionVote,
    VerifyWorkspaceMemberOptions,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmStateCore;

#[wasm_bindgen]
impl WasmStateCore {
    #[wasm_bindgen(js_name = validateMeshCatalog)]
    pub fn validate_mesh_catalog(raw: JsValue) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let catalog = meta_mesh_core::validate_mesh_catalog(raw).map_err(js_error)?;
        to_value(&catalog)
    }

    #[wasm_bindgen(js_name = validateMeshHandshake)]
    pub fn validate_mesh_handshake(raw: JsValue, expected_workspace_id: Option<String>) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let handshake = meta_mesh_core::validate_mesh_handshake(raw, expected_workspace_id.as_deref()).map_err(js_error)?;
        to_value(&handshake)
    }

    #[wasm_bindgen(js_name = meshCapabilities)]
    pub fn mesh_capabilities() -> Result<JsValue, JsValue> {
        to_value(&meta_mesh_core::MESH_CAPABILITIES)
    }

    #[wasm_bindgen(js_name = validateMeshCapabilities)]
    pub fn validate_mesh_capabilities(capabilities: JsValue) -> Result<(), JsValue> {
        let capabilities: Vec<String> = from_value(capabilities)?;
        meta_mesh_core::validate_mesh_capabilities(&capabilities).map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceMemberBundle)]
    pub fn verify_workspace_member_bundle(
        raw: JsValue,
        options: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let options: VerifyWorkspaceMemberOptions = from_value(options)?;
        let verified = meta_mesh_core::verify_workspace_member_bundle(
            raw,
            options,
            i128::from(integer(now_ms, "Invalid member timestamp")?),
        ).map_err(js_error)?;
        to_value(&verified)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceGrant)]
    pub fn verify_workspace_grant(
        grant: JsValue,
        workspace_id: &str,
        member_person_id: &str,
        authority: JsValue,
    ) -> Result<JsValue, JsValue> {
        let grant: WorkspaceGrant = from_value(grant)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        let role = meta_mesh_core::verify_workspace_grant(
            &grant,
            workspace_id,
            member_person_id,
            &meta_mesh_core::PublicIdentity {
                person_id: authority.person_id,
                public_key: authority.public_key,
                display_name: String::new(),
            },
            &authority.certificates,
        )
        .map_err(js_error)?;
        to_value(&role)
    }

    #[wasm_bindgen(js_name = hasConflictingOwnershipTransfers)]
    pub fn has_conflicting_ownership_transfers(records: JsValue) -> Result<bool, JsValue> {
        let records: Vec<serde_json::Value> = from_value(records)?;
        Ok(meta_mesh_core::has_conflicting_ownership_transfers(
            &records,
        ))
    }

    #[wasm_bindgen(js_name = hasConflictingBreakGlassClaims)]
    pub fn has_conflicting_break_glass_claims(records: JsValue) -> Result<bool, JsValue> {
        let records: Vec<serde_json::Value> = from_value(records)?;
        Ok(meta_mesh_core::has_conflicting_break_glass_claims(&records))
    }

    #[wasm_bindgen(js_name = summarizeSuccession)]
    pub fn summarize_succession(
        policy: JsValue,
        claims: JsValue,
        votes: JsValue,
        transfers: JsValue,
        break_glass_claims: JsValue,
        revocations: JsValue,
        epoch: f64,
    ) -> Result<JsValue, JsValue> {
        let policy: Option<serde_json::Value> = optional_value(policy)?;
        let claims: Vec<serde_json::Value> = from_value(claims)?;
        let votes: Vec<serde_json::Value> = from_value(votes)?;
        let transfers: Vec<serde_json::Value> = from_value(transfers)?;
        let break_glass_claims: Vec<serde_json::Value> = from_value(break_glass_claims)?;
        let revocations: Vec<serde_json::Value> = from_value(revocations)?;
        to_value(&meta_mesh_core::summarize_succession(policy.as_ref(), &claims, &votes, &transfers,
            &break_glass_claims, &revocations, unsigned_integer(epoch, "Invalid succession epoch")?).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = eligibleEditorPersonIds)]
    pub fn eligible_editor_person_ids(peers: JsValue) -> Result<JsValue, JsValue> {
        let peers: Vec<serde_json::Value> = from_value(peers)?;
        to_value(&meta_mesh_core::eligible_editor_person_ids(&peers))
    }

    #[wasm_bindgen(js_name = canonicalRevocations)]
    pub fn canonical_revocations(records: JsValue) -> Result<JsValue, JsValue> {
        let records: Vec<serde_json::Value> = from_value(records)?;
        to_value(&meta_mesh_core::canonical_revocations(&records))
    }

    #[wasm_bindgen(js_name = verifyWorkspaceRevocation)]
    pub fn verify_workspace_revocation(
        record: JsValue,
        workspace_id: &str,
        authority: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let record: WorkspaceRevocation = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::verify_workspace_revocation(
            &record,
            workspace_id,
            &authority,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&record)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceOwnershipTransfer)]
    pub fn verify_workspace_ownership_transfer(
        record: JsValue,
        workspace_id: &str,
        authority: JsValue,
        minimum_epoch: f64,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let record: WorkspaceOwnershipTransfer = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::verify_workspace_ownership_transfer(
            &record,
            workspace_id,
            &authority,
            unsigned_integer(minimum_epoch, "Invalid ownership epoch")?,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&record)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceSuccessionPolicy)]
    pub fn verify_workspace_succession_policy(
        policy: JsValue,
        workspace_id: &str,
        authority: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let policy: WorkspaceSuccessionPolicy = from_value(policy)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::verify_workspace_succession_policy(
            &policy,
            workspace_id,
            &authority,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&policy)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceSuccessionVote)]
    pub fn verify_workspace_succession_vote(
        vote: JsValue,
        policy: JsValue,
        candidate_person_id: &str,
        authority: JsValue,
        revoked: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let vote: WorkspaceSuccessionVote = from_value(vote)?;
        let policy: WorkspaceSuccessionPolicy = from_value(policy)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        let revoked: std::collections::HashSet<String> = from_value(revoked)?;
        meta_mesh_core::verify_workspace_succession_vote(
            &vote,
            &policy,
            candidate_person_id,
            &authority,
            &revoked,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&vote)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceSuccessionClaim)]
    pub fn verify_workspace_succession_claim(
        claim: JsValue,
        workspace_id: &str,
        authority: JsValue,
        minimum_epoch: f64,
        revoked: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let claim: WorkspaceSuccessionClaim = from_value(claim)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        let revoked: std::collections::HashSet<String> = from_value(revoked)?;
        meta_mesh_core::verify_workspace_succession_claim(
            &claim,
            workspace_id,
            &authority,
            unsigned_integer(minimum_epoch, "Invalid succession epoch")?,
            &revoked,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&claim)
    }

    #[wasm_bindgen(js_name = planChangeAdmission)]
    pub fn plan_change_admission(
        document_id: &str,
        changes: JsValue,
        verified_at: &str,
    ) -> Result<JsValue, JsValue> {
        let changes: Vec<IncomingDocumentChange> = from_value(changes)?;
        let plan = meta_mesh_core::plan_change_admission(document_id, changes, verified_at)
            .map_err(js_error)?;
        to_value(&plan)
    }

    #[wasm_bindgen(js_name = transitionOutboxClaim)]
    pub fn transition_outbox_claim(current: JsValue, input: JsValue) -> Result<JsValue, JsValue> {
        let current: Option<OutboxClaim> = if current.is_null() || current.is_undefined() {
            None
        } else {
            Some(from_value(current)?)
        };
        let input: OutboxClaimInput = from_value(input)?;
        let transition =
            meta_mesh_core::transition_outbox_claim(current, input).map_err(js_error)?;
        to_value(&transition)
    }

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

    #[wasm_bindgen(js_name = validateDeviceRoutePayload)]
    pub fn validate_device_route_payload(payload: JsValue) -> Result<(), JsValue> {
        let payload: DeviceRoutePayload = from_value(payload)?;
        meta_mesh_core::validate_device_route_payload(&payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = validateDurableAckPayload)]
    pub fn validate_durable_ack_payload(payload: JsValue) -> Result<(), JsValue> {
        let payload: DurableBatchAckPayload = from_value(payload)?;
        meta_mesh_core::validate_durable_ack_payload(&payload).map_err(js_error)
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

fn optional_value<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<Option<T>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        from_value(value).map(Some)
    }
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
