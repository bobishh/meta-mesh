use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::{EndpointAddr, EndpointId};
use iroh_blobs::{Hash, ticket::BlobTicket};
use meta_mesh_core::{
    AutomergeSyncEngine, AutomergeSyncFrame, ControlFrameReceiver, DEFAULT_SIGNATURE_DOMAIN,
    DeviceBatch, DeviceRoute,
    DeviceRoutePayload, DurableBatchAck, DurableBatchAckPayload, GossipBounds, GossipCandidate,
    IdentityPassphraseEnvelope, IdentityRecoveryEnvelope, IdentitySecurity, IncomingDocumentChange,
    DialMode, LiveWorkspaceSession, MeshAuthenticatedSessions, MeshHandshakeFlow, MeshRuntimeState, OutboxClaim, OutboxClaimInput, PublicIdentity, RelayDialPolicy,
    ReplicaSet, RouteHealth,
    SessionCandidate, SessionDirection, SessionKey, SignedDeviceRoute,
    SignedDurableBatchAck, SignedEnvelope, WorkspaceAuthority, WorkspaceGrant,
    WorkspaceOwnershipTransfer, WorkspacePeerRecord, WorkspaceRevocation, WorkspaceSuccessionClaim,
    WorkspaceSuccessionPolicy, WorkspaceSuccessionVote, derive_device_seed, durable_ack_matches,
    has_conflicting_ownership_transfers, identity_security_for_recovery,
    legacy_recovery_from_samples, merge_peer_records, next_verified_ownership_transition, open_identity_seed,
    open_identity_seed_with_passphrase, order_delivery_routes, parse_invitation,
    plan_change_admission, public_key_from_seed, public_key_id, reconcile_replica_sets,
    recovery_phrase_from_entropy, recovery_phrase_to_entropy, seal_identity_seed,
    seal_identity_seed_with_passphrase, select_scoped_neighbors, sign_device_route,
    sign_durable_batch_ack, sign_json_envelope, transition_outbox_claim, validate_device_route,
    verify_device_route, verify_durable_batch_ack, verify_signed_envelope, verify_workspace_grant,
    verify_workspace_ownership_transfer, verify_workspace_revocation,
    verify_workspace_succession_claim, verify_workspace_succession_policy,
    verify_workspace_succession_vote, control_frames,
};
use meta_mesh_native::{
    GossipTopicReceiver, GossipTopicSender, NativeNode, NativeNodeOptions, NativeRpcInbox,
    NativeRpcRequest,
};
use serde_json::Value;
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileMeshError {
    #[error("{detail}")]
    Failure { detail: String },
}

impl MobileMeshError {
    fn from_display(error: impl std::fmt::Display) -> Self {
        Self::Failure {
            detail: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum MobileIdentitySecurity {
    Legacy,
    Better,
    Insane,
}

impl From<MobileIdentitySecurity> for IdentitySecurity {
    fn from(value: MobileIdentitySecurity) -> Self {
        match value {
            MobileIdentitySecurity::Legacy => IdentitySecurity::Legacy,
            MobileIdentitySecurity::Better => IdentitySecurity::Better,
            MobileIdentitySecurity::Insane => IdentitySecurity::Insane,
        }
    }
}

impl From<IdentitySecurity> for MobileIdentitySecurity {
    fn from(value: IdentitySecurity) -> Self {
        match value {
            IdentitySecurity::Legacy => MobileIdentitySecurity::Legacy,
            IdentitySecurity::Better => MobileIdentitySecurity::Better,
            IdentitySecurity::Insane => MobileIdentitySecurity::Insane,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileGossipMessage {
    pub content: Vec<u8>,
    pub delivered_from: String,
}

#[uniffi::export]
pub fn mesh_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[uniffi::export]
pub fn mesh_public_key_from_seed(seed: Vec<u8>) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Identity root must contain 32 bytes")?;
    public_key_from_seed(&seed).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_public_key_id(public_key: String) -> Result<String, MobileMeshError> {
    public_key_id(&public_key).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_derive_device_seed(entropy: Vec<u8>) -> Result<Vec<u8>, MobileMeshError> {
    let entropy = exact_bytes::<32>(&entropy, "Device entropy must contain 32 bytes")?;
    derive_device_seed(&entropy)
        .map(|seed| seed.to_vec())
        .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_recovery_phrase_from_entropy(entropy: Vec<u8>) -> Result<String, MobileMeshError> {
    recovery_phrase_from_entropy(&entropy).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_recovery_phrase_to_entropy(phrase: String) -> Result<Vec<u8>, MobileMeshError> {
    recovery_phrase_to_entropy(&phrase).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_legacy_recovery_from_samples(samples: Vec<u16>) -> Result<String, MobileMeshError> {
    legacy_recovery_from_samples(&samples).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_identity_security_for_recovery(recovery_key: String) -> Option<MobileIdentitySecurity> {
    identity_security_for_recovery(&recovery_key).map(Into::into)
}

#[uniffi::export]
pub fn mesh_sign_envelope_json(
    seed: Vec<u8>,
    payload_json: String,
    signer_key_id: String,
    domain: Option<String>,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Private key seed must contain 32 bytes")?;
    let payload: Value =
        serde_json::from_str(&payload_json).map_err(MobileMeshError::from_display)?;
    let envelope = sign_json_envelope(
        &seed,
        payload,
        signer_key_id,
        domain.as_deref().unwrap_or(DEFAULT_SIGNATURE_DOMAIN),
    )
    .map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&envelope).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_verify_envelope_json(
    envelope_json: String,
    public_key: String,
    domain: Option<String>,
) -> Result<bool, MobileMeshError> {
    let envelope: SignedEnvelope<Value> =
        serde_json::from_str(&envelope_json).map_err(MobileMeshError::from_display)?;
    verify_signed_envelope(
        &envelope,
        &public_key,
        domain.as_deref().unwrap_or(DEFAULT_SIGNATURE_DOMAIN),
    )
    .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_seal_identity_seed(
    seed: Vec<u8>,
    person_id: String,
    recovery_key: String,
    security: MobileIdentitySecurity,
    salt: Vec<u8>,
    iv: Vec<u8>,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Identity root must contain 32 bytes")?;
    let salt = exact_bytes::<16>(&salt, "Recovery salt must contain 16 bytes")?;
    let iv = exact_bytes::<12>(&iv, "Recovery IV must contain 12 bytes")?;
    let envelope = seal_identity_seed(
        &seed,
        &person_id,
        &recovery_key,
        security.into(),
        &salt,
        &iv,
    )
    .map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&envelope).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_open_identity_seed(
    envelope_json: String,
    recovery_key: String,
) -> Result<Vec<u8>, MobileMeshError> {
    let envelope: IdentityRecoveryEnvelope =
        serde_json::from_str(&envelope_json).map_err(MobileMeshError::from_display)?;
    open_identity_seed(&envelope, &recovery_key)
        .map(|seed| seed.to_vec())
        .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_seal_identity_seed_with_passphrase(
    seed: Vec<u8>,
    person_id: String,
    passphrase: String,
    salt: Vec<u8>,
    iv: Vec<u8>,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Identity root must contain 32 bytes")?;
    let salt = exact_bytes::<16>(&salt, "Passphrase salt must contain 16 bytes")?;
    let iv = exact_bytes::<12>(&iv, "Passphrase IV must contain 12 bytes")?;
    let envelope = seal_identity_seed_with_passphrase(&seed, &person_id, &passphrase, &salt, &iv)
        .map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&envelope).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_open_identity_seed_with_passphrase(
    envelope_json: String,
    passphrase: String,
) -> Result<Vec<u8>, MobileMeshError> {
    let envelope: IdentityPassphraseEnvelope =
        serde_json::from_str(&envelope_json).map_err(MobileMeshError::from_display)?;
    open_identity_seed_with_passphrase(&envelope, &passphrase)
        .map(|seed| seed.to_vec())
        .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_parse_invitation_json(
    invitation_url: String,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let invitation =
        parse_invitation(&invitation_url, now_ms).map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&invitation).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_admit_peer_json(
    handshake_json: String,
    snapshot_json: String,
    remote_endpoint: String,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let handshake = serde_json::from_str(&handshake_json).map_err(MobileMeshError::from_display)?;
    let snapshot = serde_json::from_str(&snapshot_json).map_err(MobileMeshError::from_display)?;
    let admitted = meta_mesh_core::admit_mesh_peer(handshake, &snapshot, &remote_endpoint, i128::from(now_ms))
        .map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&admitted).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_merge_peer_records_json(
    existing_json: String,
    incoming_json: String,
) -> Result<String, MobileMeshError> {
    let existing: WorkspacePeerRecord = from_json(&existing_json)?;
    let incoming: WorkspacePeerRecord = from_json(&incoming_json)?;
    to_json(&merge_peer_records(&existing, &incoming).map_err(MobileMeshError::from_display)?)
}

#[uniffi::export]
pub fn mesh_reconcile_replica_sets_json(
    left_json: String,
    right_json: String,
) -> Result<String, MobileMeshError> {
    let left: ReplicaSet = from_json(&left_json)?;
    let right: ReplicaSet = from_json(&right_json)?;
    to_json(&reconcile_replica_sets(&left, &right).map_err(MobileMeshError::from_display)?)
}

#[uniffi::export]
pub fn mesh_select_scoped_neighbors_json(
    local_device_id: String,
    candidates_json: String,
    bounds_json: String,
    now_ms: i64,
    rotation: u32,
) -> Result<String, MobileMeshError> {
    let candidates: Vec<GossipCandidate> = from_json(&candidates_json)?;
    let bounds: GossipBounds = from_json(&bounds_json)?;
    to_json(
        &select_scoped_neighbors(&local_device_id, &candidates, &bounds, now_ms, rotation)
            .map_err(MobileMeshError::from_display)?,
    )
}

#[uniffi::export]
pub fn mesh_sign_device_route_json(
    seed: Vec<u8>,
    signer_key_id: String,
    payload_json: String,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Private key seed must contain 32 bytes")?;
    let payload: DeviceRoutePayload = from_json(&payload_json)?;
    to_json(
        &sign_device_route(&seed, &signer_key_id, payload)
            .map_err(MobileMeshError::from_display)?,
    )
}

#[uniffi::export]
pub fn mesh_verify_device_route_json(
    envelope_json: String,
    public_key: String,
    now_ms: i64,
    allow_expired: bool,
) -> Result<String, MobileMeshError> {
    let envelope: SignedDeviceRoute = from_json(&envelope_json)?;
    to_json(
        &verify_device_route(&envelope, &public_key, i128::from(now_ms), allow_expired)
            .map_err(MobileMeshError::from_display)?,
    )
}

#[uniffi::export]
pub fn mesh_validate_device_route_json(route_json: String) -> Result<(), MobileMeshError> {
    let route: DeviceRoute = from_json(&route_json)?;
    validate_device_route(&route).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_sign_durable_ack_json(
    seed: Vec<u8>,
    signer_key_id: String,
    payload_json: String,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Private key seed must contain 32 bytes")?;
    let payload: DurableBatchAckPayload = from_json(&payload_json)?;
    to_json(
        &sign_durable_batch_ack(&seed, &signer_key_id, payload)
            .map_err(MobileMeshError::from_display)?,
    )
}

#[uniffi::export]
pub fn mesh_verify_durable_ack_json(
    envelope_json: String,
    public_key: String,
) -> Result<String, MobileMeshError> {
    let envelope: SignedDurableBatchAck = from_json(&envelope_json)?;
    to_json(
        &verify_durable_batch_ack(&envelope, &public_key).map_err(MobileMeshError::from_display)?,
    )
}

#[uniffi::export]
pub fn mesh_durable_ack_matches_json(
    ack_json: String,
    batch_json: String,
    target_device_id: String,
) -> Result<bool, MobileMeshError> {
    let ack: DurableBatchAck = from_json(&ack_json)?;
    let batch: DeviceBatch = from_json(&batch_json)?;
    Ok(durable_ack_matches(&ack, &batch, &target_device_id))
}

#[uniffi::export]
pub fn mesh_order_delivery_routes_json(
    target_device_id: String,
    routes_json: String,
) -> Result<String, MobileMeshError> {
    let routes: Vec<RouteHealth> = from_json(&routes_json)?;
    to_json(
        &order_delivery_routes(&target_device_id, &routes)
            .map_err(MobileMeshError::from_display)?,
    )
}

#[uniffi::export]
pub fn mesh_verify_workspace_grant_json(
    grant_json: String,
    workspace_id: String,
    member_person_id: String,
    authority_json: String,
) -> Result<String, MobileMeshError> {
    let grant: WorkspaceGrant = from_json(&grant_json)?;
    let authority: WorkspaceAuthority = from_json(&authority_json)?;
    let role = verify_workspace_grant(
        &grant,
        &workspace_id,
        &member_person_id,
        &PublicIdentity {
            person_id: authority.person_id,
            public_key: authority.public_key,
            display_name: String::new(),
        },
        &authority.certificates,
    )
    .map_err(MobileMeshError::from_display)?;
    to_json(&role)
}

#[uniffi::export]
pub fn mesh_has_conflicting_ownership_transfers_json(
    records_json: String,
) -> Result<bool, MobileMeshError> {
    let records: Vec<Value> = from_json(&records_json)?;
    Ok(has_conflicting_ownership_transfers(&records))
}

#[uniffi::export]
pub fn mesh_verify_workspace_revocation_json(
    record_json: String,
    workspace_id: String,
    authority_json: String,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let record: WorkspaceRevocation = from_json(&record_json)?;
    let authority: WorkspaceAuthority = from_json(&authority_json)?;
    verify_workspace_revocation(&record, &workspace_id, &authority, i128::from(now_ms))
        .map_err(MobileMeshError::from_display)?;
    to_json(&record)
}

#[uniffi::export]
pub fn mesh_verify_workspace_ownership_transfer_json(
    record_json: String,
    workspace_id: String,
    authority_json: String,
    minimum_epoch: u64,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let record: WorkspaceOwnershipTransfer = from_json(&record_json)?;
    let authority: WorkspaceAuthority = from_json(&authority_json)?;
    verify_workspace_ownership_transfer(
        &record,
        &workspace_id,
        &authority,
        minimum_epoch,
        i128::from(now_ms),
    )
    .map_err(MobileMeshError::from_display)?;
    to_json(&record)
}

#[uniffi::export]
pub fn mesh_next_verified_ownership_transition_json(
    records_json: String,
    workspace_id: String,
    current_owner_json: String,
    current_epoch: u64,
    revoked_people: Vec<String>,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let records: Vec<Value> = from_json(&records_json)?;
    let current_owner: WorkspaceAuthority = from_json(&current_owner_json)?;
    let plan = next_verified_ownership_transition(
        &records, &workspace_id, &current_owner, current_epoch,
        &revoked_people.into_iter().collect::<HashSet<_>>(), i128::from(now_ms),
    ).map_err(MobileMeshError::from_display)?;
    to_json(&plan)
}

#[uniffi::export]
pub fn mesh_verify_workspace_succession_policy_json(
    policy_json: String,
    workspace_id: String,
    authority_json: String,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let policy: WorkspaceSuccessionPolicy = from_json(&policy_json)?;
    let authority: WorkspaceAuthority = from_json(&authority_json)?;
    verify_workspace_succession_policy(&policy, &workspace_id, &authority, i128::from(now_ms))
        .map_err(MobileMeshError::from_display)?;
    to_json(&policy)
}

#[uniffi::export]
pub fn mesh_verify_workspace_succession_vote_json(
    vote_json: String,
    policy_json: String,
    candidate_person_id: String,
    authority_json: String,
    revoked_person_ids: Vec<String>,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let vote: WorkspaceSuccessionVote = from_json(&vote_json)?;
    let policy: WorkspaceSuccessionPolicy = from_json(&policy_json)?;
    let authority: WorkspaceAuthority = from_json(&authority_json)?;
    let revoked = revoked_person_ids.into_iter().collect::<HashSet<_>>();
    verify_workspace_succession_vote(
        &vote,
        &policy,
        &candidate_person_id,
        &authority,
        &revoked,
        i128::from(now_ms),
    )
    .map_err(MobileMeshError::from_display)?;
    to_json(&vote)
}

#[uniffi::export]
pub fn mesh_verify_workspace_succession_claim_json(
    claim_json: String,
    workspace_id: String,
    authority_json: String,
    minimum_epoch: u64,
    revoked_person_ids: Vec<String>,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let claim: WorkspaceSuccessionClaim = from_json(&claim_json)?;
    let authority: WorkspaceAuthority = from_json(&authority_json)?;
    let revoked = revoked_person_ids.into_iter().collect::<HashSet<_>>();
    verify_workspace_succession_claim(
        &claim,
        &workspace_id,
        &authority,
        minimum_epoch,
        &revoked,
        i128::from(now_ms),
    )
    .map_err(MobileMeshError::from_display)?;
    to_json(&claim)
}

#[uniffi::export]
pub fn mesh_plan_change_admission_json(
    document_id: String,
    changes_json: String,
    verified_at: String,
) -> Result<String, MobileMeshError> {
    let changes: Vec<IncomingDocumentChange> = from_json(&changes_json)?;
    to_json(
        &plan_change_admission(&document_id, changes, &verified_at)
            .map_err(MobileMeshError::from_display)?,
    )
}

#[uniffi::export]
pub fn mesh_transition_outbox_claim_json(
    current_json: Option<String>,
    input_json: String,
) -> Result<String, MobileMeshError> {
    let current: Option<OutboxClaim> = current_json.map(|value| from_json(&value)).transpose()?;
    let input: OutboxClaimInput = from_json(&input_json)?;
    to_json(&transition_outbox_claim(current, input).map_err(MobileMeshError::from_display)?)
}

#[derive(uniffi::Object)]
pub struct MobileMeshAuthenticatedSessions {
    inner: Mutex<MeshAuthenticatedSessions>,
}

#[uniffi::export]
impl MobileMeshAuthenticatedSessions {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(MeshAuthenticatedSessions::default()) })
    }

    pub fn admit_json(&self, handshake_json: String, snapshot_json: String, remote_endpoint: String, now_ms: i64) -> Result<String, MobileMeshError> {
        let handshake = from_json(&handshake_json)?;
        let snapshot = from_json(&snapshot_json)?;
        let admitted = self.inner.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile mesh session lock poisoned"))?
            .admit(handshake, &snapshot, &remote_endpoint, i128::from(now_ms))
            .map_err(MobileMeshError::from_display)?;
        to_json(&admitted)
    }

    pub fn peer_json(&self, workspace_id: String, remote_endpoint: String) -> Result<Option<String>, MobileMeshError> {
        let sessions = self.inner.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile mesh session lock poisoned"))?;
        sessions.peer(&workspace_id, &remote_endpoint).map(to_json).transpose()
    }

    pub fn refresh_json(&self, snapshot_json: String, now_ms: i64) -> Result<String, MobileMeshError> {
        let snapshot = from_json(&snapshot_json)?;
        let evicted = self.inner.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile mesh session lock poisoned"))?
            .refresh(&snapshot, i128::from(now_ms))
            .map_err(MobileMeshError::from_display)?;
        to_json(&evicted)
    }

    pub fn remove(&self, workspace_id: String, remote_endpoint: String) -> Result<bool, MobileMeshError> {
        Ok(self.inner.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile mesh session lock poisoned"))?
            .remove(&workspace_id, &remote_endpoint))
    }

    pub fn clear(&self) -> Result<(), MobileMeshError> {
        self.inner.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile mesh session lock poisoned"))?
            .clear();
        Ok(())
    }
}

#[derive(uniffi::Object)]
pub struct MobileMeshHandshakeFlow {
    flow: Mutex<MeshHandshakeFlow>,
}

#[uniffi::export]
impl MobileMeshHandshakeFlow {
    #[uniffi::constructor]
    pub fn new(direction: String) -> Result<Arc<Self>, MobileMeshError> {
        Ok(Arc::new(Self { flow: Mutex::new(MeshHandshakeFlow::new(mobile_direction(&direction)?)) }))
    }

    pub fn step(&self) -> Result<String, MobileMeshError> {
        let flow = self.flow.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile handshake lock poisoned"))?;
        Ok(flow.step().as_str().to_string())
    }

    pub fn advance(&self, completed: String, decision: Option<bool>) -> Result<String, MobileMeshError> {
        let mut flow = self.flow.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile handshake lock poisoned"))?;
        flow.advance(&completed, decision).map(|step| step.as_str().to_string())
            .map_err(MobileMeshError::from_display)
    }
}

#[derive(uniffi::Object)]
pub struct MobileMeshRuntime {
    state: Mutex<MeshRuntimeState>,
    relay_policy: Mutex<RelayDialPolicy>,
    control_receivers: Mutex<BTreeMap<String, ControlFrameReceiver>>,
    transfer_sequence: Mutex<u64>,
}

#[derive(uniffi::Object)]
pub struct MobileLiveWorkspaceSession {
    inner: Mutex<LiveWorkspaceSession>,
}

#[uniffi::export]
impl MobileLiveWorkspaceSession {
    #[uniffi::constructor]
    pub fn new(workspace_id: String, secret: String) -> Result<Arc<Self>, MobileMeshError> {
        Ok(Arc::new(Self { inner: Mutex::new(
            LiveWorkspaceSession::new(workspace_id, secret).map_err(MobileMeshError::from_display)?,
        ) }))
    }

    pub fn receive_json(&self, frame: Vec<u8>) -> Result<String, MobileMeshError> {
        self.with_inner(|session| to_json(&session.receive(&frame).map_err(MobileMeshError::from_display)?))
    }

    pub fn encode(&self, frame_type: String, payload: Vec<u8>) -> Result<Vec<u8>, MobileMeshError> {
        self.with_inner(|session| session.encode(&frame_type, &payload).map_err(MobileMeshError::from_display))
    }

    pub fn encode_automerge_frame(&self, frame_json: String) -> Result<Vec<u8>, MobileMeshError> {
        let frame: AutomergeSyncFrame = from_json(&frame_json)?;
        self.with_inner(|session| session.encode_automerge_frame(&frame).map_err(MobileMeshError::from_display))
    }

    pub fn decode_automerge_payload_json(&self, payload: Vec<u8>) -> Result<String, MobileMeshError> {
        self.with_inner(|session| to_json(&session.decode_automerge_payload(&payload).map_err(MobileMeshError::from_display)?))
    }

    pub fn start_document_sync(&self, local_device_id: String, remote_device_id: String) -> Result<(), MobileMeshError> {
        self.with_inner(|session| session.start_document_sync(&local_device_id, &remote_device_id).map_err(MobileMeshError::from_display))
    }

    pub fn generate_document(&self, document: Vec<u8>, proof_json: Option<String>) -> Result<Option<Vec<u8>>, MobileMeshError> {
        let proof = proof_json.as_deref().map(from_json).transpose()?;
        self.with_inner(|session| session.generate_document(&document, proof).map_err(MobileMeshError::from_display))
    }

    pub fn prepare_document_json(&self, payload: Vec<u8>, document: Vec<u8>, response_proof_json: Option<String>) -> Result<String, MobileMeshError> {
        let response_proof = response_proof_json.as_deref().map(from_json).transpose()?;
        self.with_inner(|session| to_json(&session.prepare_document(&payload, &document, response_proof).map_err(MobileMeshError::from_display)?))
    }

    pub fn commit_document(&self) -> Result<(), MobileMeshError> {
        self.with_inner(|session| session.commit_document().map_err(MobileMeshError::from_display))
    }

    pub fn abort_document(&self) -> Result<(), MobileMeshError> {
        self.with_inner(|session| { session.abort_document(); Ok(()) })
    }

    pub fn reset_document(&self) -> Result<(), MobileMeshError> {
        self.with_inner(|session| { session.reset_document(); Ok(()) })
    }

    pub fn control_changed(&self, snapshot: Vec<u8>) -> Result<bool, MobileMeshError> {
        self.with_inner(|session| Ok(session.control_changed(&snapshot)))
    }

    pub fn control_frames(&self, snapshot: Vec<u8>) -> Result<Vec<Vec<u8>>, MobileMeshError> {
        self.with_inner(|session| session.control_frames(&snapshot).map_err(MobileMeshError::from_display))
    }

    pub fn mark_control_sent(&self, snapshot: Vec<u8>) -> Result<(), MobileMeshError> {
        self.with_inner(|session| { session.mark_control_sent(snapshot); Ok(()) })
    }

    pub fn acknowledge_saved(&self, bytes: Vec<u8>) -> Result<Vec<u8>, MobileMeshError> {
        self.with_inner(|session| session.acknowledge_saved(&bytes).map_err(MobileMeshError::from_display))
    }

    pub fn verify_saved_receipt(&self, frame: Vec<u8>, bytes: Vec<u8>) -> Result<(), MobileMeshError> {
        self.with_inner(|session| session.verify_saved_receipt(&frame, &bytes).map_err(MobileMeshError::from_display))
    }

    pub fn verify_heartbeat_ack(&self, frame: Vec<u8>) -> Result<(), MobileMeshError> {
        self.with_inner(|session| session.verify_heartbeat_ack(&frame).map_err(MobileMeshError::from_display))
    }
}

impl MobileLiveWorkspaceSession {
    fn with_inner<T>(&self, action: impl FnOnce(&mut LiveWorkspaceSession) -> Result<T, MobileMeshError>) -> Result<T, MobileMeshError> {
        let mut session = self.inner.lock().map_err(|_| MobileMeshError::from_display("Mobile live session lock poisoned"))?;
        action(&mut session)
    }
}

#[uniffi::export]
impl MobileMeshRuntime {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(MeshRuntimeState::default()),
            relay_policy: Mutex::new(RelayDialPolicy::default()),
            control_receivers: Mutex::new(BTreeMap::new()),
            transfer_sequence: Mutex::new(0),
        })
    }

    pub fn start(&self) -> Result<(), MobileMeshError> {
        self.with_state(|state| { state.start(); Ok(()) })
    }

    pub fn stop(&self) -> Result<Vec<String>, MobileMeshError> {
        self.with_state(|state| Ok(state.stop()))
    }

    pub fn is_running(&self) -> Result<bool, MobileMeshError> {
        self.with_state(|state| Ok(state.is_running()))
    }

    pub fn sessions_json(&self) -> Result<String, MobileMeshError> {
        let sessions = self.with_state(|state| Ok(state.sessions().cloned().collect::<Vec<_>>()))?;
        to_json(&sessions)
    }

    pub fn begin_route_attempt_json(
        &self,
        route_key: String,
        now_ms: u64,
    ) -> Result<String, MobileMeshError> {
        let attempt = self.with_state(|state| Ok(state.begin_route_attempt(route_key, now_ms)))?;
        to_json(&attempt)
    }

    pub fn route_attempt_active(&self, route_key: String) -> Result<bool, MobileMeshError> {
        self.with_state(|state| Ok(state.route_attempt_active(&route_key)))
    }

    pub fn clear_route_attempt(&self, route_key: String) -> Result<(), MobileMeshError> {
        self.with_state(|state| { state.clear_route_attempt(&route_key); Ok(()) })
    }

    pub fn finish_route_attempt(&self, route_key: String, token: u64) -> Result<bool, MobileMeshError> {
        self.with_state(|state| Ok(state.finish_route_attempt(&route_key, token)))
    }

    pub fn admit_session_json(
        &self,
        candidate_json: String,
        preferred_direction: String,
    ) -> Result<String, MobileMeshError> {
        let candidate: SessionCandidate = from_json(&candidate_json)?;
        let preferred = mobile_direction(&preferred_direction)?;
        let admission = self.with_state(|state| Ok(state.admit_session(candidate, preferred)))?;
        to_json(&admission)
    }

    pub fn remove_session_json(
        &self,
        key_json: String,
        generation: u64,
    ) -> Result<Option<String>, MobileMeshError> {
        let key: SessionKey = from_json(&key_json)?;
        self.with_state(|state| Ok(state.remove_session(&key, generation)))
    }

    pub fn schedule_reconnect_json(
        &self,
        route_key: String,
        now_ms: u64,
        base_delay_ms: u64,
        maximum_delay_ms: u64,
    ) -> Result<String, MobileMeshError> {
        let value = self.with_state(|state| Ok(state.schedule_reconnect(
            route_key, now_ms, base_delay_ms, maximum_delay_ms,
        )))?;
        to_json(&value)
    }

    pub fn due_reconnects(&self, now_ms: u64) -> Result<Vec<String>, MobileMeshError> {
        self.with_state(|state| Ok(state.due_reconnects(now_ms)))
    }

    pub fn reconnect_state_json(&self, route_key: String) -> Result<Option<String>, MobileMeshError> {
        self.with_state(|state| Ok(state.reconnect_state(&route_key)))?
            .map(|value| to_json(&value)).transpose()
    }

    pub fn clear_reconnect(&self, route_key: String) -> Result<(), MobileMeshError> {
        self.with_state(|state| { state.clear_reconnect(&route_key); Ok(()) })
    }

    pub fn clear_reconnects_with_prefix(&self, prefix: String) -> Result<(), MobileMeshError> {
        self.with_state(|state| { state.clear_reconnects_with_prefix(&prefix); Ok(()) })
    }

    pub fn connected_devices(&self, workspace_id: String) -> Result<Vec<String>, MobileMeshError> {
        self.with_state(|state| Ok(state.connected_devices(&workspace_id).into_iter().collect()))
    }

    pub fn set_gossip_endpoints_json(
        &self,
        workspace_id: String,
        endpoints: Vec<String>,
    ) -> Result<String, MobileMeshError> {
        let topology = self.with_state(|state| Ok(state.set_gossip_endpoints(workspace_id, endpoints)))?;
        to_json(&topology)
    }

    pub fn clear_gossip(&self, workspace_id: String) -> Result<(), MobileMeshError> {
        self.with_state(|state| { state.clear_gossip(&workspace_id); Ok(()) })
    }

    pub fn plan_dial_json(
        &self,
        peer_key: String,
        relay_available: bool,
        now_ms: u64,
    ) -> Result<String, MobileMeshError> {
        let mut policy = self.relay_policy.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile dial policy lock poisoned"))?;
        to_json(&policy.plan(&peer_key, relay_available, now_ms))
    }

    pub fn record_network_failure(&self, peer_key: String, now_ms: u64) -> Result<(), MobileMeshError> {
        let mut policy = self.relay_policy.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile dial policy lock poisoned"))?;
        policy.record_network_failure(peer_key, now_ms);
        Ok(())
    }

    pub fn record_dial_success(
        &self,
        peer_key: String,
        mode: String,
        now_ms: u64,
    ) -> Result<(), MobileMeshError> {
        let mode = match mode.as_str() {
            "direct" => DialMode::Direct,
            "relay" => DialMode::Relay,
            _ => return Err(MobileMeshError::from_display("Invalid dial mode")),
        };
        let mut policy = self.relay_policy.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile dial policy lock poisoned"))?;
        policy.record_success(&peer_key, mode, now_ms);
        Ok(())
    }

    pub fn control_frames(
        &self,
        workspace_id: String,
        bytes: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, MobileMeshError> {
        let mut sequence = self.transfer_sequence.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile runtime transfer lock poisoned"))?;
        *sequence = sequence.saturating_add(1);
        control_frames(&workspace_id, &format!("mobile-{sequence}"), &bytes)
            .map_err(MobileMeshError::from_display)
    }

    pub fn receive_control_frame(
        &self,
        receiver_id: String,
        workspace_id: String,
        frame: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, MobileMeshError> {
        let mut receivers = self.control_receivers.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile runtime control lock poisoned"))?;
        receivers.entry(receiver_id).or_insert_with(|| ControlFrameReceiver::new(workspace_id))
            .receive(&frame).map_err(MobileMeshError::from_display)
    }
}

impl MobileMeshRuntime {
    fn with_state<T>(
        &self,
        action: impl FnOnce(&mut MeshRuntimeState) -> Result<T, String>,
    ) -> Result<T, MobileMeshError> {
        let mut state = self.state.lock()
            .map_err(|_| MobileMeshError::from_display("Mobile runtime lock poisoned"))?;
        action(&mut state).map_err(MobileMeshError::from_display)
    }
}

fn mobile_direction(value: &str) -> Result<SessionDirection, MobileMeshError> {
    match value {
        "incoming" => Ok(SessionDirection::Incoming),
        "outgoing" => Ok(SessionDirection::Outgoing),
        _ => Err(MobileMeshError::from_display("Invalid session direction")),
    }
}

#[derive(uniffi::Object)]
pub struct MobileAutomergeSyncEngine {
    engine: Mutex<AutomergeSyncEngine>,
}

#[uniffi::export]
impl MobileAutomergeSyncEngine {
    #[uniffi::constructor]
    pub fn new(
        local_device_id: String,
        maximum_frame_bytes: Option<u64>,
    ) -> Result<Arc<Self>, MobileMeshError> {
        let maximum_frame_bytes = maximum_frame_bytes
            .map(usize::try_from)
            .transpose()
            .map_err(MobileMeshError::from_display)?;
        let engine = AutomergeSyncEngine::new(local_device_id, maximum_frame_bytes)
            .map_err(MobileMeshError::from_display)?;
        Ok(Arc::new(Self {
            engine: Mutex::new(engine),
        }))
    }

    pub fn load_document(
        &self,
        scope_id: String,
        document_id: String,
        bytes: Vec<u8>,
    ) -> Result<(), MobileMeshError> {
        self.with_engine(|engine| engine.load_document(scope_id, document_id, &bytes))
    }

    pub fn save_document(&self, document_id: String) -> Result<Vec<u8>, MobileMeshError> {
        self.with_engine(|engine| engine.save_document(&document_id))
    }

    pub fn heads(&self, document_id: String) -> Result<Vec<String>, MobileMeshError> {
        self.with_engine(|engine| engine.heads(&document_id))
    }

    pub fn reset(
        &self,
        document_id: String,
        remote_device_id: String,
    ) -> Result<(), MobileMeshError> {
        self.with_engine(|engine| {
            engine.reset(&document_id, &remote_device_id);
            Ok(())
        })
    }

    pub fn generate_json(
        &self,
        document_id: String,
        remote_device_id: String,
        authorized: bool,
        proof_json: Option<String>,
    ) -> Result<Option<String>, MobileMeshError> {
        let proof = proof_json.map(|value| from_json(&value)).transpose()?;
        self.with_engine(|engine| {
            engine.generate(&document_id, &remote_device_id, authorized, proof)
        })?
        .map(|frame| to_json(&frame))
        .transpose()
    }

    pub fn receive_json(
        &self,
        remote_device_id: String,
        frame_json: String,
        authorized: bool,
        response_proof_json: Option<String>,
    ) -> Result<String, MobileMeshError> {
        let frame: AutomergeSyncFrame = from_json(&frame_json)?;
        let response_proof = response_proof_json
            .map(|value| from_json(&value))
            .transpose()?;
        let result = self.with_engine(|engine| {
            engine.receive(&remote_device_id, frame, authorized, response_proof)
        })?;
        to_json(&result)
    }

    pub fn prepare_receive_json(
        &self,
        remote_device_id: String,
        frame_json: String,
        authorized: bool,
        response_proof_json: Option<String>,
    ) -> Result<String, MobileMeshError> {
        let frame: AutomergeSyncFrame = from_json(&frame_json)?;
        let response_proof = response_proof_json.map(|value| from_json(&value)).transpose()?;
        let result = self.with_engine(|engine| {
            engine.prepare_receive(&remote_device_id, frame, authorized, response_proof)
        })?;
        to_json(&result)
    }

    pub fn commit_prepared_receive(
        &self,
        document_id: String,
        remote_device_id: String,
    ) -> Result<(), MobileMeshError> {
        self.with_engine(|engine| engine.commit_prepared_receive(&document_id, &remote_device_id))
    }

    pub fn abort_prepared_receive(
        &self,
        document_id: String,
        remote_device_id: String,
    ) -> Result<(), MobileMeshError> {
        self.with_engine(|engine| {
            engine.abort_prepared_receive(&document_id, &remote_device_id);
            Ok(())
        })
    }
}

impl MobileAutomergeSyncEngine {
    fn with_engine<T>(
        &self,
        action: impl FnOnce(&mut AutomergeSyncEngine) -> Result<T, String>,
    ) -> Result<T, MobileMeshError> {
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile Automerge lock poisoned"))?;
        action(&mut engine).map_err(MobileMeshError::from_display)
    }
}

#[derive(uniffi::Object)]
pub struct MobileMeshNode {
    runtime: Arc<Runtime>,
    node: Mutex<Option<NativeNode>>,
    rpc_inbox: Arc<NativeRpcInbox>,
}

#[derive(uniffi::Object)]
pub struct MobileRpcRequest {
    remote_endpoint_id: String,
    payload_json: String,
    request: Mutex<Option<NativeRpcRequest>>,
}

#[uniffi::export]
impl MobileRpcRequest {
    pub fn remote_endpoint_id(&self) -> String {
        self.remote_endpoint_id.clone()
    }

    pub fn payload_json(&self) -> String {
        self.payload_json.clone()
    }

    pub fn respond_json(&self, response_json: String) -> Result<(), MobileMeshError> {
        validate_json(&response_json)?;
        self.take_request()?
            .respond(response_json.into_bytes())
            .map_err(MobileMeshError::from_display)
    }

    pub fn fail(&self, message: String) -> Result<(), MobileMeshError> {
        let response = serde_json::to_vec(&serde_json::json!({ "error": message }))
            .map_err(MobileMeshError::from_display)?;
        self.take_request()?
            .respond(response)
            .map_err(MobileMeshError::from_display)
    }
}

impl MobileRpcRequest {
    fn take_request(&self) -> Result<NativeRpcRequest, MobileMeshError> {
        self.request
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile RPC request lock poisoned"))?
            .take()
            .ok_or_else(|| MobileMeshError::from_display("Mobile RPC request already answered"))
    }
}

#[uniffi::export]
impl MobileMeshNode {
    #[uniffi::constructor]
    pub fn start(
        secret: Option<Vec<u8>>,
        allowed_peer_ids: Vec<String>,
        allow_unknown_peers: bool,
        storage_path: Option<String>,
    ) -> Result<Arc<Self>, MobileMeshError> {
        let secret = secret
            .map(|value| exact_bytes::<32>(&value, "Node secret must contain 32 bytes"))
            .transpose()?;
        let allowed_peers = allowed_peer_ids
            .iter()
            .map(|value| EndpointId::from_str(value).map_err(MobileMeshError::from_display))
            .collect::<Result<Vec<_>, _>>()?;
        let runtime = Arc::new(Runtime::new().map_err(MobileMeshError::from_display)?);
        let node = runtime
            .block_on(NativeNode::start_with_options(NativeNodeOptions {
                secret,
                allowed_peers,
                allow_any: allow_unknown_peers,
                storage_path: storage_path.map(PathBuf::from),
                ..NativeNodeOptions::default()
            }))
            .map_err(MobileMeshError::from_display)?;
        let rpc_inbox = node.rpc_inbox();
        Ok(Arc::new(Self {
            runtime,
            node: Mutex::new(Some(node)),
            rpc_inbox,
        }))
    }

    pub fn endpoint_id(&self) -> Result<String, MobileMeshError> {
        self.with_node(|node| Ok(node.endpoint_id().to_string()))
    }

    pub fn endpoint_addr_json(&self) -> Result<String, MobileMeshError> {
        self.with_node(|node| {
            serde_json::to_string(&node.addr()).map_err(MobileMeshError::from_display)
        })
    }

    pub fn authorize_peer(&self, peer_id: String) -> Result<(), MobileMeshError> {
        let peer = EndpointId::from_str(&peer_id).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            node.authorize_peer(peer);
            Ok(())
        })
    }

    pub fn revoke_peer(&self, peer_id: String) -> Result<(), MobileMeshError> {
        let peer = EndpointId::from_str(&peer_id).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            node.revoke_peer(&peer);
            Ok(())
        })
    }

    pub fn request_json(
        &self,
        endpoint: String,
        payload_json: String,
        timeout_ms: u64,
    ) -> Result<String, MobileMeshError> {
        validate_json(&payload_json)?;
        let endpoint = parse_endpoint_addr(&endpoint)?;
        let response = self.with_node(|node| {
            self.runtime
                .block_on(node.request(
                    endpoint,
                    payload_json.as_bytes(),
                    Duration::from_millis(timeout_ms),
                ))
                .map_err(MobileMeshError::from_display)
        })?;
        let response = String::from_utf8(response).map_err(MobileMeshError::from_display)?;
        let value = validate_json(&response)?;
        if let Some(message) = value.get("error").and_then(Value::as_str) {
            return Err(MobileMeshError::from_display(message));
        }
        Ok(response)
    }

    pub fn receive_request(
        &self,
        timeout_ms: u64,
    ) -> Result<Option<Arc<MobileRpcRequest>>, MobileMeshError> {
        let request = self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(timeout_ms), self.rpc_inbox.receive()).await
        });
        let Some(request) = (match request {
            Ok(request) => request,
            Err(_) => return Ok(None),
        }) else {
            return Ok(None);
        };
        let payload_json =
            String::from_utf8(request.payload().to_vec()).map_err(MobileMeshError::from_display)?;
        validate_json(&payload_json)?;
        Ok(Some(Arc::new(MobileRpcRequest {
            remote_endpoint_id: request.remote_endpoint_id().to_string(),
            payload_json,
            request: Mutex::new(Some(request)),
        })))
    }

    pub fn add_blob(&self, data: Vec<u8>) -> Result<String, MobileMeshError> {
        self.with_node(|node| {
            self.runtime
                .block_on(node.add_blob(&data))
                .map(|ticket| ticket.to_string())
                .map_err(MobileMeshError::from_display)
        })
    }

    pub fn get_blob(&self, hash: String) -> Result<Option<Vec<u8>>, MobileMeshError> {
        let hash = Hash::from_str(&hash).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            self.runtime
                .block_on(node.get_blob(hash))
                .map_err(MobileMeshError::from_display)
        })
    }

    pub fn fetch_blob(&self, ticket: String) -> Result<Vec<u8>, MobileMeshError> {
        let ticket = BlobTicket::from_str(&ticket).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            self.runtime
                .block_on(node.fetch_blob(&ticket))
                .map_err(MobileMeshError::from_display)
        })
    }

    pub fn join_gossip(
        &self,
        topic: String,
        bootstrap_peer_addrs_json: Vec<String>,
    ) -> Result<Arc<MobileGossipTopic>, MobileMeshError> {
        let peers = bootstrap_peer_addrs_json
            .iter()
            .map(|value| {
                serde_json::from_str::<EndpointAddr>(value).map_err(MobileMeshError::from_display)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.with_node(|node| {
            let (sender, receiver) = self
                .runtime
                .block_on(node.join_gossip(&topic, peers))
                .map_err(MobileMeshError::from_display)?;
            Ok(Arc::new(MobileGossipTopic {
                runtime: self.runtime.clone(),
                sender,
                receiver: Mutex::new(receiver),
            }))
        })
    }

    pub fn shutdown(&self) -> Result<(), MobileMeshError> {
        let node = self
            .node
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile node lock poisoned"))?
            .take();
        if let Some(node) = node {
            self.runtime
                .block_on(node.close())
                .map_err(MobileMeshError::from_display)?;
        }
        Ok(())
    }
}

impl MobileMeshNode {
    fn with_node<T>(
        &self,
        action: impl FnOnce(&NativeNode) -> Result<T, MobileMeshError>,
    ) -> Result<T, MobileMeshError> {
        let guard = self
            .node
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile node lock poisoned"))?;
        let node = guard
            .as_ref()
            .ok_or_else(|| MobileMeshError::from_display("Mobile node is closed"))?;
        action(node)
    }
}

impl Drop for MobileMeshNode {
    fn drop(&mut self) {
        let Some(node) = self.node.get_mut().ok().and_then(Option::take) else {
            return;
        };
        let _ = self.runtime.block_on(node.close());
    }
}

#[derive(uniffi::Object)]
pub struct MobileGossipTopic {
    runtime: Arc<Runtime>,
    sender: GossipTopicSender,
    receiver: Mutex<GossipTopicReceiver>,
}

#[uniffi::export]
impl MobileGossipTopic {
    pub fn broadcast(&self, content: Vec<u8>) -> Result<(), MobileMeshError> {
        self.runtime
            .block_on(self.sender.broadcast(content))
            .map_err(MobileMeshError::from_display)
    }

    pub fn receive(&self, timeout_ms: u64) -> Result<Option<MobileGossipMessage>, MobileMeshError> {
        let mut receiver = self
            .receiver
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile gossip lock poisoned"))?;
        let received = self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(timeout_ms), receiver.recv()).await
        });
        match received {
            Ok(Ok(Some(message))) => Ok(Some(MobileGossipMessage {
                content: message.content.to_vec(),
                delivered_from: message.delivered_from.to_string(),
            })),
            Ok(Ok(None)) => Ok(None),
            Ok(Err(error)) => Err(MobileMeshError::from_display(error)),
            Err(_) => Ok(None),
        }
    }
}

fn exact_bytes<const N: usize>(value: &[u8], error: &str) -> Result<[u8; N], MobileMeshError> {
    value
        .try_into()
        .map_err(|_| MobileMeshError::from_display(error))
}

fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, MobileMeshError> {
    serde_json::from_str(value).map_err(MobileMeshError::from_display)
}

fn validate_json(value: &str) -> Result<Value, MobileMeshError> {
    serde_json::from_str(value).map_err(MobileMeshError::from_display)
}

fn parse_endpoint_addr(value: &str) -> Result<EndpointAddr, MobileMeshError> {
    if value.trim_start().starts_with('{') {
        return serde_json::from_str(value).map_err(MobileMeshError::from_display);
    }
    EndpointId::from_str(value)
        .map(EndpointAddr::from)
        .map_err(MobileMeshError::from_display)
}

fn to_json(value: &impl serde::Serialize) -> Result<String, MobileMeshError> {
    serde_json::to_string(value).map_err(MobileMeshError::from_display)
}

#[cfg(test)]
mod tests {
    use automerge::{AutoCommit, ROOT, transaction::Transactable};

    use super::*;

    #[test]
    fn mobile_identity_api_matches_core() {
        let seed = vec![7; 32];
        let public_key = mesh_public_key_from_seed(seed.clone()).unwrap();
        let person_id = mesh_public_key_id(public_key).unwrap();
        let envelope = mesh_sign_envelope_json(
            seed,
            r#"{"kind":"mobile-test","version":1}"#.to_string(),
            person_id,
            None,
        )
        .unwrap();
        assert!(
            mesh_verify_envelope_json(
                envelope,
                mesh_public_key_from_seed(vec![7; 32]).unwrap(),
                None
            )
            .unwrap()
        );
    }

    #[test]
    fn mobile_native_nodes_exchange_blob_and_gossip() {
        let node_1 = MobileMeshNode::start(Some(vec![1; 32]), vec![], false, None).unwrap();
        let node_2 = MobileMeshNode::start(
            Some(vec![2; 32]),
            vec![node_1.endpoint_id().unwrap()],
            false,
            None,
        )
        .unwrap();
        node_1
            .authorize_peer(node_2.endpoint_id().unwrap())
            .unwrap();

        let ticket = node_1.add_blob(b"mobile-blob".to_vec()).unwrap();
        assert_eq!(node_2.fetch_blob(ticket).unwrap(), b"mobile-blob");

        let topic_1 = node_1
            .join_gossip("mobile-topic".to_string(), vec![])
            .unwrap();
        let topic_2 = node_2
            .join_gossip(
                "mobile-topic".to_string(),
                vec![node_1.endpoint_addr_json().unwrap()],
            )
            .unwrap();
        topic_1.broadcast(b"hello-mobile".to_vec()).unwrap();
        let message = topic_2.receive(5_000).unwrap().unwrap();
        assert_eq!(message.content, b"hello-mobile");

        node_1.shutdown().unwrap();
        node_2.shutdown().unwrap();
    }

    #[test]
    fn mobile_native_nodes_exchange_rpc_and_propagate_handler_errors() {
        let node_1 = MobileMeshNode::start(Some(vec![3; 32]), vec![], false, None).unwrap();
        let node_2 = MobileMeshNode::start(
            Some(vec![4; 32]),
            vec![node_1.endpoint_id().unwrap()],
            false,
            None,
        )
        .unwrap();
        let node_1_id = node_1.endpoint_id().unwrap();
        let node_2_addr = node_2.endpoint_addr_json().unwrap();

        let responder = node_2.clone();
        let success = std::thread::spawn(move || {
            let request = responder.receive_request(5_000).unwrap().unwrap();
            assert_eq!(request.remote_endpoint_id(), node_1_id);
            assert_eq!(request.payload_json(), r#"{"kind":"ping","version":1}"#);
            request
                .respond_json(r#"{"kind":"pong","version":1}"#.into())
                .unwrap();
        });
        assert_eq!(
            node_1
                .request_json(
                    node_2_addr.clone(),
                    r#"{"kind":"ping","version":1}"#.into(),
                    5_000,
                )
                .unwrap(),
            r#"{"kind":"pong","version":1}"#,
        );
        success.join().unwrap();

        let responder = node_2.clone();
        let failure = std::thread::spawn(move || {
            responder
                .receive_request(5_000)
                .unwrap()
                .unwrap()
                .fail("Request rejected".into())
                .unwrap();
        });
        let error = node_1
            .request_json(
                node_2_addr,
                r#"{"kind":"denied","version":1}"#.into(),
                5_000,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "Request rejected");
        failure.join().unwrap();

        node_1.shutdown().unwrap();
        node_2.shutdown().unwrap();
    }

    #[test]
    fn mobile_rpc_rejects_unauthorized_peers_before_delivery() {
        let node_1 = MobileMeshNode::start(Some(vec![5; 32]), vec![], false, None).unwrap();
        let node_2 = MobileMeshNode::start(Some(vec![6; 32]), vec![], false, None).unwrap();

        let error = node_1
            .request_json(
                node_2.endpoint_addr_json().unwrap(),
                r#"{"kind":"must-not-arrive","version":1}"#.into(),
                1_000,
            )
            .unwrap_err();
        assert!(!error.to_string().is_empty());
        assert!(node_2.receive_request(100).unwrap().is_none());

        node_1.shutdown().unwrap();
        node_2.shutdown().unwrap();
    }

    #[test]
    fn mobile_public_rpc_accepts_unknown_peer_for_application_admission() {
        let node_1 = MobileMeshNode::start(Some(vec![7; 32]), vec![], false, None).unwrap();
        let node_2 = MobileMeshNode::start(Some(vec![8; 32]), vec![], true, None).unwrap();
        let listener = std::thread::spawn({
            let node_2 = node_2.clone();
            move || {
                let request = node_2.receive_request(2_000).unwrap().unwrap();
                request
                    .respond_json(r#"{"status":"admitted"}"#.into())
                    .unwrap();
            }
        });

        assert_eq!(
            node_1
                .request_json(
                    node_2.endpoint_addr_json().unwrap(),
                    r#"{"kind":"contact-request","version":1}"#.into(),
                    2_000,
                )
                .unwrap(),
            r#"{"status":"admitted"}"#,
        );

        listener.join().unwrap();
        node_1.shutdown().unwrap();
        node_2.shutdown().unwrap();
    }

    #[test]
    fn mobile_automerge_binding_converges() {
        let mut source = AutoCommit::new();
        source.put(ROOT, "title", "mobile-rust").unwrap();
        let source = source.save();
        let mut empty = AutoCommit::new();
        let empty = empty.save();
        let left = MobileAutomergeSyncEngine::new("left".into(), None).unwrap();
        let right = MobileAutomergeSyncEngine::new("right".into(), None).unwrap();
        left.load_document("scope".into(), "doc".into(), source)
            .unwrap();
        right
            .load_document("scope".into(), "doc".into(), empty)
            .unwrap();
        let mut frame: AutomergeSyncFrame = from_json(
            &left
                .generate_json("doc".into(), "right".into(), true, None)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        for _ in 0..20 {
            let before = right.heads("doc".into()).unwrap();
            let result: meta_mesh_core::AutomergeSyncResult = from_json(
                &right
                    .prepare_receive_json("left".into(), to_json(&frame).unwrap(), true, None)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(right.heads("doc".into()).unwrap(), before);
            right.commit_prepared_receive("doc".into(), "left".into()).unwrap();
            let Some(response) = result.response else {
                break;
            };
            let result: meta_mesh_core::AutomergeSyncResult = from_json(
                &left
                    .receive_json("right".into(), to_json(&response).unwrap(), true, None)
                    .unwrap(),
            )
            .unwrap();
            let Some(response) = result.response else {
                break;
            };
            frame = response;
        }
        assert_eq!(
            left.heads("doc".into()).unwrap(),
            right.heads("doc".into()).unwrap()
        );
    }

    #[test]
    fn mobile_runtime_uses_shared_session_and_control_state_machine() {
        let runtime = MobileMeshRuntime::new();
        runtime.start().unwrap();
        assert!(runtime.is_running().unwrap());
        let candidate = |connection: &str, sequence: u64| {
            serde_json::json!({
                "key": { "workspaceId": "workspace", "deviceId": "device", "instanceId": "instance" },
                "connectionId": connection,
                "remoteIssuedAt": "2026-09-21T00:00:00Z",
                "remoteRouteSequence": sequence,
                "direction": "incoming"
            }).to_string()
        };
        let first: meta_mesh_core::SessionAdmission = from_json(&runtime
            .admit_session_json(candidate("first", 1), "incoming".into()).unwrap()).unwrap();
        let replacement: meta_mesh_core::SessionAdmission = from_json(&runtime
            .admit_session_json(candidate("replacement", 2), "incoming".into()).unwrap()).unwrap();
        assert!(matches!(first, meta_mesh_core::SessionAdmission::Accepted { .. }));
        assert!(matches!(replacement, meta_mesh_core::SessionAdmission::Accepted {
            replaced_connection_id: Some(value), ..
        } if value == "first"));
        assert_eq!(runtime.connected_devices("workspace".into()).unwrap(), vec!["device"]);
        let sessions: Vec<meta_mesh_core::RuntimeSession> = from_json(&runtime.sessions_json().unwrap()).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].connection_id, "replacement");

        let bytes = vec![3_u8; meta_mesh_core::MAX_CONTROL_FRAME_BYTES + 1];
        let frames = runtime.control_frames("workspace".into(), bytes.clone()).unwrap();
        let mut result = None;
        for frame in frames.into_iter().rev() {
            if let Some(value) = runtime.receive_control_frame(
                "receiver".into(), "workspace".into(), frame,
            ).unwrap() { result = Some(value); }
        }
        assert_eq!(result, Some(bytes));
        assert_eq!(runtime.stop().unwrap(), vec!["replacement"]);
        assert!(!runtime.is_running().unwrap());
    }

    #[test]
    fn mobile_live_workspace_session_confirms_only_saved_data() {
        let sender = MobileLiveWorkspaceSession::new("board".into(), "secret".into()).unwrap();
        let receiver = MobileLiveWorkspaceSession::new("board".into(), "secret".into()).unwrap();
        let bytes = b"document and authorization".to_vec();
        let frame = sender.encode("mesh-durable-batch".into(), bytes.clone()).unwrap();
        let action: Option<meta_mesh_core::LiveSessionAction> = from_json(&receiver.receive_json(frame).unwrap()).unwrap();
        assert_eq!(action, Some(meta_mesh_core::LiveSessionAction::DurableBatch(bytes.clone())));
        let receipt = receiver.acknowledge_saved(bytes.clone()).unwrap();
        sender.verify_saved_receipt(receipt.clone(), bytes.clone()).unwrap();
        assert!(sender.verify_saved_receipt(receipt, b"different".to_vec()).is_err());
    }

    #[test]
    fn mobile_runtime_matches_browser_route_reconnect_gossip_and_relay_decisions() {
        let runtime = MobileMeshRuntime::new();
        let first: meta_mesh_core::RouteAttempt = from_json(&runtime.begin_route_attempt_json("peer".into(), 10).unwrap()).unwrap();
        let second: meta_mesh_core::RouteAttempt = from_json(&runtime.begin_route_attempt_json("peer".into(), 11).unwrap()).unwrap();
        assert!(runtime.route_attempt_active("peer".into()).unwrap());
        assert!(!runtime.finish_route_attempt("peer".into(), first.token).unwrap());
        assert!(runtime.finish_route_attempt("peer".into(), second.token).unwrap());

        let reconnect: meta_mesh_core::ReconnectState = from_json(&runtime.schedule_reconnect_json(
            "peer".into(), 100, 50, 1_000,
        ).unwrap()).unwrap();
        assert_eq!(reconnect.retry_at_ms, 150);
        assert_eq!(runtime.due_reconnects(149).unwrap(), Vec::<String>::new());
        assert_eq!(runtime.due_reconnects(150).unwrap(), vec!["peer"]);
        assert!(runtime.reconnect_state_json("peer".into()).unwrap().is_some());
        runtime.clear_reconnects_with_prefix("pe".into()).unwrap();
        assert!(runtime.reconnect_state_json("peer".into()).unwrap().is_none());

        let topology: meta_mesh_core::GossipTopology = from_json(&runtime.set_gossip_endpoints_json(
            "workspace".into(), vec!["b".into(), "a".into(), "a".into()],
        ).unwrap()).unwrap();
        assert_eq!(topology.endpoints, vec!["a", "b"]);
        assert!(topology.changed);
        let unchanged: meta_mesh_core::GossipTopology = from_json(&runtime.set_gossip_endpoints_json(
            "workspace".into(), vec!["a".into(), "b".into()],
        ).unwrap()).unwrap();
        assert!(!unchanged.changed);

        let direct: meta_mesh_core::DialPlan = from_json(&runtime.plan_dial_json("peer".into(), true, 100).unwrap()).unwrap();
        assert_eq!(direct.mode, DialMode::Direct);
        assert_eq!(direct.relay_fallback_at_ms, Some(1_600));
        runtime.record_network_failure("peer".into(), 200).unwrap();
        let relay: meta_mesh_core::DialPlan = from_json(&runtime.plan_dial_json("peer".into(), true, 201).unwrap()).unwrap();
        assert_eq!(relay.mode, DialMode::Relay);
        runtime.record_dial_success("peer".into(), "direct".into(), 202).unwrap();
        let recovered: meta_mesh_core::DialPlan = from_json(&runtime.plan_dial_json("peer".into(), true, 203).unwrap()).unwrap();
        assert_eq!(recovered.mode, DialMode::Direct);
    }
}
