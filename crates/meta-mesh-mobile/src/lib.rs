use std::{
    collections::HashSet,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::{EndpointAddr, EndpointId};
use iroh_blobs::{Hash, ticket::BlobTicket};
use meta_mesh_core::{
    AutomergeSyncEngine, AutomergeSyncFrame, DEFAULT_SIGNATURE_DOMAIN, DeviceBatch, DeviceRoute,
    DeviceRoutePayload, DurableBatchAck, DurableBatchAckPayload, GossipBounds, GossipCandidate,
    IdentityPassphraseEnvelope, IdentityRecoveryEnvelope, IdentitySecurity,
    IncomingDocumentChange, OutboxClaim, OutboxClaimInput, PublicIdentity, ReplicaSet, RouteHealth,
    SignedDeviceRoute, SignedDurableBatchAck, SignedEnvelope, WorkspaceAuthority, WorkspaceGrant,
    WorkspaceOwnershipTransfer, WorkspacePeerRecord, WorkspaceRevocation,
    WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy, WorkspaceSuccessionVote,
    derive_device_seed, durable_ack_matches, has_conflicting_ownership_transfers,
    identity_security_for_recovery, legacy_recovery_from_samples, merge_peer_records,
    open_identity_seed, open_identity_seed_with_passphrase, order_delivery_routes,
    parse_invitation, plan_change_admission, public_key_from_seed, public_key_id,
    reconcile_replica_sets, recovery_phrase_from_entropy, recovery_phrase_to_entropy,
    seal_identity_seed, seal_identity_seed_with_passphrase, select_scoped_neighbors,
    sign_device_route, sign_durable_batch_ack, sign_json_envelope, transition_outbox_claim,
    validate_device_route, verify_device_route, verify_durable_batch_ack, verify_signed_envelope,
    verify_workspace_grant, verify_workspace_ownership_transfer, verify_workspace_revocation,
    verify_workspace_succession_claim, verify_workspace_succession_policy,
    verify_workspace_succession_vote,
};
use meta_mesh_native::{GossipTopicReceiver, GossipTopicSender, NativeNode, NativeNodeOptions};
use serde_json::Value;
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileMeshError {
    #[error("{message}")]
    Failure { message: String },
}

impl MobileMeshError {
    fn from_display(error: impl std::fmt::Display) -> Self {
        Self::Failure {
            message: error.to_string(),
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
    let records: Vec<WorkspaceOwnershipTransfer> = from_json(&records_json)?;
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
    let current: Option<OutboxClaim> = current_json
        .map(|value| from_json(&value))
        .transpose()?;
    let input: OutboxClaimInput = from_json(&input_json)?;
    to_json(&transition_outbox_claim(current, input).map_err(MobileMeshError::from_display)?)
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
}

#[uniffi::export]
impl MobileMeshNode {
    #[uniffi::constructor]
    pub fn start(
        secret: Option<Vec<u8>>,
        allowed_peer_ids: Vec<String>,
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
                storage_path: storage_path.map(PathBuf::from),
                ..NativeNodeOptions::default()
            }))
            .map_err(MobileMeshError::from_display)?;
        Ok(Arc::new(Self {
            runtime,
            node: Mutex::new(Some(node)),
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

    pub fn close(&self) -> Result<(), MobileMeshError> {
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
        let node_1 = MobileMeshNode::start(Some(vec![1; 32]), vec![], None).unwrap();
        let node_2 =
            MobileMeshNode::start(Some(vec![2; 32]), vec![node_1.endpoint_id().unwrap()], None)
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

        node_1.close().unwrap();
        node_2.close().unwrap();
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
            let result: meta_mesh_core::AutomergeSyncResult = from_json(
                &right
                    .receive_json("left".into(), to_json(&frame).unwrap(), true, None)
                    .unwrap(),
            )
            .unwrap();
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
}
