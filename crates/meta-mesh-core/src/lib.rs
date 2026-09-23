pub mod authority;
pub mod access;
pub mod authorization;
pub mod automerge;
pub mod catalog;
pub mod handshake;
pub mod handshake_flow;
pub mod identity;
pub mod invitation;
pub mod member;
pub mod pairing;
pub mod persistence;
pub mod recovery;
pub mod replication;
pub mod runtime;
pub mod session_admission;
pub mod state;

pub use access::{WorkspaceAccessDecisionInput, WorkspaceDepartureEvidence, decide_workspace_access};

pub use authority::{
    SuccessionSummary, SuccessionVoteSummary, WorkspaceAuthority, WorkspaceDeviceRevocation,
    WorkspaceDeviceRevocationPayload, WorkspaceOwnershipTransfer,
    WorkspaceOwnershipTransferPayload, WorkspaceRevocation, WorkspaceRevocationPayload,
    WorkspaceSuccessionClaim, WorkspaceSuccessionClaimPayload, WorkspaceSuccessionPolicy,
    WorkspaceSuccessionPolicyPayload, WorkspaceSuccessionVote, WorkspaceSuccessionVotePayload,
    canonical_revocations, eligible_editor_person_ids, has_conflicting_ownership_transfers,
    plan_ownership_transitions, summarize_succession, verify_workspace_ownership_transfer,
    verify_workspace_revocation, verify_workspace_succession_claim,
    verify_workspace_succession_policy, verify_workspace_succession_vote,
};
pub use authorization::{
    AuthorizedWorkspaceChange, IncomingWorkspaceChangeAuthorization, WorkspaceChangeAuthorization,
    WorkspaceChangeAuthorizationPayload, WorkspaceDeviceRevocationEvidence, WorkspaceGrant,
    WorkspaceGrantPayload, WorkspaceRole, WorkspaceWriteAuthorizationSnapshot,
    admit_workspace_change_authorization, admit_workspace_change_authorizations,
    verify_device_signed_envelope, verify_workspace_grant,
};
pub use automerge::{
    AutomergeSyncEngine, AutomergeSyncFrame, AutomergeSyncResult, DEFAULT_MAX_AUTOMERGE_FRAME_BYTES,
};
pub use catalog::{MeshCatalog, validate_mesh_catalog};
pub use handshake::{MeshHandshake, validate_mesh_handshake};
pub use handshake_flow::{HandshakeStep, MeshHandshakeFlow};
pub use identity::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload,
    MAX_CERTIFICATE_CHAIN_LENGTH, PublicIdentity, SignedEnvelope, canonicalize_json,
    certificate_hash, derive_device_seed, public_key_from_seed, public_key_id,
    sign_device_certificate, sign_json_envelope, signature_input, verify_device_certificate_chain,
    verify_signed_envelope,
};
pub use invitation::{
    DeviceEnrollmentInvitation, InvitationIssuer, PairingInvite, ScopedInvitation, WorkspaceItem,
    WorkspaceJoinInvitation, create_device_enrollment_invitation, create_workspace_join_invitation,
    invitation_url, pairing_invite_url, parse_invitation, parse_pairing_invite,
};
pub use member::{
    PeerAdvertisement, PeerAdvertisementPayload, VerifiedWorkspaceMember,
    VerifyWorkspaceMemberOptions, verify_workspace_member_bundle,
};
pub use pairing::{
    PAIRING_VERSION, PairingCodec, PairingFrameHeader, WorkspaceJoinAck, WorkspaceJoinHandshake,
    WorkspaceJoinHandoff, WorkspaceJoinHandoffOutcome, WorkspaceJoinResponse,
};
pub use persistence::{
    ChangeAdmissionPlan, IncomingDocumentChange, OutboxClaim, OutboxClaimInput,
    OutboxClaimTransition, StoredDocumentChange, plan_change_admission, transition_outbox_claim,
};
pub use recovery::{
    IdentityPassphraseEnvelope, IdentityRecoveryEnvelope, IdentitySecurity,
    identity_security_for_recovery, legacy_recovery_from_samples, normalize_secret,
    open_identity_seed, open_identity_seed_with_passphrase, recovery_phrase_from_entropy,
    recovery_phrase_to_entropy, seal_identity_seed, seal_identity_seed_with_passphrase,
};
pub use replication::{
    DeviceBatch, DeviceChange, DeviceRoute, DeviceRouteCatalog, DeviceRoutePayload,
    DurableBatchAck, DurableBatchAckPayload, RouteHealth, SignedDeviceRoute, SignedDurableBatchAck,
    durable_ack_matches, order_delivery_routes, sign_device_route, sign_durable_batch_ack,
    validate_device_route, validate_device_route_payload, validate_durable_ack_payload,
    verify_device_route, verify_durable_batch_ack,
};
pub use runtime::{
    CONTROL_CHUNK_BYTES, ControlChunk, ControlFrameReceiver, DialMode, DialPlan, GossipTopology,
    MAX_CONTROL_FRAME_BYTES, MAX_CONTROL_SNAPSHOT_BYTES, MESH_CAPABILITIES, MeshRuntimeState,
    ReconnectState, RelayDialPolicy, RouteAttempt, RuntimeSession, SessionAdmission,
    SessionCandidate, SessionDirection, SessionKey, control_frames, validate_mesh_capabilities,
};
pub use session_admission::{MeshPeerAdmission, admit_mesh_peer};
pub use state::{
    GossipBounds, GossipCandidate, PeerTransportInstance, ReplicaRecord, ReplicaSet,
    ReplicaTombstone, WorkspacePeerRecord, merge_peer_records, reconcile_replica_sets,
    select_scoped_neighbors, validate_peer_record,
};
