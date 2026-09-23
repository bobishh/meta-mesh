pub mod authority;
pub mod authority_command;
pub mod gossip_payload;
pub mod access;
pub mod authorization;
pub mod automerge;
pub mod catalog;
pub mod handshake;
pub mod handshake_flow;
pub mod identity;
pub mod ownership_merge;
pub mod bundle_reuse;
pub mod transfer_selection;
pub mod credential_access;
pub mod dial_schedule;
pub mod invitation_plan;
pub mod invitation;
pub mod live_session;
pub mod member_grant;
pub mod ownership_adoption;
pub mod member;
pub mod pairing;
pub mod persistence;
pub mod recovery;
pub mod replication;
pub mod runtime;
pub mod session_admission;
pub mod state;
pub mod succession_merge;
pub mod workspace_set;

pub use access::{WorkspaceAccessDecisionInput, WorkspaceDepartureEvidence, decide_workspace_access};

pub use authority::{
    SuccessionSummary, SuccessionVoteSummary, VerifiedOwnershipTransition, WorkspaceAuthority, WorkspaceDeviceRevocation,
    WorkspaceDeviceRevocationPayload, WorkspaceOwnershipTransfer,
    WorkspaceOwnershipTransferPayload, WorkspaceRevocation, WorkspaceRevocationPayload,
    WorkspaceSuccessionClaim, WorkspaceSuccessionClaimPayload, WorkspaceSuccessionPolicy,
    WorkspaceSuccessionPolicyPayload, WorkspaceSuccessionVote, WorkspaceSuccessionVotePayload,
    canonical_revocations, eligible_editor_person_ids, has_conflicting_ownership_transfers,
    next_verified_ownership_transition, plan_ownership_transitions, summarize_succession, verify_workspace_ownership_transfer,
    verify_workspace_revocation, verify_workspace_succession_claim,
    verify_workspace_succession_policy, verify_workspace_succession_vote,
};
pub use authority_command::{AuthorityAction, AuthorityCommandInput, plan_authority_command};
pub use authority_command::{CatalogMergeAction, AuthorityImportAction, plan_catalog_merge,
    plan_authority_import};
pub use gossip_payload::{encode_workspace_update, is_workspace_update};
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
pub use live_session::{LiveSessionAction, LiveWorkspaceSession, PreparedLiveDocument, WorkspaceControlSnapshot};
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
pub use runtime::{MeshHandshakeFeatures, mesh_handshake_features};
pub use session_admission::{MeshAuthenticatedSessions, MeshPeerAdmission, admit_mesh_peer};
pub use state::{
    GossipBounds, GossipCandidate, PeerTransportInstance, ReplicaRecord, ReplicaSet,
    ReplicaTombstone, WorkspacePeerRecord, merge_peer_records, reconcile_replica_sets,
    select_scoped_neighbors, validate_peer_record,
};
pub use workspace_set::{WorkspaceSetEntry, decode_workspace_set, encode_workspace_set};
pub use succession_merge::{SuccessionMergeInput, SuccessionMergePlan, SuccessionPolicyRefresh,
    SuccessionCatalogInput, SuccessionCatalogPlan, plan_succession_merge,
    plan_succession_policy_refresh, plan_succession_catalog};
pub use ownership_adoption::{OwnershipAdoptionInput, OwnershipAdoptionPlan, OwnershipAdoptionRecord, plan_ownership_adoption};
pub use member_grant::{MemberGrantInput, MemberGrantPlan, decide_owner_credential, plan_member_grant, plan_owner_certificate_refresh};
pub use invitation_plan::{InvitationPlanInput, InvitationPlanEntry, InvitationCredentialInput,
    GuestAdvertisementInput, GuestAdvertisementEntry, IssuerWorkspaceInput,
    plan_invitation, plan_invitation_credential, plan_guest_advertisements,
    validate_owner_workspace_offer, knows_workspace_issuer, missing_owner_workspaces};
pub use dial_schedule::{DialRouteInput, DialScheduleInput, DialSchedulePlan, plan_dial_schedule};
pub use credential_access::{credential_belongs_to_profile, has_left_workspace, is_device_revoked,
    is_grant_revoked, is_workspace_envelope, next_access_epoch, CredentialPartitionInput,
    CredentialPartition, partition_credentials, owned_workspace_ids, can_remove_workspace_device};
pub use transfer_selection::{TransferPeerInput, TransferRecordInput, TransferSelectionInput,
    TransferSelectionPlan, select_ownership_transfer};
pub use bundle_reuse::{BundleReuseInput, can_reuse_member_bundle};
pub use ownership_merge::{OwnershipMergeInput, OwnershipMergePlan, OwnershipMergeStep,
    plan_ownership_merge};
mod authority_merge;
pub use authority_merge::{AuthorityMergeInput, AuthorityMergePlan, AuthorityMergeRecords, SignedDeparture, SignedDeviceRevocation, plan_authority_merge};
