pub mod access;
pub mod authority;
pub mod authority_command;
pub mod authority_flow;
pub mod authorization;
pub mod automerge;
pub mod bundle_reuse;
pub mod catalog;
pub mod change_admission_flow;
pub mod credential_access;
pub mod dial_schedule;
pub mod gossip_lifecycle;
pub mod gossip_payload;
pub mod handshake;
pub mod handshake_flow;
pub mod identity;
pub mod invitation;
pub mod invitation_plan;
pub mod live_session;
pub mod member;
pub mod member_grant;
pub mod ownership_adoption;
pub mod ownership_merge;
pub mod pairing;
pub mod persistence;
pub mod recovery;
pub mod replication;
pub mod runtime;
pub mod scope_authority;
pub mod session_admission;
pub mod session_lifecycle;
pub mod state;
pub mod succession_merge;
pub mod transfer_selection;
pub mod workspace_set;
pub mod write_evidence;

pub use access::{
    decide_workspace_access, WorkspaceAccessDecisionInput, WorkspaceDepartureEvidence,
};

pub use authority::{
    canonical_revocations, eligible_editor_person_ids, has_conflicting_ownership_transfers,
    next_verified_ownership_transition, plan_ownership_transitions, summarize_succession,
    verify_workspace_ownership_transfer, verify_workspace_revocation,
    verify_workspace_succession_claim, verify_workspace_succession_policy,
    verify_workspace_succession_vote, SuccessionSummary, SuccessionVoteSummary,
    VerifiedOwnershipTransition, WorkspaceAuthority, WorkspaceDeviceRevocation,
    WorkspaceDeviceRevocationPayload, WorkspaceOwnershipTransfer,
    WorkspaceOwnershipTransferPayload, WorkspaceRevocation, WorkspaceRevocationPayload,
    WorkspaceSuccessionClaim, WorkspaceSuccessionClaimPayload, WorkspaceSuccessionPolicy,
    WorkspaceSuccessionPolicyPayload, WorkspaceSuccessionVote, WorkspaceSuccessionVotePayload,
};
pub use authority_command::{plan_authority_command, AuthorityAction, AuthorityCommandInput};
pub use authority_command::{
    plan_authority_import, plan_catalog_merge, AuthorityImportAction, CatalogMergeAction,
};
pub use authority_flow::{
    plan_ownership_authority_flow, OwnershipAuthorityFlowInput, OwnershipAuthorityFlowPlan,
};
pub use authorization::{
    admit_workspace_change_authorization, admit_workspace_change_authorizations,
    verify_device_signed_envelope, verify_workspace_grant, AuthorizedWorkspaceChange,
    IncomingWorkspaceChangeAuthorization, WorkspaceChangeAuthorization,
    WorkspaceChangeAuthorizationPayload, WorkspaceDeviceRevocationEvidence, WorkspaceGrant,
    WorkspaceGrantPayload, WorkspaceRole, WorkspaceWriteAuthorizationSnapshot,
};
pub use automerge::{
    AutomergeSyncEngine, AutomergeSyncFrame, AutomergeSyncResult, DEFAULT_MAX_AUTOMERGE_FRAME_BYTES,
};
pub use bundle_reuse::{can_reuse_member_bundle, BundleReuseInput};
pub use catalog::{validate_mesh_catalog, MeshCatalog};
pub use change_admission_flow::{
    plan_change_admission_flow, unsigned_change_error, ChangeAdmissionChange,
    ChangeAdmissionFlowInput, ChangeAdmissionFlowPlan,
};
pub use credential_access::{
    can_remove_workspace_device, credential_belongs_to_profile, has_left_workspace,
    is_device_revoked, is_grant_revoked, is_workspace_envelope, next_access_epoch,
    owned_workspace_ids, partition_credentials, CredentialPartition, CredentialPartitionInput,
};
pub use dial_schedule::{plan_dial_schedule, DialRouteInput, DialScheduleInput, DialSchedulePlan};
pub use gossip_lifecycle::{
    GossipBroadcastPlan, GossipDeliveryAction, GossipLifecycleNeighborChange, GossipLifecycleState,
    GossipNeighborPlan, GossipRebuildAction, GossipRebuildInput, GossipRebuildPlan,
    GossipReceiveAction, DEFAULT_GOSSIP_TOPIC_PREFIX,
};
pub use gossip_payload::{encode_workspace_update, is_workspace_update};
pub use handshake::{validate_mesh_handshake, MeshHandshake};
pub use handshake_flow::{HandshakeStep, MeshHandshakeFlow};
pub use identity::{
    canonicalize_json, certificate_hash, derive_device_seed, public_key_from_seed, public_key_id,
    sign_device_certificate, sign_json_envelope, signature_input, verify_device_certificate_chain,
    verify_signed_envelope, DeviceCertificate, DeviceCertificatePayload, PublicIdentity,
    SignedEnvelope, DEFAULT_SIGNATURE_DOMAIN, MAX_CERTIFICATE_CHAIN_LENGTH,
};
pub use invitation::{
    create_device_enrollment_invitation, create_workspace_join_invitation, invitation_url,
    pairing_invite_url, parse_invitation, parse_pairing_invite, DeviceEnrollmentInvitation,
    InvitationIssuer, PairingInvite, ScopedInvitation, WorkspaceItem, WorkspaceJoinInvitation,
};
pub use invitation_plan::{
    knows_workspace_issuer, missing_owner_workspaces, plan_guest_advertisements, plan_invitation,
    plan_invitation_credential, validate_owner_workspace_offer, GuestAdvertisementEntry,
    GuestAdvertisementInput, InvitationCredentialInput, InvitationPlanEntry, InvitationPlanInput,
    IssuerWorkspaceInput,
};
pub use live_session::{
    LiveSessionAction, LiveSessionEffect, LiveSessionPublishPlan, LiveSessionReceivePlan,
    LiveSessionSnapshotPlan, LiveWorkspaceSession, PreparedLiveDocument, WorkspaceControlSnapshot,
};
pub use member::{
    verify_workspace_member_bundle, PeerAdvertisement, PeerAdvertisementPayload,
    VerifiedWorkspaceMember, VerifyWorkspaceMemberOptions,
};
pub use member_grant::{
    decide_owner_credential, plan_member_grant, plan_owner_certificate_refresh, MemberGrantInput,
    MemberGrantPlan,
};
pub use ownership_adoption::{
    plan_ownership_adoption, OwnershipAdoptionInput, OwnershipAdoptionPlan, OwnershipAdoptionRecord,
};
pub use ownership_merge::{
    plan_ownership_merge, OwnershipMergeInput, OwnershipMergePlan, OwnershipMergeStep,
};
pub use pairing::{
    PairingCodec, PairingFrameHeader, WorkspaceJoinAck, WorkspaceJoinHandoff,
    WorkspaceJoinHandoffOutcome, WorkspaceJoinHandshake, WorkspaceJoinResponse, PAIRING_VERSION,
};
pub use persistence::{
    plan_change_admission, transition_outbox_claim, ChangeAdmissionPlan, IncomingDocumentChange,
    OutboxClaim, OutboxClaimInput, OutboxClaimTransition, StoredDocumentChange,
};
pub use recovery::{
    identity_security_for_recovery, legacy_recovery_from_samples, normalize_secret,
    open_identity_seed, open_identity_seed_with_passphrase, recovery_phrase_from_entropy,
    recovery_phrase_to_entropy, seal_identity_seed, seal_identity_seed_with_passphrase,
    IdentityPassphraseEnvelope, IdentityRecoveryEnvelope, IdentitySecurity,
};
pub use replication::{
    durable_ack_matches, order_delivery_routes, sign_device_route, sign_durable_batch_ack,
    validate_device_route, validate_device_route_payload, validate_durable_ack_payload,
    verify_device_route, verify_durable_batch_ack, DeviceBatch, DeviceChange, DeviceRoute,
    DeviceRouteCatalog, DeviceRoutePayload, DurableBatchAck, DurableBatchAckPayload, RouteHealth,
    SignedDeviceRoute, SignedDurableBatchAck,
};
pub use runtime::{
    control_frames, preferred_session_direction, validate_mesh_capabilities, ControlChunk,
    ControlFrameReceiver, DialMode, DialPlan, MeshLifecycleState, MeshRuntimeState, ReconnectState,
    RelayDialPolicy, RouteAttempt, RuntimeSession, SessionAdmission, SessionCandidate,
    SessionDirection, SessionKey, CONTROL_CHUNK_BYTES, MAX_CONTROL_FRAME_BYTES,
    MAX_CONTROL_SNAPSHOT_BYTES, MESH_CAPABILITIES,
};
pub use runtime::{mesh_handshake_features, MeshHandshakeFeatures};
pub use scope_authority::{
    create_scope_control_transfer_payload, create_scope_genesis, create_scope_genesis_payload, sign_scope_record,
    validate_scope_authority, verify_scope_capability_grant, verify_scope_capability_revocation,
    verify_scope_control_transfer, verify_scope_genesis, ScopeAuthority, ScopeAuthoritySnapshot,
    ScopeCapability, ScopeCapabilityGrant, ScopeCapabilityGrantPayload, ScopeCapabilityRevocation,
    ScopeCapabilityRevocationPayload, ScopeControlTransfer, ScopeControlTransferPayload,
    ScopeControlTransferPayloadInput,
    ScopeGenesis, ScopeGenesisInput, ScopeGenesisPayload, ScopeGenesisPayloadInput,
    ScopeGrantIssuerEvidence, SignedScopeGenesis, ValidatedScopeAuthority,
};
pub use session_admission::{admit_mesh_peer, MeshAuthenticatedSessions, MeshPeerAdmission};
pub use session_lifecycle::{
    MeshSessionLifecycleState, SessionEvictionDecision, SessionInstallDecision,
    DEFAULT_SESSION_STABLE_AFTER_MS,
};
pub use state::{
    merge_peer_records, reconcile_replica_sets, select_scoped_neighbors, validate_peer_record,
    GossipBounds, GossipCandidate, PeerTransportInstance, ReplicaRecord, ReplicaSet,
    ReplicaTombstone, WorkspacePeerRecord,
};
pub use succession_merge::{
    plan_succession_catalog, plan_succession_merge, plan_succession_policy_refresh,
    SuccessionCatalogInput, SuccessionCatalogPlan, SuccessionMergeInput, SuccessionMergePlan,
    SuccessionPolicyRefresh,
};
pub use transfer_selection::{
    select_ownership_transfer, TransferPeerInput, TransferRecordInput, TransferSelectionInput,
    TransferSelectionPlan,
};
pub use workspace_set::{decode_workspace_set, encode_workspace_set, WorkspaceSetEntry};
mod authority_merge;
pub use authority_merge::{
    plan_authority_merge, AuthorityMergeInput, AuthorityMergePlan, AuthorityMergeRecords,
    SignedDeparture, SignedDeviceRevocation,
};
pub use write_evidence::{
    has_authority_conflict, prepare_write_evidence, require_change_authorization_coverage,
    WriteEvidenceInput,
};
