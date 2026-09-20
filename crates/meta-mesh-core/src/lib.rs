pub mod authorization;
pub mod identity;
pub mod invitation;
pub mod pairing;
pub mod recovery;

pub use authorization::{
    WorkspaceGrant, WorkspaceGrantPayload, WorkspaceRole, verify_device_signed_envelope,
    verify_workspace_grant,
};
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
pub use pairing::{PAIRING_VERSION, PairingCodec, PairingFrameHeader};
pub use recovery::{
    IdentityPassphraseEnvelope, IdentityRecoveryEnvelope, IdentitySecurity,
    identity_security_for_recovery, legacy_recovery_from_samples, normalize_secret,
    open_identity_seed, open_identity_seed_with_passphrase, recovery_phrase_from_entropy,
    recovery_phrase_to_entropy, seal_identity_seed, seal_identity_seed_with_passphrase,
};
