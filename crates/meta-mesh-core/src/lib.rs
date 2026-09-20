pub mod identity;
pub mod pairing;

pub use identity::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload,
    MAX_CERTIFICATE_CHAIN_LENGTH, PublicIdentity, SignedEnvelope, canonicalize_json,
    certificate_hash, public_key_from_seed, public_key_id, sign_device_certificate,
    sign_json_envelope, signature_input, verify_device_certificate_chain, verify_signed_envelope,
};
pub use pairing::{PAIRING_VERSION, PairingCodec, PairingFrameHeader};
