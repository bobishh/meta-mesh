use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::{DeviceCertificate, PublicIdentity, SignedEnvelope, verify_device_certificate_chain, verify_signed_envelope};

/// Exact short-lived session proof shared by native consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceLoginPayload {
    pub kind: String,
    pub version: u8,
    pub origin: String,
    pub challenge: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// The public identity evidence returned by an Identity portal approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceLoginEvidence {
    pub identity: PublicIdentity,
    pub device_id: String,
    pub certificates: Vec<DeviceCertificate>,
    pub proof: SignedEnvelope<ServiceLoginPayload>,
}

/// Verified identity result. Product roles and service permissions remain caller-owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedServiceLogin {
    pub person_id: String,
    pub device_id: String,
}

/// Failure categories shared by native application adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLoginVerificationError {
    InvalidOrigin,
    InvalidChallenge,
    ExpiredRequest,
    RequestMismatch,
    InvalidCertificate,
    InvalidSignature,
}

impl std::fmt::Display for ServiceLoginVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidOrigin => "Invalid service origin",
            Self::InvalidChallenge => "Invalid service login challenge",
            Self::ExpiredRequest => "Service login request expired",
            Self::RequestMismatch => "Service login request mismatch",
            Self::InvalidCertificate => "Invalid identity device certificate",
            Self::InvalidSignature => "Invalid identity service login signature",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ServiceLoginVerificationError {}

/// Verify a fresh portal proof against the exact pending service request.
///
/// This proves the person approved a login for one origin and challenge. It does
/// not grant the application any role or product-specific permission.
pub fn verify_service_login(
    evidence: &ServiceLoginEvidence,
    expected_origin: &str,
    expected_challenge: &str,
    expected_expires_at_ms: u64,
    now_ms: u64,
) -> Result<VerifiedServiceLogin, ServiceLoginVerificationError> {
    if !valid_origin(expected_origin) || !valid_origin(&evidence.proof.payload.origin) {
        return Err(ServiceLoginVerificationError::InvalidOrigin);
    }
    if !is_challenge(expected_challenge) {
        return Err(ServiceLoginVerificationError::InvalidChallenge);
    }
    let payload = &evidence.proof.payload;
    if payload.kind != "mesh-service-login" || payload.version != 1 || payload.origin != expected_origin ||
        payload.challenge != expected_challenge || payload.expires_at != expected_expires_at_ms ||
        evidence.proof.signer_key_id != evidence.device_id {
        return Err(ServiceLoginVerificationError::RequestMismatch);
    }
    if expected_expires_at_ms <= now_ms || expected_expires_at_ms > now_ms.saturating_add(120_000) ||
        payload.issued_at > now_ms.saturating_add(30_000) ||
        now_ms.saturating_sub(payload.issued_at) > 120_000 || payload.expires_at <= payload.issued_at ||
        payload.expires_at > payload.issued_at.saturating_add(120_000) {
        return Err(ServiceLoginVerificationError::ExpiredRequest);
    }
    let key = verify_device_certificate_chain(&evidence.identity, &evidence.device_id, &evidence.certificates, "MATCH/1")
        .map_err(|_| ServiceLoginVerificationError::InvalidCertificate)?;
    if !verify_signed_envelope(&evidence.proof, &key, "MESH-SERVICE-LOGIN/1")
        .map_err(|_| ServiceLoginVerificationError::InvalidSignature)? {
        return Err(ServiceLoginVerificationError::InvalidSignature);
    }
    Ok(VerifiedServiceLogin { person_id: evidence.identity.person_id.clone(), device_id: evidence.device_id.clone() })
}

fn is_challenge(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_origin(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else { return false; };
    if url.origin().ascii_serialization() != value || !url.username().is_empty() || url.password().is_some() ||
        url.path() != "/" || url.query().is_some() || url.fragment().is_some() { return false; }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => true,
        ("http", Some(Host::Domain("localhost"))) => true,
        ("http", Some(Host::Ipv4(address))) => address.is_loopback(),
        ("http", Some(Host::Ipv6(address))) => address.is_loopback(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceCertificatePayload, public_key_from_seed, public_key_id, sign_device_certificate, sign_json_envelope};
    use serde_json::json;

    fn fixture() -> (ServiceLoginEvidence, String, String, u64) {
        let root = [1; 32];
        let device = [2; 32];
        let identity_key = public_key_from_seed(&root).unwrap();
        let device_key = public_key_from_seed(&device).unwrap();
        let person_id = public_key_id(&identity_key).unwrap();
        let device_id = public_key_id(&device_key).unwrap();
        let identity = PublicIdentity { person_id: person_id.clone(), public_key: identity_key,
            display_name: "Owner".into() };
        let certificate = sign_device_certificate(&root, DeviceCertificatePayload {
            kind: "device-certificate".into(), version: 1, person_id: person_id.clone(),
            device_id: device_id.clone(), device_public_key: device_key, issuer_certificate_hash: None,
            can_enroll_devices: false,
        }, person_id, "MATCH/1").unwrap();
        let expires_at_ms = 1_000_000;
        let proof = sign_json_envelope(&device, json!({ "kind": "mesh-service-login", "version": 1,
            "origin": "https://service.example", "challenge": "a".repeat(64),
            "issuedAt": 900_000, "expiresAt": expires_at_ms }), device_id.clone(), "MESH-SERVICE-LOGIN/1").unwrap();
        let proof: SignedEnvelope<ServiceLoginPayload> = serde_json::from_value(serde_json::to_value(proof).unwrap()).unwrap();
        (ServiceLoginEvidence { identity, device_id, certificates: vec![certificate], proof },
            "https://service.example".into(), "a".repeat(64), expires_at_ms)
    }

    #[test]
    fn fresh_origin_bound_login_returns_only_authenticated_identity() {
        let (evidence, origin, challenge, expiry) = fixture();
        let verified = verify_service_login(&evidence, &origin, &challenge, expiry, 950_000).unwrap();
        assert_eq!(verified.person_id, evidence.identity.person_id);
        assert_eq!(verified.device_id, evidence.device_id);
    }

    #[test]
    fn rejects_origin_challenge_expiry_and_signature_substitution() {
        let (evidence, origin, challenge, expiry) = fixture();
        assert!(verify_service_login(&evidence, "https://other.example", &challenge, expiry, 950_000).is_err());
        assert!(verify_service_login(&evidence, &origin, &"b".repeat(64), expiry, 950_000).is_err());
        assert!(verify_service_login(&evidence, &origin, &challenge, expiry, expiry).is_err());
        let mut altered = evidence.clone();
        altered.proof.signature = "invalid".into();
        assert!(verify_service_login(&altered, &origin, &challenge, expiry, 950_000).is_err());
    }

    #[test]
    fn session_expiry_does_not_affect_a_separately_retained_device_certificate() {
        let (evidence, origin, challenge, expiry) = fixture();
        assert!(verify_service_login(&evidence, &origin, &challenge, expiry, expiry).is_err());
        crate::verify_device_certificate_chain(&evidence.identity, &evidence.device_id, &evidence.certificates, "MATCH/1").unwrap();
    }
}
