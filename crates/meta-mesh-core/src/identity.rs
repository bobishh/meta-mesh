use std::collections::{HashMap, HashSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const DEFAULT_SIGNATURE_DOMAIN: &str = "MATCH/1";
pub const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEnvelope<T> {
    pub payload: T,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicIdentity {
    pub person_id: String,
    pub public_key: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCertificatePayload {
    pub kind: String,
    pub version: u8,
    pub person_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub issuer_certificate_hash: Option<String>,
    pub can_enroll_devices: bool,
}

pub type DeviceCertificate = SignedEnvelope<DeviceCertificatePayload>;

pub fn canonicalize_json(value: &Value) -> Result<String, String> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).map_err(|_| "JSON canonicalization failed".to_string())
        }
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonicalize_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", values.join(",")))
        }
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let fields = keys
                .into_iter()
                .map(|key| {
                    let encoded_key = serde_json::to_string(key)
                        .map_err(|_| "JSON canonicalization failed".to_string())?;
                    let encoded_value = canonicalize_json(&object[key])?;
                    Ok(format!("{encoded_key}:{encoded_value}"))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

pub fn signature_input(payload_kind: &str, canonical_payload: &str, domain: &str) -> Vec<u8> {
    let mut input = format!("{domain}/{payload_kind}\0").into_bytes();
    input.extend_from_slice(canonical_payload.as_bytes());
    input
}

pub fn public_key_from_seed(seed: &[u8; 32]) -> Result<String, String> {
    if seed.iter().all(|byte| *byte == 0) {
        return Err("Invalid private key seed".to_string());
    }
    let key_pair = KeyPair::from_seed(Seed::new(*seed));
    Ok(URL_SAFE_NO_PAD.encode(key_pair.pk.as_ref()))
}

pub fn derive_device_seed(device_entropy: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut seed = [0; 32];
    Hkdf::<Sha256>::new(Some(b"meta-mesh/identity/v1"), device_entropy)
        .expand(b"device", &mut seed)
        .map_err(|_| "Device key derivation failed".to_string())?;
    Ok(seed)
}

pub fn public_key_id(public_key: &str) -> Result<String, String> {
    let bytes = decode_public_key(public_key)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

pub fn sign_json_envelope(
    seed: &[u8; 32],
    payload: Value,
    signer_key_id: impl Into<String>,
    domain: &str,
) -> Result<SignedEnvelope<Value>, String> {
    if seed.iter().all(|byte| *byte == 0) {
        return Err("Invalid private key seed".to_string());
    }
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty())
        .ok_or_else(|| "Signed payload kind missing".to_string())?;
    let canonical = canonicalize_json(&payload)?;
    let key_pair = KeyPair::from_seed(Seed::new(*seed));
    let signature = key_pair
        .sk
        .sign(signature_input(kind, &canonical, domain), None);
    Ok(SignedEnvelope {
        payload,
        signer_key_id: signer_key_id.into(),
        signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
    })
}

pub fn sign_device_certificate(
    seed: &[u8; 32],
    payload: DeviceCertificatePayload,
    signer_key_id: impl Into<String>,
    domain: &str,
) -> Result<DeviceCertificate, String> {
    let signed = sign_json_envelope(
        seed,
        serde_json::to_value(&payload).map_err(|_| "Device certificate invalid".to_string())?,
        signer_key_id,
        domain,
    )?;
    Ok(DeviceCertificate {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    })
}

pub fn verify_signed_envelope<T: Serialize>(
    envelope: &SignedEnvelope<T>,
    public_key: &str,
    domain: &str,
) -> Result<bool, String> {
    let payload = serde_json::to_value(&envelope.payload)
        .map_err(|_| "Signed payload invalid".to_string())?;
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty())
        .ok_or_else(|| "Signed payload kind missing".to_string())?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.signature)
        .map_err(|_| "Invalid signature".to_string())?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| "Invalid signature".to_string())?;
    let key = PublicKey::from_slice(&decode_public_key(public_key)?)
        .map_err(|_| "Invalid public key".to_string())?;
    let canonical = canonicalize_json(&payload)?;
    Ok(key
        .verify(signature_input(kind, &canonical, domain), &signature)
        .is_ok())
}

pub fn certificate_hash(certificate: &DeviceCertificate) -> Result<String, String> {
    let value =
        serde_json::to_value(certificate).map_err(|_| "Device certificate invalid".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonicalize_json(&value)?.as_bytes())))
}

pub fn verify_device_certificate_chain(
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &[DeviceCertificate],
    domain: &str,
) -> Result<String, String> {
    if public_key_id(&identity.public_key)? != identity.person_id {
        return Err("Identity does not match its key".to_string());
    }
    if certificates.is_empty() || certificates.len() > MAX_CERTIFICATE_CHAIN_LENGTH {
        return Err("Invalid certificate chain".to_string());
    }

    let mut by_hash = HashMap::with_capacity(certificates.len());
    for certificate in certificates {
        by_hash.insert(certificate_hash(certificate)?, certificate);
    }
    let leaf = certificates
        .iter()
        .find(|certificate| certificate.payload.device_id == device_id)
        .ok_or_else(|| "Missing device certificate".to_string())?;
    let mut current = leaf;
    let mut seen = HashSet::new();

    loop {
        let payload = &current.payload;
        if payload.kind != "device-certificate"
            || payload.version != 1
            || payload.person_id != identity.person_id
            || public_key_id(&payload.device_public_key)? != payload.device_id
            || !seen.insert(payload.device_id.clone())
        {
            return Err("Invalid device certificate".to_string());
        }

        match &payload.issuer_certificate_hash {
            None => {
                if current.signer_key_id != identity.person_id
                    || !verify_signed_envelope(current, &identity.public_key, domain)?
                {
                    return Err("Invalid root certificate".to_string());
                }
                return Ok(leaf.payload.device_public_key.clone());
            }
            Some(issuer_hash) => {
                let issuer = by_hash
                    .get(issuer_hash)
                    .copied()
                    .ok_or_else(|| "Invalid certificate chain".to_string())?;
                if !issuer.payload.can_enroll_devices
                    || current.signer_key_id != issuer.payload.device_id
                    || !verify_signed_envelope(current, &issuer.payload.device_public_key, domain)?
                {
                    return Err("Invalid certificate chain".to_string());
                }
                current = issuer;
            }
        }
    }
}

fn decode_public_key(public_key: &str) -> Result<Vec<u8>, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|_| "Invalid public key".to_string())?;
    if bytes.len() != PublicKey::BYTES {
        return Err("Invalid public key".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signature_matches_typescript_webcrypto_golden_vector() {
        let seed = std::array::from_fn(|index| index as u8 + 1);
        let payload = json!({
            "version": 1,
            "kind": "workspace-grant",
            "role": "editor",
            "personId": "person-1",
            "workspaceId": "workspace-1",
            "grantId": "grant-1"
        });
        let envelope =
            sign_json_envelope(&seed, payload, "device-1", DEFAULT_SIGNATURE_DOMAIN).unwrap();
        assert_eq!(
            canonicalize_json(&envelope.payload).unwrap(),
            r#"{"grantId":"grant-1","kind":"workspace-grant","personId":"person-1","role":"editor","version":1,"workspaceId":"workspace-1"}"#
        );
        assert_eq!(
            public_key_from_seed(&seed).unwrap(),
            "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"
        );
        assert_eq!(
            envelope.signature,
            "u9fYht_E2GPi-WDgoSsdQnBFdtw4e7qbUxFgI1jVhyJCRu4FcIiWw0TChNdGl_dzHBbKRMKNdqSp6bZ6FBCoAQ"
        );
        assert!(
            verify_signed_envelope(
                &envelope,
                &public_key_from_seed(&seed).unwrap(),
                DEFAULT_SIGNATURE_DOMAIN
            )
            .unwrap()
        );
    }

    #[test]
    fn certificate_chain_accepts_delegation_and_rejects_forgery() {
        let identity_seed = [11; 32];
        let root_device_seed = [22; 32];
        let leaf_device_seed = [33; 32];
        let identity_public_key = public_key_from_seed(&identity_seed).unwrap();
        let person_id = public_key_id(&identity_public_key).unwrap();
        let root_public_key = public_key_from_seed(&root_device_seed).unwrap();
        let root_device_id = public_key_id(&root_public_key).unwrap();
        let leaf_public_key = public_key_from_seed(&leaf_device_seed).unwrap();
        let leaf_device_id = public_key_id(&leaf_public_key).unwrap();
        let identity = PublicIdentity {
            person_id: person_id.clone(),
            public_key: identity_public_key,
            display_name: "Mesh user".to_string(),
        };
        let root = sign_device_certificate(
            &identity_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".to_string(),
                version: 1,
                person_id: person_id.clone(),
                device_id: root_device_id.clone(),
                device_public_key: root_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let leaf = sign_device_certificate(
            &root_device_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".to_string(),
                version: 1,
                person_id,
                device_id: leaf_device_id.clone(),
                device_public_key: leaf_public_key.clone(),
                issuer_certificate_hash: Some(certificate_hash(&root).unwrap()),
                can_enroll_devices: true,
            },
            root_device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        assert_eq!(
            verify_device_certificate_chain(
                &identity,
                &leaf_device_id,
                &[leaf.clone(), root.clone()],
                DEFAULT_SIGNATURE_DOMAIN,
            )
            .unwrap(),
            leaf_public_key
        );

        let mut forged = leaf;
        forged.payload.can_enroll_devices = false;
        assert!(
            verify_device_certificate_chain(
                &identity,
                &leaf_device_id,
                &[forged, root],
                DEFAULT_SIGNATURE_DOMAIN,
            )
            .is_err()
        );
    }

    #[test]
    fn device_seed_matches_webcrypto_hkdf_vector() {
        let entropy = std::array::from_fn(|index| 255 - index as u8);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(derive_device_seed(&entropy).unwrap()),
            "dRzdinYBvvWHE_zjjIaMIQw38_B_Drlz3d2pH7inmQ8"
        );
    }
}
