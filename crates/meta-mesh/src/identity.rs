use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, IdentityPassphraseEnvelope,
    IdentityRecoveryEnvelope, IdentitySecurity, PublicIdentity, SignedEnvelope, WorkspaceGrant,
    canonicalize_json, certificate_hash, derive_device_seed, identity_security_for_recovery,
    legacy_recovery_from_samples, open_identity_seed, open_identity_seed_with_passphrase,
    public_key_from_seed, public_key_id, recovery_phrase_from_entropy, recovery_phrase_to_entropy,
    seal_identity_seed, seal_identity_seed_with_passphrase, sign_json_envelope,
    verify_device_certificate_chain, verify_signed_envelope, verify_workspace_grant,
};
use serde_json::Value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmIdentityCrypto;

#[wasm_bindgen]
impl WasmIdentityCrypto {
    #[wasm_bindgen(js_name = canonicalizeJson)]
    pub fn canonicalize_json(value: JsValue) -> Result<String, JsValue> {
        let value: Value = serde_wasm_bindgen::from_value(value).map_err(js_error)?;
        canonicalize_json(&value).map_err(js_error)
    }

    #[wasm_bindgen(js_name = publicKeyFromSeed)]
    pub fn public_key_from_seed(seed: &[u8]) -> Result<String, JsValue> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| JsError::new("Invalid private key seed"))?;
        public_key_from_seed(&seed).map_err(js_error)
    }

    #[wasm_bindgen(js_name = publicKeyId)]
    pub fn public_key_id(public_key: &str) -> Result<String, JsValue> {
        public_key_id(public_key).map_err(js_error)
    }

    #[wasm_bindgen(js_name = deriveDeviceSeed)]
    pub fn derive_device_seed(device_entropy: &[u8]) -> Result<Vec<u8>, JsValue> {
        let entropy = exact_bytes::<32>(device_entropy, "Device entropy must contain 32 bytes")?;
        derive_device_seed(&entropy)
            .map(|seed| seed.to_vec())
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = recoveryPhraseFromEntropy)]
    pub fn recovery_phrase_from_entropy(entropy: &[u8]) -> Result<String, JsValue> {
        recovery_phrase_from_entropy(entropy).map_err(js_error)
    }

    #[wasm_bindgen(js_name = recoveryPhraseToEntropy)]
    pub fn recovery_phrase_to_entropy(value: &str) -> Result<Vec<u8>, JsValue> {
        recovery_phrase_to_entropy(value).map_err(js_error)
    }

    #[wasm_bindgen(js_name = legacyRecoveryFromSamples)]
    pub fn legacy_recovery_from_samples(samples: &[u16]) -> Result<String, JsValue> {
        legacy_recovery_from_samples(samples).map_err(js_error)
    }

    #[wasm_bindgen(js_name = identitySecurityForRecovery)]
    pub fn identity_security_for_recovery(value: &str) -> Option<String> {
        identity_security_for_recovery(value).map(|security| match security {
            IdentitySecurity::Legacy => "legacy".to_string(),
            IdentitySecurity::Better => "better".to_string(),
            IdentitySecurity::Insane => "insane".to_string(),
        })
    }

    #[wasm_bindgen(js_name = signEnvelope)]
    pub fn sign_envelope(
        seed: &[u8],
        payload: JsValue,
        signer_key_id: &str,
        domain: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| JsError::new("Invalid private key seed"))?;
        let payload: Value = serde_wasm_bindgen::from_value(payload).map_err(js_error)?;
        let envelope = sign_json_envelope(
            &seed,
            payload,
            signer_key_id,
            domain.as_deref().unwrap_or(DEFAULT_SIGNATURE_DOMAIN),
        )
        .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&envelope).map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifyEnvelope)]
    pub fn verify_envelope(
        envelope: JsValue,
        public_key: &str,
        domain: Option<String>,
    ) -> Result<bool, JsValue> {
        let envelope: SignedEnvelope<Value> =
            serde_wasm_bindgen::from_value(envelope).map_err(js_error)?;
        verify_signed_envelope(
            &envelope,
            public_key,
            domain.as_deref().unwrap_or(DEFAULT_SIGNATURE_DOMAIN),
        )
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = certificateHash)]
    pub fn certificate_hash(certificate: JsValue) -> Result<String, JsValue> {
        let certificate: DeviceCertificate =
            serde_wasm_bindgen::from_value(certificate).map_err(js_error)?;
        certificate_hash(&certificate).map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifyDeviceCertificateChain)]
    pub fn verify_device_certificate_chain(
        identity: JsValue,
        device_id: &str,
        certificates: JsValue,
        domain: Option<String>,
    ) -> Result<String, JsValue> {
        let identity: PublicIdentity =
            serde_wasm_bindgen::from_value(identity).map_err(js_error)?;
        let certificates: Vec<DeviceCertificate> =
            serde_wasm_bindgen::from_value(certificates).map_err(js_error)?;
        verify_device_certificate_chain(
            &identity,
            device_id,
            &certificates,
            domain.as_deref().unwrap_or(DEFAULT_SIGNATURE_DOMAIN),
        )
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceGrant)]
    pub fn verify_workspace_grant(
        grant: JsValue,
        workspace_id: &str,
        member_person_id: &str,
        owner: JsValue,
        owner_certificates: JsValue,
    ) -> Result<String, JsValue> {
        let grant: WorkspaceGrant = serde_wasm_bindgen::from_value(grant).map_err(js_error)?;
        let owner: PublicIdentity = serde_wasm_bindgen::from_value(owner).map_err(js_error)?;
        let owner_certificates: Vec<DeviceCertificate> =
            serde_wasm_bindgen::from_value(owner_certificates).map_err(js_error)?;
        let role = verify_workspace_grant(
            &grant,
            workspace_id,
            member_person_id,
            &owner,
            &owner_certificates,
        )
        .map_err(js_error)?;
        serde_json::to_value(role)
            .map_err(js_error)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| js_error("Invalid workspace role"))
    }

    #[wasm_bindgen(js_name = sealIdentitySeed)]
    pub fn seal_identity_seed(
        seed: &[u8],
        person_id: &str,
        recovery_key: &str,
        security: &str,
        salt: &[u8],
        iv: &[u8],
    ) -> Result<JsValue, JsValue> {
        let seed = exact_bytes::<32>(seed, "Identity root must contain 32 bytes")?;
        let salt = exact_bytes::<16>(salt, "Recovery salt must contain 16 bytes")?;
        let iv = exact_bytes::<12>(iv, "Recovery IV must contain 12 bytes")?;
        let envelope = seal_identity_seed(
            &seed,
            person_id,
            recovery_key,
            parse_security(security)?,
            &salt,
            &iv,
        )
        .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&envelope).map_err(js_error)
    }

    #[wasm_bindgen(js_name = openIdentitySeed)]
    pub fn open_identity_seed(envelope: JsValue, recovery_key: &str) -> Result<Vec<u8>, JsValue> {
        let envelope: IdentityRecoveryEnvelope =
            serde_wasm_bindgen::from_value(envelope).map_err(js_error)?;
        open_identity_seed(&envelope, recovery_key)
            .map(|seed| seed.to_vec())
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = sealIdentitySeedWithPassphrase)]
    pub fn seal_identity_seed_with_passphrase(
        seed: &[u8],
        person_id: &str,
        passphrase: &str,
        salt: &[u8],
        iv: &[u8],
    ) -> Result<JsValue, JsValue> {
        let seed = exact_bytes::<32>(seed, "Identity root must contain 32 bytes")?;
        let salt = exact_bytes::<16>(salt, "Passphrase salt must contain 16 bytes")?;
        let iv = exact_bytes::<12>(iv, "Passphrase IV must contain 12 bytes")?;
        let envelope = seal_identity_seed_with_passphrase(&seed, person_id, passphrase, &salt, &iv)
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&envelope).map_err(js_error)
    }

    #[wasm_bindgen(js_name = openIdentitySeedWithPassphrase)]
    pub fn open_identity_seed_with_passphrase(
        envelope: JsValue,
        passphrase: &str,
    ) -> Result<Vec<u8>, JsValue> {
        let envelope: IdentityPassphraseEnvelope =
            serde_wasm_bindgen::from_value(envelope).map_err(js_error)?;
        open_identity_seed_with_passphrase(&envelope, passphrase)
            .map(|seed| seed.to_vec())
            .map_err(js_error)
    }
}

fn exact_bytes<const N: usize>(bytes: &[u8], error: &str) -> Result<[u8; N], JsValue> {
    bytes.try_into().map_err(|_| JsError::new(error).into())
}

fn parse_security(value: &str) -> Result<IdentitySecurity, JsValue> {
    match value {
        "legacy" => Ok(IdentitySecurity::Legacy),
        "better" => Ok(IdentitySecurity::Better),
        "insane" => Ok(IdentitySecurity::Insane),
        _ => Err(JsError::new("Invalid identity recovery").into()),
    }
}

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}
