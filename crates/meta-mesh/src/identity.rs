use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope, WorkspaceGrant,
    canonicalize_json, certificate_hash, public_key_from_seed, public_key_id, sign_json_envelope,
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
}

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}
