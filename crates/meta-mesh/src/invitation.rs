use meta_mesh_core::{
    InvitationIssuer, PairingInvite, ScopedInvitation, WorkspaceItem,
    create_device_enrollment_invitation, create_workspace_join_invitation, invitation_url,
    pairing_invite_url, parse_invitation, parse_pairing_invite,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmInvitations;

#[wasm_bindgen]
impl WasmInvitations {
    #[wasm_bindgen(js_name = pairingInviteUrl)]
    pub fn pairing_invite_url(origin: &str, invite: JsValue) -> Result<String, JsValue> {
        let invite: PairingInvite = serde_wasm_bindgen::from_value(invite).map_err(js_error)?;
        pairing_invite_url(origin, &invite).map_err(js_error)
    }

    #[wasm_bindgen(js_name = parsePairingInvite)]
    pub fn parse_pairing_invite(raw: &str) -> Result<JsValue, JsValue> {
        let invite = parse_pairing_invite(raw).map_err(js_error)?;
        serde_wasm_bindgen::to_value(&invite).map_err(js_error)
    }

    #[wasm_bindgen(js_name = createDeviceEnrollment)]
    pub fn create_device_enrollment(
        endpoint: &str,
        secret: &str,
        issuer: JsValue,
        invitation_id: &str,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let issuer: InvitationIssuer = serde_wasm_bindgen::from_value(issuer).map_err(js_error)?;
        let invite = create_device_enrollment_invitation(
            endpoint,
            secret,
            &issuer,
            invitation_id,
            timestamp(now_ms)?,
        )
        .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&invite).map_err(js_error)
    }

    #[wasm_bindgen(js_name = createWorkspaceJoin)]
    pub fn create_workspace_join(
        endpoint: &str,
        secret: &str,
        issuer: JsValue,
        invitation_id: &str,
        workspaces: JsValue,
        role: &str,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let issuer: InvitationIssuer = serde_wasm_bindgen::from_value(issuer).map_err(js_error)?;
        let workspaces: Vec<WorkspaceItem> =
            serde_wasm_bindgen::from_value(workspaces).map_err(js_error)?;
        let invite = create_workspace_join_invitation(
            endpoint,
            secret,
            &issuer,
            invitation_id,
            workspaces,
            role,
            timestamp(now_ms)?,
        )
        .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&invite).map_err(js_error)
    }

    #[wasm_bindgen(js_name = invitationUrl)]
    pub fn invitation_url(origin: &str, invitation: JsValue) -> Result<String, JsValue> {
        let invitation: ScopedInvitation =
            serde_wasm_bindgen::from_value(invitation).map_err(js_error)?;
        invitation_url(origin, &invitation).map_err(js_error)
    }

    #[wasm_bindgen(js_name = parseInvitation)]
    pub fn parse_invitation(raw: &str, now_ms: f64) -> Result<JsValue, JsValue> {
        let invitation = parse_invitation(raw, timestamp(now_ms)?).map_err(js_error)?;
        serde_wasm_bindgen::to_value(&invitation).map_err(js_error)
    }
}

fn timestamp(value: f64) -> Result<i64, JsValue> {
    if !value.is_finite()
        || value.fract() != 0.0
        || value < i64::MIN as f64
        || value > i64::MAX as f64
    {
        return Err(JsError::new("Invalid invitation timestamp").into());
    }
    Ok(value as i64)
}

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}
