use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope, WorkspaceAuthority,
    WorkspaceGrant, WorkspaceRole, public_key_id, verify_device_certificate_chain,
    verify_signed_envelope, verify_workspace_grant,
};

pub const MAX_PEER_ADVERTISEMENT_SIZE: usize = 65_536;
pub const MAX_ENDPOINT_LENGTH: usize = 2_048;
pub const MAX_STRING_LENGTH: usize = 256;
pub const MAX_FUTURE_TOLERANCE_MS: i128 = 5 * 60 * 1000;
pub const MAX_STALE_TOLERANCE_MS: i128 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerAdvertisementPayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub person_id: String,
    pub device_id: String,
    pub instance_id: Option<String>,
    pub endpoint: String,
    pub issued_at: String,
    pub route_sequence: Option<u64>,
    pub expires_at: Option<String>,
    pub device_name: Option<String>,
    pub user_agent: Option<String>,
}

pub type PeerAdvertisement = SignedEnvelope<PeerAdvertisementPayload>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyWorkspaceMemberOptions {
    pub workspace_id: Option<String>,
    pub owner_person_id: Option<String>,
    pub owner_public_key: Option<String>,
    #[serde(default)]
    pub owner_certificates: Vec<DeviceCertificate>,
    #[serde(default)]
    pub owner_history: Vec<WorkspaceAuthority>,
    pub max_byte_length: Option<usize>,
    pub allow_stale_route: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedWorkspaceMember {
    pub advertisement: PeerAdvertisement,
    pub signed: PeerAdvertisement,
    pub payload: PeerAdvertisementPayload,
    pub signer_key_id: String,
    pub signature: String,
    pub public_key: String,
    pub certificates: Vec<DeviceCertificate>,
    pub device_public_key: String,
    pub role: WorkspaceRole,
    pub grant: Option<WorkspaceGrant>,
    pub owner_public_key: String,
    pub owner_certificates: Vec<DeviceCertificate>,
}

pub fn verify_workspace_member_bundle(raw: Value, opts: VerifyWorkspaceMemberOptions, now_ms: i128) -> Result<VerifiedWorkspaceMember, String> {
    if serde_json::to_vec(&raw).map_err(|_| "Invalid peer advertisement".to_string())?.len()
        > opts.max_byte_length.unwrap_or(MAX_PEER_ADVERTISEMENT_SIZE) {
        return Err("Peer advertisement too large".to_string());
    }
    let object = raw.as_object().ok_or_else(|| "Invalid peer advertisement bundle: must be an object".to_string())?;
    let raw_advertisement = object.get("advertisement").or_else(|| object.get("signed"))
        .or_else(|| object.get("payload").and(object.get("signature")))
        .ok_or_else(|| "Missing peer advertisement in bundle".to_string())?;
    let advertisement: PeerAdvertisement = serde_json::from_value(raw_advertisement.clone())
        .map_err(|_| "Invalid peer advertisement payload".to_string())?;
    validate_payload(&advertisement.payload, &opts, now_ms)?;
    if advertisement.signer_key_id != advertisement.payload.device_id { return Err("Advertisement signerKeyId does not match deviceId".to_string()); }
    let public_key = required_string(object.get("publicKey"), "Missing member identity public key")?;
    if public_key_id(&public_key)? != advertisement.payload.person_id { return Err("Identity does not match its key".to_string()); }
    let certificates: Vec<DeviceCertificate> = value_as(object.get("certificates"), "Missing device certificates in bundle")?;
    let identity = PublicIdentity { person_id: advertisement.payload.person_id.clone(), public_key: public_key.clone(), display_name: String::new() };
    let device_public_key = verify_device_certificate_chain(&identity, &advertisement.payload.device_id, &certificates, DEFAULT_SIGNATURE_DOMAIN)?;
    if !verify_signed_envelope(&advertisement, &device_public_key, DEFAULT_SIGNATURE_DOMAIN)? { return Err("Invalid advertisement signature".to_string()); }
    let grant: Option<WorkspaceGrant> = object.get("grant").map(|value| value_as(Some(value), "Invalid workspace grant")).transpose()?;
    let mut owner_public_key = opts.owner_public_key.or_else(|| object.get("ownerPublicKey").and_then(Value::as_str).map(str::to_owned));
    let mut owner_person_id = opts.owner_person_id;
    if owner_public_key.is_none() && grant.is_none() { owner_public_key = Some(public_key.clone()); }
    if owner_person_id.is_none() { owner_person_id = owner_public_key.as_deref().map(public_key_id).transpose()?; }
    let mut owner_certificates = opts.owner_certificates;
    if let Some(value) = object.get("ownerCertificates") {
        let embedded: Vec<DeviceCertificate> = value_as(Some(value), "Invalid owner certificate chain")?;
        owner_certificates.extend(embedded);
    }
    if owner_certificates.len() > 32 { return Err("Invalid owner certificate chain".to_string()); }
    let is_owner = owner_person_id.as_deref() == Some(&advertisement.payload.person_id);
    let role = if is_owner {
        WorkspaceRole::Owner
    } else {
        let owner_person_id = owner_person_id.ok_or_else(|| "Missing workspace owner".to_string())?;
        let owner_public_key = owner_public_key.as_ref().ok_or_else(|| "Missing workspace owner".to_string())?;
        let mut authorities = vec![WorkspaceAuthority { person_id: owner_person_id, public_key: owner_public_key.clone(), certificates: owner_certificates.clone() }];
        authorities.extend(opts.owner_history);
        authorities.into_iter().find_map(|authority| verify_workspace_grant(
            grant.as_ref()?, opts.workspace_id.as_deref().unwrap_or(&advertisement.payload.workspace_id),
            &advertisement.payload.person_id, &PublicIdentity { person_id: authority.person_id, public_key: authority.public_key, display_name: String::new() }, &authority.certificates).ok()
        ).ok_or_else(|| "Invalid workspace grant signature".to_string())?
    };
    Ok(VerifiedWorkspaceMember { signed: advertisement.clone(), payload: advertisement.payload.clone(), signer_key_id: advertisement.signer_key_id.clone(), signature: advertisement.signature.clone(), advertisement, public_key, certificates, device_public_key, role, grant, owner_public_key: owner_public_key.unwrap_or_default(), owner_certificates })
}

fn validate_payload(payload: &PeerAdvertisementPayload, opts: &VerifyWorkspaceMemberOptions, now_ms: i128) -> Result<(), String> {
    if payload.kind != "peer-advertisement" || payload.version != 1 || !bounded(&payload.workspace_id, MAX_STRING_LENGTH) || !bounded(&payload.person_id, MAX_STRING_LENGTH) || !bounded(&payload.device_id, MAX_STRING_LENGTH) || !bounded(&payload.endpoint, MAX_ENDPOINT_LENGTH) || payload.instance_id.as_ref().is_some_and(|value| !bounded(value, MAX_STRING_LENGTH)) { return Err("Invalid peer advertisement payload".to_string()); }
    if opts.workspace_id.as_deref().is_some_and(|workspace| workspace != payload.workspace_id) { return Err("Workspace ID does not match expected workspace".to_string()); }
    let issued = parse_time(&payload.issued_at)?;
    if issued > now_ms + MAX_FUTURE_TOLERANCE_MS { return Err("Peer advertisement timestamp is in the future (> 5 minutes)".to_string()); }
    if !opts.allow_stale_route && issued < now_ms - MAX_STALE_TOLERANCE_MS { return Err("Peer advertisement timestamp is stale (> 30 days)".to_string()); }
    if let Some(expiry) = &payload.expires_at { let expiry = parse_time(expiry)?; if expiry <= issued || expiry > issued + 10 * 60 * 1000 { return Err("Invalid peer route expiry".to_string()); } }
    Ok(())
}
fn bounded(value: &str, max: usize) -> bool { !value.is_empty() && value.len() <= max }
fn parse_time(value: &str) -> Result<i128, String> { OffsetDateTime::parse(value, &Rfc3339).map(|time| time.unix_timestamp_nanos() / 1_000_000).map_err(|_| "Invalid timestamp".to_string()) }
fn required_string(value: Option<&Value>, message: &str) -> Result<String, String> { value.and_then(Value::as_str).filter(|value| !value.is_empty()).map(str::to_owned).ok_or_else(|| message.to_string()) }
fn value_as<T: serde::de::DeserializeOwned>(value: Option<&Value>, message: &str) -> Result<T, String> { value.cloned().ok_or_else(|| message.to_string()).and_then(|value| serde_json::from_value(value).map_err(|_| message.to_string())) }
