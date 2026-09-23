use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleReuseInput {
    pub bundle: Option<Value>,
    pub current_peer: Option<Value>,
    pub credential: Value,
    pub local_person_id: String,
    pub local_public_key: String,
    pub expected_device_name: String,
    pub expected_user_agent: Option<String>,
    pub endpoint: String,
    pub instance_id: String,
    pub certificates: Vec<Value>,
    pub local_grant: Option<Value>,
    pub now_ms: u64,
    pub renew_ms: u64,
}

pub fn can_reuse_member_bundle(input: BundleReuseInput) -> bool {
    let Some(bundle) = input.bundle.as_ref() else {
        return false;
    };
    let Some(payload) = bundle.pointer("/advertisement/payload") else {
        return false;
    };
    if payload
        .get("issuedAt")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return false;
    }
    let Some(expires_at) = payload.get("expiresAt").and_then(Value::as_str) else {
        return false;
    };
    let Ok(expires_at) = OffsetDateTime::parse(expires_at, &Rfc3339) else {
        return false;
    };
    if expires_at.unix_timestamp_nanos()
        <= i128::from(input.now_ms.saturating_add(input.renew_ms)) * 1_000_000
    {
        return false;
    }
    let Some(current) = input.current_peer.as_ref() else {
        return false;
    };
    let role = if input
        .credential
        .get("ownerPersonId")
        .and_then(Value::as_str)
        == Some(&input.local_person_id)
    {
        Some("owner")
    } else {
        input
            .local_grant
            .as_ref()
            .and_then(|grant| grant.pointer("/payload/role"))
            .and_then(Value::as_str)
    };
    if current.get("endpoint").and_then(Value::as_str) != Some(&input.endpoint)
        || current.get("role").and_then(Value::as_str) != role
        || (!input.instance_id.is_empty()
            && payload.get("instanceId").and_then(Value::as_str) != Some(&input.instance_id))
    {
        return false;
    }
    if payload.get("deviceName").and_then(Value::as_str) != Some(&input.expected_device_name)
        || payload.get("userAgent").and_then(Value::as_str) != input.expected_user_agent.as_deref()
        || bundle.get("publicKey").and_then(Value::as_str) != Some(&input.local_public_key)
        || bundle.get("ownerPublicKey") != input.credential.get("ownerPublicKey")
    {
        return false;
    }
    if bundle.pointer("/grant/signature")
        != input
            .local_grant
            .as_ref()
            .and_then(|grant| grant.get("signature"))
    {
        return false;
    }
    signatures(bundle.get("certificates")) == signatures(Some(&Value::Array(input.certificates)))
        && signatures(bundle.get("ownerCertificates"))
            == signatures(input.credential.get("ownerCertificates"))
}

fn signatures(value: Option<&Value>) -> Vec<String> {
    let mut result = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.get("signature")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    result.sort();
    result
}
