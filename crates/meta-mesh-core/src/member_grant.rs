use crate::DeviceCertificate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum MemberGrantInput {
    Prefer {
        previous: Option<Value>,
        incoming: Value,
    },
    PersistLocal {
        credential: Value,
        local_person_id: String,
        grant: Option<Value>,
        owner_certificates: Value,
        updated_at: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberGrantPlan {
    pub bundle: Option<Value>,
    pub credential: Option<Value>,
    pub grant: Option<Value>,
    pub grant_id: Option<String>,
}

pub fn plan_member_grant(input: MemberGrantInput) -> Result<MemberGrantPlan, String> {
    match input {
        MemberGrantInput::Prefer {
            previous,
            mut incoming,
        } => {
            if let Some(previous) = previous {
                let same_owner = previous.get("ownerPublicKey") == incoming.get("ownerPublicKey");
                let old = previous.get("grant");
                let new = incoming.get("grant");
                if same_owner
                    && old.is_some()
                    && new.is_some()
                    && old.and_then(|grant| grant.pointer("/payload/personId"))
                        == new.and_then(|grant| grant.pointer("/payload/personId"))
                    && epoch(old) > epoch(new)
                {
                    let incoming = incoming
                        .as_object_mut()
                        .ok_or("Invalid workspace member bundle")?;
                    incoming.insert(
                        "grant".into(),
                        old.cloned().ok_or("Invalid workspace member grant")?,
                    );
                    if let Some(certificates) = previous.get("ownerCertificates") {
                        incoming.insert("ownerCertificates".into(), certificates.clone());
                    }
                }
            }
            Ok(MemberGrantPlan {
                bundle: Some(incoming),
                credential: None,
                grant: None,
                grant_id: None,
            })
        }
        MemberGrantInput::PersistLocal {
            mut credential,
            local_person_id,
            grant,
            owner_certificates,
            updated_at,
        } => {
            let Some(grant) = grant else {
                return Ok(no_local_update());
            };
            if grant.pointer("/payload/personId").and_then(Value::as_str) != Some(&local_person_id)
                || credential.get("localGrant").is_some_and(|existing| {
                    !existing.is_null() && epoch(Some(&grant)) <= epoch(Some(existing))
                })
            {
                return Ok(no_local_update());
            }
            let grant_id = grant
                .pointer("/payload/grantId")
                .and_then(Value::as_str)
                .ok_or("Invalid workspace member grant")?
                .to_string();
            let next = credential
                .as_object_mut()
                .ok_or("Invalid workspace credential")?;
            next.insert("ownerCertificates".into(), owner_certificates);
            next.insert("localGrant".into(), grant.clone());
            next.insert("updatedAt".into(), json!(updated_at));
            Ok(MemberGrantPlan {
                bundle: None,
                credential: Some(credential),
                grant: Some(grant),
                grant_id: Some(grant_id),
            })
        }
    }
}

pub fn decide_owner_credential(
    existing_owner_person_id: Option<&str>,
    local_person_id: &str,
) -> Result<&'static str, String> {
    match existing_owner_person_id {
        Some(owner) if owner != local_person_id => {
            Err("Only the workspace owner can invite peers".into())
        }
        Some(_) => Ok("refresh"),
        None => Ok("create"),
    }
}

pub fn plan_owner_certificate_refresh(
    mut credential: Value,
    local_person_id: &str,
    certificates: Vec<DeviceCertificate>,
    updated_at: &str,
) -> Result<Option<Value>, String> {
    let owner = credential
        .get("ownerPersonId")
        .and_then(Value::as_str)
        .ok_or("Invalid workspace credential")?
        .to_string();
    if owner != local_person_id {
        return Ok(None);
    }
    let existing: Vec<DeviceCertificate> = serde_json::from_value(
        credential
            .get("ownerCertificates")
            .cloned()
            .ok_or("Invalid workspace credential")?,
    )
    .map_err(|_| "Invalid workspace credential")?;
    let old_len = existing.len();
    let mut merged = Vec::<DeviceCertificate>::new();
    for certificate in existing.into_iter().chain(certificates) {
        if certificate.payload.person_id != owner {
            continue;
        }
        if let Some(position) = merged
            .iter()
            .position(|item| item.signature == certificate.signature)
        {
            merged[position] = certificate;
        } else {
            merged.push(certificate);
        }
    }
    if merged.len() == old_len && credential.get("localGrant").is_none() {
        return Ok(None);
    }
    let value = credential
        .as_object_mut()
        .ok_or("Invalid workspace credential")?;
    value.remove("localGrant");
    value.insert("ownerCertificates".into(), json!(merged));
    value.insert("updatedAt".into(), json!(updated_at));
    Ok(Some(credential))
}

fn no_local_update() -> MemberGrantPlan {
    MemberGrantPlan {
        bundle: None,
        credential: None,
        grant: None,
        grant_id: None,
    }
}

fn epoch(grant: Option<&Value>) -> u64 {
    grant
        .and_then(|value| value.pointer("/payload/accessEpoch"))
        .and_then(Value::as_u64)
        .unwrap_or(1)
}
