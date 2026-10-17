//! Resource capabilities shared by native and browser SDKs. Storage and approval UI are host-owned.
use crate::{
    DeviceCertificate, PublicIdentity, SignedEnvelope, canonicalize_json, public_key_id,
    verify_device_signed_envelope,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const RESOURCE_SIGNATURE_DOMAIN: &str = "MESH-RESOURCE/1";
const REQUEST_LIFETIME: i64 = 120_000;
const GRANT_LIFETIME: i64 = 30 * 24 * 60 * 60 * 1000;
const CLOCK_TOLERANCE: i64 = 30_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceDescriptor {
    pub kind: String,
    pub version: u8,
    pub id: String,
    pub title: String,
    pub issuer: PublicIdentity,
    pub audience: String,
    pub epoch: u64,
    pub actions: Vec<String>,
    pub read_scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceSignature<T> {
    pub payload: T,
    pub signer_key_id: String,
    pub signature: String,
    pub identity: PublicIdentity,
    pub device_id: String,
    pub certificates: Vec<DeviceCertificate>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub kind: String,
    pub version: u8,
    pub request_id: String,
    pub nonce: String,
    pub resource_id: String,
    pub resource_epoch: u64,
    pub issuer_person_id: String,
    pub subject_person_id: String,
    pub audience: String,
    pub actions: Vec<String>,
    pub requested_expires_at: i64,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Connection {
    pub kind: String,
    pub version: u8,
    pub request_id: String,
    pub challenge_hash: String,
    pub resource_id: String,
    pub issuer_person_id: String,
    pub subject_person_id: String,
    pub audience: String,
    pub actions: Vec<String>,
    pub requested_expires_at: i64,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceGrant {
    pub kind: String,
    pub version: u8,
    pub grant_id: String,
    pub request_id: String,
    pub resource_id: String,
    pub resource_epoch: u64,
    pub issuer_person_id: String,
    pub subject_person_id: String,
    pub audience: String,
    pub actions: Vec<String>,
    pub read_scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceOperation {
    pub kind: String,
    pub version: u8,
    pub nonce: String,
    pub grant_hash: String,
    pub resource_id: String,
    pub audience: String,
    pub action: String,
    pub body_digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Command {
    ValidateDescriptor {
        resource: ResourceDescriptor,
    },
    ChallengePayload {
        resource: ResourceDescriptor,
        subject_person_id: String,
        request_id: String,
        actions: Vec<String>,
        requested_expires_at: i64,
        nonce: String,
        now: i64,
    },
    ConnectionPayload {
        resource: ResourceDescriptor,
        challenge: ResourceSignature<Challenge>,
        subject_person_id: String,
        request_id: String,
        actions: Vec<String>,
        requested_expires_at: i64,
        now: i64,
    },
    VerifyConnection {
        resource: ResourceDescriptor,
        challenge: ResourceSignature<Challenge>,
        request: ResourceSignature<Connection>,
        now: i64,
    },
    GrantPayload {
        resource: ResourceDescriptor,
        challenge: ResourceSignature<Challenge>,
        request: ResourceSignature<Connection>,
        actions: Vec<String>,
        expires_at: i64,
        grant_id: String,
        now: i64,
    },
    VerifyGrant {
        resource: ResourceDescriptor,
        grant: ResourceSignature<ResourceGrant>,
        now: i64,
        revoked_grants: Vec<String>,
        revoked_devices: Vec<String>,
    },
    OperationPayload {
        grant: ResourceSignature<ResourceGrant>,
        action: String,
        body_digest: String,
        nonce: String,
        now: i64,
    },
    Authorize {
        resource: ResourceDescriptor,
        grant: ResourceSignature<ResourceGrant>,
        proof: ResourceSignature<ResourceOperation>,
        action: String,
        body_digest: String,
        now: i64,
        revoked_grants: Vec<String>,
        revoked_devices: Vec<String>,
    },
}
fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}
fn digest(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32)
}
fn actions(value: &[String]) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.iter().all(|action| {
            identifier(action, 128)
                && action
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
        })
        && value.iter().collect::<HashSet<_>>().len() == value.len()
}
fn identity(value: &PublicIdentity) -> bool {
    public_key_id(&value.public_key).is_ok_and(|id| id == value.person_id)
}
fn resource(value: &ResourceDescriptor) -> Result<(), String> {
    require(
        value.kind == "mesh-resource"
            && value.version == 1
            && identifier(&value.id, 256)
            && identifier(&value.title, 512)
            && identifier(&value.audience, 2048)
            && identity(&value.issuer)
            && value.epoch > 0
            && value.epoch <= MAX_SAFE as u64
            && actions(&value.actions)
            && identifier(&value.read_scope, 4096),
        "Invalid resource descriptor",
    )
}
fn interval(issued: i64, expires: i64, now: i64, maximum: i64) -> Result<(), String> {
    require(
        now >= 0
            && now < MAX_SAFE - GRANT_LIFETIME
            && issued >= 0
            && issued <= now + CLOCK_TOLERANCE
            && expires > issued
            && expires > now
            && expires <= MAX_SAFE
            && expires - issued <= maximum,
        "Resource authorization expired or invalid time",
    )
}
fn hash(value: &impl Serialize) -> Result<String, String> {
    let raw = serde_json::to_value(value).map_err(|_| "Invalid resource JSON")?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonicalize_json(&raw)?.as_bytes())))
}
fn signature<T: Serialize>(value: &ResourceSignature<T>) -> Result<(), String> {
    let envelope = SignedEnvelope {
        payload: &value.payload,
        signer_key_id: value.signer_key_id.clone(),
        signature: value.signature.clone(),
    };
    verify_device_signed_envelope(
        &value.identity,
        &value.device_id,
        &value.certificates,
        &envelope,
        RESOURCE_SIGNATURE_DOMAIN,
    )
}
fn issuer<T: Serialize>(
    value: &ResourceSignature<T>,
    expected: &PublicIdentity,
) -> Result<(), String> {
    require(
        value.identity.person_id == expected.person_id
            && value.identity.public_key == expected.public_key,
        "Resource issuer mismatch",
    )?;
    signature(value)
}
fn verify_challenge(
    r: &ResourceDescriptor,
    signed: &ResourceSignature<Challenge>,
    now: i64,
) -> Result<(), String> {
    resource(r)?;
    issuer(signed, &r.issuer)?;
    let c = &signed.payload;
    interval(c.issued_at, c.expires_at, now, REQUEST_LIFETIME)?;
    require(
        c.kind == "mesh-resource-challenge"
            && c.version == 1
            && c.resource_id == r.id
            && c.resource_epoch == r.epoch
            && c.issuer_person_id == r.issuer.person_id
            && c.audience == r.audience
            && digest(&c.subject_person_id)
            && digest(&c.nonce)
            && identifier(&c.request_id, 128)
            && actions(&c.actions)
            && c.actions.iter().all(|action| r.actions.contains(action))
            && c.requested_expires_at > now
            && c.requested_expires_at - c.issued_at <= GRANT_LIFETIME,
        "Resource challenge binding mismatch",
    )
}
fn verify_connection(
    r: &ResourceDescriptor,
    challenge: &ResourceSignature<Challenge>,
    request: &ResourceSignature<Connection>,
    now: i64,
) -> Result<(), String> {
    verify_challenge(r, challenge, now)?;
    signature(request)?;
    let c = &challenge.payload;
    let p = &request.payload;
    interval(p.issued_at, p.expires_at, now, REQUEST_LIFETIME)?;
    require(
        p.kind == "mesh-resource-connection"
            && p.version == 1
            && p.challenge_hash == hash(challenge)?
            && p.request_id == c.request_id
            && p.resource_id == c.resource_id
            && p.issuer_person_id == c.issuer_person_id
            && p.subject_person_id == c.subject_person_id
            && request.identity.person_id == c.subject_person_id
            && p.audience == c.audience
            && p.actions == c.actions
            && p.requested_expires_at == c.requested_expires_at
            && p.expires_at <= c.expires_at,
        "Resource connection binding mismatch",
    )
}
fn verify_grant(
    r: &ResourceDescriptor,
    grant: &ResourceSignature<ResourceGrant>,
    now: i64,
    revoked: &[String],
    devices: &[String],
) -> Result<(), String> {
    resource(r)?;
    issuer(grant, &r.issuer)?;
    let g = &grant.payload;
    require(
        !revoked.contains(&g.grant_id) && !devices.contains(&grant.device_id),
        "Resource grant revoked",
    )?;
    interval(g.issued_at, g.expires_at, now, GRANT_LIFETIME)?;
    require(
        g.kind == "mesh-resource-grant"
            && g.version == 1
            && identifier(&g.grant_id, 128)
            && identifier(&g.request_id, 128)
            && g.resource_id == r.id
            && g.resource_epoch == r.epoch
            && g.issuer_person_id == r.issuer.person_id
            && g.audience == r.audience
            && digest(&g.subject_person_id)
            && actions(&g.actions)
            && g.actions.iter().all(|action| r.actions.contains(action))
            && g.read_scope == r.read_scope,
        "Resource grant binding mismatch",
    )
}
/// The host supplies current durable resource authority, not authority copied from a caller's grant.
pub fn evaluate_resource_access(input: Value) -> Result<Value, String> {
    require(
        canonicalize_json(&input)?.len() <= 131_072,
        "Resource command exceeds size limit",
    )?;
    let command: Command = serde_json::from_value(input)
        .map_err(|error| format!("Invalid resource command: {error}"))?;
    match command {
        Command::ValidateDescriptor { resource: r } => {
            resource(&r)?;
            Ok(json!(r))
        }
        Command::ChallengePayload {
            resource: r,
            subject_person_id,
            request_id,
            actions: requested,
            requested_expires_at,
            nonce,
            now,
        } => {
            resource(&r)?;
            interval(now, requested_expires_at, now, GRANT_LIFETIME)?;
            require(
                digest(&subject_person_id)
                    && digest(&nonce)
                    && identifier(&request_id, 128)
                    && actions(&requested)
                    && requested.iter().all(|action| r.actions.contains(action)),
                "Invalid resource connection options",
            )?;
            Ok(json!(Challenge {
                kind: "mesh-resource-challenge".into(),
                version: 1,
                request_id,
                nonce,
                resource_id: r.id,
                resource_epoch: r.epoch,
                issuer_person_id: r.issuer.person_id,
                subject_person_id,
                audience: r.audience,
                actions: requested,
                requested_expires_at,
                issued_at: now,
                expires_at: now + REQUEST_LIFETIME
            }))
        }
        Command::ConnectionPayload {
            resource: r,
            challenge,
            subject_person_id,
            request_id,
            actions,
            requested_expires_at,
            now,
        } => {
            verify_challenge(&r, &challenge, now)?;
            let c = &challenge.payload;
            require(
                subject_person_id == c.subject_person_id
                    && request_id == c.request_id
                    && actions == c.actions
                    && requested_expires_at == c.requested_expires_at,
                "Resource challenge request mismatch",
            )?;
            Ok(json!(Connection {
                kind: "mesh-resource-connection".into(),
                version: 1,
                request_id,
                challenge_hash: hash(&challenge)?,
                resource_id: r.id,
                issuer_person_id: r.issuer.person_id,
                subject_person_id,
                audience: r.audience,
                actions,
                requested_expires_at,
                issued_at: now,
                expires_at: c.expires_at
            }))
        }
        Command::VerifyConnection {
            resource: r,
            challenge,
            request,
            now,
        } => {
            verify_connection(&r, &challenge, &request, now)?;
            Ok(json!(request.payload))
        }
        Command::GrantPayload {
            resource: r,
            challenge,
            request,
            actions: approved,
            expires_at,
            grant_id,
            now,
        } => {
            verify_connection(&r, &challenge, &request, now)?;
            interval(now, expires_at, now, GRANT_LIFETIME)?;
            require(
                actions(&approved)
                    && approved
                        .iter()
                        .all(|action| request.payload.actions.contains(action))
                    && expires_at <= request.payload.requested_expires_at
                    && identifier(&grant_id, 128),
                "Approval exceeds requested resource access",
            )?;
            Ok(json!(ResourceGrant {
                kind: "mesh-resource-grant".into(),
                version: 1,
                grant_id,
                request_id: request.payload.request_id,
                resource_id: r.id,
                resource_epoch: r.epoch,
                issuer_person_id: r.issuer.person_id,
                subject_person_id: request.identity.person_id,
                audience: r.audience,
                actions: approved,
                read_scope: r.read_scope,
                issued_at: now,
                expires_at
            }))
        }
        Command::VerifyGrant {
            resource: r,
            grant,
            now,
            revoked_grants,
            revoked_devices,
        } => {
            verify_grant(&r, &grant, now, &revoked_grants, &revoked_devices)?;
            Ok(json!(grant.payload))
        }
        Command::OperationPayload {
            grant,
            action,
            body_digest,
            nonce,
            now,
        } => {
            signature(&grant)?;
            interval(
                grant.payload.issued_at,
                grant.payload.expires_at,
                now,
                GRANT_LIFETIME,
            )?;
            require(
                identifier(&action, 128) && digest(&body_digest) && digest(&nonce),
                "Invalid resource operation",
            )?;
            Ok(json!(ResourceOperation {
                kind: "mesh-resource-operation".into(),
                version: 1,
                nonce,
                grant_hash: hash(&grant)?,
                resource_id: grant.payload.resource_id,
                audience: grant.payload.audience,
                action,
                body_digest,
                issued_at: now,
                expires_at: (now + REQUEST_LIFETIME).min(grant.payload.expires_at)
            }))
        }
        Command::Authorize {
            resource: r,
            grant,
            proof,
            action,
            body_digest,
            now,
            revoked_grants,
            revoked_devices,
        } => {
            verify_grant(&r, &grant, now, &revoked_grants, &revoked_devices)?;
            signature(&proof)?;
            let p = &proof.payload;
            let g = &grant.payload;
            interval(p.issued_at, p.expires_at, now, REQUEST_LIFETIME)?;
            require(
                !revoked_devices.contains(&proof.device_id),
                "Resource device revoked",
            )?;
            require(
                p.kind == "mesh-resource-operation"
                    && p.version == 1
                    && p.grant_hash == hash(&grant)?
                    && proof.identity.person_id == g.subject_person_id
                    && p.resource_id == r.id
                    && p.audience == r.audience
                    && p.action == action
                    && g.actions.contains(&action)
                    && p.body_digest == body_digest
                    && digest(&body_digest)
                    && digest(&p.nonce)
                    && p.expires_at <= g.expires_at,
                "Resource operation binding mismatch",
            )?;
            Ok(
                json!({"resourceId":r.id,"subjectPersonId":g.subject_person_id,"grantId":g.grant_id,"action":action,"requestId":p.nonce,"expiresAt":p.expires_at}),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCertificatePayload, public_key_from_seed, sign_device_certificate, sign_json_envelope,
    };

    fn signer(root: u8, device: u8) -> (PublicIdentity, DeviceCertificate, [u8; 32]) {
        let root_seed = [root; 32];
        let seed = [device; 32];
        let public_key = public_key_from_seed(&root_seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let identity = PublicIdentity {
            person_id: person_id.clone(),
            public_key,
            display_name: "Fixture".into(),
        };
        let certificate = sign_device_certificate(
            &root_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id,
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            person_id,
            "MATCH/1",
        )
        .unwrap();
        (identity, certificate, seed)
    }
    fn signed(payload: Value, signer: &(PublicIdentity, DeviceCertificate, [u8; 32])) -> Value {
        let envelope = sign_json_envelope(
            &signer.2,
            payload,
            &signer.1.payload.device_id,
            RESOURCE_SIGNATURE_DOMAIN,
        )
        .unwrap();
        json!({"payload":envelope.payload,"signerKeyId":envelope.signer_key_id,"signature":envelope.signature,
            "identity":signer.0,"deviceId":signer.1.payload.device_id,"certificates":[signer.1]})
    }
    fn fixture() -> (
        Value,
        Value,
        Value,
        Value,
        (PublicIdentity, DeviceCertificate, [u8; 32]),
        i64,
    ) {
        let owner = signer(11, 12);
        let node = signer(21, 22);
        let now = 1_800_000_000_000;
        let r = json!({"kind":"mesh-resource","version":1,"id":"board-a","title":"Board A","issuer":owner.0,
            "audience":"https://board.example","epoch":1,"actions":["read","create"],"readScope":"Entire Board A"});
        let challenge = signed(
            evaluate_resource_access(json!({"operation":"challengePayload","resource":r,
            "subjectPersonId":node.0.person_id,"requestId":"request-one","actions":["read"],
            "requestedExpiresAt":now+60_000,"nonce":URL_SAFE_NO_PAD.encode([31;32]),"now":now}))
            .unwrap(),
            &owner,
        );
        let connection = signed(evaluate_resource_access(json!({"operation":"connectionPayload","resource":r,"challenge":challenge,
            "subjectPersonId":node.0.person_id,"requestId":"request-one","actions":["read"],"requestedExpiresAt":now+60_000,"now":now})).unwrap(), &node);
        let grant = signed(evaluate_resource_access(json!({"operation":"grantPayload","resource":r,"challenge":challenge,"request":connection,
            "actions":["read"],"expiresAt":now+60_000,"grantId":"grant-one","now":now})).unwrap(), &owner);
        (r, challenge, connection, grant, node, now)
    }
    #[test]
    fn resource_access_native_authorizes_only_exact_signed_operation() {
        let (resource, _, _, grant, node, now) = fixture();
        let body = URL_SAFE_NO_PAD.encode(Sha256::digest(b"body"));
        let proof = signed(
            evaluate_resource_access(json!({"operation":"operationPayload","grant":grant,
            "action":"read","bodyDigest":body,"nonce":URL_SAFE_NO_PAD.encode([41;32]),"now":now}))
            .unwrap(),
            &node,
        );
        let command = json!({"operation":"authorize","resource":resource,"grant":grant,"proof":proof,"action":"read",
            "bodyDigest":body,"now":now,"revokedGrants":[],"revokedDevices":[]});
        assert_eq!(
            evaluate_resource_access(command.clone()).unwrap()["subjectPersonId"],
            node.0.person_id
        );
        for (key, value) in [
            ("action", json!("create")),
            ("bodyDigest", json!(URL_SAFE_NO_PAD.encode([1; 32]))),
            ("now", json!(now + 61_000)),
            ("revokedGrants", json!(["grant-one"])),
            ("revokedDevices", json!([node.1.payload.device_id])),
        ] {
            let mut changed = command.clone();
            changed[key] = value;
            assert!(
                evaluate_resource_access(changed).is_err(),
                "accepted changed {key}"
            );
        }
        let mut changed = command.clone();
        changed["resource"]["epoch"] = json!(2);
        assert!(evaluate_resource_access(changed).is_err());
        let mut changed = command;
        changed["grant"]["payload"]["actions"] = json!(["read", "create"]);
        assert!(evaluate_resource_access(changed).is_err());
    }
    #[test]
    fn resource_access_native_rejects_foreign_issuer_and_approval_expansion() {
        let (resource, challenge, request, grant, _, now) = fixture();
        let command = json!({"operation":"grantPayload","resource":resource,"challenge":challenge,"request":request,
            "actions":["create"],"expiresAt":now+60_000,"grantId":"grant-other","now":now});
        assert!(evaluate_resource_access(command).is_err());
        let mut resource = resource;
        resource["issuer"] = json!(signer(51, 52).0);
        assert!(
            evaluate_resource_access(
                json!({"operation":"verifyGrant","resource":resource,"grant":grant,
            "now":now,"revokedGrants":[],"revokedDevices":[]})
            )
            .is_err()
        );
    }
}
