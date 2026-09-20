use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description};
use url::{Url, form_urlencoded};

use crate::PAIRING_VERSION;

pub const INVITATION_VERSION: u8 = 1;
pub const INVITATION_LIFETIME_MS: i64 = 10 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingInvite {
    pub version: String,
    pub endpoint: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationIssuer {
    pub person_id: String,
    pub device_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceItem {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEnrollmentInvitation {
    pub version: u8,
    pub kind: String,
    pub invitation_id: String,
    pub issuer_person_id: String,
    pub issuer_device_id: String,
    pub issuer_public_key: String,
    pub issuer_endpoint: String,
    pub created_at: String,
    pub expires_at: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceJoinInvitation {
    pub version: u8,
    pub kind: String,
    pub invitation_id: String,
    pub issuer_person_id: String,
    pub issuer_device_id: String,
    pub issuer_public_key: String,
    pub issuer_endpoint: String,
    pub workspace_id: String,
    pub workspace_title: String,
    pub workspaces: Vec<WorkspaceItem>,
    pub role: String,
    pub created_at: String,
    pub expires_at: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopedInvitation {
    DeviceEnrollment(DeviceEnrollmentInvitation),
    WorkspaceJoin(WorkspaceJoinInvitation),
}

pub fn pairing_invite_url(origin: &str, invite: &PairingInvite) -> Result<String, String> {
    let mut url = pair_url(origin)?;
    let fragment = form_urlencoded::Serializer::new(String::new())
        .append_pair("v", &invite.version)
        .append_pair("endpoint", &invite.endpoint)
        .append_pair("secret", &invite.secret)
        .finish();
    url.set_fragment(Some(&fragment));
    Ok(url.to_string())
}

pub fn parse_pairing_invite(raw: &str) -> Result<PairingInvite, String> {
    let url = Url::parse(raw.trim()).map_err(|_| "Invalid pairing link".to_string())?;
    let parameters = if url.scheme() == "match" && url.host_str() == Some("pair") {
        url.query().unwrap_or_default()
    } else if url.path().trim_end_matches('/') == "/pair" && url.fragment().is_some() {
        url.fragment().unwrap_or_default()
    } else {
        return Err("Invalid pairing link".to_string());
    };
    let parameters = parse_parameters(parameters);
    let version = parameter(&parameters, "v");
    let endpoint = parameter(&parameters, "endpoint");
    let secret = parameter(&parameters, "secret");
    if version != PAIRING_VERSION || endpoint.is_empty() || secret.is_empty() {
        return Err("Invalid pairing link".to_string());
    }
    Ok(PairingInvite {
        version,
        endpoint,
        secret,
    })
}

pub fn create_device_enrollment_invitation(
    endpoint: impl Into<String>,
    secret: impl Into<String>,
    issuer: &InvitationIssuer,
    invitation_id: impl Into<String>,
    now_ms: i64,
) -> Result<DeviceEnrollmentInvitation, String> {
    Ok(DeviceEnrollmentInvitation {
        version: INVITATION_VERSION,
        kind: "device-enrollment".to_string(),
        invitation_id: invitation_id.into(),
        issuer_person_id: issuer.person_id.clone(),
        issuer_device_id: issuer.device_id.clone(),
        issuer_public_key: issuer.public_key.clone(),
        issuer_endpoint: endpoint.into(),
        created_at: iso_timestamp(now_ms)?,
        expires_at: iso_timestamp(now_ms + INVITATION_LIFETIME_MS)?,
        secret: secret.into(),
    })
}

pub fn create_workspace_join_invitation(
    endpoint: impl Into<String>,
    secret: impl Into<String>,
    issuer: &InvitationIssuer,
    invitation_id: impl Into<String>,
    workspaces: Vec<WorkspaceItem>,
    role: &str,
    now_ms: i64,
) -> Result<WorkspaceJoinInvitation, String> {
    let primary = workspaces
        .first()
        .ok_or_else(|| "At least one workspace must be selected".to_string())?;
    if role != "editor" && role != "visitor" {
        return Err("Invalid workspace role".to_string());
    }
    Ok(WorkspaceJoinInvitation {
        version: INVITATION_VERSION,
        kind: "workspace-join".to_string(),
        invitation_id: invitation_id.into(),
        issuer_person_id: issuer.person_id.clone(),
        issuer_device_id: issuer.device_id.clone(),
        issuer_public_key: issuer.public_key.clone(),
        issuer_endpoint: endpoint.into(),
        workspace_id: primary.id.clone(),
        workspace_title: primary.title.clone(),
        workspaces,
        role: role.to_string(),
        created_at: iso_timestamp(now_ms)?,
        expires_at: iso_timestamp(now_ms + INVITATION_LIFETIME_MS)?,
        secret: secret.into(),
    })
}

pub fn invitation_url(origin: &str, invitation: &ScopedInvitation) -> Result<String, String> {
    let mut url = pair_url(origin)?;
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("v", "1");
    match invitation {
        ScopedInvitation::DeviceEnrollment(invitation) => {
            append_common(
                &mut serializer,
                &invitation.kind,
                &invitation.invitation_id,
                &invitation.issuer_person_id,
                &invitation.issuer_device_id,
                &invitation.issuer_public_key,
                &invitation.issuer_endpoint,
                &invitation.created_at,
                &invitation.expires_at,
                &invitation.secret,
            );
        }
        ScopedInvitation::WorkspaceJoin(invitation) => {
            append_common(
                &mut serializer,
                &invitation.kind,
                &invitation.invitation_id,
                &invitation.issuer_person_id,
                &invitation.issuer_device_id,
                &invitation.issuer_public_key,
                &invitation.issuer_endpoint,
                &invitation.created_at,
                &invitation.expires_at,
                &invitation.secret,
            );
            serializer
                .append_pair("workspaceId", &invitation.workspace_id)
                .append_pair("workspaceTitle", &invitation.workspace_title)
                .append_pair("role", &invitation.role);
            if !invitation.workspaces.is_empty() {
                serializer.append_pair(
                    "workspaceIds",
                    &invitation
                        .workspaces
                        .iter()
                        .map(|workspace| workspace.id.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                );
                serializer.append_pair(
                    "workspaceTitles",
                    &invitation
                        .workspaces
                        .iter()
                        .map(|workspace| {
                            utf8_percent_encode(&workspace.title, NON_ALPHANUMERIC).to_string()
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
        }
    }
    url.set_fragment(Some(&serializer.finish()));
    Ok(url.to_string())
}

pub fn parse_invitation(raw: &str, now_ms: i64) -> Result<ScopedInvitation, String> {
    let base = Url::parse("http://localhost").expect("static base URL");
    let url = Url::parse(raw.trim())
        .or_else(|_| base.join(raw.trim()))
        .map_err(|_| "Invalid pairing link".to_string())?;
    let parameters = parse_parameters(url.fragment().unwrap_or_default());
    let version = parameter(&parameters, "v");
    let secret = parameter(&parameters, "secret");
    if secret.is_empty() {
        return Err("This pairing link is invalid.".to_string());
    }
    if version == PAIRING_VERSION || !has_parameter(&parameters, "kind") {
        return Err(
            "This sync link was created by an older version of Match. Please create a new invitation."
                .to_string(),
        );
    }
    if version != "1" {
        return Err("Invalid pairing link".to_string());
    }

    let kind = parameter(&parameters, "kind");
    let invitation_id = parameter(&parameters, "invitationId");
    let issuer_person_id = parameter(&parameters, "issuerPersonId");
    let issuer_device_id = parameter(&parameters, "issuerDeviceId");
    let issuer_public_key = parameter(&parameters, "issuerPublicKey");
    let endpoint = parameter(&parameters, "endpoint");
    let created_at = parameter(&parameters, "createdAt");
    let expires_at = parameter(&parameters, "expiresAt");
    if invitation_id.is_empty() || endpoint.is_empty() {
        return Err("Invalid pairing link".to_string());
    }
    if !expires_at.is_empty() {
        if let Ok(expiry) = OffsetDateTime::parse(&expires_at, &Rfc3339) {
            if expiry.unix_timestamp_nanos() <= i128::from(now_ms) * 1_000_000 {
                return Err("This invitation has expired.".to_string());
            }
        }
    }

    match kind.as_str() {
        "device-enrollment" => {
            if ["workspaceId", "role", "workspaceTitle"]
                .iter()
                .any(|name| has_parameter(&parameters, name))
            {
                return Err(
                    "Invalid invitation: wrong-kind fields present on device-enrollment"
                        .to_string(),
                );
            }
            Ok(ScopedInvitation::DeviceEnrollment(
                DeviceEnrollmentInvitation {
                    version: INVITATION_VERSION,
                    kind,
                    invitation_id,
                    issuer_person_id,
                    issuer_device_id,
                    issuer_public_key,
                    issuer_endpoint: endpoint,
                    created_at,
                    expires_at,
                    secret,
                },
            ))
        }
        "workspace-join" => {
            let workspace_id = parameter(&parameters, "workspaceId");
            let workspace_title = default_workspace_title(parameter(&parameters, "workspaceTitle"));
            let role = parameter(&parameters, "role");
            if workspace_id.is_empty() || (role != "editor" && role != "visitor") {
                return Err(
                    "Invalid invitation: missing workspace or valid role on workspace-join"
                        .to_string(),
                );
            }
            let ids = parameter(&parameters, "workspaceIds");
            let titles = parameter(&parameters, "workspaceTitles");
            let decoded_titles = if titles.is_empty() {
                Vec::new()
            } else {
                titles
                    .split(',')
                    .map(|title| {
                        percent_decode_str(title.trim())
                            .decode_utf8()
                            .map(|value| value.into_owned())
                            .map_err(|_| "Invalid pairing link".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };
            let mut workspaces = if ids.is_empty() {
                Vec::new()
            } else {
                ids.split(',')
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .enumerate()
                    .map(|(index, id)| WorkspaceItem {
                        id: id.to_string(),
                        title: decoded_titles.get(index).cloned().unwrap_or_else(|| {
                            if id == workspace_id {
                                workspace_title.clone()
                            } else {
                                "Workspace".to_string()
                            }
                        }),
                    })
                    .collect()
            };
            if workspaces.is_empty() {
                workspaces.push(WorkspaceItem {
                    id: workspace_id,
                    title: workspace_title,
                });
            }
            Ok(ScopedInvitation::WorkspaceJoin(WorkspaceJoinInvitation {
                version: INVITATION_VERSION,
                kind,
                invitation_id,
                issuer_person_id,
                issuer_device_id,
                issuer_public_key,
                issuer_endpoint: endpoint,
                workspace_id: workspaces[0].id.clone(),
                workspace_title: workspaces[0].title.clone(),
                workspaces,
                role,
                created_at,
                expires_at,
                secret,
            }))
        }
        _ => Err("Invalid pairing link".to_string()),
    }
}

fn pair_url(origin: &str) -> Result<Url, String> {
    let mut url = Url::parse(origin).map_err(|_| "Invalid pairing link".to_string())?;
    url.set_path("/pair");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

#[allow(clippy::too_many_arguments)]
fn append_common(
    serializer: &mut form_urlencoded::Serializer<'_, String>,
    kind: &str,
    invitation_id: &str,
    issuer_person_id: &str,
    issuer_device_id: &str,
    issuer_public_key: &str,
    endpoint: &str,
    created_at: &str,
    expires_at: &str,
    secret: &str,
) {
    serializer
        .append_pair("kind", kind)
        .append_pair("invitationId", invitation_id)
        .append_pair("issuerPersonId", issuer_person_id)
        .append_pair("issuerDeviceId", issuer_device_id)
        .append_pair("issuerPublicKey", issuer_public_key)
        .append_pair("endpoint", endpoint)
        .append_pair("createdAt", created_at)
        .append_pair("expiresAt", expires_at)
        .append_pair("secret", secret);
}

fn parse_parameters(value: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(value.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn parameter(parameters: &[(String, String)], name: &str) -> String {
    parameters
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

fn has_parameter(parameters: &[(String, String)], name: &str) -> bool {
    parameters.iter().any(|(key, _)| key == name)
}

fn default_workspace_title(title: String) -> String {
    if title.is_empty() {
        "Workspace".to_string()
    } else {
        title
    }
}

fn iso_timestamp(timestamp_ms: i64) -> Result<String, String> {
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp_ms) * 1_000_000)
        .map_err(|_| "Invalid invitation timestamp".to_string())?;
    timestamp
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .map_err(|_| "Invalid invitation timestamp".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> InvitationIssuer {
        InvitationIssuer {
            person_id: "person_1".to_string(),
            device_id: "device_1".to_string(),
            public_key: "pubkey_1".to_string(),
        }
    }

    #[test]
    fn device_invitation_round_trips_and_expires() {
        let now = 1_700_000_000_000;
        let invitation = create_device_enrollment_invitation(
            "endpoint_test",
            "secret_123",
            &issuer(),
            "invitation-1",
            now,
        )
        .unwrap();
        assert_eq!(invitation.expires_at, "2023-11-14T22:23:20.000Z");
        let url = invitation_url(
            "https://match.test",
            &ScopedInvitation::DeviceEnrollment(invitation.clone()),
        )
        .unwrap();
        assert_eq!(
            parse_invitation(&url, now).unwrap(),
            ScopedInvitation::DeviceEnrollment(invitation)
        );
        assert_eq!(
            parse_invitation(&url, now + INVITATION_LIFETIME_MS).unwrap_err(),
            "This invitation has expired."
        );
    }

    #[test]
    fn workspace_invitation_round_trips_multiple_workspaces() {
        let now = 1_700_000_000_000;
        let invitation = create_workspace_join_invitation(
            "endpoint_test",
            "secret_456",
            &issuer(),
            "invitation-2",
            vec![
                WorkspaceItem {
                    id: "ws_job".to_string(),
                    title: "Job search".to_string(),
                },
                WorkspaceItem {
                    id: "ws_reading".to_string(),
                    title: "Reading list".to_string(),
                },
            ],
            "visitor",
            now,
        )
        .unwrap();
        let url = invitation_url(
            "https://match.test",
            &ScopedInvitation::WorkspaceJoin(invitation.clone()),
        )
        .unwrap();
        assert_eq!(
            url,
            "https://match.test/pair#v=1&kind=workspace-join&invitationId=invitation-2&issuerPersonId=person_1&issuerDeviceId=device_1&issuerPublicKey=pubkey_1&endpoint=endpoint_test&createdAt=2023-11-14T22%3A13%3A20.000Z&expiresAt=2023-11-14T22%3A23%3A20.000Z&secret=secret_456&workspaceId=ws_job&workspaceTitle=Job+search&role=visitor&workspaceIds=ws_job%2Cws_reading&workspaceTitles=Job%2520search%2CReading%2520list"
        );
        assert_eq!(
            parse_invitation(&url, now).unwrap(),
            ScopedInvitation::WorkspaceJoin(invitation)
        );
    }

    #[test]
    fn parser_rejects_legacy_and_wrong_kind_fields() {
        assert!(
            parse_invitation(
                "https://match.test/pair#v=0.0.1&endpoint=old&secret=secret",
                0
            )
            .unwrap_err()
            .contains("older version")
        );
        assert!(
            parse_invitation(
                "https://match.test/pair#v=1&kind=device-enrollment&invitationId=i&endpoint=e&secret=s&workspaceId=forbidden",
                0
            )
            .unwrap_err()
            .contains("wrong-kind")
        );
    }

    #[test]
    fn legacy_pairing_invitation_round_trips() {
        let invitation = PairingInvite {
            version: PAIRING_VERSION.to_string(),
            endpoint: "endpoint-a".to_string(),
            secret: "secret-a".to_string(),
        };
        let url = pairing_invite_url("https://match.test", &invitation).unwrap();
        assert_eq!(parse_pairing_invite(&url).unwrap(), invitation);
    }
}
