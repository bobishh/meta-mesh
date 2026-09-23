use serde::{Deserialize, Serialize};

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope, WorkspaceAuthority,
    WorkspaceDeviceRevocation, public_key_id, verify_device_certificate_chain,
    verify_signed_envelope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceRole {
    Owner,
    Editor,
    Visitor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceGrantPayload {
    pub kind: String,
    pub version: u8,
    pub grant_id: String,
    pub workspace_id: String,
    pub person_id: String,
    pub role: WorkspaceRole,
    // Absence is part of the signed legacy JSON. Do not materialize its
    // effective value before signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_epoch: Option<u64>,
}

impl WorkspaceGrantPayload {
    pub fn effective_access_epoch(&self) -> u64 { self.access_epoch.unwrap_or(1) }
}

pub type WorkspaceGrant = SignedEnvelope<WorkspaceGrantPayload>;

/// The signed proof a device attaches to a batch of Automerge workspace changes.
///
/// This deliberately contains no local-state assertion such as a claimed role. The
/// receiver derives the role from `WorkspaceWriteAuthorizationContext` after it
/// has verified this signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceChangeAuthorizationPayload {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub hashes: Vec<String>,
    pub person_id: String,
    pub device_id: String,
}

pub type WorkspaceChangeAuthorization = SignedEnvelope<WorkspaceChangeAuthorizationPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingWorkspaceChangeAuthorization {
    pub signed: WorkspaceChangeAuthorization,
    pub public_key: String,
    pub certificates: Vec<DeviceCertificate>,
    #[serde(default)]
    pub grant: Option<WorkspaceGrant>,
}

/// A device revocation and the identity that signed it. The evidence is checked
/// while constructing the authorization decision, rather than trusting a host
/// supplied `revoked` or `verified` flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDeviceRevocationEvidence {
    pub record: WorkspaceDeviceRevocation,
    pub signer: WorkspaceAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDepartureEvidence {
    pub record: crate::authority::WorkspaceDeparture,
    pub authority: WorkspaceAuthority,
}

/// Raw, explicit authority evidence for a document. `admit_workspace_change_authorization`
/// verifies this snapshot before it uses it; callers cannot supply a claimed
/// current owner or historical hash set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceWriteAuthorizationSnapshot {
    pub workspace_id: String,
    pub genesis_owner: WorkspaceAuthority,
    pub genesis_epoch: u64,
    pub expected_current_owner: WorkspaceAuthority,
    pub document: Vec<u8>,
    #[serde(default)]
    pub ownership_transfers: Vec<crate::WorkspaceOwnershipTransfer>,
    #[serde(default)]
    pub succession_claims: Vec<crate::WorkspaceSuccessionClaim>,
    #[serde(default)]
    pub revocations: Vec<crate::WorkspaceRevocation>,
    #[serde(default)]
    pub device_revocations: Vec<WorkspaceDeviceRevocationEvidence>,
    #[serde(default)]
    pub departures: Vec<WorkspaceDepartureEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedWorkspaceChange {
    pub hash: String,
    pub role: WorkspaceRole,
}

pub const MAX_WORKSPACE_CHANGE_AUTHORIZATION_HASHES: usize = 256;
pub const MAX_WORKSPACE_DEVICE_REVOCATIONS: usize = 512;

/// Verifies a signed workspace-change authorization against explicit authority
/// state. The returned hashes are restricted to `needed_hashes`; callers must
/// still validate the actual document changes separately.
pub fn admit_workspace_change_authorization(
    incoming: &IncomingWorkspaceChangeAuthorization,
    snapshot: &WorkspaceWriteAuthorizationSnapshot,
    needed_hashes: &[String],
    now_ms: i128,
) -> Result<Vec<AuthorizedWorkspaceChange>, String> {
    let context = ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(snapshot, now_ms)?;
    admit_with_context(incoming, &context, needed_hashes)
}

/// Validates one authority snapshot for the entire batch. No partial result is
/// returned when any proof fails, including on an empty batch with invalid context.
pub fn admit_workspace_change_authorizations(
    incoming: &[IncomingWorkspaceChangeAuthorization],
    snapshot: &WorkspaceWriteAuthorizationSnapshot,
    needed_hashes: &[String],
    now_ms: i128,
) -> Result<Vec<AuthorizedWorkspaceChange>, String> {
    if incoming.len() > 20_000 {
        return Err("Too many workspace change authorizations".to_string());
    }
    let context = ValidatedWorkspaceWriteAuthorizationContext::from_snapshot(snapshot, now_ms)?;
    let mut admitted = Vec::new();
    for record in incoming {
        admitted.extend(admit_with_context(record, &context, needed_hashes)?);
    }
    Ok(admitted)
}

fn admit_with_context(
    incoming: &IncomingWorkspaceChangeAuthorization,
    context: &ValidatedWorkspaceWriteAuthorizationContext,
    needed_hashes: &[String],
) -> Result<Vec<AuthorizedWorkspaceChange>, String> {
    let payload = &incoming.signed.payload;
    if payload.kind != "workspace-changes"
        || payload.version != 1
        || payload.workspace_id != context.workspace_id
        || payload.hashes.is_empty()
        || payload.hashes.len() > MAX_WORKSPACE_CHANGE_AUTHORIZATION_HASHES
        || payload.hashes.iter().any(|hash| hash.is_empty())
    {
        return Err("Invalid workspace change authorization".to_string());
    }
    let needed = needed_hashes.iter().collect::<std::collections::HashSet<_>>();
    if !payload.hashes.iter().any(|hash| needed.contains(hash)) {
        return Err("Workspace change authorization does not cover an incoming change".to_string());
    }
    let identity = PublicIdentity {
        person_id: payload.person_id.clone(),
        public_key: incoming.public_key.clone(),
        display_name: String::new(),
    };
    if public_key_id(&identity.public_key)? != identity.person_id {
        return Err("Invalid workspace change identity".to_string());
    }
    verify_device_signed_envelope(
        &identity,
        &payload.device_id,
        &incoming.certificates,
        &incoming.signed,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    let (role, grant_epoch) = context.role_for(&payload.person_id, &payload.device_id, incoming.grant.as_ref())?;
    Ok(payload.hashes.iter().filter(|hash| needed.contains(hash)).filter_map(|hash| {
        if !context.revocation_allows(&payload.person_id, grant_epoch, hash)
            || !context.device_revocation_allows(&payload.person_id, &payload.device_id, hash)
            || (role == WorkspaceRole::Owner
            && payload.person_id != context.current_owner.person_id
            && !context.historical_hashes.get(&payload.person_id).is_some_and(|hashes| hashes.contains(hash)))
        {
            None
        } else {
            Some(AuthorizedWorkspaceChange { hash: hash.clone(), role })
        }
    }).collect())
}

pub(crate) struct ValidatedWorkspaceWriteAuthorizationContext {
    pub(crate) workspace_id: String,
    pub(crate) current_owner: WorkspaceAuthority,
    pub(crate) historical_owners: Vec<WorkspaceAuthority>,
    pub(crate) historical_hashes: std::collections::HashMap<String, std::collections::HashSet<String>>,
    revoked_devices: std::collections::HashMap<(String, String), Vec<std::collections::HashSet<String>>>,
    revocation_boundaries: std::collections::HashMap<String, Vec<RevocationBoundary>>,
    departure_boundaries: std::collections::HashMap<String, Vec<RevocationBoundary>>,
}

struct RevocationBoundary {
    epoch: u64,
    hashes: std::collections::HashSet<String>,
}

impl ValidatedWorkspaceWriteAuthorizationContext {
    pub(crate) fn from_snapshot(raw: &WorkspaceWriteAuthorizationSnapshot, now_ms: i128) -> Result<Self, String> {
        if raw.workspace_id.is_empty() || raw.document.is_empty()
            || raw.ownership_transfers.len() > 32 || raw.succession_claims.len() > 32
            || raw.revocations.len() > 512 || raw.departures.len() > 512
            || raw.device_revocations.len() > MAX_WORKSPACE_DEVICE_REVOCATIONS
        {
            return Err("Invalid workspace write authority context".to_string());
        }
        validate_authority(&raw.genesis_owner)?;
        validate_authority(&raw.expected_current_owner)?;
        let (current_owner, historical_owners, _) = verified_ownership_chain(raw, now_ms, &std::collections::HashSet::new(), true)?;
        if current_owner.person_id != raw.expected_current_owner.person_id
            || current_owner.public_key != raw.expected_current_owner.public_key
        {
            return Err("Workspace ownership chain does not match the expected owner".to_string());
        }
        let mut authorities = historical_owners.clone();
        authorities.push(current_owner.clone());
        let revocation_boundaries = verified_revocation_boundaries(raw, &authorities, now_ms)?;
        let revoked_people = revocation_boundaries.keys().cloned().collect::<std::collections::HashSet<_>>();
        let (current_owner, historical_owners, historical_hashes) = verified_ownership_chain(raw, now_ms, &revoked_people, true)?;
        let mut revoked_devices = std::collections::HashMap::<(String, String), Vec<std::collections::HashSet<String>>>::new();
        let by_hash = document_hashes(&raw.document)?;
        for evidence in &raw.device_revocations {
            validate_authority(&evidence.signer)?;
            let signed_by_owner = crate::authority::verify_workspace_device_revocation(&evidence.record, &raw.workspace_id,
                &current_owner.person_id, &current_owner, now_ms).is_ok();
            let signed_by_subject = !signed_by_owner && crate::authority::verify_workspace_device_revocation(&evidence.record,
                &raw.workspace_id, &current_owner.person_id, &evidence.signer, now_ms).is_ok();
            if !signed_by_owner && !signed_by_subject {
                return Err("Invalid workspace device revocation".to_string());
            }
            let payload = &evidence.record.payload;
            let hashes = ancestry(&payload.workspace_heads, &by_hash)?;
            let key = (payload.person_id.clone(), payload.device_id.clone());
            revoked_devices.entry(key).or_default().push(hashes);
        }
        let departure_boundaries = verified_departure_boundaries(raw, now_ms)?;
        Ok(Self { workspace_id: raw.workspace_id.clone(), current_owner,
            historical_owners, historical_hashes, revoked_devices, revocation_boundaries, departure_boundaries })
    }

    fn role_for(&self, person_id: &str, _device_id: &str, grant: Option<&WorkspaceGrant>) -> Result<(WorkspaceRole, Option<u64>), String> {
        if person_id == self.current_owner.person_id {
            return Ok((WorkspaceRole::Owner, None));
        }
        let verified_grant = self.current_owner_and_history().into_iter().find_map(|authority| {
            let grant = grant?;
            let role = verify_workspace_grant(grant, &self.workspace_id, person_id,
                &PublicIdentity { person_id: authority.person_id, public_key: authority.public_key, display_name: String::new() },
                &authority.certificates).ok()?;
            Some((role, grant.payload.effective_access_epoch()))
        });
        if let Some((WorkspaceRole::Editor, epoch)) = verified_grant {
            Ok((WorkspaceRole::Editor, Some(epoch)))
        } else if self.historical_hashes.contains_key(person_id) {
            Ok((WorkspaceRole::Owner, None))
        } else {
            Err("Visitors cannot write workspace changes".to_string())
        }
    }

    fn current_owner_and_history(&self) -> Vec<WorkspaceAuthority> {
        let mut authorities = Vec::with_capacity(self.historical_owners.len() + 1);
        authorities.push(self.current_owner.clone());
        authorities.extend(self.historical_owners.clone());
        authorities
    }

    fn revocation_allows(&self, person_id: &str, grant_epoch: Option<u64>, hash: &str) -> bool {
        self.boundaries_allow(self.revocation_boundaries.get(person_id), grant_epoch, hash)
            && self.boundaries_allow(self.departure_boundaries.get(person_id), grant_epoch, hash)
    }

    fn boundaries_allow(&self, boundaries: Option<&Vec<RevocationBoundary>>, grant_epoch: Option<u64>, hash: &str) -> bool {
        boundaries.is_none_or(|boundaries| boundaries.iter().all(|boundary|
            grant_epoch.is_some_and(|epoch| epoch > boundary.epoch) || boundary.hashes.contains(hash)))
    }

    fn device_revocation_allows(&self, person_id: &str, device_id: &str, hash: &str) -> bool {
        self.revoked_devices.get(&(person_id.to_string(), device_id.to_string()))
            .is_none_or(|boundaries| boundaries.iter().all(|hashes| hashes.contains(hash)))
    }

    pub(crate) fn device_was_revoked(&self, person_id: &str, device_id: &str) -> bool {
        self.revoked_devices.contains_key(&(person_id.to_string(), device_id.to_string()))
    }
}

pub(crate) fn validate_authority(authority: &WorkspaceAuthority) -> Result<(), String> {
    if authority.person_id.is_empty() || authority.public_key.is_empty()
        || public_key_id(&authority.public_key)? != authority.person_id
    {
        return Err("Invalid workspace authority".to_string());
    }
    Ok(())
}

#[derive(Clone)]
enum OwnershipTransition {
    Transfer(crate::WorkspaceOwnershipTransfer),
    Succession(crate::WorkspaceSuccessionClaim),
}

impl OwnershipTransition {
    fn from_owner(&self) -> &str {
        match self { Self::Transfer(record) => &record.payload.from_owner_person_id, Self::Succession(record) => &record.payload.from_owner_person_id }
    }
    fn epoch(&self) -> u64 {
        match self { Self::Transfer(record) => record.payload.epoch, Self::Succession(record) => record.payload.epoch }
    }
    fn heads(&self) -> &[String] {
        match self { Self::Transfer(record) => &record.payload.workspace_heads, Self::Succession(record) => &record.payload.workspace_heads }
    }
    fn next_authority(&self) -> WorkspaceAuthority {
        match self {
            Self::Transfer(record) => WorkspaceAuthority { person_id: record.payload.to_owner_person_id.clone(), public_key: record.payload.to_owner_public_key.clone(), certificates: record.payload.to_owner_certificates.clone() },
            Self::Succession(record) => WorkspaceAuthority { person_id: record.payload.to_owner_person_id.clone(), public_key: record.payload.to_owner_public_key.clone(), certificates: record.payload.to_owner_certificates.clone() },
        }
    }
}

pub(crate) fn verified_ownership_chain(raw: &WorkspaceWriteAuthorizationSnapshot, now_ms: i128,
    revoked_people: &std::collections::HashSet<String>, require_document_heads: bool)
    -> Result<(WorkspaceAuthority, Vec<WorkspaceAuthority>, std::collections::HashMap<String, std::collections::HashSet<String>>), String> {
    let by_hash = if require_document_heads { document_hashes(&raw.document)? } else { std::collections::HashMap::new() };
    let mut transitions = raw.ownership_transfers.iter().cloned().map(OwnershipTransition::Transfer)
        .chain(raw.succession_claims.iter().cloned().map(OwnershipTransition::Succession)).collect::<Vec<_>>();
    let mut current = raw.genesis_owner.clone();
    let mut epoch = raw.genesis_epoch;
    let mut history = Vec::new();
    let mut historical_hashes = std::collections::HashMap::new();
    while !transitions.is_empty() {
        let next_epoch = transitions.iter().filter(|record| record.from_owner() == current.person_id && record.epoch() > epoch)
            .map(OwnershipTransition::epoch).min().ok_or_else(|| "Missing workspace ownership transition".to_string())?;
        let candidates = transitions.iter().enumerate().filter(|(_, record)| record.from_owner() == current.person_id && record.epoch() == next_epoch)
            .map(|(index, _)| index).collect::<Vec<_>>();
        if candidates.len() > 1 { return Err("Conflicting workspace ownership transitions".to_string()); }
        let Some(index) = candidates.first().copied() else {
            return Err("Missing workspace ownership transition".to_string());
        };
        let transition = transitions.remove(index);
        match &transition {
            OwnershipTransition::Transfer(record) => crate::authority::verify_workspace_ownership_transfer(record,
                &raw.workspace_id, &current, epoch, now_ms)?,
            OwnershipTransition::Succession(record) => crate::authority::verify_workspace_succession_claim(record,
                &raw.workspace_id, &current, epoch, revoked_people, now_ms)?,
        }
        let allowed = if require_document_heads { ancestry(transition.heads(), &by_hash)? } else { std::collections::HashSet::new() };
        historical_hashes.entry(current.person_id.clone()).or_insert_with(std::collections::HashSet::new).extend(allowed);
        history.push(current);
        current = transition.next_authority();
        epoch = next_epoch;
    }
    Ok((current, history, historical_hashes))
}

fn ancestry(heads: &[String], by_hash: &std::collections::HashMap<String, Vec<String>>) -> Result<std::collections::HashSet<String>, String> {
    let mut allowed = std::collections::HashSet::new();
    let mut pending = heads.to_vec();
    while let Some(hash) = pending.pop() {
        if !allowed.insert(hash.clone()) { continue; }
        let dependencies = by_hash.get(&hash).ok_or_else(|| "Workspace ownership boundary is missing from the document".to_string())?;
        pending.extend(dependencies.iter().cloned());
    }
    Ok(allowed)
}

fn document_hashes(document_bytes: &[u8]) -> Result<std::collections::HashMap<String, Vec<String>>, String> {
    let mut document = automerge::AutoCommit::load(document_bytes)
        .map_err(|_| "Invalid workspace authority document".to_string())?;
    Ok(document.get_changes(&[]).iter().map(|change| (change.hash().to_string(),
        change.deps().iter().map(ToString::to_string).collect())).collect())
}

fn verified_revocation_boundaries(raw: &WorkspaceWriteAuthorizationSnapshot, authorities: &[WorkspaceAuthority], now_ms: i128)
    -> Result<std::collections::HashMap<String, Vec<RevocationBoundary>>, String> {
    let by_hash = document_hashes(&raw.document)?;
    let mut boundaries = std::collections::HashMap::<String, Vec<RevocationBoundary>>::new();
    for record in &raw.revocations {
        let authority = authorities.iter().find(|authority| authority.person_id == record.payload.owner_person_id)
            .ok_or_else(|| "Workspace revocation has an unknown owner".to_string())?;
        crate::authority::verify_workspace_revocation(record, &raw.workspace_id, authority, now_ms)?;
        let hashes = ancestry(&record.payload.workspace_heads, &by_hash)?;
        boundaries.entry(record.payload.person_id.clone()).or_default()
            .push(RevocationBoundary { epoch: record.payload.epoch, hashes });
    }
    Ok(boundaries)
}

fn verified_departure_boundaries(raw: &WorkspaceWriteAuthorizationSnapshot, now_ms: i128)
    -> Result<std::collections::HashMap<String, Vec<RevocationBoundary>>, String> {
    let by_hash = document_hashes(&raw.document)?;
    let mut boundaries = std::collections::HashMap::<String, Vec<RevocationBoundary>>::new();
    for evidence in &raw.departures {
        validate_authority(&evidence.authority)?;
        crate::authority::verify_workspace_departure(&evidence.record, &raw.workspace_id, &evidence.authority, now_ms)?;
        let hashes = ancestry(&evidence.record.payload.workspace_heads, &by_hash)?;
        let person_id = &evidence.record.payload.person_id;
        let epoch = evidence.record.payload.access_epoch;
        boundaries.entry(person_id.clone()).or_default().push(RevocationBoundary { epoch, hashes });
    }
    Ok(boundaries)
}

pub fn verify_device_signed_envelope<T: Serialize>(
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &[DeviceCertificate],
    envelope: &SignedEnvelope<T>,
    domain: &str,
) -> Result<(), String> {
    if envelope.signer_key_id != device_id {
        return Err("Signed envelope device mismatch".to_string());
    }
    let device_public_key = verify_device_certificate_chain(
        identity,
        device_id,
        certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    if !verify_signed_envelope(envelope, &device_public_key, domain)? {
        return Err("Invalid signed envelope signature".to_string());
    }
    Ok(())
}

pub fn verify_workspace_grant(
    grant: &WorkspaceGrant,
    workspace_id: &str,
    member_person_id: &str,
    owner: &PublicIdentity,
    owner_certificates: &[DeviceCertificate],
) -> Result<WorkspaceRole, String> {
    let payload = &grant.payload;
    if payload.kind != "workspace-grant"
        || payload.version != 1
        || payload.workspace_id != workspace_id
        || payload.person_id != member_person_id
        || payload.grant_id.is_empty()
        || payload.effective_access_epoch() == 0
    {
        return Err("Invalid workspace grant".to_string());
    }
    if owner.person_id != public_key_id(&owner.public_key)? {
        return Err("Invalid workspace owner".to_string());
    }
    // Legacy invitations used the identity root key while labeling the envelope
    // with the active device id. Root verification stays first for wire parity.
    if verify_signed_envelope(grant, &owner.public_key, DEFAULT_SIGNATURE_DOMAIN)? {
        return Ok(payload.role);
    }
    let signer_key = verify_device_certificate_chain(
        owner,
        &grant.signer_key_id,
        owner_certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .map_err(|_| "Invalid workspace grant signature".to_string())?;
    if verify_signed_envelope(grant, &signer_key, DEFAULT_SIGNATURE_DOMAIN)? {
        Ok(payload.role)
    } else {
        Err("Invalid workspace grant signature".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCertificatePayload, certificate_hash, public_key_from_seed, sign_device_certificate,
        sign_json_envelope,
    };

    fn signed_grant(
        seed: &[u8; 32],
        signer_key_id: &str,
        payload: &WorkspaceGrantPayload,
    ) -> WorkspaceGrant {
        let signed = sign_json_envelope(
            seed,
            serde_json::to_value(payload).unwrap(),
            signer_key_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        WorkspaceGrant {
            payload: payload.clone(),
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        }
    }

    fn authority(seed: [u8; 32], device_seed: [u8; 32]) -> (WorkspaceAuthority, [u8; 32], String, Vec<DeviceCertificate>) {
        let public_key = public_key_from_seed(&seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(&seed, DeviceCertificatePayload {
            kind: "device-certificate".into(), version: 1, person_id: person_id.clone(),
            device_id: device_id.clone(), device_public_key, issuer_certificate_hash: None,
            can_enroll_devices: true,
        }, &person_id, DEFAULT_SIGNATURE_DOMAIN).unwrap();
        (WorkspaceAuthority { person_id, public_key, certificates: vec![certificate.clone()] }, device_seed, device_id, vec![certificate])
    }

    fn change_authorization(authority: &WorkspaceAuthority, device_seed: &[u8; 32], device_id: &str,
        certificates: Vec<DeviceCertificate>, hashes: Vec<&str>) -> IncomingWorkspaceChangeAuthorization {
        let payload = WorkspaceChangeAuthorizationPayload {
            kind: "workspace-changes".into(), version: 1, workspace_id: "workspace".into(),
            hashes: hashes.into_iter().map(str::to_owned).collect(), person_id: authority.person_id.clone(), device_id: device_id.into(),
        };
        let signed = sign_json_envelope(device_seed, serde_json::to_value(&payload).unwrap(), device_id,
            DEFAULT_SIGNATURE_DOMAIN).unwrap();
        IncomingWorkspaceChangeAuthorization {
            signed: WorkspaceChangeAuthorization { payload, signer_key_id: signed.signer_key_id, signature: signed.signature },
            public_key: authority.public_key.clone(), certificates, grant: None,
        }
    }

    fn snapshot(owner: WorkspaceAuthority) -> WorkspaceWriteAuthorizationSnapshot {
        WorkspaceWriteAuthorizationSnapshot { workspace_id: "workspace".into(), genesis_owner: owner.clone(), genesis_epoch: 1, expected_current_owner: owner,
            document: automerge::AutoCommit::new().save(), ownership_transfers: vec![], succession_claims: vec![],
            revocations: vec![], device_revocations: vec![], departures: vec![] }
    }

    fn transfer(owner: &WorkspaceAuthority, owner_seed: &[u8; 32], owner_device_seed: &[u8; 32], owner_device_id: &str,
        next: &WorkspaceAuthority, heads: Vec<String>, epoch: u64) -> crate::WorkspaceOwnershipTransfer {
        let to_owner = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1, grant_id: "next-owner".into(),
            workspace_id: "workspace".into(), person_id: next.person_id.clone(), role: WorkspaceRole::Owner, access_epoch: Some(2) };
        let former_owner = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1, grant_id: "former-owner".into(),
            workspace_id: "workspace".into(), person_id: owner.person_id.clone(), role: WorkspaceRole::Editor, access_epoch: Some(2) };
        let to_owner_grant = signed_grant(owner_seed, &owner.person_id, &to_owner);
        let former_owner_grant = signed_grant(owner_seed, &owner.person_id, &former_owner);
        assert_eq!(verify_workspace_grant(&to_owner_grant, "workspace", &next.person_id, &PublicIdentity { person_id: owner.person_id.clone(), public_key: owner.public_key.clone(), display_name: String::new() }, &owner.certificates).unwrap(), WorkspaceRole::Owner);
        assert_eq!(verify_workspace_grant(&former_owner_grant, "workspace", &owner.person_id, &PublicIdentity { person_id: owner.person_id.clone(), public_key: owner.public_key.clone(), display_name: String::new() }, &owner.certificates).unwrap(), WorkspaceRole::Editor);
        let payload = crate::WorkspaceOwnershipTransferPayload { kind: "workspace-ownership-transfer".into(), version: 1,
            workspace_id: "workspace".into(), from_owner_person_id: owner.person_id.clone(), to_owner_person_id: next.person_id.clone(),
            to_owner_public_key: next.public_key.clone(), to_owner_certificates: next.certificates.clone(),
            to_owner_grant, former_owner_grant,
            workspace_heads: heads, epoch, transferred_at: "1970-01-01T00:00:00.000Z".into() };
        let signed = sign_json_envelope(owner_device_seed, serde_json::to_value(&payload).unwrap(), owner_device_id, DEFAULT_SIGNATURE_DOMAIN).unwrap();
        crate::WorkspaceOwnershipTransfer { payload, signer_key_id: signed.signer_key_id, signature: signed.signature }
    }

    fn revocation(owner: &WorkspaceAuthority, owner_seed: &[u8; 32], person_id: &str,
        heads: Vec<String>, epoch: u64) -> crate::WorkspaceRevocation {
        let payload = crate::WorkspaceRevocationPayload { kind: "workspace-revocation".into(), version: 1,
            workspace_id: "workspace".into(), owner_person_id: owner.person_id.clone(), person_id: person_id.into(),
            epoch, workspace_heads: heads, revoked_at: "1970-01-01T00:00:00.000Z".into() };
        let signed = sign_json_envelope(owner_seed, serde_json::to_value(&payload).unwrap(), &owner.person_id,
            DEFAULT_SIGNATURE_DOMAIN).unwrap();
        crate::WorkspaceRevocation { payload, signer_key_id: signed.signer_key_id, signature: signed.signature }
    }

    fn device_revocation(owner: &WorkspaceAuthority, owner_device_seed: &[u8; 32], owner_device_id: &str,
        person_id: &str, device_id: &str, heads: Vec<String>) -> WorkspaceDeviceRevocationEvidence {
        let payload = crate::WorkspaceDeviceRevocationPayload { kind: "workspace-device-revocation".into(), version: 1,
            workspace_id: "workspace".into(), person_id: person_id.into(), device_id: device_id.into(),
            workspace_heads: heads, revoked_at: "1970-01-01T00:00:00.000Z".into() };
        let signed = sign_json_envelope(owner_device_seed, serde_json::to_value(&payload).unwrap(), owner_device_id,
            DEFAULT_SIGNATURE_DOMAIN).unwrap();
        WorkspaceDeviceRevocationEvidence { record: WorkspaceDeviceRevocation { payload,
            signer_key_id: signed.signer_key_id, signature: signed.signature }, signer: owner.clone() }
    }

    fn departure(person: &WorkspaceAuthority, device_seed: &[u8; 32], device_id: &str,
        heads: Vec<String>, epoch: u64) -> WorkspaceDepartureEvidence {
        let payload = crate::authority::WorkspaceDeparturePayload { kind: "workspace-departure".into(), version: 1,
            workspace_id: "workspace".into(), person_id: person.person_id.clone(), access_epoch: epoch,
            workspace_heads: heads, left_at: "1970-01-01T00:00:00.000Z".into() };
        let signed = sign_json_envelope(device_seed, serde_json::to_value(&payload).unwrap(), device_id,
            DEFAULT_SIGNATURE_DOMAIN).unwrap();
        WorkspaceDepartureEvidence { record: crate::authority::WorkspaceDeparture { payload,
            signer_key_id: signed.signer_key_id, signature: signed.signature }, authority: person.clone() }
    }

    #[test]
    fn batch_admission_rejects_everything_when_one_signature_is_invalid() {
        let (owner, seed, device, certs) = authority([1; 32], [2; 32]);
        let first = change_authorization(&owner, &seed, &device, certs.clone(), vec!["first"]);
        let mut second = change_authorization(&owner, &seed, &device, certs, vec!["second"]);
        let context = snapshot(owner);
        let needed = vec!["first".into(), "second".into()];
        assert_eq!(admit_workspace_change_authorizations(&[first.clone(), second.clone()], &context, &needed, 0).unwrap().len(), 2);
        second.signed.payload.hashes = vec!["first".into()];
        assert!(admit_workspace_change_authorizations(&[first, second], &context, &needed, 0).is_err());
        let mut invalid_context = context;
        invalid_context.workspace_id.clear();
        assert!(admit_workspace_change_authorizations(&[], &invalid_context, &[], 0).is_err());
    }

    #[test]
    fn admits_a_current_owner_change_authorization() {
        let (owner, device_seed, device_id, certificates) = authority([1; 32], [2; 32]);
        let incoming = change_authorization(&owner, &device_seed, &device_id, certificates, vec!["current"]);
        assert_eq!(admit_workspace_change_authorization(&incoming, &snapshot(owner), &["current".into()], 0).unwrap(),
            vec![AuthorizedWorkspaceChange { hash: "current".into(), role: WorkspaceRole::Owner }]);
    }

    #[test]
    fn admits_an_editor_with_a_current_owner_grant() {
        let (owner, _, _, _) = authority([3; 32], [4; 32]);
        let (editor, device_seed, device_id, certificates) = authority([5; 32], [6; 32]);
        let grant_payload = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1, grant_id: "editor".into(),
            workspace_id: "workspace".into(), person_id: editor.person_id.clone(), role: WorkspaceRole::Editor, access_epoch: Some(1) };
        let mut incoming = change_authorization(&editor, &device_seed, &device_id, certificates, vec!["editor-change"]);
        incoming.grant = Some(signed_grant(&[3; 32], &owner.person_id, &grant_payload));
        assert_eq!(admit_workspace_change_authorization(&incoming, &snapshot(owner), &["editor-change".into()], 0).unwrap()[0].role,
            WorkspaceRole::Editor);
    }

    #[test]
    fn revocation_boundary_keeps_old_history_denies_new_hashes_and_allows_newer_grant() {
        use automerge::transaction::Transactable;
        let (owner, _, _, _) = authority([31; 32], [32; 32]);
        let (editor, device_seed, device_id, certificates) = authority([33; 32], [34; 32]);
        let mut document = automerge::AutoCommit::new();
        document.put(automerge::ROOT, "before", "value").unwrap();
        document.commit();
        let before = document.get_heads()[0].to_string();
        let heads = document.get_heads().iter().map(ToString::to_string).collect();
        document.put(automerge::ROOT, "after", "value").unwrap();
        document.commit();
        let after = document.get_heads()[0].to_string();

        let make_incoming = |access_epoch| {
            let grant_payload = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1,
                grant_id: format!("editor-{access_epoch}"), workspace_id: "workspace".into(),
                person_id: editor.person_id.clone(), role: WorkspaceRole::Editor, access_epoch: Some(access_epoch) };
            let mut incoming = change_authorization(&editor, &device_seed, &device_id, certificates.clone(),
                vec![&before, &after]);
            incoming.grant = Some(signed_grant(&[31; 32], &owner.person_id, &grant_payload));
            incoming
        };
        let mut context = snapshot(owner.clone());
        context.document = document.save();
        context.revocations.push(revocation(&owner, &[31; 32], &editor.person_id, heads, 2));

        let stale = admit_workspace_change_authorization(&make_incoming(1), &context,
            &[before.clone(), after.clone()], 0).unwrap();
        assert_eq!(stale, vec![AuthorizedWorkspaceChange { hash: before.clone(), role: WorkspaceRole::Editor }]);

        let renewed = admit_workspace_change_authorization(&make_incoming(3), &context,
            &[before.clone(), after.clone()], 0).unwrap();
        assert_eq!(renewed, vec![
            AuthorizedWorkspaceChange { hash: before.clone(), role: WorkspaceRole::Editor },
            AuthorizedWorkspaceChange { hash: after.clone(), role: WorkspaceRole::Editor },
        ]);

        let mut forged = make_incoming(99);
        forged.grant = Some(signed_grant(&[99; 32], &owner.person_id, &forged.grant.unwrap().payload));
        assert!(admit_workspace_change_authorization(&forged, &context, &[after], 0).is_err());
    }

    #[test]
    fn departure_boundary_preserves_old_history_and_denies_new_changes() {
        use automerge::transaction::Transactable;
        let (owner, _, _, _) = authority([43; 32], [44; 32]);
        let (editor, device_seed, device_id, certificates) = authority([45; 32], [46; 32]);
        let mut document = automerge::AutoCommit::new();
        document.put(automerge::ROOT, "before", "value").unwrap();
        document.commit();
        let before = document.get_heads()[0].to_string();
        let heads = document.get_heads().iter().map(ToString::to_string).collect();
        document.put(automerge::ROOT, "after", "value").unwrap();
        document.commit();
        let after = document.get_heads()[0].to_string();
        let grant_payload = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1, grant_id: "editor".into(),
            workspace_id: "workspace".into(), person_id: editor.person_id.clone(), role: WorkspaceRole::Editor, access_epoch: Some(1) };
        let mut incoming = change_authorization(&editor, &device_seed, &device_id, certificates, vec![&before, &after]);
        incoming.grant = Some(signed_grant(&[43; 32], &owner.person_id, &grant_payload));
        let mut context = snapshot(owner);
        context.document = document.save();
        context.departures.push(departure(&editor, &device_seed, &device_id, heads, 1));
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &[before.clone(), after], 0).unwrap(),
            vec![AuthorizedWorkspaceChange { hash: before, role: WorkspaceRole::Editor }]);
    }

    #[test]
    fn device_revocation_preserves_boundary_history_and_denies_later_device_changes() {
        use automerge::transaction::Transactable;
        let (owner, owner_device_seed, owner_device_id, _) = authority([47; 32], [48; 32]);
        let (editor, editor_device_seed, editor_device_id, certificates) = authority([49; 32], [50; 32]);
        let mut document = automerge::AutoCommit::new();
        document.put(automerge::ROOT, "before", "value").unwrap();
        document.commit();
        let before = document.get_heads()[0].to_string();
        let heads = document.get_heads().iter().map(ToString::to_string).collect();
        document.put(automerge::ROOT, "after", "value").unwrap();
        document.commit();
        let after = document.get_heads()[0].to_string();
        let grant_payload = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1, grant_id: "editor".into(),
            workspace_id: "workspace".into(), person_id: editor.person_id.clone(), role: WorkspaceRole::Editor, access_epoch: Some(1) };
        let mut incoming = change_authorization(&editor, &editor_device_seed, &editor_device_id, certificates, vec![&before, &after]);
        incoming.grant = Some(signed_grant(&[47; 32], &owner.person_id, &grant_payload));
        let mut context = snapshot(owner.clone());
        context.document = document.save();
        context.device_revocations.push(device_revocation(&owner, &owner_device_seed, &owner_device_id,
            &editor.person_id, &editor_device_id, heads));
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &[before.clone(), after], 0).unwrap(),
            vec![AuthorizedWorkspaceChange { hash: before, role: WorkspaceRole::Editor }]);
    }

    #[test]
    fn rejects_revocation_boundary_missing_from_document() {
        use automerge::transaction::Transactable;
        let (owner, _, _, _) = authority([35; 32], [36; 32]);
        let (editor, device_seed, device_id, certificates) = authority([37; 32], [38; 32]);
        let mut document = automerge::AutoCommit::new();
        document.put(automerge::ROOT, "before", "value").unwrap();
        document.commit();
        let hash = document.get_heads()[0].to_string();
        let grant_payload = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1,
            grant_id: "editor".into(), workspace_id: "workspace".into(), person_id: editor.person_id.clone(),
            role: WorkspaceRole::Editor, access_epoch: Some(1) };
        let mut incoming = change_authorization(&editor, &device_seed, &device_id, certificates, vec![&hash]);
        incoming.grant = Some(signed_grant(&[35; 32], &owner.person_id, &grant_payload));
        let mut context = snapshot(owner.clone());
        context.document = document.save();
        context.revocations.push(revocation(&owner, &[35; 32], &editor.person_id, vec!["missing-head".into()], 2));
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &[hash], 0).unwrap_err(),
            "Workspace ownership boundary is missing from the document");
    }

    #[test]
    fn rejects_a_visitor_even_with_a_valid_visitor_grant() {
        let (owner, _, _, _) = authority([7; 32], [8; 32]);
        let (visitor, device_seed, device_id, certificates) = authority([9; 32], [10; 32]);
        let grant_payload = WorkspaceGrantPayload { kind: "workspace-grant".into(), version: 1, grant_id: "visitor".into(),
            workspace_id: "workspace".into(), person_id: visitor.person_id.clone(), role: WorkspaceRole::Visitor, access_epoch: Some(1) };
        let mut incoming = change_authorization(&visitor, &device_seed, &device_id, certificates, vec!["visitor-change"]);
        incoming.grant = Some(signed_grant(&[7; 32], &owner.person_id, &grant_payload));
        assert_eq!(admit_workspace_change_authorization(&incoming, &snapshot(owner), &["visitor-change".into()], 0).unwrap_err(),
            "Visitors cannot write workspace changes");
    }

    #[test]
    fn limits_a_historical_owner_to_its_transfer_boundary() {
        use automerge::transaction::Transactable;
        let (owner, owner_device_seed, owner_device_id, _) = authority([11; 32], [12; 32]);
        let (former, _, _, _) = authority([13; 32], [14; 32]);
        let mut document = automerge::AutoCommit::new();
        document.put(automerge::ROOT, "before", "value").unwrap();
        document.commit();
        let boundary = document.get_heads()[0].to_string();
        document.put(automerge::ROOT, "after", "value").unwrap();
        document.commit();
        let after = document.get_heads()[0].to_string();
        let incoming = change_authorization(&owner, &owner_device_seed, &owner_device_id, owner.certificates.clone(), vec![&boundary, &after]);
        let mut context = snapshot(owner.clone());
        context.document = document.save();
        context.expected_current_owner = former.clone();
        context.ownership_transfers.push(transfer(&owner, &[11; 32], &owner_device_seed, &owner_device_id, &former, vec![boundary.clone()], 2));
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &[boundary.clone(), after], 0).unwrap(),
            vec![AuthorizedWorkspaceChange { hash: boundary, role: WorkspaceRole::Owner }]);
    }

    #[test]
    fn rejects_conflicting_or_missing_ownership_boundaries() {
        use automerge::transaction::Transactable;
        let (owner, owner_device_seed, owner_device_id, _) = authority([17; 32], [18; 32]);
        let (next, _, _, _) = authority([19; 32], [20; 32]);
        let mut document = automerge::AutoCommit::new();
        document.put(automerge::ROOT, "change", "value").unwrap();
        let head = document.get_heads()[0].to_string();
        let valid = transfer(&owner, &[17; 32], &owner_device_seed, &owner_device_id, &next, vec![head], 2);
        let mut context = snapshot(owner.clone());
        context.document = document.save();
        context.ownership_transfers = vec![valid.clone(), valid];
        let incoming = change_authorization(&owner, &owner_device_seed, &owner_device_id, owner.certificates.clone(), vec!["change"]);
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &["change".into()], 0).unwrap_err(), "Conflicting workspace ownership transitions");
        context.ownership_transfers = vec![transfer(&owner, &[17; 32], &owner_device_seed, &owner_device_id, &next, vec!["forged".into()], 2)];
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &["change".into()], 0).unwrap_err(), "Workspace ownership boundary is missing from the document");
    }

    #[test]
    fn admits_a_monotonic_transfer_epoch_after_access_epoch_changes() {
        use automerge::transaction::Transactable;
        let (owner, owner_device_seed, owner_device_id, _) = authority([21; 32], [22; 32]);
        let (next, _, _, _) = authority([23; 32], [24; 32]);
        let mut document = automerge::AutoCommit::new();
        document.put(automerge::ROOT, "change", "value").unwrap();
        document.commit();
        let boundary = document.get_heads()[0].to_string();
        let incoming = change_authorization(&owner, &owner_device_seed, &owner_device_id, owner.certificates.clone(), vec![&boundary]);
        let mut context = snapshot(owner.clone());
        context.document = document.save();
        context.expected_current_owner = next.clone();
        context.ownership_transfers.push(transfer(&owner, &[21; 32], &owner_device_seed, &owner_device_id, &next, vec![boundary.clone()], 5));
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &[boundary.clone()], 0).unwrap(),
            vec![AuthorizedWorkspaceChange { hash: boundary, role: WorkspaceRole::Owner }]);
    }

    #[test]
    fn rejects_an_absent_authority_context() {
        let (owner, device_seed, device_id, certificates) = authority([15; 32], [16; 32]);
        let incoming = change_authorization(&owner, &device_seed, &device_id, certificates, vec!["change"]);
        let context = WorkspaceWriteAuthorizationSnapshot { workspace_id: String::new(), genesis_owner: owner.clone(), genesis_epoch: 1, expected_current_owner: owner,
            document: automerge::AutoCommit::new().save(), ownership_transfers: vec![], succession_claims: vec![],
            revocations: vec![], device_revocations: vec![], departures: vec![] };
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &["change".into()], 0).unwrap_err(),
            "Invalid workspace write authority context");
    }

    #[test]
    fn rejects_legacy_break_glass_claims_at_the_snapshot_boundary() {
        let (owner, _, _, _) = authority([21; 32], [22; 32]);
        let mut raw = serde_json::to_value(snapshot(owner)).unwrap();
        raw["breakGlassClaims"] = serde_json::json!([]);
        assert!(serde_json::from_value::<WorkspaceWriteAuthorizationSnapshot>(raw).is_err());
    }

    #[test]
    fn rejects_a_chain_that_does_not_match_the_trusted_current_owner() {
        let (owner, device_seed, device_id, certificates) = authority([25; 32], [26; 32]);
        let (other, _, _, _) = authority([27; 32], [28; 32]);
        let incoming = change_authorization(&owner, &device_seed, &device_id, certificates, vec!["change"]);
        let mut context = snapshot(owner);
        context.expected_current_owner = other;
        assert_eq!(admit_workspace_change_authorization(&incoming, &context, &["change".into()], 0).unwrap_err(),
            "Workspace ownership chain does not match the expected owner");
    }

    #[test]
    fn owner_root_and_certified_device_can_issue_scoped_grants() {
        let owner_seed = [41; 32];
        let owner_public_key = public_key_from_seed(&owner_seed).unwrap();
        let owner_person_id = public_key_id(&owner_public_key).unwrap();
        let owner = PublicIdentity {
            person_id: owner_person_id.clone(),
            public_key: owner_public_key,
            display_name: "Owner".to_string(),
        };
        let device_seed = [42; 32];
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &owner_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".to_string(),
                version: 1,
                person_id: owner_person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &owner_person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        assert!(!certificate_hash(&certificate).unwrap().is_empty());
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".to_string(),
            version: 1,
            grant_id: "grant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            person_id: "member-1".to_string(),
            role: WorkspaceRole::Editor,
            access_epoch: Some(1),
        };

        let root_grant = signed_grant(&owner_seed, &owner_person_id, &payload);
        assert_eq!(
            verify_workspace_grant(
                &root_grant,
                "workspace-1",
                "member-1",
                &owner,
                &[certificate.clone()]
            )
            .unwrap(),
            WorkspaceRole::Editor
        );

        let device_grant = signed_grant(&device_seed, &device_id, &payload);
        assert_eq!(
            verify_workspace_grant(
                &device_grant,
                "workspace-1",
                "member-1",
                &owner,
                &[certificate]
            )
            .unwrap(),
            WorkspaceRole::Editor
        );
        assert!(
            verify_workspace_grant(&device_grant, "workspace-other", "member-1", &owner, &[])
                .is_err()
        );
    }

    #[test]
    fn legacy_grant_without_access_epoch_keeps_its_signed_json_shape() {
        let seed = [51; 32];
        let public_key = public_key_from_seed(&seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(), version: 1, grant_id: "legacy".into(), workspace_id: "workspace".into(),
            person_id: "member".into(), role: WorkspaceRole::Editor, access_epoch: None,
        };
        let grant = signed_grant(&seed, &person_id, &payload);
        let raw = serde_json::to_value(&grant).unwrap();
        assert!(raw["payload"].get("accessEpoch").is_none());
        let decoded: WorkspaceGrant = serde_json::from_value(raw).unwrap();
        assert_eq!(decoded.payload.effective_access_epoch(), 1);
        assert_eq!(serde_json::to_value(&decoded).unwrap()["payload"].get("accessEpoch"), None);
        assert_eq!(verify_workspace_grant(&decoded, "workspace", "member", &PublicIdentity { person_id, public_key, display_name: "Owner".into() }, &[]).unwrap(), WorkspaceRole::Editor);
    }

    #[test]
    fn explicit_access_epoch_one_is_not_dropped_from_signed_json() {
        let payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(), version: 1, grant_id: "explicit".into(), workspace_id: "workspace".into(),
            person_id: "member".into(), role: WorkspaceRole::Editor, access_epoch: Some(1),
        };
        let raw = serde_json::to_value(&payload).unwrap();
        assert_eq!(raw["accessEpoch"], 1);
        let decoded: WorkspaceGrantPayload = serde_json::from_value(raw).unwrap();
        assert_eq!(decoded.access_epoch, Some(1));
        assert_eq!(serde_json::to_value(decoded).unwrap()["accessEpoch"], 1);
    }

    #[test]
    fn null_access_epoch_is_not_accepted_as_a_valid_grant() {
        let raw = serde_json::json!({"kind":"workspace-grant","version":1,"grantId":"g","workspaceId":"w","personId":"p","role":"editor","accessEpoch":null});
        let payload: WorkspaceGrantPayload = serde_json::from_value(raw).unwrap();
        assert_eq!(payload.effective_access_epoch(), 1);
        // It serializes without the field, so a signature over the hostile null
        // shape cannot validate as a legacy grant.
        assert!(serde_json::to_value(payload).unwrap().get("accessEpoch").is_none());
    }
}
