//! Explicit, platform-neutral authority ledger for any replicated scope.
//! Product documents never supply implicit creator, controller, or recovery data.

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope,
    WorkspaceAuthority, WorkspaceRevocation, WorkspaceSuccessionClaim, public_key_id,
    sign_json_envelope, verify_device_certificate_chain, verify_signed_envelope,
    verify_workspace_revocation, verify_workspace_succession_claim,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub const SCOPE_AUTHORITY_VERSION: u8 = 1;
pub const MAX_SCOPE_CAPABILITIES: usize = 16;
pub const MAX_SCOPE_GRANTS: usize = 4_096;
pub const MAX_SCOPE_REVOCATIONS: usize = 4_096;
pub const MAX_SCOPE_CONTROL_TRANSFERS: usize = 128;
pub const MAX_SCOPE_SUCCESSION_TRANSFERS: usize = 128;

/// Initial browser-adapter descriptor. Not an authority proof.
/// New authority decisions require `SignedScopeGenesis`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeGenesisInput {
    pub scope_id: String,
    pub creator_person_id: String,
    pub creator_public_key: String,
    pub creator_certificate: DeviceCertificate,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeGenesis {
    pub scope_id: String,
    pub creator_person_id: String,
    pub creator_public_key: String,
    pub creator_certificates: Vec<DeviceCertificate>,
}
pub fn create_scope_genesis(input: ScopeGenesisInput) -> Result<ScopeGenesis, String> {
    valid_scope_id(&input.scope_id)?;
    validate_creator(
        &input.creator_person_id,
        &input.creator_public_key,
        std::slice::from_ref(&input.creator_certificate),
    )?;
    Ok(ScopeGenesis {
        scope_id: input.scope_id,
        creator_person_id: input.creator_person_id,
        creator_public_key: input.creator_public_key,
        creator_certificates: vec![input.creator_certificate],
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeAuthority {
    pub person_id: String,
    pub public_key: String,
    pub certificates: Vec<DeviceCertificate>,
}
impl ScopeAuthority {
    fn identity(&self) -> PublicIdentity {
        PublicIdentity {
            person_id: self.person_id.clone(),
            public_key: self.public_key.clone(),
            display_name: String::new(),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.person_id.is_empty()
            || self.public_key.is_empty()
            || self.certificates.is_empty()
            || public_key_id(&self.public_key)? != self.person_id
        {
            return Err("Invalid scope authority".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeGenesisPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub creator: ScopeAuthority,
    pub control_epoch: u64,
}
pub type SignedScopeGenesis = SignedEnvelope<ScopeGenesisPayload>;

/// Builds the immutable payload a platform signer seals as the first
/// authority record. Private keys remain outside platform-neutral core.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeGenesisPayloadInput {
    pub scope_id: String,
    pub creator: ScopeAuthority,
}

/// Explicit genesis decision for document-backed scopes. The host still signs
/// the returned payload, but ownership binding stays in platform-neutral core.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeGenesisPlanInput {
    pub scope_id: String,
    pub document_owner_person_id: String,
    pub creator: ScopeAuthority,
}

pub fn plan_scope_genesis(input: ScopeGenesisPlanInput) -> Result<ScopeGenesisPayload, String> {
    if input.document_owner_person_id != input.creator.person_id {
        return Err("Workspace genesis owner does not match scope creator".into());
    }
    create_scope_genesis_payload(ScopeGenesisPayloadInput {
        scope_id: input.scope_id,
        creator: input.creator,
    })
}

pub fn create_scope_genesis_payload(
    input: ScopeGenesisPayloadInput,
) -> Result<ScopeGenesisPayload, String> {
    valid_scope_id(&input.scope_id)?;
    input.creator.validate()?;
    validate_creator(
        &input.creator.person_id,
        &input.creator.public_key,
        &input.creator.certificates,
    )?;
    Ok(ScopeGenesisPayload {
        kind: "scope-genesis".into(),
        version: SCOPE_AUTHORITY_VERSION,
        scope_id: input.scope_id,
        creator: input.creator,
        control_epoch: 1,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeCapability {
    Read,
    Write,
    Invite,
    ManageMembers,
    Grant,
    Control,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCapabilityGrantPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub grant_id: String,
    pub issuer_person_id: String,
    pub subject_person_id: String,
    pub capabilities: Vec<ScopeCapability>,
    pub control_epoch: u64,
}
pub type ScopeCapabilityGrant = SignedEnvelope<ScopeCapabilityGrantPayload>;
/// Explicit signing identity for a non-controller grant issuer. It is kept in
/// the authority ledger rather than inferred from a channel participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeGrantIssuerEvidence {
    pub grant_id: String,
    pub issuer: ScopeAuthority,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCapabilityRevocationPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub grant_id: String,
    pub revoked_by_person_id: String,
    pub control_epoch: u64,
}
pub type ScopeCapabilityRevocation = SignedEnvelope<ScopeCapabilityRevocationPayload>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeControlTransferPayload {
    pub kind: String,
    pub version: u8,
    pub scope_id: String,
    pub from_controller_person_id: String,
    pub to_controller: ScopeAuthority,
    pub from_control_epoch: u64,
    pub to_control_epoch: u64,
}
pub type ScopeControlTransfer = SignedEnvelope<ScopeControlTransferPayload>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeControlTransferPayloadInput {
    pub snapshot: ScopeAuthoritySnapshot,
    pub to_controller: ScopeAuthority,
}

/// Builds the next transfer from the validated controller only. A platform
/// signer seals this payload with that controller's device key.
pub fn create_scope_control_transfer_payload(
    input: ScopeControlTransferPayloadInput,
) -> Result<ScopeControlTransferPayload, String> {
    create_scope_control_transfer_payload_at(input, 0)
}

pub fn create_scope_control_transfer_payload_at(
    input: ScopeControlTransferPayloadInput,
    now_ms: i128,
) -> Result<ScopeControlTransferPayload, String> {
    let authority = validate_scope_authority_at(&input.snapshot, now_ms)?;
    input.to_controller.validate()?;
    validate_creator(
        &input.to_controller.person_id,
        &input.to_controller.public_key,
        &input.to_controller.certificates,
    )?;
    if input.to_controller.person_id == authority.controller.person_id {
        return Err("Scope control transfer requires another controller".into());
    }
    Ok(ScopeControlTransferPayload {
        kind: "scope-control-transfer".into(),
        version: SCOPE_AUTHORITY_VERSION,
        scope_id: authority.scope_id,
        from_controller_person_id: authority.controller.person_id,
        to_controller: input.to_controller,
        from_control_epoch: authority.control_epoch,
        to_control_epoch: authority.control_epoch + 1,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeAuthoritySnapshot {
    pub genesis: SignedScopeGenesis,
    #[serde(default)]
    pub grants: Vec<ScopeCapabilityGrant>,
    #[serde(default)]
    pub grant_issuers: Vec<ScopeGrantIssuerEvidence>,
    #[serde(default)]
    pub revocations: Vec<ScopeCapabilityRevocation>,
    #[serde(default)]
    pub control_transfers: Vec<ScopeControlTransfer>,
    #[serde(default)]
    pub succession_transfers: Vec<ScopeSuccessionTransfer>,
}

/// A workspace recovery claim also transfers scope control. The policy epoch
/// binds to `from_control_epoch` so old claims cannot be replayed after control returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeSuccessionTransfer {
    pub from_control_epoch: u64,
    pub claim: WorkspaceSuccessionClaim,
    #[serde(default)]
    pub revocations: Vec<WorkspaceRevocation>,
}

/// Merge authenticated gossip without letting a stale peer erase signed
/// authority evidence already held locally. A changed genesis or a fork in the
/// combined ledger is rejected by validation.
pub fn merge_scope_authority_snapshots(
    current: Option<&ScopeAuthoritySnapshot>,
    incoming: &ScopeAuthoritySnapshot,
) -> Result<ScopeAuthoritySnapshot, String> {
    merge_scope_authority_snapshots_at(current, incoming, 0)
}

pub fn merge_scope_authority_snapshots_at(
    current: Option<&ScopeAuthoritySnapshot>,
    incoming: &ScopeAuthoritySnapshot,
    now_ms: i128,
) -> Result<ScopeAuthoritySnapshot, String> {
    validate_scope_authority_at(incoming, now_ms)?;
    let Some(current) = current else {
        return Ok(incoming.clone());
    };
    validate_scope_authority_at(current, now_ms)?;
    if current.genesis != incoming.genesis {
        return Err("Scope authority genesis cannot change".into());
    }
    let mut merged = current.clone();
    append_unique(&mut merged.grants, &incoming.grants);
    append_unique(&mut merged.grant_issuers, &incoming.grant_issuers);
    append_unique(&mut merged.revocations, &incoming.revocations);
    append_unique(&mut merged.control_transfers, &incoming.control_transfers);
    merge_succession_transfers(
        &mut merged.succession_transfers,
        &incoming.succession_transfers,
    );
    validate_scope_authority_at(&merged, now_ms)?;
    Ok(merged)
}

fn append_unique<T: Clone + PartialEq>(current: &mut Vec<T>, incoming: &[T]) {
    for record in incoming {
        if !current.contains(record) {
            current.push(record.clone());
        }
    }
}

fn merge_succession_transfers(
    current: &mut Vec<ScopeSuccessionTransfer>,
    incoming: &[ScopeSuccessionTransfer],
) {
    for transfer in incoming {
        if let Some(existing) = current.iter_mut().find(|existing| {
            existing.from_control_epoch == transfer.from_control_epoch
                && existing.claim == transfer.claim
        }) {
            append_unique(&mut existing.revocations, &transfer.revocations);
        } else if !current.iter().any(|existing| existing == transfer) {
            current.push(transfer.clone());
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedScopeAuthority {
    pub scope_id: String,
    pub creator: ScopeAuthority,
    pub controller: ScopeAuthority,
    pub control_epoch: u64,
    pub grants: Vec<ScopeCapabilityGrant>,
}
impl ValidatedScopeAuthority {
    pub fn capabilities_for(&self, person_id: &str) -> Vec<ScopeCapability> {
        if self.controller.person_id == person_id {
            return base_controller_capabilities();
        }
        let mut caps = self
            .grants
            .iter()
            .filter(|g| g.payload.subject_person_id == person_id)
            .flat_map(|g| g.payload.capabilities.iter().cloned())
            .collect::<Vec<_>>();
        caps.sort_by_key(capability_rank);
        caps.dedup();
        caps
    }
    pub fn allows(&self, person_id: &str, capability: ScopeCapability) -> bool {
        self.capabilities_for(person_id).contains(&capability)
    }
}

/// Complete ledger validation. Unknown/forked/gapped authority records fail.
pub fn validate_scope_authority(
    snapshot: &ScopeAuthoritySnapshot,
) -> Result<ValidatedScopeAuthority, String> {
    validate_scope_authority_at(snapshot, 0)
}

pub fn validate_scope_authority_at(
    snapshot: &ScopeAuthoritySnapshot,
    now_ms: i128,
) -> Result<ValidatedScopeAuthority, String> {
    if snapshot.grants.len() > MAX_SCOPE_GRANTS
        || snapshot.revocations.len() > MAX_SCOPE_REVOCATIONS
        || snapshot.control_transfers.len() > MAX_SCOPE_CONTROL_TRANSFERS
        || snapshot.succession_transfers.len() > MAX_SCOPE_SUCCESSION_TRANSFERS
        || snapshot
            .succession_transfers
            .iter()
            .fold(0usize, |total, transfer| {
                total.saturating_add(transfer.revocations.len())
            })
            > MAX_SCOPE_REVOCATIONS
    {
        return Err("Scope authority record limit exceeded".into());
    }
    let genesis = verify_scope_genesis(&snapshot.genesis)?;
    let mut controller = genesis.creator.clone();
    let mut epoch = genesis.control_epoch;
    let mut controllers = BTreeMap::new();
    controllers.insert(epoch, controller.clone());
    let mut pending_transfers = snapshot.control_transfers.iter().collect::<Vec<_>>();
    let mut pending_successions = snapshot.succession_transfers.iter().collect::<Vec<_>>();
    while !pending_transfers.is_empty() || !pending_successions.is_empty() {
        let transfer_matches = pending_transfers
            .iter()
            .enumerate()
            .filter(|(_, r)| r.payload.from_control_epoch == epoch)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let succession_matches = pending_successions
            .iter()
            .enumerate()
            .filter(|(_, r)| r.from_control_epoch == epoch)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        if transfer_matches.len() + succession_matches.len() != 1 {
            return Err("Scope control chain is forked or has a gap".into());
        }
        let next_epoch = epoch.checked_add(1).ok_or("Scope control epoch overflow")?;
        if let Some(index) = transfer_matches.first() {
            let transfer = pending_transfers.remove(*index);
            verify_scope_control_transfer(transfer, &genesis.scope_id, &controller)?;
            if transfer.payload.to_control_epoch != next_epoch {
                return Err("Scope control transfer epoch is invalid".into());
            }
            controller = transfer.payload.to_controller.clone();
        } else {
            let transfer = pending_successions.remove(succession_matches[0]);
            let authority = WorkspaceAuthority {
                person_id: controller.person_id.clone(),
                public_key: controller.public_key.clone(),
                certificates: controller.certificates.clone(),
            };
            let mut revoked_people = HashSet::new();
            for revocation in &transfer.revocations {
                let mut verified = false;
                for signer in controllers
                    .values()
                    .filter(|value| value.person_id == revocation.payload.owner_person_id)
                {
                    let signer = WorkspaceAuthority {
                        person_id: signer.person_id.clone(),
                        public_key: signer.public_key.clone(),
                        certificates: signer.certificates.clone(),
                    };
                    if verify_workspace_revocation(revocation, &genesis.scope_id, &signer, now_ms)
                        .is_ok()
                    {
                        verified = true;
                        break;
                    }
                }
                if !verified {
                    return Err(
                        "Scope succession revocation has no authenticated owner signature".into(),
                    );
                }
                revoked_people.insert(revocation.payload.person_id.clone());
            }
            let claim = &transfer.claim;
            if claim.payload.policy.payload.epoch != epoch {
                return Err("Succession policy epoch does not match scope control epoch".into());
            }
            verify_workspace_succession_claim(
                claim,
                &genesis.scope_id,
                &authority,
                epoch,
                &revoked_people,
                now_ms,
            )?;
            controller = ScopeAuthority {
                person_id: claim.payload.to_owner_person_id.clone(),
                public_key: claim.payload.to_owner_public_key.clone(),
                certificates: claim.payload.to_owner_certificates.clone(),
            };
        }
        epoch = next_epoch;
        controllers.insert(epoch, controller.clone());
    }
    let mut revoked = HashSet::new();
    for r in &snapshot.revocations {
        let a = controllers
            .get(&r.payload.control_epoch)
            .ok_or("Scope revocation has an unknown control epoch")?;
        verify_scope_capability_revocation(r, &genesis.scope_id, a)?;
        revoked.insert(r.payload.grant_id.clone());
    }
    let mut issuers = BTreeMap::new();
    for evidence in &snapshot.grant_issuers {
        if evidence.grant_id.is_empty()
            || issuers
                .insert(evidence.grant_id.clone(), evidence.issuer.clone())
                .is_some()
        {
            return Err("Duplicate scope grant issuer evidence".into());
        }
    }
    let mut seen = HashSet::new();
    let mut pending = snapshot.grants.iter().collect::<Vec<_>>();
    pending.sort_by(|left, right| left.payload.grant_id.cmp(&right.payload.grant_id));
    if pending
        .iter()
        .any(|grant| !seen.insert(grant.payload.grant_id.clone()))
    {
        return Err("Duplicate scope capability grant".into());
    }
    let mut grants = Vec::new();
    while !pending.is_empty() {
        let mut accepted = None;
        for (index, g) in pending.iter().enumerate() {
            let controller = controllers
                .get(&g.payload.control_epoch)
                .ok_or("Scope grant has an unknown control epoch")?;
            let issuer = issuers.get(&g.payload.grant_id).unwrap_or(controller);
            if issuer.person_id != g.payload.issuer_person_id {
                return Err("Scope grant issuer evidence does not match payload".into());
            }
            verify_scope_capability_grant(g, &genesis.scope_id, issuer)?;
            let controller_issued = issuer.person_id == controller.person_id
                && issuer.public_key == controller.public_key;
            let issuer_caps = effective_capabilities(&grants, &revoked, &issuer.person_id);
            if !controller_issued
                && (!(issuer_caps.contains(&ScopeCapability::Grant)
                    || issuer_caps.contains(&ScopeCapability::ManageMembers))
                    || !g
                        .payload
                        .capabilities
                        .iter()
                        .all(|capability| issuer_caps.contains(capability)))
            {
                continue;
            }
            accepted = Some(index);
            break;
        }
        if let Some(index) = accepted {
            let grant = pending.remove(index);
            if !revoked.contains(&grant.payload.grant_id) {
                grants.push(grant.clone());
            }
        } else {
            return Err("Scope capability delegation is cyclic or exceeds issuer authority".into());
        }
    }
    Ok(ValidatedScopeAuthority {
        scope_id: genesis.scope_id,
        creator: genesis.creator,
        controller,
        control_epoch: epoch,
        grants,
    })
}

pub fn verify_scope_genesis(record: &SignedScopeGenesis) -> Result<ScopeGenesisPayload, String> {
    let p = &record.payload;
    if p.kind != "scope-genesis" || p.version != SCOPE_AUTHORITY_VERSION || p.control_epoch != 1 {
        return Err("Invalid scope genesis".into());
    }
    valid_scope_id(&p.scope_id)?;
    p.creator.validate()?;
    verify_authority_envelope(record, &p.creator, "scope genesis")?;
    Ok(p.clone())
}
pub fn verify_scope_capability_grant(
    record: &ScopeCapabilityGrant,
    scope_id: &str,
    issuer: &ScopeAuthority,
) -> Result<(), String> {
    let p = &record.payload;
    if p.kind != "scope-capability-grant"
        || p.version != SCOPE_AUTHORITY_VERSION
        || p.scope_id != scope_id
        || p.grant_id.is_empty()
        || p.issuer_person_id != issuer.person_id
        || p.subject_person_id.is_empty()
        || p.capabilities.is_empty()
        || p.capabilities.len() > MAX_SCOPE_CAPABILITIES
        || duplicate_capabilities(&p.capabilities)
        || p.capabilities.contains(&ScopeCapability::Control)
    {
        return Err("Invalid scope capability grant".into());
    }
    verify_authority_envelope(record, issuer, "scope capability grant")
}
pub fn verify_scope_capability_revocation(
    record: &ScopeCapabilityRevocation,
    scope_id: &str,
    controller: &ScopeAuthority,
) -> Result<(), String> {
    let p = &record.payload;
    if p.kind != "scope-capability-revocation"
        || p.version != SCOPE_AUTHORITY_VERSION
        || p.scope_id != scope_id
        || p.grant_id.is_empty()
        || p.revoked_by_person_id != controller.person_id
    {
        return Err("Invalid scope capability revocation".into());
    }
    verify_authority_envelope(record, controller, "scope capability revocation")
}
pub fn verify_scope_control_transfer(
    record: &ScopeControlTransfer,
    scope_id: &str,
    controller: &ScopeAuthority,
) -> Result<(), String> {
    let p = &record.payload;
    if p.kind != "scope-control-transfer"
        || p.version != SCOPE_AUTHORITY_VERSION
        || p.scope_id != scope_id
        || p.from_controller_person_id != controller.person_id
        || p.from_control_epoch == 0
        || p.to_control_epoch == 0
        || p.to_controller.person_id == controller.person_id
    {
        return Err("Invalid scope control transfer".into());
    }
    p.to_controller.validate()?;
    verify_authority_envelope(record, controller, "scope control transfer")
}
pub fn sign_scope_record<T>(
    seed: &[u8; 32],
    payload: T,
    signer_key_id: impl Into<String>,
) -> Result<SignedEnvelope<T>, String>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    let signed = sign_json_envelope(
        seed,
        serde_json::to_value(&payload).map_err(|_| "Scope payload invalid")?,
        signer_key_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    Ok(SignedEnvelope {
        payload,
        signer_key_id: signed.signer_key_id,
        signature: signed.signature,
    })
}
fn verify_authority_envelope<T: Serialize>(
    record: &SignedEnvelope<T>,
    authority: &ScopeAuthority,
    label: &str,
) -> Result<(), String> {
    authority.validate()?;
    if verify_signed_envelope(record, &authority.public_key, DEFAULT_SIGNATURE_DOMAIN)? {
        return Ok(());
    }
    let device_key = verify_device_certificate_chain(
        &authority.identity(),
        &record.signer_key_id,
        &authority.certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .map_err(|_| format!("Invalid {label} signer"))?;
    if verify_signed_envelope(record, &device_key, DEFAULT_SIGNATURE_DOMAIN)? {
        Ok(())
    } else {
        Err(format!("Invalid {label} signature"))
    }
}
fn validate_creator(
    person_id: &str,
    public_key: &str,
    certificates: &[DeviceCertificate],
) -> Result<(), String> {
    if person_id.is_empty() || public_key_id(public_key)? != person_id {
        return Err("Invalid scope creator".into());
    }
    let identity = PublicIdentity {
        person_id: person_id.into(),
        public_key: public_key.into(),
        display_name: String::new(),
    };
    let device_id = certificates
        .first()
        .ok_or("Invalid scope creator")?
        .payload
        .device_id
        .clone();
    verify_device_certificate_chain(
        &identity,
        &device_id,
        certificates,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    Ok(())
}
fn valid_scope_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 {
        Err("Invalid scope id".into())
    } else {
        Ok(())
    }
}
fn duplicate_capabilities(caps: &[ScopeCapability]) -> bool {
    let mut ranks = caps.iter().map(capability_rank).collect::<Vec<_>>();
    ranks.sort_unstable();
    ranks.windows(2).any(|p| p[0] == p[1])
}
fn effective_capabilities(
    grants: &[ScopeCapabilityGrant],
    revoked: &HashSet<String>,
    person_id: &str,
) -> Vec<ScopeCapability> {
    let mut caps = grants
        .iter()
        .filter(|grant| {
            !revoked.contains(&grant.payload.grant_id)
                && grant.payload.subject_person_id == person_id
        })
        .flat_map(|grant| grant.payload.capabilities.iter().cloned())
        .collect::<Vec<_>>();
    caps.sort_by_key(capability_rank);
    caps.dedup();
    caps
}
fn capability_rank(cap: &ScopeCapability) -> u8 {
    match cap {
        ScopeCapability::Read => 0,
        ScopeCapability::Write => 1,
        ScopeCapability::Invite => 2,
        ScopeCapability::ManageMembers => 3,
        ScopeCapability::Grant => 4,
        ScopeCapability::Control => 5,
    }
}
fn base_controller_capabilities() -> Vec<ScopeCapability> {
    vec![
        ScopeCapability::Read,
        ScopeCapability::Write,
        ScopeCapability::Invite,
        ScopeCapability::ManageMembers,
        ScopeCapability::Grant,
        ScopeCapability::Control,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCertificatePayload, WorkspaceGrant, WorkspaceGrantPayload, WorkspaceRevocation,
        WorkspaceRevocationPayload, WorkspaceRole, WorkspaceSuccessionClaim,
        WorkspaceSuccessionClaimPayload, WorkspaceSuccessionPolicyPayload, WorkspaceSuccessionVote,
        WorkspaceSuccessionVotePayload, public_key_from_seed, sign_device_certificate,
        sign_json_envelope,
    };
    use serde_json::json;
    fn authority(root: [u8; 32], device: [u8; 32]) -> (ScopeAuthority, [u8; 32], String) {
        let public_key = public_key_from_seed(&root).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&device).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let cert = sign_device_certificate(
            &root,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        (
            ScopeAuthority {
                person_id,
                public_key,
                certificates: vec![cert],
            },
            device,
            device_id,
        )
    }
    fn genesis(a: &ScopeAuthority, seed: &[u8; 32], device: &str) -> SignedScopeGenesis {
        sign_scope_record(
            seed,
            ScopeGenesisPayload {
                kind: "scope-genesis".into(),
                version: 1,
                scope_id: "scope-a".into(),
                creator: a.clone(),
                control_epoch: 1,
            },
            device,
        )
        .unwrap()
    }

    const TEST_NOW_MS: i128 = 1_791_926_400_000;
    const TEST_TIME: &str = "2026-10-02T00:00:00.000Z";

    fn signed_grant(
        seed: &[u8; 32],
        signer: &str,
        payload: WorkspaceGrantPayload,
    ) -> WorkspaceGrant {
        let signed = sign_json_envelope(
            seed,
            serde_json::to_value(&payload).unwrap(),
            signer,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        SignedEnvelope {
            payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        }
    }

    fn succession_claim(
        owner: &ScopeAuthority,
        owner_seed: &[u8; 32],
        _owner_device: &str,
        candidate: &ScopeAuthority,
        candidate_root: &[u8; 32],
        candidate_device_seed: &[u8; 32],
        candidate_device: &str,
        epoch: u64,
        named: bool,
        voters: &[(&ScopeAuthority, &[u8; 32], &str)],
    ) -> WorkspaceSuccessionClaim {
        let candidate_grant = signed_grant(
            owner_seed,
            &owner.person_id,
            WorkspaceGrantPayload {
                kind: "workspace-grant".into(),
                version: 1,
                grant_id: "candidate-editor".into(),
                workspace_id: "scope-a".into(),
                person_id: candidate.person_id.clone(),
                role: WorkspaceRole::Editor,
                access_epoch: Some(epoch),

                automation: None,
            },
        );
        let former_owner_grant = signed_grant(
            candidate_root,
            &candidate.person_id,
            WorkspaceGrantPayload {
                kind: "workspace-grant".into(),
                version: 1,
                grant_id: "former-owner-editor".into(),
                workspace_id: "scope-a".into(),
                person_id: owner.person_id.clone(),
                role: WorkspaceRole::Editor,
                access_epoch: Some(epoch + 1),

                automation: None,
            },
        );
        let mut eligible = vec![candidate.person_id.clone()];
        eligible.extend(voters.iter().map(|(voter, _, _)| voter.person_id.clone()));
        eligible.sort();
        eligible.dedup();
        let policy_payload = WorkspaceSuccessionPolicyPayload {
            kind: "workspace-succession-policy".into(),
            version: 1,
            workspace_id: "scope-a".into(),
            owner_person_id: owner.person_id.clone(),
            successor_person_id: named.then(|| candidate.person_id.clone()),
            eligible_editor_person_ids: eligible,
            epoch,
            updated_at: TEST_TIME.into(),
        };
        let policy_signed = sign_json_envelope(
            owner_seed,
            serde_json::to_value(&policy_payload).unwrap(),
            &owner.person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        assert!(
            verify_signed_envelope(&policy_signed, &owner.public_key, DEFAULT_SIGNATURE_DOMAIN)
                .unwrap()
        );
        let policy = SignedEnvelope {
            payload: policy_payload,
            signer_key_id: policy_signed.signer_key_id,
            signature: policy_signed.signature,
        };
        let votes = voters
            .iter()
            .map(|(voter, seed, device)| {
                let payload = WorkspaceSuccessionVotePayload {
                    kind: "workspace-succession-vote".into(),
                    version: 1,
                    workspace_id: "scope-a".into(),
                    owner_person_id: owner.person_id.clone(),
                    voter_person_id: voter.person_id.clone(),
                    candidate_person_id: candidate.person_id.clone(),
                    policy_signature: policy.signature.clone(),
                    voted_at: TEST_TIME.into(),
                };
                let signed = sign_json_envelope(
                    seed,
                    serde_json::to_value(&payload).unwrap(),
                    *device,
                    DEFAULT_SIGNATURE_DOMAIN,
                )
                .unwrap();
                let voter_grant = signed_grant(
                    owner_seed,
                    &owner.person_id,
                    WorkspaceGrantPayload {
                        kind: "workspace-grant".into(),
                        version: 1,
                        grant_id: format!("voter-{}", voter.person_id),
                        workspace_id: "scope-a".into(),
                        person_id: voter.person_id.clone(),
                        role: WorkspaceRole::Editor,
                        access_epoch: Some(epoch),

                        automation: None,
                    },
                );
                WorkspaceSuccessionVote {
                    signed: SignedEnvelope {
                        payload,
                        signer_key_id: signed.signer_key_id,
                        signature: signed.signature,
                    },
                    voter_public_key: voter.public_key.clone(),
                    voter_certificates: voter.certificates.clone(),
                    voter_grant,
                }
            })
            .collect::<Vec<_>>();
        let payload = WorkspaceSuccessionClaimPayload {
            kind: "workspace-succession-claim".into(),
            version: 1,
            workspace_id: "scope-a".into(),
            from_owner_person_id: owner.person_id.clone(),
            to_owner_person_id: candidate.person_id.clone(),
            to_owner_public_key: candidate.public_key.clone(),
            to_owner_certificates: candidate.certificates.clone(),
            candidate_grant,
            former_owner_grant,
            policy,
            votes,
            workspace_heads: vec!["head-a".into()],
            epoch: epoch + 1,
            claimed_at: TEST_TIME.into(),
        };
        let signed = sign_json_envelope(
            candidate_device_seed,
            serde_json::to_value(&payload).unwrap(),
            candidate_device,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        SignedEnvelope {
            payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        }
    }

    fn succession_snapshot(claim: WorkspaceSuccessionClaim, epoch: u64) -> ScopeAuthoritySnapshot {
        let (owner, owner_device_seed, owner_device) = authority([1; 32], [2; 32]);
        ScopeAuthoritySnapshot {
            genesis: genesis(&owner, &owner_device_seed, &owner_device),
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![],
            succession_transfers: vec![ScopeSuccessionTransfer {
                from_control_epoch: epoch,
                claim,
                revocations: vec![],
            }],
        }
    }

    fn workspace_revocation(
        owner: &ScopeAuthority,
        owner_seed: &[u8; 32],
        person_id: &str,
        epoch: u64,
    ) -> WorkspaceRevocation {
        let payload = WorkspaceRevocationPayload {
            kind: "workspace-revocation".into(),
            version: 1,
            workspace_id: "scope-a".into(),
            owner_person_id: owner.person_id.clone(),
            person_id: person_id.into(),
            epoch,
            workspace_heads: vec!["head-a".into()],
            revoked_at: TEST_TIME.into(),
        };
        let signed = sign_json_envelope(
            owner_seed,
            serde_json::to_value(&payload).unwrap(),
            &owner.person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        SignedEnvelope {
            payload,
            signer_key_id: signed.signer_key_id,
            signature: signed.signature,
        }
    }

    #[test]
    fn named_and_quorum_succession_become_authenticated_scope_transitions() {
        let (owner, _owner_device_seed, owner_device) = authority([1; 32], [2; 32]);
        let owner_seed = [1; 32];
        let (candidate, candidate_device_seed, candidate_device) = authority([3; 32], [4; 32]);
        let named = succession_claim(
            &owner,
            &owner_seed,
            &owner_device,
            &candidate,
            &[3; 32],
            &candidate_device_seed,
            &candidate_device,
            1,
            true,
            &[],
        );
        let mut named_snapshot = succession_snapshot(named, 1);
        let validated = validate_scope_authority_at(&named_snapshot, TEST_NOW_MS).unwrap();
        assert_eq!(validated.control_epoch, 2);
        assert_eq!(validated.controller.person_id, candidate.person_id);

        let mut forged = named_snapshot.succession_transfers[0].claim.clone();
        forged.signature = "forged-signature".into();
        let mut forged_snapshot = named_snapshot.clone();
        forged_snapshot.succession_transfers[0].claim = forged;
        assert!(validate_scope_authority_at(&forged_snapshot, TEST_NOW_MS).is_err());
        let mut wrong_scope = named_snapshot.succession_transfers[0].claim.clone();
        wrong_scope.payload.workspace_id = "scope-other".into();
        let signed = sign_json_envelope(
            &candidate_device_seed,
            serde_json::to_value(&wrong_scope.payload).unwrap(),
            &candidate_device,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        wrong_scope.signer_key_id = signed.signer_key_id;
        wrong_scope.signature = signed.signature;
        let mut wrong_scope_snapshot = named_snapshot.clone();
        wrong_scope_snapshot.succession_transfers[0].claim = wrong_scope;
        assert!(validate_scope_authority_at(&wrong_scope_snapshot, TEST_NOW_MS).is_err());

        let (voter_a, voter_a_seed, voter_a_device) = authority([5; 32], [6; 32]);
        let (voter_b, voter_b_seed, voter_b_device) = authority([7; 32], [8; 32]);
        let quorum = succession_claim(
            &owner,
            &owner_seed,
            &owner_device,
            &candidate,
            &[3; 32],
            &candidate_device_seed,
            &candidate_device,
            1,
            false,
            &[
                (&voter_a, &voter_a_seed, &voter_a_device),
                (&voter_b, &voter_b_seed, &voter_b_device),
            ],
        );
        let quorum_snapshot = succession_snapshot(quorum, 1);
        assert_eq!(
            validate_scope_authority_at(&quorum_snapshot, TEST_NOW_MS)
                .unwrap()
                .controller
                .person_id,
            candidate.person_id
        );
        let insufficient = succession_claim(
            &owner,
            &owner_seed,
            &owner_device,
            &candidate,
            &[3; 32],
            &candidate_device_seed,
            &candidate_device,
            1,
            false,
            &[(&voter_a, &voter_a_seed, &voter_a_device)],
        );
        assert!(
            validate_scope_authority_at(&succession_snapshot(insufficient, 1), TEST_NOW_MS)
                .unwrap_err()
                .contains("quorum requires 2 votes")
        );

        // Replay an authentic old claim after control moved A → B → A.
        let (other, _, _) = authority([9; 32], [10; 32]);
        let other_seed = [9; 32];
        let transfer_ab = sign_scope_record(
            &owner_seed,
            ScopeControlTransferPayload {
                kind: "scope-control-transfer".into(),
                version: SCOPE_AUTHORITY_VERSION,
                scope_id: "scope-a".into(),
                from_controller_person_id: owner.person_id.clone(),
                to_controller: other.clone(),
                from_control_epoch: 1,
                to_control_epoch: 2,
            },
            &owner.person_id,
        )
        .unwrap();
        let transfer_ba = sign_scope_record(
            &other_seed,
            ScopeControlTransferPayload {
                kind: "scope-control-transfer".into(),
                version: SCOPE_AUTHORITY_VERSION,
                scope_id: "scope-a".into(),
                from_controller_person_id: other.person_id.clone(),
                to_controller: owner.clone(),
                from_control_epoch: 2,
                to_control_epoch: 3,
            },
            &other.person_id,
        )
        .unwrap();
        named_snapshot.control_transfers = vec![transfer_ab, transfer_ba];
        named_snapshot.succession_transfers[0].from_control_epoch = 3;
        assert_eq!(
            validate_scope_authority_at(&named_snapshot, TEST_NOW_MS).unwrap_err(),
            "Succession policy epoch does not match scope control epoch"
        );
    }

    #[test]
    fn succession_binds_historical_revocations_and_gossip_merges_evidence() {
        let (owner_a, _, owner_a_device) = authority([1; 32], [2; 32]);
        let (owner_b, _, owner_b_device) = authority([9; 32], [10; 32]);
        let (candidate, candidate_device_seed, candidate_device) = authority([11; 32], [12; 32]);
        let (other_candidate, other_device_seed, other_device) = authority([13; 32], [14; 32]);
        let owner_a_seed = [1; 32];
        let owner_b_seed = [9; 32];
        let transfer_ab = sign_scope_record(
            &owner_a_seed,
            ScopeControlTransferPayload {
                kind: "scope-control-transfer".into(),
                version: SCOPE_AUTHORITY_VERSION,
                scope_id: "scope-a".into(),
                from_controller_person_id: owner_a.person_id.clone(),
                to_controller: owner_b.clone(),
                from_control_epoch: 1,
                to_control_epoch: 2,
            },
            &owner_a.person_id,
        )
        .unwrap();
        let claim = succession_claim(
            &owner_b,
            &owner_b_seed,
            &owner_b_device,
            &candidate,
            &[11; 32],
            &candidate_device_seed,
            &candidate_device,
            2,
            true,
            &[],
        );
        let prior_revocation = workspace_revocation(&owner_a, &owner_a_seed, "revoked-member", 2);
        let snapshot = ScopeAuthoritySnapshot {
            genesis: genesis(&owner_a, &[2; 32], &owner_a_device),
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![transfer_ab.clone()],
            succession_transfers: vec![ScopeSuccessionTransfer {
                from_control_epoch: 2,
                claim: claim.clone(),
                revocations: vec![prior_revocation.clone()],
            }],
        };
        assert_eq!(
            validate_scope_authority_at(&snapshot, TEST_NOW_MS)
                .unwrap()
                .controller
                .person_id,
            candidate.person_id
        );

        let mut gossip = snapshot.clone();
        gossip.succession_transfers[0]
            .revocations
            .push(workspace_revocation(
                &owner_b,
                &owner_b_seed,
                "another-revoked-member",
                3,
            ));
        let merged =
            merge_scope_authority_snapshots_at(Some(&snapshot), &gossip, TEST_NOW_MS).unwrap();
        assert_eq!(merged.succession_transfers[0].revocations.len(), 2);

        let (voter_a, voter_a_seed, voter_a_device) = authority([15; 32], [16; 32]);
        let (voter_b, voter_b_seed, voter_b_device) = authority([17; 32], [18; 32]);
        let revoked_voter_claim = succession_claim(
            &owner_b,
            &owner_b_seed,
            &owner_b_device,
            &candidate,
            &[11; 32],
            &candidate_device_seed,
            &candidate_device,
            2,
            false,
            &[
                (&voter_a, &voter_a_seed, &voter_a_device),
                (&voter_b, &voter_b_seed, &voter_b_device),
            ],
        );
        let mut revoked_voter_snapshot = snapshot.clone();
        revoked_voter_snapshot.succession_transfers[0] = ScopeSuccessionTransfer {
            from_control_epoch: 2,
            claim: revoked_voter_claim,
            revocations: vec![
                prior_revocation.clone(),
                workspace_revocation(&owner_b, &owner_b_seed, &voter_a.person_id, 3),
            ],
        };
        assert!(validate_scope_authority_at(&revoked_voter_snapshot, TEST_NOW_MS).is_err());

        let fork_claim = succession_claim(
            &owner_b,
            &owner_b_seed,
            &owner_b_device,
            &other_candidate,
            &[13; 32],
            &other_device_seed,
            &other_device,
            2,
            true,
            &[],
        );
        let fork = ScopeAuthoritySnapshot {
            genesis: snapshot.genesis.clone(),
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![transfer_ab],
            succession_transfers: vec![ScopeSuccessionTransfer {
                from_control_epoch: 2,
                claim: fork_claim,
                revocations: vec![],
            }],
        };
        assert!(merge_scope_authority_snapshots_at(Some(&snapshot), &fork, TEST_NOW_MS).is_err());

        let revoked_claim = succession_claim(
            &owner_b,
            &owner_b_seed,
            &owner_b_device,
            &candidate,
            &[11; 32],
            &candidate_device_seed,
            &candidate_device,
            2,
            true,
            &[],
        );
        let mut revoked_snapshot = snapshot;
        revoked_snapshot.succession_transfers[0] = ScopeSuccessionTransfer {
            from_control_epoch: 2,
            claim: revoked_claim,
            revocations: vec![workspace_revocation(
                &owner_b,
                &owner_b_seed,
                &candidate.person_id,
                3,
            )],
        };
        assert!(validate_scope_authority_at(&revoked_snapshot, TEST_NOW_MS).is_err());
    }
    #[test]
    fn signed_ledger_grants_revokes_and_transfers() {
        let (creator, seed, device) = authority([1; 32], [2; 32]);
        let (next, _, _) = authority([3; 32], [4; 32]);
        let g = sign_scope_record(
            &seed,
            ScopeCapabilityGrantPayload {
                kind: "scope-capability-grant".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "member".into(),
                issuer_person_id: creator.person_id.clone(),
                subject_person_id: "member-a".into(),
                capabilities: vec![ScopeCapability::Read, ScopeCapability::Write],
                control_epoch: 1,
            },
            &device,
        )
        .unwrap();
        let t = sign_scope_record(
            &seed,
            ScopeControlTransferPayload {
                kind: "scope-control-transfer".into(),
                version: 1,
                scope_id: "scope-a".into(),
                from_controller_person_id: creator.person_id.clone(),
                to_controller: next.clone(),
                from_control_epoch: 1,
                to_control_epoch: 2,
            },
            &device,
        )
        .unwrap();
        let r = validate_scope_authority(&ScopeAuthoritySnapshot {
            genesis: genesis(&creator, &seed, &device),
            grants: vec![g],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![t],
            succession_transfers: vec![],
        })
        .unwrap();
        assert_eq!(r.creator, creator);
        assert_eq!(r.controller, next);
        assert!(r.allows(&r.controller.person_id, ScopeCapability::Write));
        assert!(r.allows(&r.controller.person_id, ScopeCapability::Invite));
        assert!(r.allows("member-a", ScopeCapability::Write));
    }

    #[test]
    fn merging_a_stale_ledger_preserves_verified_authority_records() {
        let (creator, seed, device) = authority([8; 32], [9; 32]);
        let (next, _, _) = authority([10; 32], [11; 32]);
        let grant = sign_scope_record(
            &seed,
            ScopeCapabilityGrantPayload {
                kind: "scope-capability-grant".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "member".into(),
                issuer_person_id: creator.person_id.clone(),
                subject_person_id: "member-a".into(),
                capabilities: vec![ScopeCapability::Read],
                control_epoch: 1,
            },
            &device,
        )
        .unwrap();
        let revocation = sign_scope_record(
            &seed,
            ScopeCapabilityRevocationPayload {
                kind: "scope-capability-revocation".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "member".into(),
                revoked_by_person_id: creator.person_id.clone(),
                control_epoch: 1,
            },
            &device,
        )
        .unwrap();
        let control_transfer = sign_scope_record(
            &seed,
            ScopeControlTransferPayload {
                kind: "scope-control-transfer".into(),
                version: 1,
                scope_id: "scope-a".into(),
                from_controller_person_id: creator.person_id.clone(),
                to_controller: next,
                from_control_epoch: 1,
                to_control_epoch: 2,
            },
            &device,
        )
        .unwrap();
        let signed_genesis = genesis(&creator, &seed, &device);
        let current = ScopeAuthoritySnapshot {
            genesis: signed_genesis.clone(),
            grants: vec![grant],
            grant_issuers: vec![],
            revocations: vec![revocation],
            control_transfers: vec![control_transfer],
            succession_transfers: vec![],
        };
        let stale = ScopeAuthoritySnapshot {
            genesis: signed_genesis,
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![],
            succession_transfers: vec![],
        };
        let merged = merge_scope_authority_snapshots(Some(&current), &stale).unwrap();
        assert_eq!(merged.grants, current.grants);
        assert_eq!(merged.revocations, current.revocations);
        assert_eq!(merged.control_transfers, current.control_transfers);
        assert!(
            !validate_scope_authority(&merged)
                .unwrap()
                .allows("member-a", ScopeCapability::Read)
        );

        let (other_creator, other_seed, other_device) = authority([12; 32], [13; 32]);
        let other_genesis = ScopeAuthoritySnapshot {
            genesis: genesis(&other_creator, &other_seed, &other_device),
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![],
            succession_transfers: vec![],
        };
        assert!(merge_scope_authority_snapshots(Some(&current), &other_genesis).is_err());

        let (fork_controller, _, _) = authority([14; 32], [15; 32]);
        let fork = sign_scope_record(
            &seed,
            ScopeControlTransferPayload {
                kind: "scope-control-transfer".into(),
                version: 1,
                scope_id: "scope-a".into(),
                from_controller_person_id: creator.person_id.clone(),
                to_controller: fork_controller,
                from_control_epoch: 1,
                to_control_epoch: 2,
            },
            &device,
        )
        .unwrap();
        let forked = ScopeAuthoritySnapshot {
            genesis: current.genesis.clone(),
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![fork],
            succession_transfers: vec![],
        };
        assert!(merge_scope_authority_snapshots(Some(&current), &forked).is_err());
    }
    #[test]
    fn forged_genesis_revocation_and_fork_reject() {
        let (creator, seed, device) = authority([10; 32], [11; 32]);
        let (other, other_seed, other_device) = authority([12; 32], [13; 32]);
        let valid = genesis(&creator, &seed, &device);
        let forged = sign_scope_record(&other_seed, valid.payload.clone(), &other_device).unwrap();
        assert!(
            validate_scope_authority(&ScopeAuthoritySnapshot {
                genesis: forged,
                grants: vec![],
                grant_issuers: vec![],
                revocations: vec![],
                control_transfers: vec![],
                succession_transfers: vec![],
            })
            .is_err()
        );
        let g = sign_scope_record(
            &seed,
            ScopeCapabilityGrantPayload {
                kind: "scope-capability-grant".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "gone".into(),
                issuer_person_id: creator.person_id.clone(),
                subject_person_id: "member".into(),
                capabilities: vec![ScopeCapability::Read],
                control_epoch: 1,
            },
            &device,
        )
        .unwrap();
        let v = sign_scope_record(
            &seed,
            ScopeCapabilityRevocationPayload {
                kind: "scope-capability-revocation".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "gone".into(),
                revoked_by_person_id: creator.person_id.clone(),
                control_epoch: 1,
            },
            &device,
        )
        .unwrap();
        assert!(
            validate_scope_authority(&ScopeAuthoritySnapshot {
                genesis: valid.clone(),
                grants: vec![g.clone()],
                grant_issuers: vec![],
                revocations: vec![v],
                control_transfers: vec![],
                succession_transfers: vec![],
            })
            .unwrap()
            .grants
            .is_empty()
        );
        let transfer = |to: ScopeAuthority| {
            sign_scope_record(
                &seed,
                ScopeControlTransferPayload {
                    kind: "scope-control-transfer".into(),
                    version: 1,
                    scope_id: "scope-a".into(),
                    from_controller_person_id: creator.person_id.clone(),
                    to_controller: to,
                    from_control_epoch: 1,
                    to_control_epoch: 2,
                },
                &device,
            )
            .unwrap()
        };
        assert!(
            validate_scope_authority(&ScopeAuthoritySnapshot {
                genesis: valid,
                grants: vec![g],
                grant_issuers: vec![],
                revocations: vec![],
                control_transfers: vec![transfer(other.clone()), transfer(creator.clone())],
                succession_transfers: vec![],
            })
            .is_err()
        );
    }

    #[test]
    fn delegated_admin_can_only_issue_a_subset_and_cycles_fail_deterministically() {
        let (controller, controller_seed, controller_device) = authority([40; 32], [41; 32]);
        let (admin, admin_seed, admin_device) = authority([42; 32], [43; 32]);
        let root_grant = sign_scope_record(
            &controller_seed,
            ScopeCapabilityGrantPayload {
                kind: "scope-capability-grant".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "admin".into(),
                issuer_person_id: controller.person_id.clone(),
                subject_person_id: admin.person_id.clone(),
                capabilities: vec![
                    ScopeCapability::Read,
                    ScopeCapability::Write,
                    ScopeCapability::Grant,
                ],
                control_epoch: 1,
            },
            &controller_device,
        )
        .unwrap();
        let member_grant = sign_scope_record(
            &admin_seed,
            ScopeCapabilityGrantPayload {
                kind: "scope-capability-grant".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "member".into(),
                issuer_person_id: admin.person_id.clone(),
                subject_person_id: "member".into(),
                capabilities: vec![ScopeCapability::Read, ScopeCapability::Write],
                control_epoch: 1,
            },
            &admin_device,
        )
        .unwrap();
        let valid = ScopeAuthoritySnapshot {
            genesis: genesis(&controller, &controller_seed, &controller_device),
            grants: vec![member_grant],
            grant_issuers: vec![ScopeGrantIssuerEvidence {
                grant_id: "member".into(),
                issuer: admin.clone(),
            }],
            revocations: vec![],
            control_transfers: vec![],
            succession_transfers: vec![],
        };
        assert!(validate_scope_authority(&valid).is_err());
        let mut unordered = valid;
        unordered.grants.push(root_grant);
        assert!(
            validate_scope_authority(&unordered)
                .unwrap()
                .allows("member", ScopeCapability::Write)
        );
        let control = sign_scope_record(
            &admin_seed,
            ScopeCapabilityGrantPayload {
                kind: "scope-capability-grant".into(),
                version: 1,
                scope_id: "scope-a".into(),
                grant_id: "control".into(),
                issuer_person_id: admin.person_id.clone(),
                subject_person_id: "member".into(),
                capabilities: vec![ScopeCapability::Control],
                control_epoch: 1,
            },
            &admin_device,
        )
        .unwrap();
        unordered.grants.push(control);
        unordered.grant_issuers.push(ScopeGrantIssuerEvidence {
            grant_id: "control".into(),
            issuer: admin,
        });
        assert!(validate_scope_authority(&unordered).is_err());
    }

    #[test]
    fn adjacent_product_records_cannot_create_or_replace_authority() {
        let (creator, seed, device) = authority([30; 32], [31; 32]);
        let snapshot = ScopeAuthoritySnapshot {
            genesis: genesis(&creator, &seed, &device),
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![],
            succession_transfers: vec![],
        };
        let mut raw = serde_json::to_value(snapshot).unwrap();
        raw.as_object_mut().unwrap().insert(
            "conversation".into(),
            json!({
                "creatorPersonId": "forged-owner",
                "participants": [{ "personId": "forged-owner", "role": "admin" }]
            }),
        );
        assert!(serde_json::from_value::<ScopeAuthoritySnapshot>(raw).is_err());
    }

    #[test]
    fn genesis_payload_requires_explicit_validated_creator() {
        let (creator, _, _) = authority([33; 32], [34; 32]);
        let payload = create_scope_genesis_payload(ScopeGenesisPayloadInput {
            scope_id: "workspace:board".into(),
            creator,
        })
        .unwrap();
        assert_eq!(payload.kind, "scope-genesis");
        assert_eq!(payload.control_epoch, 1);
    }

    #[test]
    fn genesis_plan_binds_creator_to_document_owner() {
        let (creator, _, _) = authority([39; 32], [40; 32]);
        assert_eq!(
            plan_scope_genesis(ScopeGenesisPlanInput {
                scope_id: "scope-a".into(),
                document_owner_person_id: "different-owner".into(),
                creator: creator.clone(),
            })
            .unwrap_err(),
            "Workspace genesis owner does not match scope creator"
        );
        let payload = plan_scope_genesis(ScopeGenesisPlanInput {
            scope_id: "scope-a".into(),
            document_owner_person_id: creator.person_id.clone(),
            creator,
        })
        .unwrap();
        assert_eq!(payload.control_epoch, 1);
    }

    #[test]
    fn transfer_payload_uses_validated_controller_epoch() {
        let (creator, seed, device) = authority([35; 32], [36; 32]);
        let (next, _, _) = authority([37; 32], [38; 32]);
        let payload = create_scope_control_transfer_payload(ScopeControlTransferPayloadInput {
            snapshot: ScopeAuthoritySnapshot {
                genesis: genesis(&creator, &seed, &device),
                grants: vec![],
                grant_issuers: vec![],
                revocations: vec![],
                control_transfers: vec![],
                succession_transfers: vec![],
            },
            to_controller: next,
        })
        .unwrap();
        assert_eq!(payload.from_controller_person_id, creator.person_id);
        assert_eq!(payload.from_control_epoch, 1);
        assert_eq!(payload.to_control_epoch, 2);
    }
}
