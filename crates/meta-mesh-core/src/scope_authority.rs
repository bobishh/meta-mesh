//! Explicit, platform-neutral authority ledger for any replicated scope.
//! Product documents never supply implicit creator, controller, or recovery data.

use crate::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, PublicIdentity, SignedEnvelope, public_key_id,
    sign_json_envelope, verify_device_certificate_chain, verify_signed_envelope,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub const SCOPE_AUTHORITY_VERSION: u8 = 1;
pub const MAX_SCOPE_CAPABILITIES: usize = 16;
pub const MAX_SCOPE_GRANTS: usize = 4_096;
pub const MAX_SCOPE_REVOCATIONS: usize = 4_096;
pub const MAX_SCOPE_CONTROL_TRANSFERS: usize = 128;

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
    let authority = validate_scope_authority(&input.snapshot)?;
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
}

/// Merge authenticated gossip without letting a stale peer erase signed
/// authority evidence already held locally. A changed genesis or a fork in the
/// combined ledger is rejected by validation.
pub fn merge_scope_authority_snapshots(
    current: Option<&ScopeAuthoritySnapshot>,
    incoming: &ScopeAuthoritySnapshot,
) -> Result<ScopeAuthoritySnapshot, String> {
    validate_scope_authority(incoming)?;
    let Some(current) = current else {
        return Ok(incoming.clone());
    };
    validate_scope_authority(current)?;
    if current.genesis != incoming.genesis {
        return Err("Scope authority genesis cannot change".into());
    }
    let mut merged = current.clone();
    append_unique(&mut merged.grants, &incoming.grants);
    append_unique(&mut merged.grant_issuers, &incoming.grant_issuers);
    append_unique(&mut merged.revocations, &incoming.revocations);
    append_unique(&mut merged.control_transfers, &incoming.control_transfers);
    validate_scope_authority(&merged)?;
    Ok(merged)
}

fn append_unique<T: Clone + PartialEq>(current: &mut Vec<T>, incoming: &[T]) {
    for record in incoming {
        if !current.contains(record) {
            current.push(record.clone());
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
    if snapshot.grants.len() > MAX_SCOPE_GRANTS
        || snapshot.revocations.len() > MAX_SCOPE_REVOCATIONS
        || snapshot.control_transfers.len() > MAX_SCOPE_CONTROL_TRANSFERS
    {
        return Err("Scope authority record limit exceeded".into());
    }
    let genesis = verify_scope_genesis(&snapshot.genesis)?;
    let mut controller = genesis.creator.clone();
    let mut epoch = genesis.control_epoch;
    let mut controllers = BTreeMap::new();
    controllers.insert(epoch, controller.clone());
    let mut pending = snapshot.control_transfers.iter().collect::<Vec<_>>();
    while !pending.is_empty() {
        let matching = pending
            .iter()
            .enumerate()
            .filter(|(_, r)| r.payload.from_control_epoch == epoch)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err("Scope control chain is forked or has a gap".into());
        }
        let transfer = pending.remove(matching[0]);
        verify_scope_control_transfer(transfer, &genesis.scope_id, &controller)?;
        if transfer.payload.to_control_epoch
            != epoch.checked_add(1).ok_or("Scope control epoch overflow")?
        {
            return Err("Scope control transfer epoch is invalid".into());
        }
        controller = transfer.payload.to_controller.clone();
        epoch = transfer.payload.to_control_epoch;
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
    use crate::{DeviceCertificatePayload, public_key_from_seed, sign_device_certificate};
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
        };
        let stale = ScopeAuthoritySnapshot {
            genesis: signed_genesis,
            grants: vec![],
            grant_issuers: vec![],
            revocations: vec![],
            control_transfers: vec![],
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
                control_transfers: vec![]
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
                control_transfers: vec![]
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
                control_transfers: vec![transfer(other.clone()), transfer(creator.clone())]
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
            },
            to_controller: next,
        })
        .unwrap();
        assert_eq!(payload.from_controller_person_id, creator.person_id);
        assert_eq!(payload.from_control_epoch, 1);
        assert_eq!(payload.to_control_epoch, 2);
    }
}
