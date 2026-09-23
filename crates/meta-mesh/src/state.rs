use std::collections::HashSet;

use meta_mesh_core::{
    DeviceRoute, DeviceRouteCatalog, DeviceRoutePayload, DurableBatchAck, DurableBatchAckPayload,
    GossipBounds, GossipCandidate, IncomingDocumentChange, OutboxClaim, OutboxClaimInput,
    ReplicaSet, RouteHealth, SignedDeviceRoute, SignedDurableBatchAck, WorkspaceAuthority,
    WorkspaceGrant, WorkspaceOwnershipTransfer, WorkspacePeerRecord, WorkspaceRevocation,
    WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy, WorkspaceSuccessionVote,
    VerifyWorkspaceMemberOptions, IncomingWorkspaceChangeAuthorization,
    WorkspaceWriteAuthorizationSnapshot, WorkspaceAccessDecisionInput,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmMeshAuthenticatedSessions {
    inner: meta_mesh_core::MeshAuthenticatedSessions,
}

#[wasm_bindgen]
impl WasmMeshAuthenticatedSessions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { inner: meta_mesh_core::MeshAuthenticatedSessions::default() }
    }

    pub fn admit(&mut self, handshake: JsValue, snapshot: JsValue, remote_endpoint: &str, now_ms: f64) -> Result<JsValue, JsValue> {
        let handshake: serde_json::Value = from_value(handshake)?;
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let admitted = self.inner.admit(handshake, &snapshot, remote_endpoint,
            i128::from(integer(now_ms, "Invalid member timestamp")?)).map_err(js_error)?;
        to_value(&admitted)
    }

    pub fn peer(&self, workspace_id: &str, remote_endpoint: &str) -> Result<JsValue, JsValue> {
        to_value(&self.inner.peer(workspace_id, remote_endpoint))
    }

    pub fn refresh(&mut self, snapshot: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let evicted = self.inner.refresh(&snapshot,
            i128::from(integer(now_ms, "Invalid member timestamp")?)).map_err(js_error)?;
        to_value(&evicted)
    }

    pub fn remove(&mut self, workspace_id: &str, remote_endpoint: &str) -> bool { self.inner.remove(workspace_id, remote_endpoint) }
    pub fn clear(&mut self) { self.inner.clear(); }
}

#[wasm_bindgen]
pub struct WasmStateCore;

#[wasm_bindgen]
impl WasmStateCore {
    #[wasm_bindgen(js_name = planSuccessionCatalog)]
    pub fn plan_succession_catalog(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::SuccessionCatalogInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_succession_catalog(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planOwnershipMerge)]
    pub fn plan_ownership_merge(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::OwnershipMergeInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_ownership_merge(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = canRemoveWorkspaceDevice)]
    pub fn can_remove_workspace_device(credential: JsValue, local_person_id: &str,
        local_public_key: &str, local_device_id: &str, target_person_id: &str,
        target_device_id: &str, peer_person_id: Option<String>) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        meta_mesh_core::can_remove_workspace_device(&credential, local_person_id, local_public_key,
            local_device_id, target_person_id, target_device_id, peer_person_id.as_deref()).map_err(js_error)
    }

    #[wasm_bindgen(js_name = partitionCredentials)]
    pub fn partition_credentials(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::CredentialPartitionInput = from_value(raw)?;
        to_value(&meta_mesh_core::partition_credentials(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = ownedWorkspaceIds)]
    pub fn owned_workspace_ids(credentials: JsValue, person_id: &str,
        public_key: &str) -> Result<JsValue, JsValue> {
        let credentials: Vec<serde_json::Value> = from_value(credentials)?;
        to_value(&meta_mesh_core::owned_workspace_ids(&credentials, person_id, public_key))
    }

    #[wasm_bindgen(js_name = planAuthorityImport)]
    pub fn plan_authority_import(kind: &str, has_revocations: bool,
        has_transfers: bool) -> Result<JsValue, JsValue> {
        to_value(&meta_mesh_core::plan_authority_import(kind, has_revocations,
            has_transfers).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = meshHandshakeFeatures)]
    pub fn mesh_handshake_features(raw: JsValue) -> Result<JsValue, JsValue> {
        let capabilities: Vec<String> = from_value(raw)?;
        to_value(&meta_mesh_core::mesh_handshake_features(&capabilities))
    }

    #[wasm_bindgen(js_name = credentialBelongsToProfile)]
    pub fn credential_belongs_to_profile(credential: JsValue, person_id: &str,
        public_key: &str) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        meta_mesh_core::credential_belongs_to_profile(&credential, person_id, public_key).map_err(js_error)
    }

    #[wasm_bindgen(js_name = canReuseMemberBundle)]
    pub fn can_reuse_member_bundle(raw: JsValue) -> Result<bool, JsValue> {
        let input: meta_mesh_core::BundleReuseInput = from_value(raw)?;
        Ok(meta_mesh_core::can_reuse_member_bundle(input))
    }

    #[wasm_bindgen(js_name = planSuccessionPolicyRefresh)]
    pub fn plan_succession_policy_refresh(current: JsValue, eligible: JsValue,
        epoch: f64) -> Result<JsValue, JsValue> {
        let current: meta_mesh_core::WorkspaceSuccessionPolicy = from_value(current)?;
        let eligible: Vec<String> = from_value(eligible)?;
        let epoch = u64::try_from(integer(epoch, "Invalid authority epoch")?)
            .map_err(js_error)?;
        to_value(&meta_mesh_core::plan_succession_policy_refresh(&current, &eligible, epoch))
    }

    #[wasm_bindgen(js_name = missingOwnerWorkspaces)]
    pub fn missing_owner_workspaces(owned: JsValue, remote: JsValue) -> Result<JsValue, JsValue> {
        let owned: Vec<String> = from_value(owned)?;
        let remote: serde_json::Value = from_value(remote)?;
        to_value(&meta_mesh_core::missing_owner_workspaces(&owned, &remote))
    }

    #[wasm_bindgen(js_name = planGuestAdvertisements)]
    pub fn plan_guest_advertisements(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::GuestAdvertisementInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_guest_advertisements(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = validateOwnerWorkspaceOffer)]
    pub fn validate_owner_workspace_offer(raw: JsValue, remote_person_id: &str,
        local_person_id: &str) -> Result<String, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        meta_mesh_core::validate_owner_workspace_offer(&raw, remote_person_id, local_person_id).map_err(js_error)
    }

    #[wasm_bindgen(js_name = knowsWorkspaceIssuer)]
    pub fn knows_workspace_issuer(raw: JsValue, issuer_person_id: &str, local_person_id: &str,
        local_device_id: &str) -> Result<bool, JsValue> {
        let raw: Vec<meta_mesh_core::IssuerWorkspaceInput> = from_value(raw)?;
        Ok(meta_mesh_core::knows_workspace_issuer(&raw, issuer_person_id, local_person_id,
            local_device_id))
    }

    #[wasm_bindgen(js_name = nextAccessEpoch)]
    pub fn next_access_epoch(credential: JsValue, issued_grants: JsValue) -> Result<f64, JsValue> {
        let credential: Option<serde_json::Value> = from_value(credential)?;
        let issued_grants: Vec<serde_json::Value> = from_value(issued_grants)?;
        Ok(meta_mesh_core::next_access_epoch(credential.as_ref(), &issued_grants).map_err(js_error)? as f64)
    }

    #[wasm_bindgen(js_name = planInvitationCredential)]
    pub fn plan_invitation_credential(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::InvitationCredentialInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_invitation_credential(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planCatalogMerge)]
    pub fn plan_catalog_merge() -> Result<JsValue, JsValue> {
        to_value(&meta_mesh_core::plan_catalog_merge())
    }

    #[wasm_bindgen(js_name = selectOwnershipTransfer)]
    pub fn select_ownership_transfer(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::TransferSelectionInput = from_value(raw)?;
        to_value(&meta_mesh_core::select_ownership_transfer(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = isWorkspaceEnvelope)]
    pub fn is_workspace_envelope(raw: JsValue) -> Result<bool, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        meta_mesh_core::is_workspace_envelope(&raw).map_err(js_error)
    }

    #[wasm_bindgen(js_name = hasLeftWorkspace)]
    pub fn has_left_workspace(credential: JsValue, person_id: &str, grant: JsValue) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        let grant: Option<serde_json::Value> = from_value(grant)?;
        Ok(meta_mesh_core::has_left_workspace(&credential, person_id, grant.as_ref()))
    }

    #[wasm_bindgen(js_name = isGrantRevoked)]
    pub fn is_grant_revoked(credential: JsValue, person_id: &str, grant: JsValue) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        let grant: Option<serde_json::Value> = from_value(grant)?;
        Ok(meta_mesh_core::is_grant_revoked(&credential, person_id, grant.as_ref()))
    }

    #[wasm_bindgen(js_name = isDeviceRevoked)]
    pub fn is_device_revoked(credential: JsValue, person_id: &str, device_id: &str) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        Ok(meta_mesh_core::is_device_revoked(&credential, person_id, device_id))
    }

    #[wasm_bindgen(js_name = planDialSchedule)]
    pub fn plan_dial_schedule(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::DialScheduleInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_dial_schedule(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planOwnerCertificateRefresh)]
    pub fn plan_owner_certificate_refresh(credential: JsValue, local_person_id: &str,
        certificates: JsValue, updated_at: &str) -> Result<JsValue, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        let certificates: Vec<meta_mesh_core::DeviceCertificate> = from_value(certificates)?;
        to_value(&meta_mesh_core::plan_owner_certificate_refresh(credential, local_person_id,
            certificates, updated_at).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = decideOwnerCredential)]
    pub fn decide_owner_credential(existing_owner_person_id: Option<String>, local_person_id: &str) -> Result<String, JsValue> {
        meta_mesh_core::decide_owner_credential(existing_owner_person_id.as_deref(), local_person_id)
            .map(str::to_string).map_err(js_error)
    }

    #[wasm_bindgen(js_name = planInvitation)]
    pub fn plan_invitation(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::InvitationPlanInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_invitation(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planMemberGrant)]
    pub fn plan_member_grant(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::MemberGrantInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_member_grant(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planAuthorityMerge)]
    pub fn plan_authority_merge(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::AuthorityMergeInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_authority_merge(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planOwnershipAdoption)]
    pub fn plan_ownership_adoption(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::OwnershipAdoptionInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_ownership_adoption(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planSuccessionMerge)]
    pub fn plan_succession_merge(raw: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::SuccessionMergeInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_succession_merge(input,
            i128::from(integer(now_ms, "Invalid authority timestamp")?)).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = encodeWorkspaceSet)]
    pub fn encode_workspace_set(entries: JsValue) -> Result<Vec<u8>, JsValue> {
        let entries: Vec<meta_mesh_core::WorkspaceSetEntry> = from_value(entries)?;
        meta_mesh_core::encode_workspace_set(&entries).map_err(js_error)
    }

    #[wasm_bindgen(js_name = decodeWorkspaceSet)]
    pub fn decode_workspace_set(bytes: &[u8], allowed_ids: JsValue) -> Result<JsValue, JsValue> {
        let allowed_ids: Vec<String> = from_value(allowed_ids)?;
        to_value(&meta_mesh_core::decode_workspace_set(bytes, &allowed_ids).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planAuthorityCommand)]
    pub fn plan_authority_command(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::AuthorityCommandInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_authority_command(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = decideWorkspaceAccess)]
    pub fn decide_workspace_access(raw: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let input: WorkspaceAccessDecisionInput = from_value(raw)?;
        let role = meta_mesh_core::decide_workspace_access(
            &input,
            i128::from(integer(now_ms, "Invalid access decision timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&role)
    }

    #[wasm_bindgen(js_name = validateMeshCatalog)]
    pub fn validate_mesh_catalog(raw: JsValue) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let catalog = meta_mesh_core::validate_mesh_catalog(raw).map_err(js_error)?;
        to_value(&catalog)
    }

    #[wasm_bindgen(js_name = validateMeshHandshake)]
    pub fn validate_mesh_handshake(raw: JsValue, expected_workspace_id: Option<String>) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let handshake = meta_mesh_core::validate_mesh_handshake(raw, expected_workspace_id.as_deref()).map_err(js_error)?;
        to_value(&handshake)
    }

    #[wasm_bindgen(js_name = admitMeshPeer)]
    pub fn admit_mesh_peer(handshake: JsValue, snapshot: JsValue, remote_endpoint: &str, now_ms: f64) -> Result<JsValue, JsValue> {
        let handshake: serde_json::Value = from_value(handshake)?;
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let admitted = meta_mesh_core::admit_mesh_peer(handshake, &snapshot, remote_endpoint,
            i128::from(integer(now_ms, "Invalid member timestamp")?)).map_err(js_error)?;
        to_value(&admitted)
    }

    #[wasm_bindgen(js_name = meshCapabilities)]
    pub fn mesh_capabilities() -> Result<JsValue, JsValue> {
        to_value(&meta_mesh_core::MESH_CAPABILITIES)
    }

    #[wasm_bindgen(js_name = validateMeshCapabilities)]
    pub fn validate_mesh_capabilities(capabilities: JsValue) -> Result<(), JsValue> {
        let capabilities: Vec<String> = from_value(capabilities)?;
        meta_mesh_core::validate_mesh_capabilities(&capabilities).map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceMemberBundle)]
    pub fn verify_workspace_member_bundle(
        raw: JsValue,
        options: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let options: VerifyWorkspaceMemberOptions = from_value(options)?;
        let verified = meta_mesh_core::verify_workspace_member_bundle(
            raw,
            options,
            i128::from(integer(now_ms, "Invalid member timestamp")?),
        ).map_err(js_error)?;
        to_value(&verified)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceGrant)]
    pub fn verify_workspace_grant(
        grant: JsValue,
        workspace_id: &str,
        member_person_id: &str,
        authority: JsValue,
    ) -> Result<JsValue, JsValue> {
        let grant: WorkspaceGrant = from_value(grant)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        let role = meta_mesh_core::verify_workspace_grant(
            &grant,
            workspace_id,
            member_person_id,
            &meta_mesh_core::PublicIdentity {
                person_id: authority.person_id,
                public_key: authority.public_key,
                display_name: String::new(),
            },
            &authority.certificates,
        )
        .map_err(js_error)?;
        to_value(&role)
    }

    #[wasm_bindgen(js_name = admitWorkspaceChangeAuthorization)]
    pub fn admit_workspace_change_authorization(
        authorization: JsValue,
        snapshot: JsValue,
        needed_hashes: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let authorization: IncomingWorkspaceChangeAuthorization = from_value(authorization)?;
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let needed_hashes: Vec<String> = from_value(needed_hashes)?;
        let admitted = meta_mesh_core::admit_workspace_change_authorization(
            &authorization,
            &snapshot,
            &needed_hashes,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        ).map_err(js_error)?;
        to_value(&admitted)
    }

    #[wasm_bindgen(js_name = admitWorkspaceChangeAuthorizations)]
    pub fn admit_workspace_change_authorizations(
        authorization: JsValue,
        snapshot: JsValue,
        needed_hashes: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let authorization: Vec<IncomingWorkspaceChangeAuthorization> = from_value(authorization)?;
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let needed_hashes: Vec<String> = from_value(needed_hashes)?;
        let admitted = meta_mesh_core::admit_workspace_change_authorizations(
            &authorization,
            &snapshot,
            &needed_hashes,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        ).map_err(js_error)?;
        to_value(&admitted)
    }

    #[wasm_bindgen(js_name = hasConflictingOwnershipTransfers)]
    pub fn has_conflicting_ownership_transfers(records: JsValue) -> Result<bool, JsValue> {
        let records: Vec<serde_json::Value> = from_value(records)?;
        Ok(meta_mesh_core::has_conflicting_ownership_transfers(
            &records,
        ))
    }

    #[wasm_bindgen(js_name = planOwnershipTransitions)]
    pub fn plan_ownership_transitions(
        records: JsValue,
        initial_owner_person_id: String,
        initial_epoch: f64,
    ) -> Result<JsValue, JsValue> {
        let records: Vec<serde_json::Value> = from_value(records)?;
        to_value(&meta_mesh_core::plan_ownership_transitions(
            &records,
            &initial_owner_person_id,
            unsigned_integer(initial_epoch, "Invalid ownership epoch")?,
        ))
    }

    #[wasm_bindgen(js_name = nextVerifiedOwnershipTransition)]
    pub fn next_verified_ownership_transition(
        records: JsValue,
        workspace_id: &str,
        current_owner: JsValue,
        current_epoch: f64,
        revoked_people: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let records: Vec<serde_json::Value> = from_value(records)?;
        let current_owner: WorkspaceAuthority = from_value(current_owner)?;
        let revoked_people: Vec<String> = from_value(revoked_people)?;
        let plan = meta_mesh_core::next_verified_ownership_transition(
            &records,
            workspace_id,
            &current_owner,
            unsigned_integer(current_epoch, "Invalid ownership epoch")?,
            &revoked_people.into_iter().collect::<HashSet<_>>(),
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        ).map_err(js_error)?;
        to_value(&plan)
    }

    #[wasm_bindgen(js_name = summarizeSuccession)]
    pub fn summarize_succession(
        policy: JsValue,
        claims: JsValue,
        votes: JsValue,
        transfers: JsValue,
        revocations: JsValue,
        epoch: f64,
    ) -> Result<JsValue, JsValue> {
        let policy: Option<serde_json::Value> = optional_value(policy)?;
        let claims: Vec<serde_json::Value> = from_value(claims)?;
        let votes: Vec<serde_json::Value> = from_value(votes)?;
        let transfers: Vec<serde_json::Value> = from_value(transfers)?;
        let revocations: Vec<serde_json::Value> = from_value(revocations)?;
        to_value(&meta_mesh_core::summarize_succession(policy.as_ref(), &claims, &votes, &transfers,
            &revocations, unsigned_integer(epoch, "Invalid succession epoch")?).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = eligibleEditorPersonIds)]
    pub fn eligible_editor_person_ids(peers: JsValue) -> Result<JsValue, JsValue> {
        let peers: Vec<serde_json::Value> = from_value(peers)?;
        to_value(&meta_mesh_core::eligible_editor_person_ids(&peers))
    }

    #[wasm_bindgen(js_name = canonicalRevocations)]
    pub fn canonical_revocations(records: JsValue) -> Result<JsValue, JsValue> {
        let records: Vec<serde_json::Value> = from_value(records)?;
        to_value(&meta_mesh_core::canonical_revocations(&records))
    }

    #[wasm_bindgen(js_name = verifyWorkspaceDeparture)]
    pub fn verify_workspace_departure(record: JsValue, workspace_id: &str, authority: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let record: meta_mesh_core::authority::WorkspaceDeparture = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::authority::verify_workspace_departure(&record, workspace_id, &authority,
            i128::from(integer(now_ms, "Invalid authority timestamp")?)).map_err(js_error)?;
        to_value(&record)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceDeviceRevocation)]
    pub fn verify_workspace_device_revocation(record: JsValue, workspace_id: &str,
        owner_person_id: &str, authority: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let record: meta_mesh_core::authority::WorkspaceDeviceRevocation = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::authority::verify_workspace_device_revocation(&record, workspace_id,
            owner_person_id, &authority, i128::from(integer(now_ms, "Invalid authority timestamp")?)).map_err(js_error)?;
        to_value(&record)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceRevocation)]
    pub fn verify_workspace_revocation(
        record: JsValue,
        workspace_id: &str,
        authority: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let record: WorkspaceRevocation = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::verify_workspace_revocation(
            &record,
            workspace_id,
            &authority,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&record)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceOwnershipTransfer)]
    pub fn verify_workspace_ownership_transfer(
        record: JsValue,
        workspace_id: &str,
        authority: JsValue,
        minimum_epoch: f64,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let record: WorkspaceOwnershipTransfer = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::verify_workspace_ownership_transfer(
            &record,
            workspace_id,
            &authority,
            unsigned_integer(minimum_epoch, "Invalid ownership epoch")?,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&record)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceSuccessionPolicy)]
    pub fn verify_workspace_succession_policy(
        policy: JsValue,
        workspace_id: &str,
        authority: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let policy: WorkspaceSuccessionPolicy = from_value(policy)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::verify_workspace_succession_policy(
            &policy,
            workspace_id,
            &authority,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&policy)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceSuccessionVote)]
    pub fn verify_workspace_succession_vote(
        vote: JsValue,
        policy: JsValue,
        candidate_person_id: &str,
        authority: JsValue,
        revoked: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let vote: WorkspaceSuccessionVote = from_value(vote)?;
        let policy: WorkspaceSuccessionPolicy = from_value(policy)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        let revoked: std::collections::HashSet<String> = from_value(revoked)?;
        meta_mesh_core::verify_workspace_succession_vote(
            &vote,
            &policy,
            candidate_person_id,
            &authority,
            &revoked,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&vote)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceSuccessionClaim)]
    pub fn verify_workspace_succession_claim(
        claim: JsValue,
        workspace_id: &str,
        authority: JsValue,
        minimum_epoch: f64,
        revoked: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let claim: WorkspaceSuccessionClaim = from_value(claim)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        let revoked: std::collections::HashSet<String> = from_value(revoked)?;
        meta_mesh_core::verify_workspace_succession_claim(
            &claim,
            workspace_id,
            &authority,
            unsigned_integer(minimum_epoch, "Invalid succession epoch")?,
            &revoked,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&claim)
    }

    #[wasm_bindgen(js_name = planChangeAdmission)]
    pub fn plan_change_admission(
        document_id: &str,
        changes: JsValue,
        verified_at: &str,
    ) -> Result<JsValue, JsValue> {
        let changes: Vec<IncomingDocumentChange> = from_value(changes)?;
        let plan = meta_mesh_core::plan_change_admission(document_id, changes, verified_at)
            .map_err(js_error)?;
        to_value(&plan)
    }

    #[wasm_bindgen(js_name = transitionOutboxClaim)]
    pub fn transition_outbox_claim(current: JsValue, input: JsValue) -> Result<JsValue, JsValue> {
        let current: Option<OutboxClaim> = if current.is_null() || current.is_undefined() {
            None
        } else {
            Some(from_value(current)?)
        };
        let input: OutboxClaimInput = from_value(input)?;
        let transition =
            meta_mesh_core::transition_outbox_claim(current, input).map_err(js_error)?;
        to_value(&transition)
    }

    #[wasm_bindgen(js_name = mergePeerRecords)]
    pub fn merge_peer_records(existing: JsValue, incoming: JsValue) -> Result<JsValue, JsValue> {
        let existing: WorkspacePeerRecord = from_value(existing)?;
        let incoming: WorkspacePeerRecord = from_value(incoming)?;
        let merged = meta_mesh_core::merge_peer_records(&existing, &incoming).map_err(js_error)?;
        to_value(&merged)
    }

    #[wasm_bindgen(js_name = reconcileReplicaSets)]
    pub fn reconcile_replica_sets(left: JsValue, right: JsValue) -> Result<JsValue, JsValue> {
        let left: ReplicaSet = from_value(left)?;
        let right: ReplicaSet = from_value(right)?;
        let merged = meta_mesh_core::reconcile_replica_sets(&left, &right).map_err(js_error)?;
        to_value(&merged)
    }

    #[wasm_bindgen(js_name = selectScopedNeighbors)]
    pub fn select_scoped_neighbors(
        local_device_id: &str,
        candidates: JsValue,
        bounds: JsValue,
        now_ms: f64,
        rotation: u32,
    ) -> Result<Vec<String>, JsValue> {
        let candidates: Vec<GossipCandidate> = from_value(candidates)?;
        let bounds: GossipBounds = from_value(bounds)?;
        meta_mesh_core::select_scoped_neighbors(
            local_device_id,
            &candidates,
            &bounds,
            integer(now_ms, "Invalid gossip timestamp")?,
            rotation,
        )
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = validateDeviceRoute)]
    pub fn validate_device_route(route: JsValue) -> Result<(), JsValue> {
        let route: DeviceRoute = from_value(route)?;
        meta_mesh_core::validate_device_route(&route).map_err(js_error)
    }

    #[wasm_bindgen(js_name = validateDeviceRoutePayload)]
    pub fn validate_device_route_payload(payload: JsValue) -> Result<(), JsValue> {
        let payload: DeviceRoutePayload = from_value(payload)?;
        meta_mesh_core::validate_device_route_payload(&payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = validateDurableAckPayload)]
    pub fn validate_durable_ack_payload(payload: JsValue) -> Result<(), JsValue> {
        let payload: DurableBatchAckPayload = from_value(payload)?;
        meta_mesh_core::validate_durable_ack_payload(&payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = signDeviceRoute)]
    pub fn sign_device_route(
        seed: &[u8],
        signer_key_id: &str,
        payload: JsValue,
    ) -> Result<JsValue, JsValue> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| js_error("Private key seed must contain 32 bytes"))?;
        let payload: DeviceRoutePayload = from_value(payload)?;
        let signed =
            meta_mesh_core::sign_device_route(&seed, signer_key_id, payload).map_err(js_error)?;
        to_value(&signed)
    }

    #[wasm_bindgen(js_name = verifyDeviceRoute)]
    pub fn verify_device_route(
        envelope: JsValue,
        public_key: &str,
        now_ms: f64,
        allow_expired: bool,
    ) -> Result<JsValue, JsValue> {
        let envelope: SignedDeviceRoute = from_value(envelope)?;
        let route = meta_mesh_core::verify_device_route(
            &envelope,
            public_key,
            i128::from(integer(now_ms, "Invalid route timestamp")?),
            allow_expired,
        )
        .map_err(js_error)?;
        to_value(&route)
    }

    #[wasm_bindgen(js_name = signDurableAck)]
    pub fn sign_durable_ack(
        seed: &[u8],
        signer_key_id: &str,
        payload: JsValue,
    ) -> Result<JsValue, JsValue> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| js_error("Private key seed must contain 32 bytes"))?;
        let payload: DurableBatchAckPayload = from_value(payload)?;
        let signed = meta_mesh_core::sign_durable_batch_ack(&seed, signer_key_id, payload)
            .map_err(js_error)?;
        to_value(&signed)
    }

    #[wasm_bindgen(js_name = verifyDurableAck)]
    pub fn verify_durable_ack(envelope: JsValue, public_key: &str) -> Result<JsValue, JsValue> {
        let envelope: SignedDurableBatchAck = from_value(envelope)?;
        let ack =
            meta_mesh_core::verify_durable_batch_ack(&envelope, public_key).map_err(js_error)?;
        to_value(&ack)
    }

    #[wasm_bindgen(js_name = durableAckMatches)]
    pub fn durable_ack_matches(
        ack: JsValue,
        batch: JsValue,
        target_device_id: &str,
    ) -> Result<bool, JsValue> {
        let ack: DurableBatchAck = from_value(ack)?;
        let batch = from_value(batch)?;
        Ok(meta_mesh_core::durable_ack_matches(
            &ack,
            &batch,
            target_device_id,
        ))
    }

    #[wasm_bindgen(js_name = orderDeliveryRoutes)]
    pub fn order_delivery_routes(
        target_device_id: &str,
        routes: JsValue,
    ) -> Result<JsValue, JsValue> {
        let routes: Vec<RouteHealth> = from_value(routes)?;
        let ordered =
            meta_mesh_core::order_delivery_routes(target_device_id, &routes).map_err(js_error)?;
        to_value(&ordered)
    }
}

#[wasm_bindgen]
pub struct WasmDeviceRouteCatalog {
    inner: DeviceRouteCatalog,
}

#[wasm_bindgen]
impl WasmDeviceRouteCatalog {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: DeviceRouteCatalog::default(),
        }
    }

    pub fn admit(&mut self, route: JsValue) -> Result<JsValue, JsValue> {
        let route: DeviceRoute = from_value(route)?;
        let admitted = self.inner.admit(route).map_err(js_error)?;
        to_value(&admitted)
    }

    #[wasm_bindgen(js_name = routesFor)]
    pub fn routes_for(&self, scope_id: &str, device_id: &str) -> Result<JsValue, JsValue> {
        to_value(&self.inner.routes_for(scope_id, device_id))
    }
}

impl Default for WasmDeviceRouteCatalog {
    fn default() -> Self {
        Self::new()
    }
}

fn from_value<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(js_error)
}

fn optional_value<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<Option<T>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        from_value(value).map(Some)
    }
}

fn to_value(value: &impl serde::Serialize) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_maps_as_objects(true)
                .serialize_missing_as_null(true),
        )
        .map_err(js_error)
}

fn integer(value: f64, message: &str) -> Result<i64, JsValue> {
    if value.is_finite()
        && value.fract() == 0.0
        && value >= i64::MIN as f64
        && value <= i64::MAX as f64
    {
        Ok(value as i64)
    } else {
        Err(js_error(message))
    }
}

fn unsigned_integer(value: f64, message: &str) -> Result<u64, JsValue> {
    if value.is_finite() && value.fract() == 0.0 && value >= 0.0 && value <= u64::MAX as f64 {
        Ok(value as u64)
    } else {
        Err(js_error(message))
    }
}

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}
