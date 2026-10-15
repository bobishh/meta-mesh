use std::collections::HashSet;

use js_sys::{Function, Map, Uint8Array};

use meta_mesh_core::{
    DeviceRoute, DeviceRouteCatalog, DeviceRoutePayload, DurableBatchAck, DurableBatchAckPayload,
    GossipBounds, GossipCandidate, IncomingDocumentChange, IncomingWorkspaceChangeAuthorization,
    OutboxClaim, OutboxClaimInput, ReplicaSet, RouteHealth, SignedDeviceRoute,
    SignedDurableBatchAck, VerifyWorkspaceMemberOptions, WorkspaceAccessDecisionInput,
    WorkspaceAuthority, WorkspaceGrant, WorkspaceOwnershipTransfer, WorkspacePeerRecord,
    WorkspaceRevocation, WorkspaceSuccessionClaim, WorkspaceSuccessionPolicy,
    WorkspaceSuccessionVote, WorkspaceWriteAuthorizationSnapshot,
};
use wasm_bindgen::prelude::*;

const MAX_WASM_HISTORY_CAPTURE_BYTES: usize = 512 * 1024 * 1024;

#[wasm_bindgen]
pub struct WasmMeshAuthenticatedSessions {
    inner: meta_mesh_core::MeshAuthenticatedSessions,
}

#[wasm_bindgen]
impl WasmMeshAuthenticatedSessions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: meta_mesh_core::MeshAuthenticatedSessions::default(),
        }
    }

    pub fn admit(
        &mut self,
        handshake: JsValue,
        snapshot: JsValue,
        remote_endpoint: &str,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let handshake: serde_json::Value = from_value(handshake)?;
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let admitted = self
            .inner
            .admit(
                handshake,
                &snapshot,
                remote_endpoint,
                i128::from(integer(now_ms, "Invalid member timestamp")?),
            )
            .map_err(js_error)?;
        to_value(&admitted)
    }

    pub fn peer(&self, workspace_id: &str, remote_endpoint: &str) -> Result<JsValue, JsValue> {
        to_value(&self.inner.peer(workspace_id, remote_endpoint))
    }

    pub fn refresh(&mut self, snapshot: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let evicted = self
            .inner
            .refresh(
                &snapshot,
                i128::from(integer(now_ms, "Invalid member timestamp")?),
            )
            .map_err(js_error)?;
        to_value(&evicted)
    }

    pub fn remove(&mut self, workspace_id: &str, remote_endpoint: &str) -> bool {
        self.inner.remove(workspace_id, remote_endpoint)
    }
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

#[wasm_bindgen]
pub struct WasmStateCore;

/// Native-verified cold baseline candidate. Construction performs archive,
/// control, Owner, frontier, and coverage verification; callers cannot build
/// this value from serialized claims.
#[wasm_bindgen]
pub struct WasmVerifiedReceivedHistoryBaseline {
    inner: meta_mesh_core::history_baseline::VerifiedReceivedHistoryBaseline,
    encrypted_objects: Map,
    plaintext_objects: Map,
}

/// Native full-history preparation. This opaque token is produced only after
/// causal admission and owner/device-chain validation.
#[wasm_bindgen]
pub struct WasmVerifiedHistoryPreparation {
    inner: Option<meta_mesh_core::history_preparation::VerifiedHistoryPreparation>,
}

/// Native capture of the exact source evidence retained by a preparation.
#[wasm_bindgen]
pub struct WasmVerifiedHistoryArchiveCapture {
    inner: meta_mesh_core::history_capture::VerifiedHistoryArchiveCapture,
}

#[wasm_bindgen]
pub struct WasmVerifiedHistoryArchiveStorage {
    inner: meta_mesh_core::history_capture::VerifiedHistoryArchiveStorage,
}

#[wasm_bindgen]
pub struct WasmVerifiedHistoryArchiveCoverage {
    inner: meta_mesh_core::history_archive_coverage::VerifiedHistoryArchiveCoverage,
}

#[wasm_bindgen]
pub struct WasmVerifiedHistoryBaselineAttestation {
    inner: meta_mesh_core::history_baseline::VerifiedHistoryBaselineAttestation,
}

struct WasmEncryptedHistoryArchiveWriter {
    scope: meta_mesh_core::history_archive_crypto::HistoryArchiveEncryptionScope,
    nonce_source: Function,
    sink: Function,
    ensure_current: Function,
    bytes_written: usize,
    object_count: usize,
    seen_nonces: HashSet<[u8; 12]>,
}

impl WasmEncryptedHistoryArchiveWriter {
    fn ensure_current(&self) -> Result<(), String> {
        let result = self.ensure_current.call0(&JsValue::NULL)
            .map_err(|_| "History archive writer guard rejected current identity or authority")?;
        if !result.is_undefined() { return Err("History archive writer guard must return no value".into()); }
        Ok(())
    }
}

impl meta_mesh_core::history_capture::HistoryArchiveWriter for WasmEncryptedHistoryArchiveWriter {
    fn write(&mut self, object_id: &str, plaintext: &[u8], binding: &meta_mesh_core::history_capture::HistoryArchiveObjectBinding) -> Result<(), String> {
        self.ensure_current()?;
        self.object_count = self.object_count.checked_add(1).ok_or("History archive object count overflow")?;
        self.bytes_written = self.bytes_written.checked_add(plaintext.len()).ok_or("History archive size overflow")?;
        if self.object_count > 1_048_576 || self.bytes_written > MAX_WASM_HISTORY_CAPTURE_BYTES {
            return Err("History archive exceeds the bounded Native sink limit".into());
        }
        let nonce_value = self.nonce_source.call0(&JsValue::NULL)
            .map_err(|_| "History archive nonce source failed")?;
        let nonce_array = nonce_value.dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| "History archive nonce source must return 12 random bytes")?;
        if nonce_array.length() != 12 { return Err("History archive nonce source must return 12 random bytes".into()); }
        let nonce: [u8; 12] = nonce_array.to_vec().try_into().map_err(|_| "Invalid history archive nonce")?;
        if !self.seen_nonces.insert(nonce) { return Err("History archive nonce source repeated a nonce".into()); }
        let encryption_binding = meta_mesh_core::history_archive_crypto::HistoryArchiveEncryptionBinding {
            workspace_id: binding.context.workspace_id.clone(), history_epoch: binding.context.history_epoch,
            index_id: binding.context.index_id.clone(), object_id: object_id.to_owned(),
            object_kind: binding.object_kind.clone(), part_index: binding.part_index, part_count: binding.part_count,
        };
        let (ciphertext_id, encrypted) = meta_mesh_core::history_archive_crypto::seal_history_archive_object(
            &self.scope, &encryption_binding, &nonce, plaintext)?;
        let binding_js = to_value(&encryption_binding).map_err(|_| "Invalid Native history object binding")?;
        let object_js = to_value(&encrypted).map_err(|_| "Invalid encrypted history object")?;
        let result = self.sink.call3(&JsValue::NULL, &JsValue::from_str(&ciphertext_id), &binding_js, &object_js)
            .map_err(|_| "History archive sink rejected encrypted object")?;
        if !result.is_undefined() { return Err("History archive sink must queue a durable write synchronously".into()); }
        self.ensure_current()
    }
}

#[wasm_bindgen]
impl WasmVerifiedReceivedHistoryBaseline {
    #[wasm_bindgen(js_name = originalJson)]
    pub fn original_json(&self) -> Vec<u8> {
        self.inner.original_json().to_vec()
    }

    pub fn document(&self) -> Vec<u8> {
        self.inner.document().to_vec()
    }

    #[wasm_bindgen(js_name = controlJson)]
    pub fn control_json(&self) -> Vec<u8> {
        self.inner.control_json().to_vec()
    }

    pub fn envelope(&self) -> Result<JsValue, JsValue> {
        to_value(self.inner.envelope())
    }

    pub fn owner(&self) -> Result<JsValue, JsValue> {
        to_value(self.inner.owner())
    }

    /// Exact encrypted evidence needed to independently reverify this baseline
    /// after restart, including when the device is offline.
    #[wasm_bindgen(js_name = encryptedObjects)]
    pub fn encrypted_objects(&self) -> Map {
        self.encrypted_objects.clone()
    }
    #[wasm_bindgen(js_name = plaintextObjects)]
    pub fn plaintext_objects(&self) -> Map { self.plaintext_objects.clone() }
    #[wasm_bindgen(js_name = storageVerification)]
    pub fn storage_verification(&self) -> String { self.inner.storage_verification().into() }

    /// Convert only a Native-reverified baseline into an opaque proposal parent.
    #[wasm_bindgen(js_name = proposalParent)]
    pub fn proposal_parent(&self) -> WasmVerifiedHistoryBaselineAttestation {
        WasmVerifiedHistoryBaselineAttestation { inner: self.inner.proposal_parent() }
    }

    /// Verify one original entity version against this opaque baseline's signed archive, never a host root flag.
    #[wasm_bindgen(js_name = readArchivedEntityVersion)]
    pub fn read_archived_entity_version(&self, scope_id: &str, key_epoch: f64, content_key: &[u8], entity_id: &str,
        change_hash: &str, objects: Map, ensure_current: Function) -> Result<JsValue, JsValue> {
        if content_key.len() != 32 || objects.size() > 1_048_576 { return Err(js_error("Selected archived history exceeds its scope or object bounds")); }
        let mut key = [0u8; 32]; key.copy_from_slice(content_key);
        let scope = meta_mesh_core::history_archive_crypto::HistoryArchiveEncryptionScope {
            scope_id: scope_id.into(), key_epoch: unsigned_integer(key_epoch, "Invalid selected history key epoch")?, key };
        let mut reader = WasmHistoryArchiveReader { objects, ensure_current, bytes_read: 0, object_count: 0 };
        let version = meta_mesh_core::history_capture::read_archived_entity_version(&self.inner, &scope, entity_id, change_hash, &mut reader).map_err(js_error)?;
        to_value(&version)
    }
    #[wasm_bindgen(js_name = readArchivedPeerEntityVersion)]
    pub fn read_archived_peer_entity_version(&self, entity_id: &str, change_hash: &str, objects: Map, ensure_current: Function) -> Result<JsValue, JsValue> {
        if objects.size() > 1_048_576 { return Err(js_error("Selected peer history object set exceeds limit")); }
        let mut reader = WasmPlaintextHistoryReader { objects, retained: Map::new(), ensure_current,
            bytes_read: 0, object_count: 0, maximum_bytes: MAX_WASM_HISTORY_CAPTURE_BYTES, maximum_objects: 1_048_576 };
        to_value(&meta_mesh_core::history_capture::read_archived_peer_entity_version(&self.inner, entity_id, change_hash, &mut reader).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = verifyPreviousBaseline)]
    pub fn verify_previous_baseline(&self, previous: &WasmVerifiedReceivedHistoryBaseline) -> Result<(), JsValue> {
        self.inner.verify_previous_baseline(&previous.inner).map_err(js_error)
    }

    /// Acknowledge only byte-exact originals already retained by this signed archive.
    #[wasm_bindgen(js_name = verifyArchivedSnapshot)]
    pub fn verify_archived_snapshot(&self, scope_id: &str, key_epoch: f64, content_key: &[u8], document: &[u8],
        objects: Map, ensure_current: Function) -> Result<(), JsValue> {
        if content_key.len() != 32 || objects.size() > 1_048_576 { return Err(js_error("Historical snapshot scope or object bound exceeded")); }
        let mut key = [0u8; 32]; key.copy_from_slice(content_key);
        let scope = meta_mesh_core::history_archive_crypto::HistoryArchiveEncryptionScope {
            scope_id: scope_id.into(), key_epoch: unsigned_integer(key_epoch, "Invalid historical snapshot epoch")?, key };
        let mut reader = WasmHistoryArchiveReader { objects, ensure_current, bytes_read: 0, object_count: 0 };
        meta_mesh_core::history_capture::verify_archived_snapshot(&self.inner, &scope, document, &mut reader).map_err(js_error)
    }

    /// Admit ordinary changes descended from this exact verified compact basis.
    /// The host cannot supply or serialize a trusted-basis marker.
    #[wasm_bindgen(js_name = admitTail)]
    pub fn admit_tail(&self, raw: JsValue) -> Result<JsValue, JsValue> {
        let input = strict_causal_input(raw)?;
        to_value(&self.inner.admit_tail(input).map_err(js_error)?)
    }
}

#[wasm_bindgen]
impl WasmVerifiedHistoryPreparation {
    /// Freeze original JSON bytes against the Native-prepared typed history.
    #[wasm_bindgen(js_name = captureOriginals)]
    pub fn capture_originals(
        &mut self,
        history_epoch: f64,
        control_json: &[u8],
        authorization_json_raw: JsValue,
    ) -> Result<WasmVerifiedHistoryArchiveCapture, JsValue> {
        let authorization_json: Vec<Vec<u8>> = from_value(authorization_json_raw)?;
        let preparation = self.inner.take().ok_or_else(|| js_error("History preparation was already consumed"))?;
        let capture = meta_mesh_core::history_capture::capture_workspace_history(preparation,
            unsigned_integer(history_epoch, "Invalid history archive epoch")?,
            meta_mesh_core::history_capture::HistoryOriginalEvidence { control_json: control_json.to_vec(), authorization_json })
            .map_err(js_error)?;
        Ok(WasmVerifiedHistoryArchiveCapture { inner: capture })
    }
}

#[wasm_bindgen]
impl WasmVerifiedHistoryArchiveCapture {
    /// Build and encrypt the Native catalogue. `sink(ciphertextId,binding,object)`
    /// must synchronously enqueue an encrypted-object write in the caller's
    /// durable transaction; it must not return a promise or plaintext.
    #[wasm_bindgen(js_name = writeEncryptedCatalogue)]
    pub fn write_encrypted_catalogue(
        &self,
        scope_id: &str,
        key_epoch: f64,
        content_key: &[u8],
        nonce_source: Function,
        sink: Function,
        ensure_current: Function,
    ) -> Result<JsValue, JsValue> {
        if content_key.len() != 32 { return Err(js_error("Invalid history archive content key")); }
        let mut key = [0u8; 32]; key.copy_from_slice(content_key);
        let scope = meta_mesh_core::history_archive_crypto::HistoryArchiveEncryptionScope {
            scope_id: scope_id.to_owned(), key_epoch: unsigned_integer(key_epoch, "Invalid history archive key epoch")?, key,
        };
        let mut writer = WasmEncryptedHistoryArchiveWriter { scope, nonce_source, sink, ensure_current,
            bytes_written: 0, object_count: 0, seen_nonces: HashSet::new() };
        let catalogue = self.inner.write_catalogue(&mut writer).map_err(js_error)?;
        to_value(&catalogue)
    }

    /// Create a deterministic current-state rebase only from this verified preparation.
    #[wasm_bindgen(js_name = rebase)]
    pub fn rebase(&self, history_epoch: f64, transition_id: &str) -> Result<WasmVerifiedHistoryRebase, JsValue> {
        let rebase = self.inner.preparation().rebase(
            unsigned_integer(history_epoch, "Invalid history archive epoch")?, transition_id).map_err(js_error)?;
        Ok(WasmVerifiedHistoryRebase { inner: rebase })
    }

    /// Independently derive the catalogue again and verify every encrypted
    /// data/directory locator against the supplied ciphertext objects.
    #[wasm_bindgen(js_name = verifyStorageDirectory)]
    pub fn verify_storage_directory(&self, scope_id: &str, key_epoch: f64, content_key: &[u8],
        locator_root_raw: JsValue, objects: Map, ensure_current: Function) -> Result<WasmVerifiedHistoryArchiveStorage, JsValue> {
        if content_key.len() != 32 || objects.size() > 1_048_576 {
            return Err(js_error("Invalid or oversized Native archive storage evidence"));
        }
        let mut key = [0u8; 32]; key.copy_from_slice(content_key);
        let scope = meta_mesh_core::history_archive_crypto::HistoryArchiveEncryptionScope {
            scope_id: scope_id.to_owned(), key_epoch: unsigned_integer(key_epoch, "Invalid history archive key epoch")?, key,
        };
        let root: meta_mesh_core::history_locator::HistoryArchiveLocatorRoot = strict_protocol_value(locator_root_raw)?;
        let mut reader = WasmHistoryArchiveReader { objects, ensure_current, bytes_read: 0, object_count: 0 };
        let verified = self.inner.verify_storage_directory(&scope, &root, &mut reader).map_err(js_error)?;
        Ok(WasmVerifiedHistoryArchiveStorage { inner: verified })
    }

    /// Return the exact v2 Owner payload after full Native preparation,
    /// encrypted archive correspondence, storage coverage, and trusted scope
    /// authority have been joined. Signing is deliberately a separate step.
    #[wasm_bindgen(js_name = ownerAttestedProposal)]
    pub fn owner_attested_proposal(&self, rebase: &WasmVerifiedHistoryRebase,
        coverage: &WasmVerifiedHistoryArchiveCoverage, scope_authority_raw: JsValue) -> Result<JsValue, JsValue> {
        history_owner_proposal(self, rebase, coverage, scope_authority_raw, None)
    }
    #[wasm_bindgen(js_name = ownerAttestedProposalFromParent)]
    pub fn owner_attested_proposal_from_parent(&self, rebase: &WasmVerifiedHistoryRebase,
        coverage: &WasmVerifiedHistoryArchiveCoverage, scope_authority_raw: JsValue,
        previous: &WasmVerifiedHistoryBaselineAttestation) -> Result<JsValue, JsValue> {
        history_owner_proposal(self, rebase, coverage, scope_authority_raw, Some(previous))
    }

    /// Confirm the identity SDK signature against the exact Native proposal
    /// and a fresh caller-captured source/authority snapshot.
    #[wasm_bindgen(js_name = confirmOwnerAttestedProposal)]
    pub fn confirm_owner_attested_proposal(&self, rebase: &WasmVerifiedHistoryRebase,
        coverage: &WasmVerifiedHistoryArchiveCoverage, scope_authority_raw: JsValue,
        signed_json: &[u8], current_source_raw: JsValue) -> Result<WasmVerifiedHistoryBaselineAttestation, JsValue> {
        history_owner_confirm(self, rebase, coverage, scope_authority_raw, None, signed_json, current_source_raw)
    }
    #[wasm_bindgen(js_name = confirmOwnerAttestedProposalFromParent)]
    pub fn confirm_owner_attested_proposal_from_parent(&self, rebase: &WasmVerifiedHistoryRebase,
        coverage: &WasmVerifiedHistoryArchiveCoverage, scope_authority_raw: JsValue,
        previous: &WasmVerifiedHistoryBaselineAttestation, signed_json: &[u8], current_source_raw: JsValue) -> Result<WasmVerifiedHistoryBaselineAttestation, JsValue> {
        history_owner_confirm(self, rebase, coverage, scope_authority_raw, Some(previous), signed_json, current_source_raw)
    }
}

fn history_owner_proposal(capture: &WasmVerifiedHistoryArchiveCapture, rebase: &WasmVerifiedHistoryRebase,
    coverage: &WasmVerifiedHistoryArchiveCoverage, scope_authority_raw: JsValue,
    previous: Option<&WasmVerifiedHistoryBaselineAttestation>) -> Result<JsValue, JsValue> {
    let scope: meta_mesh_core::ScopeAuthoritySnapshot = strict_protocol_value(scope_authority_raw)?;
    let basis = capture.inner.bind_rebase(&rebase.inner, &coverage.inner).map_err(js_error)?;
    let parent = previous.map_or(meta_mesh_core::history_baseline::HistoryBaselineParent::Initial,
        |value| meta_mesh_core::history_baseline::HistoryBaselineParent::Previous(&value.inner));
    to_value(basis.propose_owner_attested_baseline(parent, &scope).map_err(js_error)?.payload())
}
fn history_owner_confirm(capture: &WasmVerifiedHistoryArchiveCapture, rebase: &WasmVerifiedHistoryRebase,
    coverage: &WasmVerifiedHistoryArchiveCoverage, scope_authority_raw: JsValue,
    previous: Option<&WasmVerifiedHistoryBaselineAttestation>, signed_json: &[u8], current_source_raw: JsValue)
    -> Result<WasmVerifiedHistoryBaselineAttestation, JsValue> {
    let scope: meta_mesh_core::ScopeAuthoritySnapshot = strict_protocol_value(scope_authority_raw)?;
    let source = strict_causal_input(current_source_raw)?;
    let basis = capture.inner.bind_rebase(&rebase.inner, &coverage.inner).map_err(js_error)?;
    let parent = previous.map_or(meta_mesh_core::history_baseline::HistoryBaselineParent::Initial,
        |value| meta_mesh_core::history_baseline::HistoryBaselineParent::Previous(&value.inner));
    let attestation = basis.propose_owner_attested_baseline(parent, &scope).map_err(js_error)?.confirm(signed_json, &source).map_err(js_error)?;
    Ok(WasmVerifiedHistoryBaselineAttestation { inner: attestation })
}

#[wasm_bindgen]
impl WasmVerifiedHistoryBaselineAttestation {
    pub fn document(&self) -> Vec<u8> { self.inner.document().to_vec() }
    #[wasm_bindgen(js_name = originalJson)]
    pub fn original_json(&self) -> Vec<u8> { self.inner.original_json().to_vec() }
    pub fn envelope(&self) -> Result<JsValue, JsValue> { to_value(self.inner.envelope()) }
}

#[wasm_bindgen]
pub struct WasmVerifiedHistoryRebase {
    inner: meta_mesh_core::history_rebase::VerifiedHistoryRebase,
}

#[wasm_bindgen]
impl WasmVerifiedHistoryRebase {
    pub fn document(&self) -> Vec<u8> { self.inner.document().to_vec() }
    #[wasm_bindgen(js_name = stateDigest)]
    pub fn state_digest(&self) -> String { self.inner.state_digest().to_owned() }
    #[wasm_bindgen(js_name = transitionId)]
    pub fn transition_id(&self) -> String { self.inner.transition_id().to_owned() }
}

#[wasm_bindgen]
impl WasmVerifiedHistoryArchiveStorage {
    #[wasm_bindgen(js_name = verifyCoverage)]
    pub fn verify_coverage(&self, authority_raw: JsValue, data_transition_id: &str, directory_transition_id: &str,
        data_receipt: &[u8], directory_receipt: &[u8]) -> Result<WasmVerifiedHistoryArchiveCoverage, JsValue> {
        let authority: meta_mesh_core::history_archive_coverage::HistoryArchiveCoverageAuthority = strict_protocol_value(authority_raw)?;
        let proof = meta_mesh_core::history_archive_coverage::HistoryArchiveCoverageProof {
            data_transition_id, directory_transition_id, data_receipt, directory_receipt,
        };
        let coverage = self.inner.verify_coverage(&authority, proof).map_err(js_error)?;
        Ok(WasmVerifiedHistoryArchiveCoverage { inner: coverage })
    }
}

struct WasmHistoryArchiveReader {
    objects: Map,
    ensure_current: Function,
    bytes_read: usize,
    object_count: usize,
}

impl WasmHistoryArchiveReader {
    fn ensure_current(&self) -> Result<(), String> {
        let result = self.ensure_current.call0(&JsValue::NULL)
            .map_err(|_| "History receiver guard rejected current identity or storage authority")?;
        if !result.is_undefined() {
            return Err("History receiver guard must return no value".into());
        }
        Ok(())
    }
}

impl meta_mesh_core::history_capture::HistoryArchiveEncryptedReader for WasmHistoryArchiveReader {
    fn ensure_current(&mut self) -> Result<(), String> {
        WasmHistoryArchiveReader::ensure_current(self)
    }

    fn download(&mut self, ciphertext_id: &str) -> Result<meta_mesh_core::history_archive_crypto::EncryptedHistoryArchiveObject, String> {
        self.ensure_current()?;
        let value = self.objects.get(&JsValue::from_str(ciphertext_id));
        if value.is_undefined() {
            return Err("Required encrypted history object was not fetched".into());
        }
        let parsed = strict_protocol_value::<serde_json::Value>(value.clone())
            .map_err(|_| "Invalid encrypted history object schema")?;
        let encoded = serde_json::to_vec(&parsed)
            .map_err(|_| "Invalid encrypted history object")?;
        self.bytes_read = self.bytes_read.checked_add(encoded.len()).ok_or("History evidence size overflow")?;
        self.object_count = self.object_count.checked_add(1).ok_or("History evidence count overflow")?;
        if self.bytes_read > MAX_WASM_HISTORY_CAPTURE_BYTES || self.object_count > 1_048_576 {
            return Err("History archive verification exceeds its bounded evidence limit".into());
        }
        let object = strict_protocol_value(value).map_err(|_| "Invalid encrypted history object schema")?;
        self.ensure_current()?;
        Ok(object)
    }
}

struct WasmPlaintextHistoryReader {
    objects: Map, retained: Map, ensure_current: Function, bytes_read: usize, object_count: usize,
    maximum_bytes: usize, maximum_objects: usize,
}
impl meta_mesh_core::history_capture::HistoryArchivePlaintextReader for WasmPlaintextHistoryReader {
    fn ensure_current(&mut self) -> Result<(), String> {
        let value = self.ensure_current.call0(&JsValue::NULL).map_err(|_| "Peer history reader guard rejected current access")?;
        if !value.is_undefined() { return Err("Peer history reader guard must return no value".into()); }
        Ok(())
    }
    fn read(&mut self, id: &str) -> Result<Vec<u8>, String> {
        self.ensure_current()?;
        let value = self.objects.get(&JsValue::from_str(id));
        let bytes = value.dyn_into::<Uint8Array>().map_err(|_| "Required peer plaintext archive object was not fetched")?.to_vec();
        self.bytes_read = self.bytes_read.checked_add(bytes.len()).ok_or("Peer history byte count overflow")?;
        self.object_count = self.object_count.checked_add(1).ok_or("Peer history object count overflow")?;
        if self.bytes_read > self.maximum_bytes || self.object_count > self.maximum_objects { return Err("Peer history evidence exceeds its bound".into()); }
        self.retained.set(&JsValue::from_str(id), &Uint8Array::from(bytes.as_slice()));
        self.ensure_current()?;
        Ok(bytes)
    }
}

fn verify_storage_history(signed_json: &[u8], document: &[u8], scope_id: &str, key_epoch: f64,
    content_key: &[u8], pinned_storage_raw: JsValue, trusted_scope_raw: Option<JsValue>,
    previous: Option<&WasmVerifiedReceivedHistoryBaseline>, objects: Map, ensure_current: Function)
    -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
    if content_key.len() != 32 || objects.size() > 8192 { return Err(js_error("Invalid or oversized cold history evidence")); }
    let mut key = [0u8; 32]; key.copy_from_slice(content_key);
    let scope = meta_mesh_core::history_archive_crypto::HistoryArchiveEncryptionScope {
        scope_id: scope_id.into(), key_epoch: unsigned_integer(key_epoch, "Invalid history archive key epoch")?, key };
    let pin: meta_mesh_core::history_archive_coverage::HistoryArchiveCoverageAuthority = strict_protocol_value(pinned_storage_raw)?;
    let retained_objects = objects.clone();
    let mut reader = WasmHistoryArchiveReader { objects, ensure_current, bytes_read: 0, object_count: 0 };
    let previous = previous.map(|value| &value.inner);
    let inner = if let Some(raw) = trusted_scope_raw {
        let trusted: meta_mesh_core::ScopeAuthoritySnapshot = strict_protocol_value(raw)?;
        meta_mesh_core::history_baseline::verify_received_owner_attested_history_baseline(signed_json, document,
            &scope, &pin, &trusted, previous, &mut reader)
    } else {
        meta_mesh_core::history_baseline::verify_received_history_baseline(signed_json, document,
            &scope, &pin, previous, &mut reader)
    }.map_err(js_error)?;
    Ok(WasmVerifiedReceivedHistoryBaseline { inner, encrypted_objects: retained_objects, plaintext_objects: Map::new() })
}
fn verify_peer_history(signed_json: &[u8], document: &[u8], trusted_scope_raw: JsValue,
    previous: Option<&WasmVerifiedReceivedHistoryBaseline>, objects: Map, ensure_current: Function)
    -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
    let trusted: meta_mesh_core::ScopeAuthoritySnapshot = strict_protocol_value(trusted_scope_raw)?;
    if objects.size() > 16_384 { return Err(js_error("Peer history bootstrap object set exceeds limit")); }
    let mut reader = WasmPlaintextHistoryReader { objects, retained: Map::new(), ensure_current,
        bytes_read: 0, object_count: 0, maximum_bytes: 64 * 1024 * 1024, maximum_objects: 16_384 };
    let inner = meta_mesh_core::history_baseline::verify_received_owner_attested_peer_history_baseline(signed_json,
        document, &trusted, previous.map(|value| &value.inner), &mut reader).map_err(js_error)?;
    Ok(WasmVerifiedReceivedHistoryBaseline { inner, encrypted_objects: Map::new(), plaintext_objects: reader.retained })
}

#[wasm_bindgen]
impl WasmStateCore {
    /// Run full Native causal admission and bind it to the current Owner's
    /// complete device certificate chain. The returned token cannot be built
    /// from a host-claimed admission result.
    #[wasm_bindgen(js_name = prepareWorkspaceHistory)]
    pub fn prepare_workspace_history(source_raw: JsValue, signer_raw: JsValue) -> Result<WasmVerifiedHistoryPreparation, JsValue> {
        let source = strict_causal_input(source_raw)?;
        let signer: meta_mesh_core::history_preparation::HistoryPreparationSigner = strict_protocol_value(signer_raw)?;
        let preparation = meta_mesh_core::history_preparation::prepare_workspace_history(source, signer).map_err(js_error)?;
        Ok(WasmVerifiedHistoryPreparation { inner: Some(preparation) })
    }

    /// Prepare a bounded active-tail capture descended from an opaque,
    /// independently verified compact baseline. The caller cannot provide a
    /// host-asserted basis marker or use a synthetic genesis.
    #[wasm_bindgen(js_name = prepareWorkspaceHistoryFromBasis)]
    pub fn prepare_workspace_history_from_basis(
        source_raw: JsValue,
        signer_raw: JsValue,
        basis: &WasmVerifiedReceivedHistoryBaseline,
    ) -> Result<WasmVerifiedHistoryPreparation, JsValue> {
        let source = strict_causal_input(source_raw)?;
        let signer: meta_mesh_core::history_preparation::HistoryPreparationSigner = strict_protocol_value(signer_raw)?;
        let preparation = meta_mesh_core::history_preparation::prepare_workspace_history_from_basis(
            source, signer, &basis.inner,
        ).map_err(js_error)?;
        Ok(WasmVerifiedHistoryPreparation { inner: Some(preparation) })
    }

    /// Initial and parent-bound receivers borrow opaque Native handles through the generated class ABI.
    #[wasm_bindgen(js_name = verifyReceivedHistoryBaseline)]
    pub fn verify_received_history_baseline(signed_json: &[u8], document: &[u8], scope_id: &str,
        key_epoch: f64, key: &[u8], pin: JsValue, objects: Map, guard: Function) -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
        verify_storage_history(signed_json, document, scope_id, key_epoch, key, pin, None, None, objects, guard)
    }
    #[wasm_bindgen(js_name = verifyReceivedHistoryBaselineFromParent)]
    pub fn verify_received_history_baseline_from_parent(signed_json: &[u8], document: &[u8], scope_id: &str,
        key_epoch: f64, key: &[u8], pin: JsValue, previous: &WasmVerifiedReceivedHistoryBaseline,
        objects: Map, guard: Function) -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
        verify_storage_history(signed_json, document, scope_id, key_epoch, key, pin, None, Some(previous), objects, guard)
    }
    #[wasm_bindgen(js_name = verifyOwnerAttestedHistoryBaseline)]
    pub fn verify_owner_attested_history_baseline(signed_json: &[u8], document: &[u8], scope_id: &str,
        key_epoch: f64, key: &[u8], pin: JsValue, trusted: JsValue, objects: Map, guard: Function)
        -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
        verify_storage_history(signed_json, document, scope_id, key_epoch, key, pin, Some(trusted), None, objects, guard)
    }
    #[wasm_bindgen(js_name = verifyOwnerAttestedHistoryBaselineFromParent)]
    pub fn verify_owner_attested_history_baseline_from_parent(signed_json: &[u8], document: &[u8], scope_id: &str,
        key_epoch: f64, key: &[u8], pin: JsValue, trusted: JsValue, previous: &WasmVerifiedReceivedHistoryBaseline,
        objects: Map, guard: Function) -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
        verify_storage_history(signed_json, document, scope_id, key_epoch, key, pin, Some(trusted), Some(previous), objects, guard)
    }
    #[wasm_bindgen(js_name = verifyOwnerAttestedPeerHistoryBaseline)]
    pub fn verify_owner_attested_peer_history_baseline(signed_json: &[u8], document: &[u8], trusted: JsValue,
        objects: Map, guard: Function) -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
        verify_peer_history(signed_json, document, trusted, None, objects, guard)
    }
    #[wasm_bindgen(js_name = verifyOwnerAttestedPeerHistoryBaselineFromParent)]
    pub fn verify_owner_attested_peer_history_baseline_from_parent(signed_json: &[u8], document: &[u8], trusted: JsValue,
        previous: &WasmVerifiedReceivedHistoryBaseline, objects: Map, guard: Function) -> Result<WasmVerifiedReceivedHistoryBaseline, JsValue> {
        verify_peer_history(signed_json, document, trusted, Some(previous), objects, guard)
    }

    #[wasm_bindgen(js_name = causalAdmissionPolicyId)]
    pub fn causal_admission_policy_id() -> String {
        meta_mesh_core::causal_admission::CAUSAL_ADMISSION_POLICY_ID.into()
    }

    #[wasm_bindgen(js_name = evaluateCausalAdmission)]
    pub fn evaluate_causal_admission(raw: JsValue) -> Result<JsValue, JsValue> {
        let input = strict_causal_input(raw)?;
        to_value(
            &meta_mesh_core::causal_admission::evaluate_causal_admission(input)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = createCoownershipGenesisPayload)]
    pub fn create_coownership_genesis_payload(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::coownership::CoownershipGenesisInput =
            strict_protocol_value(raw)?;
        to_value(
            &meta_mesh_core::coownership::create_coownership_genesis_payload(input)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = validateCoownershipLedger)]
    pub fn validate_coownership_ledger(raw: JsValue) -> Result<JsValue, JsValue> {
        let ledger: meta_mesh_core::coownership::CoownershipLedger = strict_protocol_value(raw)?;
        to_value(
            &meta_mesh_core::coownership::validate_coownership_ledger(&ledger).map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = mergeCoownershipLedgers)]
    pub fn merge_coownership_ledgers(
        current: JsValue,
        incoming: JsValue,
    ) -> Result<JsValue, JsValue> {
        let current: Option<meta_mesh_core::coownership::CoownershipLedger> =
            optional_strict_protocol_value(current)?;
        let incoming: meta_mesh_core::coownership::CoownershipLedger =
            strict_protocol_value(incoming)?;
        to_value(
            &meta_mesh_core::coownership::merge_coownership_ledgers(current.as_ref(), &incoming)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = planCoownershipTransition)]
    pub fn plan_coownership_transition(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::coownership::CoownershipTransitionInput =
            strict_protocol_value(raw)?;
        to_value(
            &meta_mesh_core::coownership::plan_coownership_transition(input).map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = planCoownershipResolution)]
    pub fn plan_coownership_resolution(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::coownership::CoownershipResolutionInput =
            strict_protocol_value(raw)?;
        to_value(
            &meta_mesh_core::coownership::plan_coownership_resolution(input).map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = planCoownershipFork)]
    pub fn plan_coownership_fork(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::coownership::CoownershipForkInput = strict_protocol_value(raw)?;
        to_value(&meta_mesh_core::coownership::plan_coownership_fork(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = authorizationRecordPages)]
    pub fn authorization_record_pages(raw: JsValue) -> Result<JsValue, JsValue> {
        let bundle: serde_json::Value = from_value(raw)?;
        to_value(&meta_mesh_core::authorization_record_pages(&bundle).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = authorizationExport)]
    pub fn authorization_export(document: &[u8], raw: JsValue) -> Result<JsValue, JsValue> {
        let bundle: serde_json::Value = from_value(raw)?;
        to_value(&meta_mesh_core::authorization_export(document, &bundle).map_err(js_error)?)
    }
    #[wasm_bindgen(js_name = validateScopeAuthority)]
    pub fn validate_scope_authority(raw: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let snapshot: meta_mesh_core::ScopeAuthoritySnapshot = from_value(raw)?;
        to_value(
            &meta_mesh_core::validate_scope_authority_at(
                &snapshot,
                i128::from(integer(now_ms, "Invalid scope authority timestamp")?),
            )
            .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = mergeScopeAuthoritySnapshots)]
    pub fn merge_scope_authority_snapshots(
        current: JsValue,
        incoming: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let current: Option<meta_mesh_core::ScopeAuthoritySnapshot> = from_value(current)?;
        let incoming: meta_mesh_core::ScopeAuthoritySnapshot = from_value(incoming)?;
        let merged = meta_mesh_core::merge_scope_authority_snapshots_at(
            current.as_ref(),
            &incoming,
            i128::from(integer(now_ms, "Invalid scope authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&merged)
    }

    #[wasm_bindgen(js_name = requireChangeAuthorizationCoverage)]
    pub fn require_change_authorization_coverage(
        change_hashes: JsValue,
        records: JsValue,
    ) -> Result<(), JsValue> {
        let hashes: Vec<String> = from_value(change_hashes)?;
        let records: Vec<serde_json::Value> = from_value(records)?;
        meta_mesh_core::require_change_authorization_coverage(&hashes, &records).map_err(js_error)
    }

    #[wasm_bindgen(js_name = createScopeGenesis)]
    pub fn create_scope_genesis(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::ScopeGenesisInput = from_value(raw)?;
        to_value(&meta_mesh_core::create_scope_genesis(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = createScopeGenesisPayload)]
    pub fn create_scope_genesis_payload(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::ScopeGenesisPayloadInput = from_value(raw)?;
        to_value(&meta_mesh_core::create_scope_genesis_payload(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planScopeGenesis)]
    pub fn plan_scope_genesis(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::ScopeGenesisPlanInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_scope_genesis(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = createScopeControlTransferPayload)]
    pub fn create_scope_control_transfer_payload(
        raw: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::ScopeControlTransferPayloadInput = from_value(raw)?;
        to_value(
            &meta_mesh_core::create_scope_control_transfer_payload_at(
                input,
                i128::from(integer(now_ms, "Invalid scope authority timestamp")?),
            )
            .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = preferredSessionDirection)]
    pub fn preferred_session_direction(
        local_device_id: &str,
        local_instance_id: &str,
        remote_device_id: &str,
        remote_instance_id: &str,
    ) -> Result<JsValue, JsValue> {
        to_value(&meta_mesh_core::preferred_session_direction(
            local_device_id,
            local_instance_id,
            remote_device_id,
            remote_instance_id,
        ))
    }

    #[wasm_bindgen(js_name = hasAuthorityConflict)]
    pub fn has_authority_conflict(raw: JsValue) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(raw)?;
        Ok(meta_mesh_core::has_authority_conflict(&credential))
    }

    #[wasm_bindgen(js_name = prepareWriteEvidence)]
    pub fn prepare_write_evidence(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::WriteEvidenceInput = from_value(raw)?;
        to_value(&meta_mesh_core::prepare_write_evidence(input).map_err(js_error)?)
    }

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
    pub fn can_remove_workspace_device(
        credential: JsValue,
        local_person_id: &str,
        local_public_key: &str,
        local_device_id: &str,
        target_person_id: &str,
        target_device_id: &str,
        peer_person_id: Option<String>,
    ) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        meta_mesh_core::can_remove_workspace_device(
            &credential,
            local_person_id,
            local_public_key,
            local_device_id,
            target_person_id,
            target_device_id,
            peer_person_id.as_deref(),
        )
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = partitionCredentials)]
    pub fn partition_credentials(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::CredentialPartitionInput = from_value(raw)?;
        to_value(&meta_mesh_core::partition_credentials(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = ownedWorkspaceIds)]
    pub fn owned_workspace_ids(
        credentials: JsValue,
        person_id: &str,
        public_key: &str,
    ) -> Result<JsValue, JsValue> {
        let credentials: Vec<serde_json::Value> = from_value(credentials)?;
        to_value(&meta_mesh_core::owned_workspace_ids(
            &credentials,
            person_id,
            public_key,
        ))
    }

    #[wasm_bindgen(js_name = planAuthorityImport)]
    pub fn plan_authority_import(
        kind: &str,
        has_revocations: bool,
        has_transfers: bool,
    ) -> Result<JsValue, JsValue> {
        to_value(
            &meta_mesh_core::plan_authority_import(kind, has_revocations, has_transfers)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = planMeshHandshakeAuthorityImport)]
    pub fn plan_mesh_handshake_authority_import() -> Result<JsValue, JsValue> {
        to_value(&meta_mesh_core::plan_mesh_handshake_authority_import().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = selectMeshHandshakeBundle)]
    pub fn select_mesh_handshake_bundle(
        candidates: JsValue,
        local_device_id: &str,
        local_instance_id: &str,
    ) -> Result<JsValue, JsValue> {
        let candidates: Vec<meta_mesh_core::MeshHandshakeBundleCandidate> = from_value(candidates)?;
        to_value(&meta_mesh_core::select_mesh_handshake_bundle(
            &candidates,
            local_device_id,
            local_instance_id,
        ))
    }

    #[wasm_bindgen(js_name = shouldAdvertiseOwnerWorkspaceIds)]
    pub fn should_advertise_owner_workspace_ids(
        credential_owner_person_id: &str,
        local_person_id: &str,
        remote_person_id: &str,
    ) -> bool {
        meta_mesh_core::should_advertise_owner_workspace_ids(
            credential_owner_person_id,
            local_person_id,
            remote_person_id,
        )
    }

    #[wasm_bindgen(js_name = meshHandshakeFeatures)]
    pub fn mesh_handshake_features(raw: JsValue) -> Result<JsValue, JsValue> {
        let capabilities: Vec<String> = from_value(raw)?;
        to_value(&meta_mesh_core::mesh_handshake_features(&capabilities))
    }

    #[wasm_bindgen(js_name = credentialBelongsToProfile)]
    pub fn credential_belongs_to_profile(
        credential: JsValue,
        person_id: &str,
        public_key: &str,
    ) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        meta_mesh_core::credential_belongs_to_profile(&credential, person_id, public_key)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = canReuseMemberBundle)]
    pub fn can_reuse_member_bundle(raw: JsValue) -> Result<bool, JsValue> {
        let input: meta_mesh_core::BundleReuseInput = from_value(raw)?;
        Ok(meta_mesh_core::can_reuse_member_bundle(input))
    }

    #[wasm_bindgen(js_name = planSuccessionPolicyRefresh)]
    pub fn plan_succession_policy_refresh(
        current: JsValue,
        eligible: JsValue,
        epoch: f64,
    ) -> Result<JsValue, JsValue> {
        let current: meta_mesh_core::WorkspaceSuccessionPolicy = from_value(current)?;
        let eligible: Vec<String> = from_value(eligible)?;
        let epoch = u64::try_from(integer(epoch, "Invalid authority epoch")?).map_err(js_error)?;
        to_value(&meta_mesh_core::plan_succession_policy_refresh(
            &current, &eligible, epoch,
        ))
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
    pub fn validate_owner_workspace_offer(
        raw: JsValue,
        remote_person_id: &str,
        local_person_id: &str,
    ) -> Result<String, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        meta_mesh_core::validate_owner_workspace_offer(&raw, remote_person_id, local_person_id)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = knowsWorkspaceIssuer)]
    pub fn knows_workspace_issuer(
        raw: JsValue,
        issuer_person_id: &str,
        local_person_id: &str,
        local_device_id: &str,
    ) -> Result<bool, JsValue> {
        let raw: Vec<meta_mesh_core::IssuerWorkspaceInput> = from_value(raw)?;
        Ok(meta_mesh_core::knows_workspace_issuer(
            &raw,
            issuer_person_id,
            local_person_id,
            local_device_id,
        ))
    }

    #[wasm_bindgen(js_name = nextAccessEpoch)]
    pub fn next_access_epoch(credential: JsValue, issued_grants: JsValue) -> Result<f64, JsValue> {
        let credential: Option<serde_json::Value> = from_value(credential)?;
        let issued_grants: Vec<serde_json::Value> = from_value(issued_grants)?;
        Ok(
            meta_mesh_core::next_access_epoch(credential.as_ref(), &issued_grants)
                .map_err(js_error)? as f64,
        )
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

    #[wasm_bindgen(js_name = planOwnershipAuthorityFlow)]
    pub fn plan_ownership_authority_flow(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::OwnershipAuthorityFlowInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_ownership_authority_flow(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = isWorkspaceEnvelope)]
    pub fn is_workspace_envelope(raw: JsValue, now_ms: f64) -> Result<bool, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        meta_mesh_core::is_workspace_envelope_at(
            &raw,
            i128::from(integer(now_ms, "Invalid workspace envelope timestamp")?),
        )
        .map_err(js_error)
    }

    #[wasm_bindgen(js_name = hasLeftWorkspace)]
    pub fn has_left_workspace(
        credential: JsValue,
        person_id: &str,
        grant: JsValue,
    ) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        let grant: Option<serde_json::Value> = from_value(grant)?;
        Ok(meta_mesh_core::has_left_workspace(
            &credential,
            person_id,
            grant.as_ref(),
        ))
    }

    #[wasm_bindgen(js_name = isGrantRevoked)]
    pub fn is_grant_revoked(
        credential: JsValue,
        person_id: &str,
        grant: JsValue,
    ) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        let grant: Option<serde_json::Value> = from_value(grant)?;
        Ok(meta_mesh_core::is_grant_revoked(
            &credential,
            person_id,
            grant.as_ref(),
        ))
    }

    #[wasm_bindgen(js_name = isDeviceRevoked)]
    pub fn is_device_revoked(
        credential: JsValue,
        person_id: &str,
        device_id: &str,
    ) -> Result<bool, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        Ok(meta_mesh_core::is_device_revoked(
            &credential,
            person_id,
            device_id,
        ))
    }

    #[wasm_bindgen(js_name = planDialSchedule)]
    pub fn plan_dial_schedule(raw: JsValue) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::DialScheduleInput = from_value(raw)?;
        to_value(&meta_mesh_core::plan_dial_schedule(input).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = planOwnerCertificateRefresh)]
    pub fn plan_owner_certificate_refresh(
        credential: JsValue,
        local_person_id: &str,
        certificates: JsValue,
        updated_at: &str,
    ) -> Result<JsValue, JsValue> {
        let credential: serde_json::Value = from_value(credential)?;
        let certificates: Vec<meta_mesh_core::DeviceCertificate> = from_value(certificates)?;
        to_value(
            &meta_mesh_core::plan_owner_certificate_refresh(
                credential,
                local_person_id,
                certificates,
                updated_at,
            )
            .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = decideOwnerCredential)]
    pub fn decide_owner_credential(
        existing_owner_person_id: Option<String>,
        local_person_id: &str,
    ) -> Result<String, JsValue> {
        meta_mesh_core::decide_owner_credential(
            existing_owner_person_id.as_deref(),
            local_person_id,
        )
        .map(str::to_string)
        .map_err(js_error)
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
        to_value(
            &meta_mesh_core::plan_succession_merge(
                input,
                i128::from(integer(now_ms, "Invalid authority timestamp")?),
            )
            .map_err(js_error)?,
        )
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
    pub fn validate_mesh_catalog(raw: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let catalog = meta_mesh_core::validate_mesh_catalog_at(
            raw,
            i128::from(integer(now_ms, "Invalid mesh catalog timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&catalog)
    }

    #[wasm_bindgen(js_name = validateMeshHandshake)]
    pub fn validate_mesh_handshake(
        raw: JsValue,
        expected_workspace_id: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        let handshake =
            meta_mesh_core::validate_mesh_handshake(raw, expected_workspace_id.as_deref())
                .map_err(js_error)?;
        to_value(&handshake)
    }

    #[wasm_bindgen(js_name = encodeMeshHandshake)]
    pub fn encode_mesh_handshake(
        frame_type: &str,
        secret: &str,
        raw: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let raw: serde_json::Value = from_value(raw)?;
        meta_mesh_core::encode_mesh_handshake(frame_type, secret, raw).map_err(js_error)
    }

    #[wasm_bindgen(js_name = inspectMeshHandshake)]
    pub fn inspect_mesh_handshake(frame: &[u8]) -> Result<JsValue, JsValue> {
        let header = meta_mesh_core::inspect_mesh_handshake(frame).map_err(js_error)?;
        to_value(&serde_json::json!({ "type": header.frame_type, "secret": header.secret }))
    }

    #[wasm_bindgen(js_name = decodeMeshHandshake)]
    pub fn decode_mesh_handshake(
        frame: &[u8],
        expected_type: &str,
        secret: &str,
        workspace_id: &str,
    ) -> Result<JsValue, JsValue> {
        let handshake =
            meta_mesh_core::decode_mesh_handshake(frame, expected_type, secret, workspace_id)
                .map_err(js_error)?;
        to_value(&handshake)
    }

    #[wasm_bindgen(js_name = admitMeshPeer)]
    pub fn admit_mesh_peer(
        handshake: JsValue,
        snapshot: JsValue,
        remote_endpoint: &str,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let handshake: serde_json::Value = from_value(handshake)?;
        let snapshot: WorkspaceWriteAuthorizationSnapshot = from_value(snapshot)?;
        let admitted = meta_mesh_core::admit_mesh_peer(
            handshake,
            &snapshot,
            remote_endpoint,
            i128::from(integer(now_ms, "Invalid member timestamp")?),
        )
        .map_err(js_error)?;
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
        )
        .map_err(js_error)?;
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
        )
        .map_err(js_error)?;
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
        )
        .map_err(js_error)?;
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
        )
        .map_err(js_error)?;
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
        to_value(
            &meta_mesh_core::summarize_succession(
                policy.as_ref(),
                &claims,
                &votes,
                &transfers,
                &revocations,
                unsigned_integer(epoch, "Invalid succession epoch")?,
            )
            .map_err(js_error)?,
        )
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
    pub fn verify_workspace_departure(
        record: JsValue,
        workspace_id: &str,
        authority: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let record: meta_mesh_core::authority::WorkspaceDeparture = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::authority::verify_workspace_departure(
            &record,
            workspace_id,
            &authority,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
        to_value(&record)
    }

    #[wasm_bindgen(js_name = verifyWorkspaceDeviceRevocation)]
    pub fn verify_workspace_device_revocation(
        record: JsValue,
        workspace_id: &str,
        owner_person_id: &str,
        authority: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let record: meta_mesh_core::authority::WorkspaceDeviceRevocation = from_value(record)?;
        let authority: WorkspaceAuthority = from_value(authority)?;
        meta_mesh_core::authority::verify_workspace_device_revocation(
            &record,
            workspace_id,
            owner_person_id,
            &authority,
            i128::from(integer(now_ms, "Invalid authority timestamp")?),
        )
        .map_err(js_error)?;
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

    #[wasm_bindgen(js_name = planChangeAdmissionFlow)]
    pub fn plan_change_admission_flow(raw: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let input: meta_mesh_core::ChangeAdmissionFlowInput = from_value(raw)?;
        let plan = meta_mesh_core::plan_change_admission_flow(
            input,
            i128::from(integer(now_ms, "Invalid change authorization timestamp")?),
        )
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

// serde-wasm-bindgen's struct adapter reads declared properties only. Route strict protocols
// through a JSON value so serde's deny_unknown_fields applies at every v2 level.
fn strict_causal_input(value: JsValue) -> Result<meta_mesh_core::causal_admission::CausalAdmissionInput, JsValue> {
    let source = protocol_object(value)?;
    let snapshot_key = JsValue::from_str("snapshot");
    let document_key = JsValue::from_str("document");
    if !js_sys::Object::has_own(&source, &snapshot_key) { return Err(js_error("Missing causal admission snapshot")); }
    let snapshot = protocol_object(js_sys::Reflect::get(&source, &snapshot_key)?)?;
    if !js_sys::Object::has_own(&snapshot, &document_key) { return Err(js_error("Missing causal admission document")); }
    // Keep byte vectors out of serde_json::Value; TypedArrays are not JSON values.
    // All original metadata, including unknown fields, still passes strict parsing.
    let document: Vec<u8> = from_value(js_sys::Reflect::get(&snapshot, &document_key)?)?;
    js_sys::Reflect::set(&snapshot, &document_key, &js_sys::Array::new())?;
    js_sys::Reflect::set(&source, &snapshot_key, &snapshot)?;
    let pending_key = JsValue::from_str("pendingChangeBytes");
    let pending: Option<Vec<Vec<u8>>> = if js_sys::Object::has_own(&source, &pending_key) {
        let bytes = from_value(js_sys::Reflect::get(&source, &pending_key)?)?;
        js_sys::Reflect::set(&source, &pending_key, &js_sys::Array::new())?;
        Some(bytes)
    } else { None };
    let mut input: meta_mesh_core::causal_admission::CausalAdmissionInput = strict_protocol_value(source.into())?;
    input.snapshot.document = document;
    if let Some(bytes) = pending { input.pending_change_bytes = bytes; }
    Ok(input)
}

fn protocol_object(value: JsValue) -> Result<js_sys::Object, JsValue> {
    if !value.is_object() || js_sys::Array::is_array(&value) { return Err(js_error("Invalid protocol object")); }
    let object = value.unchecked_into::<js_sys::Object>();
    // FromEntries defines own data properties, including __proto__, without invoking setters.
    js_sys::Object::from_entries(js_sys::Object::entries(&object).as_ref())
}

fn strict_protocol_value<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    let json: serde_json::Value = serde_wasm_bindgen::from_value(value).map_err(js_error)?;
    serde_json::from_value(json).map_err(js_error)
}

fn optional_strict_protocol_value<T: serde::de::DeserializeOwned>(
    value: JsValue,
) -> Result<Option<T>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        strict_protocol_value(value).map(Some)
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
