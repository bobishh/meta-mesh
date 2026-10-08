//! Bounded proof exchange. Page contents remain untrusted until complete
//! document admission; page receipts never acknowledge a durable document.
use crate::identity::canonicalize_json;
use automerge::{AutoCommit, ChangeHash};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

pub const MAX_PROOF_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_PROOF_PAGE_BYTES: usize = 224 * 1024;
pub const MAX_PROOF_REQUEST_HASHES: usize = 1024;
pub const MAX_PROOF_TRANSFER_RECORDS: usize = 1_000_000;
pub const MAX_PROOF_TRANSFER_BYTES: usize = 256 * 1024 * 1024;
const LEGACY_WIRE_BYTES: usize = 64 * 1024;
const GRANT_VARIANT_IDENTITY_MODE: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationManifest {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub heads: Vec<String>,
    pub authority: Value,
    pub records_digest: String,
    pub transfer_id: String,
    /// Present only when one signature has multiple grant provenance variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_identity_mode: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPageRequest {
    pub version: u8,
    pub manifest: AuthorizationManifest,
    pub request_id: String,
    pub hashes: Vec<String>,
    pub after: String,
    /// Omitted for legacy signature-only page identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_identity_mode: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPage {
    pub version: u8,
    pub transfer_id: String,
    pub request_id: String,
    pub after: String,
    pub next: String,
    pub complete: bool,
    pub records: Vec<Value>,
    /// Omitted for legacy signature-only page identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_identity_mode: Option<u8>,
}

fn digest(value: &Value) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonicalize_json(value)?.as_bytes())
    ))
}
fn bytes(value: &impl Serialize) -> Result<usize, String> {
    Ok(serde_json::to_vec(value).map_err(|e| e.to_string())?.len())
}
fn signature(record: &Value) -> Result<&str, String> {
    record
        .pointer("/signed/signature")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Invalid authorization record identity".into())
}
fn manifest_id(manifest: &AuthorizationManifest) -> Result<String, String> {
    let mut payload = json!({"workspaceId": manifest.workspace_id, "heads": manifest.heads,
        "authority": manifest.authority, "recordsDigest": manifest.records_digest, "version": 2});
    if let Some(mode) = manifest.record_identity_mode {
        payload["recordIdentityMode"] = json!(mode);
    }
    digest(&payload)
}
fn validate_manifest(manifest: &AuthorizationManifest) -> Result<(), String> {
    if manifest.version != 2
        || manifest.kind != "workspace-authorization-manifest"
        || manifest.workspace_id.is_empty()
        || manifest.heads.is_empty()
        || manifest.heads.len() > 256
        || !manifest.authority.is_object()
        || manifest.records_digest.len() != 64
        || manifest
            .record_identity_mode
            .is_some_and(|mode| mode != GRANT_VARIANT_IDENTITY_MODE)
        || manifest_id(manifest)? != manifest.transfer_id
        || bytes(manifest)? > MAX_PROOF_PAGE_BYTES
    {
        return Err("Invalid or oversized authorization manifest".into());
    }
    Ok(())
}

/// Extract explicitly bounded pages. The legacy 20,000-record / 16 MiB limit
/// remains unchanged. Larger aggregate evidence requires the paged v2 format.
pub fn authorization_record_pages(bundle: &Value) -> Result<Vec<Vec<Value>>, String> {
    if !bundle.get("authority").is_some_and(Value::is_object) {
        return Err("Missing workspace authority evidence".into());
    }
    match bundle.get("version").and_then(Value::as_u64) {
        Some(1) => {
            let records = bundle
                .get("records")
                .and_then(Value::as_array)
                .ok_or("Missing workspace write authorizations")?;
            if records.len() > 20_000 || bytes(bundle)? > 16 * 1024 * 1024 {
                return Err("Workspace authorization bundle exceeds size limit".into());
            }
            Ok(vec![records.clone()])
        }
        Some(2) => {
            let pages: Vec<Vec<Value>> = serde_json::from_value(
                bundle
                    .get("pages")
                    .cloned()
                    .ok_or("Missing workspace authorization pages")?,
            )
            .map_err(|_| "Invalid workspace authorization pages")?;
            if pages.len() > MAX_PROOF_TRANSFER_RECORDS
                || bytes(bundle)? > MAX_PROOF_TRANSFER_BYTES
                || bytes(bundle.get("authority").unwrap())? > MAX_PROOF_PAGE_BYTES
                || pages.iter().any(|p| p.len() > 20_000)
                || pages.iter().map(Vec::len).sum::<usize>() > MAX_PROOF_TRANSFER_RECORDS
            {
                return Err("Workspace proof transfer exceeds size limit".into());
            }
            for page in &pages {
                if bytes(page)? > MAX_PROOF_PAGE_BYTES {
                    return Err("Workspace authorization page exceeds size limit".into());
                }
            }
            Ok(pages)
        }
        _ => Err("Unsupported workspace authorization format".into()),
    }
}

pub fn authorization_records(bundle: &Value) -> Result<Vec<Value>, String> {
    Ok(authorization_record_pages(bundle)?
        .into_iter()
        .flatten()
        .collect())
}

/// Convert a trusted local aggregate to bounded admission pages without
/// changing, combining, or deleting any signed authorization record.
pub fn authorization_admission_bundle(bundle: &Value) -> Result<Value, String> {
    let mut pages: Vec<Vec<Value>> = vec![];
    let mut page: Vec<Value> = vec![];
    let mut page_bytes = 2usize;
    for record in stored_records(bundle)? {
        let record_bytes = bytes(&record)?;
        if record_bytes + 2 > MAX_PROOF_PAGE_BYTES {
            return Err("One signed authorization record exceeds page budget".into());
        }
        let additional = record_bytes + usize::from(!page.is_empty());
        if page.len() == 20_000 || page_bytes + additional > MAX_PROOF_PAGE_BYTES {
            pages.push(std::mem::take(&mut page));
            page_bytes = 2;
        }
        page_bytes += record_bytes + usize::from(!page.is_empty());
        page.push(record);
    }
    if !page.is_empty() {
        pages.push(page);
    }
    let result = json!({"version": 2, "authority": bundle.get("authority"), "pages": pages});
    authorization_record_pages(&result)?;
    Ok(result)
}

/// Storage snapshots are aggregate data, not wire bundles. Validate aggregate
/// resource bounds here without pretending they fit a legacy admission frame.
fn stored_records(bundle: &Value) -> Result<Vec<Value>, String> {
    let records = if let Some(records) = bundle.get("records").and_then(Value::as_array) {
        if records.len() > MAX_PROOF_TRANSFER_RECORDS || bytes(bundle)? > MAX_PROOF_TRANSFER_BYTES {
            return Err("Workspace proof history exceeds transfer resource limit".into());
        }
        records.clone()
    } else {
        authorization_records(bundle)?
    };
    normalize_stored_records(records)
}

fn grant_variant_key(record: &Value) -> Result<String, String> {
    let grant = record.get("grant").cloned().unwrap_or(Value::Null);
    Ok(format!("{}:{}", signature(record)?, digest(&grant)?))
}

fn record_identity_key(record: &Value, mode: Option<u8>) -> Result<String, String> {
    match mode {
        None => Ok(signature(record)?.to_owned()),
        Some(GRANT_VARIANT_IDENTITY_MODE) => grant_variant_key(record),
        Some(_) => Err("Unsupported authorization record identity mode".into()),
    }
}

fn has_grant_variants(records: &[Value]) -> Result<bool, String> {
    let mut grants = BTreeMap::<String, String>::new();
    for record in records {
        let sig = signature(record)?.to_owned();
        let grant = canonicalize_json(&record.get("grant").cloned().unwrap_or(Value::Null))?;
        if grants
            .insert(sig, grant.clone())
            .is_some_and(|previous| previous != grant)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Multiple durable replicas can retain the same signed authorization with
/// different unsigned certificate sidecars and grant provenance. Collapse
/// certificate variants per (signature, grant), while rejecting changes to
/// the signed envelope, signer, or owner identity across every grant variant.
fn normalize_stored_records(records: Vec<Value>) -> Result<Vec<Value>, String> {
    let mut normalized = BTreeMap::<String, Value>::new();
    let mut signature_identity = BTreeMap::<String, Value>::new();
    let mut owner_keys = BTreeMap::<String, Value>::new();
    for record in records {
        let record = normalize_stored_record(record)?;
        let sig = signature(&record)?.to_owned();
        let mut base_identity = record.clone();
        let base_object = base_identity
            .as_object_mut()
            .ok_or("Invalid stored authorization record")?;
        for field in [
            "certificates",
            "ownerCertificates",
            "ownerPublicKey",
            "grant",
        ] {
            base_object.remove(field);
        }
        if signature_identity
            .insert(sig.clone(), base_identity.clone())
            .is_some_and(|previous| previous != base_identity)
        {
            return Err("Conflicting stored authorization identity".into());
        }
        if let Some(owner_key) = record.get("ownerPublicKey") {
            if owner_keys
                .insert(sig.clone(), owner_key.clone())
                .is_some_and(|previous| previous != *owner_key)
            {
                return Err("Conflicting stored authorization identity".into());
            }
        }

        let identity = grant_variant_key(&record)?;
        let Some(previous) = normalized.get_mut(&identity) else {
            normalized.insert(identity, record);
            continue;
        };
        if previous.get("signed") != record.get("signed") {
            return Err("Conflicting stored authorization identity".into());
        }

        let mut previous_identity = previous.clone();
        let mut incoming_identity = record.clone();
        for value in [&mut previous_identity, &mut incoming_identity] {
            let Some(object) = value.as_object_mut() else {
                return Err("Invalid stored authorization record".into());
            };
            object.remove("certificates");
            object.remove("ownerCertificates");
            object.remove("ownerPublicKey");
            object.remove("grant");
        }
        if previous_identity != incoming_identity {
            return Err("Conflicting stored authorization identity".into());
        }

        let previous_object = previous
            .as_object_mut()
            .ok_or("Invalid stored authorization record")?;
        let incoming_object = record
            .as_object()
            .ok_or("Invalid stored authorization record")?;
        if previous_object.get("grant").is_none_or(Value::is_null)
            && incoming_object.get("grant").is_none_or(Value::is_null)
        {
            if previous_object.get("grant").is_some() || incoming_object.get("grant").is_some() {
                previous_object.insert("grant".into(), Value::Null);
            }
        }
        if let (Some(previous_key), Some(incoming_key)) = (
            previous_object.get("ownerPublicKey"),
            incoming_object.get("ownerPublicKey"),
        ) {
            if previous_key != incoming_key {
                return Err("Conflicting stored authorization identity".into());
            }
        } else if let Some(owner_key) = incoming_object.get("ownerPublicKey") {
            previous_object.insert("ownerPublicKey".into(), owner_key.clone());
        }
        for field in ["certificates", "ownerCertificates"] {
            let Some(merged) =
                merge_certificate_variants(previous_object.get(field), incoming_object.get(field))?
            else {
                continue;
            };
            previous_object.insert(field.into(), merged);
        }
    }
    for record in normalized.values_mut() {
        let sig = signature(record)?.to_owned();
        if record.get("ownerPublicKey").is_none() {
            if let Some(owner_key) = owner_keys.get(&sig) {
                record["ownerPublicKey"] = owner_key.clone();
            }
        }
    }
    Ok(normalized.into_values().collect())
}

fn normalize_stored_record(mut record: Value) -> Result<Value, String> {
    signature(&record)?;
    let object = record
        .as_object_mut()
        .ok_or("Invalid stored authorization record")?;
    for field in ["certificates", "ownerCertificates"] {
        if let Some(certificates) = object.get(field) {
            let normalized = merge_certificate_variants(Some(certificates), Some(certificates))?
                .ok_or("Invalid stored authorization certificates")?;
            object.insert(field.into(), normalized);
        }
    }
    Ok(record)
}

fn merge_certificate_variants(
    left: Option<&Value>,
    right: Option<&Value>,
) -> Result<Option<Value>, String> {
    let (Some(left), Some(right)) = (left, right) else {
        return Ok(left.or(right).cloned());
    };
    let left = left
        .as_array()
        .ok_or("Invalid stored authorization certificates")?;
    let right = right
        .as_array()
        .ok_or("Invalid stored authorization certificates")?;
    let mut merged = BTreeMap::<String, Value>::new();
    for certificate in left.iter().chain(right) {
        let signature = certificate
            .get("signature")
            .and_then(Value::as_str)
            .filter(|signature| !signature.is_empty())
            .ok_or("Invalid stored authorization certificate identity")?
            .to_owned();
        if merged
            .insert(signature, certificate.clone())
            .is_some_and(|previous| previous != *certificate)
        {
            return Err("Conflicting stored authorization certificate identity".into());
        }
    }
    Ok(Some(Value::Array(merged.into_values().collect())))
}

pub fn authorization_export(document: &[u8], bundle: &Value) -> Result<Value, String> {
    let records = stored_records(bundle)?;
    let identity_mode = has_grant_variants(&records)?.then_some(GRANT_VARIANT_IDENTITY_MODE);
    if identity_mode.is_none()
        && records.len() <= 20_000
        && bytes(bundle)? <= LEGACY_WIRE_BYTES
        && bundle.get("version").and_then(Value::as_u64) == Some(1)
    {
        return Ok(bundle.clone());
    }
    let mut doc = AutoCommit::load(document).map_err(|e| e.to_string())?;
    let workspace_id = bundle
        .pointer("/authority/genesisOwner/personId")
        .and_then(Value::as_str)
        .ok_or("Missing workspace authority")?;
    // Read workspace id from actual document, never from proof claims.
    let raw = serde_json::to_value(automerge::AutoSerde::from(&doc)).map_err(|e| e.to_string())?;
    let id = raw
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Missing workspace document id")?;
    if workspace_id.is_empty() {
        return Err("Missing workspace genesis authority".into());
    }
    let mut heads = doc
        .get_heads()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    heads.sort();
    let mut manifest = AuthorizationManifest {
        kind: "workspace-authorization-manifest".into(),
        version: 2,
        workspace_id: id.into(),
        heads,
        authority: bundle
            .get("authority")
            .cloned()
            .ok_or("Missing workspace authority")?,
        records_digest: records_digest(&records, identity_mode)?,
        transfer_id: String::new(),
        record_identity_mode: identity_mode,
    };
    manifest.transfer_id = manifest_id(&manifest)?;
    validate_manifest(&manifest)?;
    serde_json::to_value(manifest).map_err(|e| e.to_string())
}

fn request_id(manifest: &AuthorizationManifest, hashes: &[String]) -> Result<String, String> {
    digest(&json!({"transferId": manifest.transfer_id, "hashes": hashes}))
}

fn records_digest(records: &[Value], mode: Option<u8>) -> Result<String, String> {
    let mut identities = BTreeMap::new();
    for record in records {
        let key = record_identity_key(record, mode)?;
        let value = digest(record)?;
        if identities
            .insert(key, value.clone())
            .is_some_and(|previous| previous != value)
        {
            return Err("Conflicting stored authorization identity".into());
        }
    }
    digest(&serde_json::to_value(identities).map_err(|e| e.to_string())?)
}

pub fn authorization_page(
    document: &[u8],
    bundle: &Value,
    request: AuthorizationPageRequest,
) -> Result<AuthorizationPage, String> {
    PreparedAuthorizationSource::new(document, bundle, &request.manifest)?.page(request)
}

/// Frozen source index. Build once per transfer, retain whole records unchanged.
/// Later pages touch requested hashes only; authority changes require restart.
pub struct PreparedAuthorizationSource {
    transfer_id: String,
    source_hashes: BTreeSet<String>,
    records: BTreeMap<String, Value>,
    by_hash: BTreeMap<String, BTreeSet<String>>,
}
impl PreparedAuthorizationSource {
    pub fn new(
        document: &[u8],
        bundle: &Value,
        manifest: &AuthorizationManifest,
    ) -> Result<Self, String> {
        validate_manifest(manifest)?;
        if bundle.get("authority") != Some(&manifest.authority) {
            return Err("Authorization authority changed; restart document sync".into());
        }
        let mut doc = AutoCommit::load(document).map_err(|e| e.to_string())?;
        let heads = manifest
            .heads
            .iter()
            .map(|h| {
                ChangeHash::from_str(h).map_err(|_| "Invalid authorization source head".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut source = doc
            .fork_at(&heads)
            .map_err(|_| "Authorization source history unavailable")?;
        let raw =
            serde_json::to_value(automerge::AutoSerde::from(&source)).map_err(|e| e.to_string())?;
        if raw.get("id").and_then(Value::as_str) != Some(manifest.workspace_id.as_str()) {
            return Err("Wrong authorization source workspace".into());
        }
        let source_hashes = source
            .get_changes(&[])
            .iter()
            .map(|c| c.hash().to_string())
            .collect::<BTreeSet<_>>();

        let mut records = BTreeMap::new();
        let mut by_hash: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let stored = stored_records(bundle)?;
        if records_digest(&stored, manifest.record_identity_mode)? != manifest.records_digest {
            return Err("Authorization records changed; restart document sync".into());
        }
        for record in stored {
            let key = grant_variant_key(&record)?;
            if let Some(hashes) = record
                .pointer("/signed/payload/hashes")
                .and_then(Value::as_array)
            {
                for hash in hashes
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|h| source_hashes.contains(*h))
                {
                    by_hash
                        .entry(hash.to_string())
                        .or_default()
                        .insert(key.clone());
                }
            }
            if let Some(previous) = records.insert(key, record.clone()) {
                if previous != record {
                    return Err("Conflicting stored authorization identity".into());
                }
            }
        }
        Ok(Self {
            transfer_id: manifest.transfer_id.clone(),
            source_hashes,
            records,
            by_hash,
        })
    }
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }
    pub fn page(&self, request: AuthorizationPageRequest) -> Result<AuthorizationPage, String> {
        validate_manifest(&request.manifest)?;
        if request.version != 1
            || request.hashes.is_empty()
            || request.hashes.len() > MAX_PROOF_REQUEST_HASHES
            || request.hashes.windows(2).any(|p| p[0] >= p[1])
            || request_id(&request.manifest, &request.hashes)? != request.request_id
            || bytes(&request)? > MAX_PROOF_PAGE_BYTES
        {
            return Err("Invalid authorization page request".into());
        }

        if request.manifest.transfer_id != self.transfer_id {
            return Err("Wrong frozen proof source".into());
        }
        if request.record_identity_mode != request.manifest.record_identity_mode {
            if request.record_identity_mode.is_none()
                && request.manifest.record_identity_mode.is_some()
            {
                return Err(
                    "Peer must upgrade authorization page identity mode for grant provenance variants"
                        .into(),
                );
            }
            return Err("Authorization record identity mode changed; restart document sync".into());
        }
        if request
            .hashes
            .iter()
            .any(|h| !self.source_hashes.contains(h))
        {
            return Err("Requested authorization hash absent from actual source history".into());
        }
        if request.record_identity_mode.is_none()
            && has_grant_variants(&self.records.values().cloned().collect::<Vec<_>>())?
        {
            return Err(
                "Peer must upgrade authorization page identity mode for grant provenance variants"
                    .into(),
            );
        }
        let mut selected = BTreeMap::new();
        for hash in &request.hashes {
            if let Some(keys) = self.by_hash.get(hash) {
                for key in keys {
                    let record = self.records.get(key).expect("indexed record");
                    let cursor = record_identity_key(record, request.record_identity_mode)?;
                    if cursor > request.after {
                        selected.insert(cursor, key.clone());
                    }
                }
            }
        }
        let mut page = AuthorizationPage {
            version: 1,
            transfer_id: request.manifest.transfer_id,
            request_id: request.request_id,
            after: request.after.clone(),
            next: request.after,
            complete: true,
            records: vec![],
            record_identity_mode: request.record_identity_mode,
        };
        let mut page_bytes = bytes(&page)?;
        for (cursor, key) in selected {
            let record = self.records.get(&key).expect("indexed record").clone();
            let next_bytes = page_bytes
                + bytes(&record)?
                + usize::from(!page.records.is_empty())
                + bytes(&cursor)?
                - bytes(&page.next)?;
            // complete:false is one byte longer than complete:true.
            if page.records.len() == 20_000 || next_bytes + 1 > MAX_PROOF_PAGE_BYTES {
                if page.records.is_empty() {
                    return Err(
                    "One signed authorization record exceeds page budget; cannot split signature"
                        .into(),
                );
                }
                page.complete = false;
                break;
            }
            page.records.push(record);
            page.next = cursor;
            page_bytes = next_bytes;
        }
        Ok(page)
    }
}

pub struct AuthorizationPageReceiver {
    manifest: AuthorizationManifest,
    hashes: Vec<String>,
    offset: usize,
    after: String,
    pages: Vec<Vec<Value>>,
    record_count: usize,
    byte_count: usize,
    seen: BTreeMap<(String, String), String>,
    received_grant_identity: BTreeMap<String, String>,
}

impl AuthorizationPageReceiver {
    pub fn new(
        manifest: AuthorizationManifest,
        candidate: &[u8],
        local: &[u8],
    ) -> Result<Self, String> {
        validate_manifest(&manifest)?;
        let mut doc = AutoCommit::load(candidate).map_err(|e| e.to_string())?;
        let raw =
            serde_json::to_value(automerge::AutoSerde::from(&doc)).map_err(|e| e.to_string())?;
        if raw.get("id").and_then(Value::as_str) != Some(manifest.workspace_id.as_str()) {
            return Err("Wrong proof transfer workspace".into());
        }
        let mut stored = AutoCommit::load(local).map_err(|e| e.to_string())?;
        let known = stored
            .get_changes(&[])
            .iter()
            .map(|c| c.hash().to_string())
            .collect::<BTreeSet<_>>();
        let hashes = doc
            .get_changes(&[])
            .iter()
            .map(|c| c.hash().to_string())
            .filter(|h| !known.contains(h))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if hashes.len() > MAX_PROOF_TRANSFER_RECORDS {
            return Err("Proof history exceeds transfer limit".into());
        }
        Ok(Self {
            manifest,
            hashes,
            offset: 0,
            after: String::new(),
            pages: vec![],
            record_count: 0,
            byte_count: 0,
            seen: BTreeMap::new(),
            received_grant_identity: BTreeMap::new(),
        })
    }
    pub fn request(&self) -> Result<Option<AuthorizationPageRequest>, String> {
        if self.offset >= self.hashes.len() {
            return Ok(None);
        }
        let available = (self.hashes.len() - self.offset).min(MAX_PROOF_REQUEST_HASHES);
        let make = |count: usize| -> Result<AuthorizationPageRequest, String> {
            let hashes = self.hashes[self.offset..self.offset + count].to_vec();
            Ok(AuthorizationPageRequest {
                version: 1,
                manifest: self.manifest.clone(),
                request_id: request_id(&self.manifest, &hashes)?,
                hashes,
                after: self.after.clone(),
                record_identity_mode: self.manifest.record_identity_mode,
            })
        };
        let request = make(available)?;
        if bytes(&request)? <= MAX_PROOF_PAGE_BYTES {
            return Ok(Some(request));
        }
        let (mut low, mut high) = (1, available);
        if bytes(&make(1)?)? > MAX_PROOF_PAGE_BYTES {
            return Err("Authority evidence cannot fit a proof request envelope".into());
        }
        while low < high {
            let middle = (low + high + 1) / 2;
            if bytes(&make(middle)?)? <= MAX_PROOF_PAGE_BYTES {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        Ok(Some(make(low)?))
    }
    pub fn accept(&mut self, page: AuthorizationPage) -> Result<(), String> {
        let request = self.request()?.ok_or("Unexpected authorization page")?;
        if page.version != 1
            || page.transfer_id != request.manifest.transfer_id
            || page.request_id != request.request_id
            || page.after != request.after
            || bytes(&page)? > MAX_PROOF_PAGE_BYTES
            || page.records.len() > 20_000
            || page.record_identity_mode != request.record_identity_mode
        {
            return Err("Authorization page does not match pending request".into());
        }
        let mut cursor = page.after.clone();
        let mut page_grant_identity = BTreeMap::new();
        for record in &page.records {
            let sig = signature(record)?.to_owned();
            let key = record_identity_key(record, page.record_identity_mode)?;
            if key.as_str() <= cursor.as_str() {
                return Err("Authorization page cursor did not advance".into());
            }
            if page.record_identity_mode.is_none() {
                let grant_key = grant_variant_key(record)?;
                if self
                    .received_grant_identity
                    .get(&sig)
                    .is_some_and(|previous| previous != &grant_key)
                    || page_grant_identity
                        .insert(sig, grant_key.clone())
                        .is_some_and(|previous| previous != grant_key)
                {
                    return Err(
                        "Peer must upgrade authorization page identity mode for grant provenance variants"
                            .into(),
                    );
                }
            }
            cursor = key.into();
        }
        if cursor != page.next || (!page.complete && page.records.is_empty()) {
            return Err("Invalid authorization page progress".into());
        }
        let record_count = self.record_count + page.records.len();
        let byte_count = self.byte_count + bytes(&page)?;
        if record_count > MAX_PROOF_TRANSFER_RECORDS || byte_count > MAX_PROOF_TRANSFER_BYTES {
            return Err("Proof transfer exceeds aggregate resource limit".into());
        }
        self.received_grant_identity.extend(page_grant_identity);
        self.record_count = record_count;
        self.byte_count = byte_count;
        self.seen.insert(
            (page.request_id.clone(), page.after.clone()),
            digest(&serde_json::to_value(&page).map_err(|e| e.to_string())?)?,
        );
        self.pages.push(page.records);
        self.after = page.next;
        if page.complete {
            self.offset += request.hashes.len();
            self.after.clear();
        }
        Ok(())
    }
    pub fn is_replay(&self, page: &AuthorizationPage) -> Result<bool, String> {
        let Some(expected) = self
            .seen
            .get(&(page.request_id.clone(), page.after.clone()))
        else {
            return Ok(false);
        };
        if *expected != digest(&serde_json::to_value(page).map_err(|e| e.to_string())?)? {
            return Err("Conflicting replayed authorization page".into());
        }
        Ok(true)
    }
    pub fn bundle(&self) -> Result<Value, String> {
        if self.request()?.is_some() {
            return Err("Authorization transfer incomplete".into());
        }
        // Completion is structural only. Cryptographic admission must still
        // reject missing, forged, revoked, or otherwise unauthorized hashes.
        Ok(json!({"version": 2, "authority": self.manifest.authority, "pages": self.pages}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automerge::{transaction::Transactable, ROOT};

    fn signed_sidecar_fixture() -> (
        Vec<u8>,
        Vec<u8>,
        Value,
        crate::WorkspaceWriteAuthorizationSnapshot,
        Vec<crate::ChangeAdmissionChange>,
    ) {
        use crate::{
            public_key_from_seed, public_key_id, sign_device_certificate, sign_json_envelope,
            DeviceCertificatePayload, WorkspaceAuthority, DEFAULT_SIGNATURE_DOMAIN,
        };

        let root_seed = [51u8; 32];
        let device_seed = [52u8; 32];
        let other_device_seed = [53u8; 32];
        let owner_public_key = public_key_from_seed(&root_seed).unwrap();
        let owner_person_id = public_key_id(&owner_public_key).unwrap();
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let other_device_public_key = public_key_from_seed(&other_device_seed).unwrap();
        let other_device_id = public_key_id(&other_device_public_key).unwrap();
        let make_certificate = |device_id: String, device_public_key: String| {
            sign_device_certificate(
                &root_seed,
                DeviceCertificatePayload {
                    kind: "device-certificate".into(),
                    version: 1,
                    person_id: owner_person_id.clone(),
                    device_id,
                    device_public_key,
                    issuer_certificate_hash: None,
                    can_enroll_devices: true,
                },
                &owner_person_id,
                DEFAULT_SIGNATURE_DOMAIN,
            )
            .unwrap()
        };
        let certificate = make_certificate(device_id.clone(), device_public_key.clone());
        let other_certificate = make_certificate(other_device_id, other_device_public_key);

        let mut document = AutoCommit::new();
        document.put(ROOT, "id", "board").unwrap();
        document.put(ROOT, "counter", 1i64).unwrap();
        let changes = document
            .get_changes(&[])
            .iter()
            .map(|change| crate::ChangeAdmissionChange {
                hash: change.hash().to_string(),
                dependencies: change.deps().iter().map(ToString::to_string).collect(),
                actor: change.actor_id().to_hex_string(),
                message: change.message().unwrap_or_default().to_string(),
            })
            .collect::<Vec<_>>();
        let hashes = changes
            .iter()
            .map(|change| change.hash.clone())
            .collect::<Vec<_>>();
        let signed = sign_json_envelope(
            &device_seed,
            json!({"kind":"workspace-changes", "version":1, "workspaceId":"board",
                "hashes":hashes, "personId":owner_person_id, "deviceId":device_id}),
            &device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let record = json!({"signed":signed, "publicKey":owner_public_key,
            "certificates":[certificate], "ownerCertificates":[certificate], "grant":null,
            "padding":"x".repeat(70 * 1024)});
        let mut enriched = record.clone();
        enriched["certificates"] = json!([other_certificate, certificate]);
        enriched["ownerPublicKey"] = json!(owner_public_key);
        enriched["ownerCertificates"] = json!([other_certificate, certificate]);
        let authority = WorkspaceAuthority {
            person_id: owner_person_id,
            public_key: owner_public_key,
            certificates: vec![certificate, other_certificate],
        };
        let document_bytes = document.save();
        let proof = json!({"version":1, "authority":{"genesisOwner":authority},
            "records":[record, enriched]});
        let snapshot = crate::WorkspaceWriteAuthorizationSnapshot {
            workspace_id: "board".into(),
            genesis_owner: authority.clone(),
            genesis_epoch: 1,
            expected_current_owner: authority,
            document: document_bytes.clone(),
            ownership_transfers: vec![],
            succession_claims: vec![],
            revocations: vec![],
            device_revocations: vec![],
            departures: vec![],
        };
        (
            document_bytes,
            AutoCommit::new().save(),
            proof,
            snapshot,
            changes,
        )
    }

    #[test]
    fn stored_duplicate_proofs_merge_certificate_sidecars_without_weakening_admission() {
        let (document, empty, proof, snapshot, changes) = signed_sidecar_fixture();
        let exported = authorization_export(&document, &proof).unwrap();
        let mut reordered = proof.clone();
        reordered["records"].as_array_mut().unwrap().reverse();
        let reordered_export = authorization_export(&document, &reordered).unwrap();
        assert_eq!(exported, reordered_export);
        let single_enriched = json!({"version":1, "authority":proof["authority"],
            "records":[proof["records"][1].clone()]});
        assert_eq!(
            exported,
            authorization_export(&document, &single_enriched).unwrap()
        );

        let manifest: AuthorizationManifest = serde_json::from_value(exported.clone()).unwrap();
        assert_eq!(manifest.record_identity_mode, None);
        assert_eq!(serde_json::to_value(&manifest).unwrap(), exported);
        assert!(serde_json::to_value(&manifest)
            .unwrap()
            .get("recordIdentityMode")
            .is_none());
        assert_eq!(
            manifest.transfer_id,
            digest(&json!({
                "workspaceId": manifest.workspace_id,
                "heads": manifest.heads,
                "authority": manifest.authority,
                "recordsDigest": manifest.records_digest,
                "version": 2,
            }))
            .unwrap()
        );
        let source = PreparedAuthorizationSource::new(&document, &proof, &manifest).unwrap();
        let mut receiver = AuthorizationPageReceiver::new(manifest, &document, &empty).unwrap();
        while let Some(request) = receiver.request().unwrap() {
            assert_eq!(request.record_identity_mode, None);
            assert!(serde_json::to_value(&request)
                .unwrap()
                .get("recordIdentityMode")
                .is_none());
            let page = source.page(request).unwrap();
            assert_eq!(page.record_identity_mode, None);
            let old_wire_page = serde_json::to_value(&page).unwrap();
            assert!(old_wire_page.get("recordIdentityMode").is_none());
            receiver
                .accept(serde_json::from_value(old_wire_page).unwrap())
                .unwrap();
        }
        let transferred = receiver.bundle().unwrap();
        let pages = authorization_record_pages(&transferred).unwrap();
        assert_eq!(pages.iter().map(Vec::len).sum::<usize>(), 1);
        let record = &pages[0][0];
        assert_eq!(record["ownerCertificates"].as_array().unwrap().len(), 2);
        assert_eq!(record["certificates"].as_array().unwrap().len(), 2);
        assert_eq!(
            record["ownerPublicKey"],
            proof["records"][1]["ownerPublicKey"]
        );

        // The signed payload and signer credentials still pass normal crypto admission.
        let plan = crate::plan_change_admission_flow(
            crate::ChangeAdmissionFlowInput {
                records: vec![],
                record_pages: Some(pages),
                known_hashes: vec![],
                changes,
                snapshot,
            },
            0,
        )
        .unwrap();
        assert!(plan.unsigned_error.is_none());
        assert_eq!(plan.admitted_changes.len(), plan.incoming_changes.len());
    }

    #[test]
    fn stored_duplicate_proofs_reject_signed_scalar_and_certificate_conflicts() {
        let (document, _, proof, _, _) = signed_sidecar_fixture();
        let mut conflicting_signed = proof.clone();
        conflicting_signed["records"][1]["signed"]["payload"]["workspaceId"] =
            json!("another-board");
        assert!(authorization_export(&document, &conflicting_signed)
            .unwrap_err()
            .contains("Conflicting stored authorization identity"));

        let mut conflicting_owner = proof.clone();
        conflicting_owner["records"][0]["ownerPublicKey"] = json!("first-owner");
        conflicting_owner["records"][1]["ownerPublicKey"] = json!("different-owner");
        assert!(authorization_export(&document, &conflicting_owner)
            .unwrap_err()
            .contains("Conflicting stored authorization identity"));

        let mut conflicting_certificate = proof.clone();
        conflicting_certificate["records"][1]["certificates"][1]["payload"]["deviceId"] =
            json!("different-device");
        assert!(authorization_export(&document, &conflicting_certificate)
            .unwrap_err()
            .contains("Conflicting stored authorization certificate identity"));

        let mut malformed_singleton = proof;
        malformed_singleton["records"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        malformed_singleton["records"][0]["certificates"][0]
            .as_object_mut()
            .unwrap()
            .remove("signature");
        assert!(authorization_export(&document, &malformed_singleton)
            .unwrap_err()
            .contains("Invalid stored authorization certificate identity"));
    }

    #[test]
    fn rejected_legacy_page_does_not_poison_retry_identity_state() {
        let (document, empty, proof, _, _) = signed_sidecar_fixture();
        let mut record = proof["records"][0].clone();
        record["padding"] = json!("x".repeat(70 * 1024));
        let bundle = json!({
            "version": 1,
            "authority": proof["authority"],
            "records": [record.clone()],
        });
        let manifest: AuthorizationManifest =
            serde_json::from_value(authorization_export(&document, &bundle).unwrap()).unwrap();
        assert_eq!(manifest.record_identity_mode, None);
        let mut receiver =
            AuthorizationPageReceiver::new(manifest.clone(), &document, &empty).unwrap();
        let request = receiver.request().unwrap().unwrap();
        let page = AuthorizationPage {
            version: 1,
            transfer_id: manifest.transfer_id,
            request_id: request.request_id,
            after: request.after,
            next: signature(&record).unwrap().into(),
            complete: true,
            records: vec![record],
            record_identity_mode: None,
        };

        let mut malformed = page.clone();
        malformed.next = "invalid-cursor".into();
        malformed.records[0]["grant"] = json!({"provenance": "rejected-page"});
        assert!(receiver.accept(malformed).unwrap_err().contains("progress"));
        receiver.accept(page).unwrap();
        assert!(receiver.request().unwrap().is_none());
    }

    #[test]
    fn grant_provenance_variants_survive_bounded_proof_roundtrip_and_admission() {
        use crate::{
            sign_json_envelope, WorkspaceGrantPayload, WorkspaceRole, DEFAULT_SIGNATURE_DOMAIN,
        };

        let (document, empty, proof, snapshot, changes) = signed_sidecar_fixture();
        let owner_person_id = proof["authority"]["genesisOwner"]["personId"]
            .as_str()
            .unwrap();
        let make_grant = |epoch: u64| {
            let payload = serde_json::to_value(WorkspaceGrantPayload {
                kind: "workspace-grant".into(),
                version: 1,
                grant_id: format!("owner-grant-{epoch}"),
                workspace_id: "board".into(),
                person_id: owner_person_id.into(),
                role: WorkspaceRole::Owner,
                access_epoch: Some(epoch),
            })
            .unwrap();
            serde_json::to_value(
                sign_json_envelope(
                    &[51u8; 32],
                    payload,
                    owner_person_id,
                    DEFAULT_SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap()
        };

        let compact_record = json!({
            "signed": {"signature": "compact-signature", "payload": {"workspaceId": "board"}},
        });
        let compact_legacy = json!({
            "version": 1,
            "authority": proof["authority"],
            "records": [compact_record.clone()],
        });
        assert!(bytes(&compact_legacy).unwrap() < LEGACY_WIRE_BYTES);
        assert_eq!(
            authorization_export(&document, &compact_legacy).unwrap(),
            compact_legacy
        );
        let mut explicit_no_grant = compact_record.clone();
        explicit_no_grant["grant"] = Value::Null;
        let optional_grant_forms = json!({
            "version": 1,
            "authority": proof["authority"],
            "records": [compact_record.clone(), explicit_no_grant],
        });
        assert_eq!(
            authorization_export(&document, &optional_grant_forms).unwrap(),
            optional_grant_forms
        );

        let mut compact_granted = compact_record.clone();
        compact_granted["grant"] = make_grant(4);
        let compact_variants = json!({
            "version": 1,
            "authority": proof["authority"],
            "records": [compact_record, compact_granted],
        });
        assert!(bytes(&compact_variants).unwrap() < LEGACY_WIRE_BYTES);
        let compact_manifest: AuthorizationManifest =
            serde_json::from_value(authorization_export(&document, &compact_variants).unwrap())
                .unwrap();
        assert_eq!(
            compact_manifest.record_identity_mode,
            Some(GRANT_VARIANT_IDENTITY_MODE)
        );

        let mut no_grant = proof["records"][0].clone();
        no_grant.as_object_mut().unwrap().remove("grant");
        no_grant["padding"] = json!("x".repeat(70 * 1024));
        no_grant["ownerPublicKey"] = proof["authority"]["genesisOwner"]["publicKey"].clone();
        let mut older_grant = no_grant.clone();
        older_grant["grant"] = make_grant(4);
        let mut current_grant = no_grant.clone();
        current_grant["grant"] = make_grant(5);
        let variants = vec![no_grant, older_grant, current_grant];
        let aggregate = json!({
            "version": 1,
            "authority": proof["authority"],
            "records": variants,
        });

        // Fails before the fix: same signature is incorrectly treated as one grant identity.
        let manifest_value = authorization_export(&document, &aggregate).unwrap();
        let manifest: AuthorizationManifest = serde_json::from_value(manifest_value).unwrap();
        assert_eq!(
            manifest.record_identity_mode,
            Some(GRANT_VARIANT_IDENTITY_MODE)
        );
        let mut legacy_manifest = manifest.clone();
        legacy_manifest.record_identity_mode = None;
        assert!(validate_manifest(&legacy_manifest).is_err());
        let source = PreparedAuthorizationSource::new(&document, &aggregate, &manifest).unwrap();
        let mut receiver = AuthorizationPageReceiver::new(manifest, &document, &empty).unwrap();
        while let Some(request) = receiver.request().unwrap() {
            assert_eq!(
                request.record_identity_mode,
                Some(GRANT_VARIANT_IDENTITY_MODE)
            );
            let mut legacy_request = request.clone();
            legacy_request.record_identity_mode = None;
            assert!(source
                .page(legacy_request)
                .unwrap_err()
                .contains("must upgrade"));

            let page = source.page(request).unwrap();
            assert_eq!(page.record_identity_mode, Some(GRANT_VARIANT_IDENTITY_MODE));
            let mut old_wire_page = serde_json::to_value(&page).unwrap();
            old_wire_page
                .as_object_mut()
                .unwrap()
                .remove("recordIdentityMode");
            assert!(receiver
                .accept(serde_json::from_value(old_wire_page).unwrap())
                .unwrap_err()
                .contains("does not match pending request"));
            receiver.accept(page).unwrap();
        }

        let transferred = receiver.bundle().unwrap();
        let admission_bundle = authorization_admission_bundle(&transferred).unwrap();
        let pages = authorization_record_pages(&admission_bundle).unwrap();
        let records = pages
            .iter()
            .flat_map(|page| page.iter().cloned())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records
                .iter()
                .filter(|record| record.get("grant").is_none())
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["grant"].is_object())
                .count(),
            2
        );
        let epochs = records
            .iter()
            .filter_map(|record| {
                record
                    .pointer("/grant/payload/accessEpoch")
                    .and_then(Value::as_u64)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(epochs, BTreeSet::from([4, 5]));

        // Transport preserves provenance, while ordinary signed authorization policy still runs.
        let plan = crate::plan_change_admission_flow(
            crate::ChangeAdmissionFlowInput {
                records: vec![],
                record_pages: Some(pages.clone()),
                known_hashes: vec![],
                changes,
                snapshot,
            },
            0,
        )
        .unwrap();
        assert!(plan.unsigned_error.is_none());
        assert_eq!(plan.admitted_changes.len(), 3);

        let mut conflicting_signed = aggregate.clone();
        conflicting_signed["records"][1]["signed"]["payload"]["workspaceId"] =
            json!("another-board");
        assert!(authorization_export(&document, &conflicting_signed)
            .unwrap_err()
            .contains("Conflicting stored authorization identity"));
        let mut conflicting_key = aggregate.clone();
        conflicting_key["records"][1]["publicKey"] = json!("different-signer-key");
        assert!(authorization_export(&document, &conflicting_key)
            .unwrap_err()
            .contains("Conflicting stored authorization identity"));
        let mut conflicting_owner_key = aggregate;
        conflicting_owner_key["records"][1]["ownerPublicKey"] = json!("different-owner-key");
        assert!(authorization_export(&document, &conflicting_owner_key)
            .unwrap_err()
            .contains("Conflicting stored authorization identity"));
    }

    /// Deterministic full signed-history regression and separate source/crypto timings.
    /// Run explicitly in release mode; cryptography is deliberately not mocked.
    #[test]
    #[ignore = "large deterministic signed-history benchmark"]
    fn signed_initial_and_incremental_history_benchmark() {
        use crate::{
            plan_change_admission_flow, public_key_from_seed, public_key_id,
            sign_device_certificate, sign_json_envelope, ChangeAdmissionChange,
            ChangeAdmissionFlowInput, DeviceCertificatePayload, WorkspaceAuthority,
            WorkspaceWriteAuthorizationSnapshot, DEFAULT_SIGNATURE_DOMAIN,
        };
        use std::time::Instant;
        let root_seed = [41u8; 32];
        let seed = [42u8; 32];
        let public_key = public_key_from_seed(&root_seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &root_seed,
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
        let owner = WorkspaceAuthority {
            person_id: person_id.clone(),
            public_key: public_key.clone(),
            certificates: vec![certificate.clone()],
        };
        for count in [100usize, 1000, 20_001] {
            let mut doc = AutoCommit::new();
            let empty = doc.save();
            let mut records = vec![];
            for index in 0..count {
                doc.put(ROOT, "id", "board").unwrap();
                doc.put(ROOT, "counter", index as i64).unwrap();
                let hash = doc.get_heads()[0].to_string();
                let signed = sign_json_envelope(&seed, json!({"kind":"workspace-changes", "version":1,
                    "workspaceId":"board", "hashes":[hash], "personId":person_id, "deviceId":device_id}),
                    &device_id, DEFAULT_SIGNATURE_DOMAIN).unwrap();
                records.push(
                    json!({"signed":signed, "publicKey":public_key, "certificates":[certificate]}),
                );
            }
            let document = doc.save();
            let authority = json!({"genesisOwner":owner});
            let legacy = json!({"version":1,"authority":authority,"records":records});
            let wire_bytes = bytes(&legacy).unwrap();
            if count > 20_000 {
                assert!(authorization_record_pages(&legacy).is_err());
                assert!(wire_bytes > 16 * 1024 * 1024);
            }
            let source_started = Instant::now();
            let frozen_manifest = manifest(&document, &legacy);
            let source =
                PreparedAuthorizationSource::new(&document, &legacy, &frozen_manifest).unwrap();
            let source_ms = source_started.elapsed().as_millis();
            let mut receiver =
                AuthorizationPageReceiver::new(frozen_manifest, &document, &empty).unwrap();
            let pages_started = Instant::now();
            let mut page_count = 0;
            while let Some(request) = receiver.request().unwrap() {
                let page = source.page(request).unwrap();
                assert!(bytes(&page).unwrap() <= MAX_PROOF_PAGE_BYTES);
                receiver.accept(page).unwrap();
                page_count += 1;
            }
            let pages_ms = pages_started.elapsed().as_millis();
            let bundle = receiver.bundle().unwrap();
            let changes = doc
                .get_changes(&[])
                .iter()
                .map(|change| ChangeAdmissionChange {
                    hash: change.hash().to_string(),
                    dependencies: change.deps().iter().map(ToString::to_string).collect(),
                    actor: change.actor_id().to_hex_string(),
                    message: change.message().unwrap_or_default().to_string(),
                })
                .collect::<Vec<_>>();
            let snapshot = WorkspaceWriteAuthorizationSnapshot {
                workspace_id: "board".into(),
                genesis_owner: owner.clone(),
                genesis_epoch: 1,
                expected_current_owner: owner.clone(),
                document: document.clone(),
                ownership_transfers: vec![],
                succession_claims: vec![],
                revocations: vec![],
                device_revocations: vec![],
                departures: vec![],
            };
            let admission_started = Instant::now();
            let plan = plan_change_admission_flow(
                ChangeAdmissionFlowInput {
                    records: vec![],
                    record_pages: Some(authorization_record_pages(&bundle).unwrap()),
                    known_hashes: vec![],
                    changes: changes.clone(),
                    snapshot: snapshot.clone(),
                },
                0,
            )
            .unwrap();
            assert_eq!(plan.incoming_changes.len(), count);
            assert!(plan.unsigned_error.is_none());
            let admission_ms = admission_started.elapsed().as_millis();
            let known = changes.iter().map(|c| c.hash.clone()).collect();
            doc.put(ROOT, "counter", count as i64).unwrap();
            let hash = doc.get_heads()[0].to_string();
            let signed = sign_json_envelope(
                &seed,
                json!({"kind":"workspace-changes","version":1,"workspaceId":"board",
                "hashes":[hash],"personId":person_id,"deviceId":device_id}),
                &device_id,
                DEFAULT_SIGNATURE_DOMAIN,
            )
            .unwrap();
            let record =
                json!({"signed":signed,"publicKey":public_key,"certificates":[certificate]});
            let delta_started = Instant::now();
            let all_changes = doc
                .get_changes(&[])
                .iter()
                .map(|change| ChangeAdmissionChange {
                    hash: change.hash().to_string(),
                    dependencies: change.deps().iter().map(ToString::to_string).collect(),
                    actor: change.actor_id().to_hex_string(),
                    message: change.message().unwrap_or_default().to_string(),
                })
                .collect::<Vec<_>>();
            let mut delta_snapshot = snapshot;
            delta_snapshot.document = doc.save();
            let delta = plan_change_admission_flow(
                ChangeAdmissionFlowInput {
                    records: vec![],
                    record_pages: Some(vec![vec![record.clone()]]),
                    known_hashes: known,
                    changes: all_changes,
                    snapshot: delta_snapshot.clone(),
                },
                0,
            )
            .unwrap();
            assert_eq!(delta.incoming_changes.len(), 1);
            assert!(delta.unsigned_error.is_none());
            let delta_ms = delta_started.elapsed().as_millis();
            let missing = plan_change_admission_flow(
                ChangeAdmissionFlowInput {
                    records: vec![],
                    record_pages: Some(vec![]),
                    known_hashes: changes.iter().map(|c| c.hash.clone()).collect(),
                    changes: delta.incoming_changes.clone(),
                    snapshot: delta_snapshot.clone(),
                },
                0,
            )
            .unwrap();
            assert!(missing.unsigned_error.is_some());
            let mut forged = record;
            forged["signed"]["signature"] = json!("forged");
            assert!(plan_change_admission_flow(
                ChangeAdmissionFlowInput {
                    records: vec![],
                    record_pages: Some(vec![vec![forged]]),
                    known_hashes: vec![],
                    changes: delta.incoming_changes,
                    snapshot: delta_snapshot
                },
                0
            )
            .is_err());
            eprintln!(
                "proof_benchmark history={count} proofs={count} aggregate_bytes={wire_bytes} pages={page_count} source_prepare_ms={source_ms} source_pages_ms={pages_ms} full_admission_ms={admission_ms} delta_history={} delta_proofs=1 delta_admission_ms={delta_ms}",
                count + 1
            );
        }
    }
    fn fixture(records: usize, padding: usize) -> (Vec<u8>, Vec<u8>, Value) {
        let mut local = AutoCommit::new();
        let empty = local.save();
        let mut doc = AutoCommit::new();
        doc.put(ROOT, "id", "board").unwrap();
        let bytes = doc.save();
        let hash = doc.get_heads()[0].to_string();
        let proof = json!({"version": 1, "authority": {"genesisOwner": {"personId": "owner"}},
            "records": (0..records).map(|i| json!({"signed": {"signature": format!("signature-{i:06}"),
                "payload": {"hashes": [hash]}}, "padding": "x".repeat(padding)})).collect::<Vec<_>>()});
        (bytes, empty, proof)
    }
    fn manifest(bytes: &[u8], proof: &Value) -> AuthorizationManifest {
        serde_json::from_value(authorization_export(bytes, proof).unwrap()).unwrap()
    }
    #[test]
    fn initial_history_exceeds_legacy_record_limit_but_every_record_travels_in_bounded_pages() {
        let (bytes, empty, proof) = fixture(20_001, 0);
        assert!(authorization_record_pages(&proof)
            .unwrap_err()
            .contains("size limit"));
        let mut receiver =
            AuthorizationPageReceiver::new(manifest(&bytes, &proof), &bytes, &empty).unwrap();
        let mut pages = 0;
        while let Some(request) = receiver.request().unwrap() {
            assert!(receiver.bundle().is_err());
            let page = authorization_page(&bytes, &proof, request).unwrap();
            assert!(super::bytes(&page).unwrap() <= MAX_PROOF_PAGE_BYTES);
            assert!(page.records.len() <= 20_000);
            receiver.accept(page).unwrap();
            pages += 1;
        }
        assert!(pages > 1);
        assert_eq!(
            authorization_records(&receiver.bundle().unwrap())
                .unwrap()
                .len(),
            20_001
        );
    }
    #[test]
    fn byte_limit_rejection_requires_pages_and_authority_overhead_is_bounded() {
        let (bytes, empty, proof) = fixture(17, 1_000_000);
        assert!(authorization_record_pages(&proof).is_err());
        // Large indivisible records cannot be made safe by paging.
        let receiver =
            AuthorizationPageReceiver::new(manifest(&bytes, &proof), &bytes, &empty).unwrap();
        assert!(
            authorization_page(&bytes, &proof, receiver.request().unwrap().unwrap())
                .unwrap_err()
                .contains("cannot split signature")
        );
        let (_, _, mut proof) = fixture(1, 70_000);
        proof["authority"]["overflow"] = json!("x".repeat(MAX_PROOF_PAGE_BYTES));
        assert!(authorization_export(&bytes, &proof)
            .unwrap_err()
            .contains("oversized"));
    }
    #[test]
    fn request_is_derived_from_actual_candidate_and_source_rejects_claimed_unknown_hash() {
        let (bytes, empty, proof) = fixture(2, 70_000);
        let receiver =
            AuthorizationPageReceiver::new(manifest(&bytes, &proof), &bytes, &empty).unwrap();
        let mut request = receiver.request().unwrap().unwrap();
        request.hashes = vec!["0".repeat(64)];
        request.request_id = request_id(&request.manifest, &request.hashes).unwrap();
        assert!(authorization_page(&bytes, &proof, request)
            .unwrap_err()
            .contains("actual source history"));
    }
    #[test]
    fn restart_reuses_stable_request_and_revalidates_saved_page_before_continuing() {
        let (bytes, empty, proof) = fixture(4, 100_000);
        let manifest = manifest(&bytes, &proof);
        let mut receiver =
            AuthorizationPageReceiver::new(manifest.clone(), &bytes, &empty).unwrap();
        let request = receiver.request().unwrap().unwrap();
        let page = authorization_page(&bytes, &proof, request.clone()).unwrap();
        assert!(!page.complete);
        receiver.accept(page.clone()).unwrap();
        assert!(receiver.is_replay(&page).unwrap());
        let mut conflicting = page.clone();
        conflicting.records[0]["padding"] = json!("forged replacement");
        assert!(receiver.is_replay(&conflicting).is_err());
        let mut restarted = AuthorizationPageReceiver::new(manifest, &bytes, &empty).unwrap();
        assert_eq!(
            restarted.request().unwrap().unwrap().request_id,
            request.request_id
        );
        restarted.accept(page).unwrap();
        assert_eq!(
            restarted.request().unwrap().unwrap().after,
            receiver.request().unwrap().unwrap().after
        );
        assert!(restarted.bundle().is_err());
        while let Some(request) = restarted.request().unwrap() {
            restarted
                .accept(authorization_page(&bytes, &proof, request).unwrap())
                .unwrap();
        }
        assert_eq!(
            authorization_records(&restarted.bundle().unwrap())
                .unwrap()
                .len(),
            4
        );
    }
    #[test]
    fn changed_authority_or_wrong_request_page_cannot_advance_transfer() {
        let (bytes, empty, mut proof) = fixture(2, 70_000);
        let mut receiver =
            AuthorizationPageReceiver::new(manifest(&bytes, &proof), &bytes, &empty).unwrap();
        let request = receiver.request().unwrap().unwrap();
        let mut page = authorization_page(&bytes, &proof, request.clone()).unwrap();
        page.request_id = "other-request".into();
        assert!(receiver.accept(page).is_err());
        assert_eq!(receiver.request().unwrap().unwrap().after, "");
        proof["authority"]["currentEpoch"] = json!(2);
        assert!(authorization_page(&bytes, &proof, request)
            .unwrap_err()
            .contains("authority changed"));
    }
    #[test]
    fn frozen_source_avoids_reloading_and_proof_only_additions_change_identity() {
        let (document, empty, mut proof) = fixture(2, 70_000);
        let initial = manifest(&document, &proof);
        let receiver = AuthorizationPageReceiver::new(initial.clone(), &document, &empty).unwrap();
        let request = serde_json::to_vec(&receiver.request().unwrap().unwrap()).unwrap();
        let mut runtime = crate::MeshScopeRuntime::new("board", "secret").unwrap();
        assert!(runtime
            .provide_cached_proof_page(&request)
            .unwrap()
            .is_none());
        let frame = runtime
            .provide_proof_page(&request, &document, proof.clone())
            .unwrap();
        assert_eq!(
            runtime.provide_cached_proof_page(&request).unwrap(),
            Some(frame)
        );
        let mut additional = proof["records"][0].clone();
        additional["signed"]["signature"] = json!("additional-proof");
        proof["records"].as_array_mut().unwrap().push(additional);
        let changed = manifest(&document, &proof);
        assert_ne!(initial.transfer_id, changed.transfer_id);
        let receiver = AuthorizationPageReceiver::new(changed, &document, &empty).unwrap();
        let request = serde_json::to_vec(&receiver.request().unwrap().unwrap()).unwrap();
        assert!(runtime
            .provide_cached_proof_page(&request)
            .unwrap()
            .is_none());
        assert!(runtime
            .provide_proof_page(&request, &document, proof)
            .is_ok());
    }
    #[test]
    fn standalone_transfer_cannot_complete_or_publish_before_last_page() {
        let (document, empty, proof) = fixture(4, 70_000);
        let mut runtime = crate::MeshScopeRuntime::new("board", "secret").unwrap();
        let effect = runtime
            .begin_authorization_transfer(
                &document,
                &empty,
                serde_json::to_value(manifest(&document, &proof)).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            effect,
            crate::MeshScopeFrameEffect::ProofRequest { .. }
        ));
        assert!(runtime
            .complete_document_receive(true)
            .unwrap_err()
            .contains("incomplete"));
        runtime.reject_document_receive().unwrap();
        assert!(runtime
            .begin_authorization_transfer(
                &document,
                &empty,
                serde_json::to_value(manifest(&document, &proof)).unwrap()
            )
            .is_ok());
    }
    #[test]
    fn request_hash_batch_shrinks_to_include_large_authority_evidence() {
        let (mut document, empty, mut proof) = fixture(1, 0);
        let mut doc = AutoCommit::load(&document).unwrap();
        for i in 0..1200 {
            doc.put(ROOT, "counter", i as i64).unwrap();
            doc.get_heads();
        }
        document = doc.save();
        proof["authority"]["evidencePadding"] = json!("x".repeat(190_000));
        let frozen = manifest(&document, &proof);
        let receiver = AuthorizationPageReceiver::new(frozen, &document, &empty).unwrap();
        let request = receiver.request().unwrap().unwrap();
        assert!(request.hashes.len() < MAX_PROOF_REQUEST_HASHES);
        assert!(!request.hashes.is_empty());
        assert!(bytes(&request).unwrap() <= MAX_PROOF_PAGE_BYTES);
        assert_eq!(receiver.request().unwrap().unwrap().hashes, request.hashes);
    }
}
