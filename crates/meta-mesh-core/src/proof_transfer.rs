//! Bounded proof exchange. Page contents remain untrusted until complete
//! document admission; page receipts never acknowledge a durable document.
use crate::identity::canonicalize_json;
use automerge::{AutoCommit, ChangeHash};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPageRequest {
    pub version: u8,
    pub manifest: AuthorizationManifest,
    pub request_id: String,
    pub hashes: Vec<String>,
    pub after: String,
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
    digest(
        &json!({"workspaceId": manifest.workspace_id, "heads": manifest.heads,
                  "authority": manifest.authority, "recordsDigest": manifest.records_digest, "version": 2}),
    )
}
fn validate_manifest(manifest: &AuthorizationManifest) -> Result<(), String> {
    if manifest.version != 2
        || manifest.kind != "workspace-authorization-manifest"
        || manifest.workspace_id.is_empty()
        || manifest.heads.is_empty()
        || manifest.heads.len() > 256
        || !manifest.authority.is_object()
        || manifest.records_digest.len() != 64
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
    if let Some(records) = bundle.get("records").and_then(Value::as_array) {
        if records.len() > MAX_PROOF_TRANSFER_RECORDS || bytes(bundle)? > MAX_PROOF_TRANSFER_BYTES {
            return Err("Workspace proof history exceeds transfer resource limit".into());
        }
        return Ok(records.clone());
    }
    authorization_records(bundle)
}

pub fn authorization_export(document: &[u8], bundle: &Value) -> Result<Value, String> {
    let records = stored_records(bundle)?;
    if records.len() <= 20_000
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
        records_digest: records_digest(&records)?,
        transfer_id: String::new(),
    };
    manifest.transfer_id = manifest_id(&manifest)?;
    validate_manifest(&manifest)?;
    serde_json::to_value(manifest).map_err(|e| e.to_string())
}

fn request_id(manifest: &AuthorizationManifest, hashes: &[String]) -> Result<String, String> {
    digest(&json!({"transferId": manifest.transfer_id, "hashes": hashes}))
}

fn records_digest(records: &[Value]) -> Result<String, String> {
    let mut identities = BTreeMap::new();
    for record in records {
        let key = signature(record)?;
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
        if records_digest(&stored)? != manifest.records_digest {
            return Err("Authorization records changed; restart document sync".into());
        }
        for record in stored {
            let key = signature(&record)?.to_string();
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
        if request
            .hashes
            .iter()
            .any(|h| !self.source_hashes.contains(h))
        {
            return Err("Requested authorization hash absent from actual source history".into());
        }
        let mut selected = BTreeSet::new();
        for hash in &request.hashes {
            if let Some(keys) = self.by_hash.get(hash) {
                selected.extend(keys.iter().filter(|k| *k > &request.after).cloned());
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
        };
        let mut page_bytes = bytes(&page)?;
        for key in selected {
            let record = self.records.get(&key).expect("indexed record").clone();
            let next_bytes =
                page_bytes + bytes(&record)? + usize::from(!page.records.is_empty()) + bytes(&key)?
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
            page.next = key;
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
        })
    }
    pub fn request(&self) -> Result<Option<AuthorizationPageRequest>, String> {
        if self.offset >= self.hashes.len() {
            return Ok(None);
        }
        let hashes = self.hashes
            [self.offset..(self.offset + MAX_PROOF_REQUEST_HASHES).min(self.hashes.len())]
            .to_vec();
        Ok(Some(AuthorizationPageRequest {
            version: 1,
            manifest: self.manifest.clone(),
            request_id: request_id(&self.manifest, &hashes)?,
            hashes,
            after: self.after.clone(),
        }))
    }
    pub fn accept(&mut self, page: AuthorizationPage) -> Result<(), String> {
        let request = self.request()?.ok_or("Unexpected authorization page")?;
        if page.version != 1
            || page.transfer_id != request.manifest.transfer_id
            || page.request_id != request.request_id
            || page.after != request.after
            || bytes(&page)? > MAX_PROOF_PAGE_BYTES
            || page.records.len() > 20_000
        {
            return Err("Authorization page does not match pending request".into());
        }
        let mut cursor = page.after.clone();
        for record in &page.records {
            let key = signature(record)?;
            if key <= cursor.as_str() {
                return Err("Authorization page cursor did not advance".into());
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
    use automerge::{ROOT, transaction::Transactable};
    /// Deterministic full signed-history regression and separate source/crypto timings.
    /// Run explicitly in release mode; cryptography is deliberately not mocked.
    #[test]
    #[ignore = "large deterministic signed-history benchmark"]
    fn signed_initial_and_incremental_history_benchmark() {
        use crate::{
            ChangeAdmissionChange, ChangeAdmissionFlowInput, DEFAULT_SIGNATURE_DOMAIN,
            DeviceCertificatePayload, WorkspaceAuthority, WorkspaceWriteAuthorizationSnapshot,
            plan_change_admission_flow, public_key_from_seed, public_key_id,
            sign_device_certificate, sign_json_envelope,
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
            assert!(
                plan_change_admission_flow(
                    ChangeAdmissionFlowInput {
                        records: vec![],
                        record_pages: Some(vec![vec![forged]]),
                        known_hashes: vec![],
                        changes: delta.incoming_changes,
                        snapshot: delta_snapshot
                    },
                    0
                )
                .is_err()
            );
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
        assert!(
            authorization_record_pages(&proof)
                .unwrap_err()
                .contains("size limit")
        );
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
        assert!(
            authorization_export(&bytes, &proof)
                .unwrap_err()
                .contains("oversized")
        );
    }
    #[test]
    fn request_is_derived_from_actual_candidate_and_source_rejects_claimed_unknown_hash() {
        let (bytes, empty, proof) = fixture(2, 70_000);
        let receiver =
            AuthorizationPageReceiver::new(manifest(&bytes, &proof), &bytes, &empty).unwrap();
        let mut request = receiver.request().unwrap().unwrap();
        request.hashes = vec!["0".repeat(64)];
        request.request_id = request_id(&request.manifest, &request.hashes).unwrap();
        assert!(
            authorization_page(&bytes, &proof, request)
                .unwrap_err()
                .contains("actual source history")
        );
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
        assert!(
            authorization_page(&bytes, &proof, request)
                .unwrap_err()
                .contains("authority changed")
        );
    }
    #[test]
    fn frozen_source_avoids_reloading_and_proof_only_additions_change_identity() {
        let (document, empty, mut proof) = fixture(2, 70_000);
        let initial = manifest(&document, &proof);
        let receiver = AuthorizationPageReceiver::new(initial.clone(), &document, &empty).unwrap();
        let request = serde_json::to_vec(&receiver.request().unwrap().unwrap()).unwrap();
        let mut runtime = crate::MeshScopeRuntime::new("board", "secret").unwrap();
        assert!(
            runtime
                .provide_cached_proof_page(&request)
                .unwrap()
                .is_none()
        );
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
        assert!(
            runtime
                .provide_cached_proof_page(&request)
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .provide_proof_page(&request, &document, proof)
                .is_ok()
        );
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
        assert!(
            runtime
                .complete_document_receive(true)
                .unwrap_err()
                .contains("incomplete")
        );
        runtime.reject_document_receive().unwrap();
        assert!(
            runtime
                .begin_authorization_transfer(
                    &document,
                    &empty,
                    serde_json::to_value(manifest(&document, &proof)).unwrap()
                )
                .is_ok()
        );
    }
}
