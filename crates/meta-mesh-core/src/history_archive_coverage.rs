//! Exact signed coverage of Native-derived data and portable locator sets.
//! Storage evidence is not Owner baseline authority or continued availability.
use crate::{
    SignedEnvelope,
    history_archive::{MAX_HISTORY_ARCHIVE_INTEGER, history_archive_object_id, valid_digest},
    public_key_id, verify_signed_envelope,
};
use crate::{
    history_capture::{HistoryArchiveCatalogue, VerifiedHistoryArchiveStorage},
    history_locator::HistoryArchiveLocatorRoot,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveCoverageAuthority {
    pub service_public_key: String,
    pub scope_id: String,
    pub policy_revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveCoverageSummary {
    pub height: u8,
    pub object_count: u64,
    pub first_object_id: String,
    pub last_object_id: String,
    pub set_digest: String,
    pub root_covered: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveAggregatePayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub scope_id: String,
    pub policy_revision: u64,
    pub request_id: String,
    pub archive_root_id: String,
    pub height: u8,
    pub object_count: u64,
    pub first_object_id: String,
    pub last_object_id: String,
    pub set_digest: String,
    pub root_covered: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveAggregateReceipt {
    pub payload: HistoryArchiveAggregatePayload,
    pub signer_key_id: String,
    pub signature: String,
}
pub struct HistoryArchiveCoverageProof<'a> {
    pub data_transition_id: &'a str,
    pub directory_transition_id: &'a str,
    pub data_receipt: &'a [u8],
    pub directory_receipt: &'a [u8],
}
pub struct VerifiedHistoryArchiveCoverage {
    catalogue: HistoryArchiveCatalogue,
    locator_root: HistoryArchiveLocatorRoot,
    authority: HistoryArchiveCoverageAuthority,
    key_epoch: u64,
    key_digest: String,
    data_transition_id: String,
    directory_transition_id: String,
    data_receipt: HistoryArchiveAggregateReceipt,
    directory_receipt: HistoryArchiveAggregateReceipt,
}
impl VerifiedHistoryArchiveCoverage {
    pub fn catalogue(&self) -> &HistoryArchiveCatalogue {
        &self.catalogue
    }
    pub fn locator_root(&self) -> &HistoryArchiveLocatorRoot {
        &self.locator_root
    }
    pub fn authority(&self) -> &HistoryArchiveCoverageAuthority {
        &self.authority
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn key_digest(&self) -> &str {
        &self.key_digest
    }
    pub fn data_transition_id(&self) -> &str {
        &self.data_transition_id
    }
    pub fn directory_transition_id(&self) -> &str {
        &self.directory_transition_id
    }
    pub fn data_receipt(&self) -> &HistoryArchiveAggregateReceipt {
        &self.data_receipt
    }
    pub fn directory_receipt(&self) -> &HistoryArchiveAggregateReceipt {
        &self.directory_receipt
    }
}

pub fn derive_history_archive_coverage<I>(
    root: &str,
    key_epoch: u64,
    objects: I,
) -> Result<HistoryArchiveCoverageSummary, String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    valid_digest(root)?;
    positive(key_epoch)?;
    let mut levels: Vec<Vec<HistoryArchiveCoverageSummary>> = Vec::new();
    let mut batch = Vec::with_capacity(64);
    let mut previous: Option<String> = None;
    let mut count = 0usize;
    for object in objects {
        let id = object.as_ref();
        valid_digest(id)?;
        if previous.as_deref().is_some_and(|previous| previous >= id) || count == 1_048_576 {
            return Err("Invalid archive coverage object order or count".into());
        }
        count += 1;
        previous = Some(id.to_owned());
        batch.push(id.to_owned());
        if batch.len() == 64 {
            push(root, &mut levels, leaf(root, key_epoch, &batch)?)?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        push(root, &mut levels, leaf(root, key_epoch, &batch)?)?;
    }
    if count == 0 {
        return Err("Archive coverage set is empty".into());
    }
    for height in 0..32 {
        if levels.get(height).is_none_or(|bucket| bucket.is_empty()) {
            continue;
        }
        let mut bucket = std::mem::take(&mut levels[height]);
        if height > 0
            && bucket.len() == 1
            && levels
                .iter()
                .skip(height + 1)
                .all(|bucket| bucket.is_empty())
        {
            return Ok(bucket.pop().unwrap());
        }
        push(root, &mut levels, branch(root, &bucket)?)?;
    }
    Err("Archive coverage depth exceeded".into())
}
fn positive(value: u64) -> Result<(), String> {
    if value == 0 || value > MAX_HISTORY_ARCHIVE_INTEGER {
        return Err("Invalid archive coverage integer".into());
    }
    Ok(())
}
fn opaque(value: &str, minimum: usize, maximum: usize) -> Result<(), String> {
    if !(minimum..=maximum).contains(&value.len())
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("Invalid archive coverage scope or transition".into());
    }
    Ok(())
}
fn validate_authority(authority: &HistoryArchiveCoverageAuthority) -> Result<(), String> {
    valid_digest(&authority.service_public_key)?;
    opaque(&authority.scope_id, 1, 128)?;
    positive(authority.policy_revision)
}
fn coverage_digest(value: &serde_json::Value) -> Result<String, String> {
    Ok(history_archive_object_id(
        format!(
            "MESH-HISTORY/1/coverage-set\0{}",
            crate::canonicalize_json(value)?
        )
        .as_bytes(),
    ))
}
fn leaf(
    root: &str,
    key_epoch: u64,
    objects: &[String],
) -> Result<HistoryArchiveCoverageSummary, String> {
    let entries = objects
        .iter()
        .map(|id| json!({"objectId": id, "keyEpoch": key_epoch}))
        .collect::<Vec<_>>();
    Ok(HistoryArchiveCoverageSummary {
        height: 0,
        object_count: objects.len() as u64,
        first_object_id: objects
            .first()
            .ok_or("Empty archive coverage leaf")?
            .clone(),
        last_object_id: objects.last().unwrap().clone(),
        root_covered: objects.iter().any(|id| id == root),
        set_digest: coverage_digest(
            &json!({"kind":"archive-coverage-set-leaf", "version":1, "objects":entries}),
        )?,
    })
}
fn branch(
    root: &str,
    children: &[HistoryArchiveCoverageSummary],
) -> Result<HistoryArchiveCoverageSummary, String> {
    let first = children.first().ok_or("Empty archive coverage branch")?;
    if children.len() > 8 || first.height >= 31 {
        return Err("Archive coverage fanout or depth exceeded".into());
    }
    let mut count = 0u64;
    for (i, child) in children.iter().enumerate() {
        if child.height != first.height
            || i > 0 && children[i - 1].last_object_id >= child.first_object_id
        {
            return Err("Archive coverage children overlap or have different heights".into());
        }
        count = count
            .checked_add(child.object_count)
            .ok_or("Archive coverage count overflow")?;
        positive(count)?;
    }
    Ok(HistoryArchiveCoverageSummary {
        height: first.height + 1,
        object_count: count,
        first_object_id: first.first_object_id.clone(),
        last_object_id: children.last().unwrap().last_object_id.clone(),
        root_covered: children.iter().any(|child| child.root_covered),
        set_digest: coverage_digest(
            &json!({"kind":"archive-coverage-set-branch", "version":1, "archiveRootId":root, "children":children}),
        )?,
    })
}
fn push(
    root: &str,
    levels: &mut Vec<Vec<HistoryArchiveCoverageSummary>>,
    mut node: HistoryArchiveCoverageSummary,
) -> Result<(), String> {
    loop {
        let height = node.height as usize;
        if height >= 32 {
            return Err("Archive coverage depth exceeded".into());
        }
        if levels.len() <= height {
            levels.resize_with(height + 1, Vec::new);
        }
        levels[height].push(node);
        if levels[height].len() < 8 {
            return Ok(());
        }
        let bucket = std::mem::take(&mut levels[height]);
        node = branch(root, &bucket)?;
    }
}
pub(crate) fn verify_receipt(
    bytes: &[u8],
    authority: &HistoryArchiveCoverageAuthority,
    root: &str,
    transition_id: &str,
    expected: &HistoryArchiveCoverageSummary,
) -> Result<HistoryArchiveAggregateReceipt, String> {
    validate_authority(authority)?;
    opaque(transition_id, 20, 64)?;
    valid_digest(root)?;
    if bytes.len() > 8192 {
        return Err("Archive coverage receipt exceeds size limit".into());
    }
    let receipt: HistoryArchiveAggregateReceipt =
        serde_json::from_slice(bytes).map_err(|_| "Invalid archive coverage receipt schema")?;
    let p = &receipt.payload;
    let service_id = public_key_id(&authority.service_public_key)?;
    let summary = HistoryArchiveCoverageSummary {
        height: p.height,
        object_count: p.object_count,
        first_object_id: p.first_object_id.clone(),
        last_object_id: p.last_object_id.clone(),
        set_digest: p.set_digest.clone(),
        root_covered: p.root_covered,
    };
    let request_id = history_archive_object_id(format!("MESH-HISTORY/1/coverage-request\0{}", crate::canonicalize_json(&json!({
        "authority":authority,"archiveRootId":root,"transitionId":transition_id,"summary":expected}))?).as_bytes());
    if p.kind != "blind-archive-coverage-aggregate-receipt"
        || p.version != 1
        || p.service_id != service_id
        || receipt.signer_key_id != service_id
        || p.scope_id != authority.scope_id
        || p.policy_revision != authority.policy_revision
        || p.archive_root_id != root
        || p.request_id != request_id
        || summary != *expected
        || !summary.root_covered
        || summary.height == 0
        || summary.height >= 32
    {
        return Err(
            "Archive coverage receipt does not match exact Native set and preparation".into(),
        );
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&receipt.signature)
        .map_err(|_| "Invalid archive coverage signature encoding")?;
    if signature.len() != 64 || URL_SAFE_NO_PAD.encode(&signature) != receipt.signature {
        return Err("Invalid archive coverage signature encoding".into());
    }
    if !verify_signed_envelope(
        &SignedEnvelope {
            payload: p.clone(),
            signer_key_id: receipt.signer_key_id.clone(),
            signature: receipt.signature.clone(),
        },
        &authority.service_public_key,
        "RUSTY/2",
    )? {
        return Err("Invalid archive coverage service signature".into());
    }
    Ok(receipt)
}
impl VerifiedHistoryArchiveStorage {
    pub fn verify_coverage(
        &self,
        authority: &HistoryArchiveCoverageAuthority,
        proof: HistoryArchiveCoverageProof<'_>,
    ) -> Result<VerifiedHistoryArchiveCoverage, String> {
        validate_authority(authority)?;
        opaque(proof.data_transition_id, 20, 64)?;
        opaque(proof.directory_transition_id, 20, 64)?;
        if authority.scope_id != self.scope_id()
            || proof.data_transition_id == proof.directory_transition_id
        {
            return Err("Archive coverage scope or directory preparation binding mismatch".into());
        }
        let expected_data = derive_history_archive_coverage(
            self.catalogue_ciphertext_id(),
            self.key_epoch(),
            self.data_ciphertext_ids(),
        )?;
        let expected_directory = derive_history_archive_coverage(
            &self.locator_root().root.ciphertext_id,
            self.key_epoch(),
            self.directory_ciphertext_ids(),
        )?;
        let data_receipt = verify_receipt(
            proof.data_receipt,
            authority,
            self.catalogue_ciphertext_id(),
            proof.data_transition_id,
            &expected_data,
        )?;
        let directory_receipt = verify_receipt(
            proof.directory_receipt,
            authority,
            &self.locator_root().root.ciphertext_id,
            proof.directory_transition_id,
            &expected_directory,
        )?;
        Ok(VerifiedHistoryArchiveCoverage {
            catalogue: self.catalogue().clone(),
            locator_root: self.locator_root().clone(),
            authority: authority.clone(),
            key_epoch: self.key_epoch(),
            key_digest: self.key_digest().into(),
            data_transition_id: proof.data_transition_id.into(),
            directory_transition_id: proof.directory_transition_id.into(),
            data_receipt,
            directory_receipt,
        })
    }
}

#[cfg(test)]
mod tests;
