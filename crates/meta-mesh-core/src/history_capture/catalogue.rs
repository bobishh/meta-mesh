use super::{
    VerifiedHistoryArchiveCapture,
    writer::{self, HistoryArchiveBytesReference, HistoryArchiveWriter, IndexBuilder},
};
use crate::{
    causal_admission::CausalAdmissionStatus,
    history_archive::{HistoryArchiveIndexRoot, HistoryArchiveTreeContext},
};
use automerge::{AutoCommit, Change, PatchAction, Prop, ROOT, ReadDoc};
use serde::{Deserialize, Serialize};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashMap};

/// Content summary, not an authority token. Only the separate signed Owner
/// transition may authorize activation; receivers must still verify that policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveCatalogue {
    pub kind: String,
    pub version: u8,
    pub context: HistoryArchiveTreeContext,
    pub root: HistoryArchiveIndexRoot,
    pub admission_revision: String,
    pub authority_revision: String,
    pub capture_revision: String,
    pub change_count: u64,
    pub authorization_count: u64,
    pub pending_original_count: u64,
    pub admitted_count: u64,
    pub pending_count: u64,
    pub quarantined_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryCapturedChange {
    pub kind: String,
    pub version: u8,
    pub workspace_id: String,
    pub history_epoch: u64,
    pub hash: String,
    pub bytes: HistoryArchiveBytesReference,
    pub dependencies: HistoryArchiveBytesReference,
    pub dependency_count: u64,
    pub authorizations: HistoryArchiveIndexRoot,
    pub observation: CausalAdmissionStatus,
    pub admission_policy: String,
    pub admission_revision: String,
    pub authority_revision: String,
    pub capture_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HistoryCapturedChangeMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryCapturedChangeMetadata {
    pub time: i64,
    pub actor: String,
    pub action: String,
    pub entity_ids: Vec<String>,
    pub person_id: Option<String>,
    pub device_id: Option<String>,
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub imported: bool,
}
fn is_false(value: &bool) -> bool { !*value }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryCapturedEntityIndex {
    pub kind: String,
    pub version: u8,
    pub entity_id: String,
    pub context: HistoryArchiveTreeContext,
    pub root: HistoryArchiveIndexRoot,
}

/// Entity names remain values; fixed ASCII digests are only bounded index lookup keys.
pub fn history_entity_index_id(entity_id: &str) -> Result<String, String> {
    if entity_id.is_empty() || entity_id.len() > 1024 || entity_id.contains('\0') {
        return Err("Invalid archived entity id".into());
    }
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(entity_id.as_bytes())))
}
pub(super) fn change_metadata(change: &Change) -> Option<HistoryCapturedChangeMetadata> {
    let message = change.message()?;
    let metadata: serde_json::Value = serde_json::from_str(message).ok()?;
    if metadata.get("version")?.as_u64()? != 1 { return None; }
    let action = metadata.get("action")?.as_str()?;
    let entities = metadata.get("entityIds")?.as_array()?;
    if action.len() > 2048 || entities.len() > 16_384 { return None; }
    let entity_ids = entities.iter().map(|id| id.as_str().filter(|id| history_entity_index_id(id).is_ok()).map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()?.into_iter().collect::<Vec<_>>();
    Some(HistoryCapturedChangeMetadata { time: change.timestamp(), actor: change.actor_id().to_hex_string(), action: action.into(), entity_ids,
        person_id: metadata.get("personId").and_then(|value| value.as_str()).map(str::to_owned),
        device_id: metadata.get("deviceId").and_then(|value| value.as_str()).map(str::to_owned),
        message: (message.len() <= 16 * 1024).then(|| message.to_owned()), imported: false, })
}

/// Legacy metadata is a lookup aid derived from exact causal views, never an author claim.
pub(super) fn archive_change_metadata(raw: &mut AutoCommit, change: &Change) -> Result<Option<HistoryCapturedChangeMetadata>, String> {
    if let Some(metadata) = change_metadata(change) { return Ok(Some(metadata)); }
    if change.deps().iter().any(|hash| raw.get_change_by_hash(hash).is_none()) { return Ok(None); }
    let mut replay;
    let view = if raw.get_change_by_hash(&change.hash()).is_some() { raw } else {
        replay = raw.fork_at(change.deps()).map_err(|_| "Legacy history dependency view is unavailable")?;
        replay.apply_changes(vec![change.clone()]).map_err(|_| "Legacy history change cannot be reconstructed")?;
        &mut replay
    };
    let after = [change.hash()];
    let mut entities = BTreeSet::new();
    for patch in view.diff(change.deps(), &after) {
        if matches!(patch.path.first(), Some((_, Prop::Map(key))) if key == "entities") {
            if let Some((_, Prop::Map(id))) = patch.path.get(1) {
                entities.insert(id.clone());
            } else {
                match patch.action {
                    PatchAction::PutMap { key, .. } | PatchAction::DeleteMap { key } => { entities.insert(key); },
                    PatchAction::Conflict { prop: Prop::Map(key) } | PatchAction::Increment { prop: Prop::Map(key), .. } => { entities.insert(key); },
                    _ => {},
                }
            }
        } else if patch.path.is_empty() && matches!(&patch.action,
            PatchAction::PutMap { key, .. } | PatchAction::DeleteMap { key } if key == "entities") {
            // Replacing/removing the whole entity map affects both the old and new keys.
            for frontier in [change.deps(), after.as_slice()] {
                if let Some((_, map)) = view.get_at(ROOT, "entities", frontier).map_err(|_| "Legacy entity map view is unavailable")? {
                    entities.extend(view.keys_at(&map, frontier));
                }
            }
        }
        if entities.len() > 16_384 { return Err("Legacy change entity index exceeds limit".into()); }
    }
    if entities.is_empty() { return Ok(None); }
    for id in &entities { history_entity_index_id(id)?; }
    let message = change.message().filter(|message| message.len() <= 16 * 1024).map(str::to_owned);
    Ok(Some(HistoryCapturedChangeMetadata { time: change.timestamp(), actor: change.actor_id().to_hex_string(),
        action: "change".into(), entity_ids: entities.into_iter().collect(), person_id: None, device_id: None, message, imported: true }))
}

impl VerifiedHistoryArchiveCapture {
    pub fn write_catalogue(
        &self,
        writer: &mut impl HistoryArchiveWriter,
    ) -> Result<HistoryArchiveCatalogue, String> {
        let source = self.preparation.source();
        let context = HistoryArchiveTreeContext {
            workspace_id: source.snapshot.workspace_id.clone(),
            history_epoch: self.history_epoch,
            index_id: "catalogue".into(),
        };
        let mut index = IndexBuilder::new(context.clone())?;
        // Proof references can be reused by several changes without rewriting or
        // attributing the proof to a manufactured replacement author.
        let mut proof_ids = Vec::with_capacity(self.originals.authorization_json.len());
        for (i, original) in self.originals.authorization_json.iter().enumerate() {
            let reference = writer::bytes(
                writer,
                child(&context, format!("source-proof/{i:016x}")),
                original,
            )?;
            proof_ids.push(record(writer, &context, &reference)?);
        }
        let mut by_hash = HashMap::<&str, Vec<usize>>::new();
        for (i, proof) in source.records.iter().enumerate() {
            for hash in &proof.signed.payload.hashes {
                let indices = by_hash.entry(hash.as_str()).or_default();
                if indices.last() != Some(&i) {
                    indices.push(i);
                }
            }
        }
        let decisions = self
            .preparation
            .admission()
            .decisions
            .iter()
            .map(|decision| (decision.hash.as_str(), &decision.status))
            .collect::<HashMap<_, _>>();
        let mut document = AutoCommit::load(&source.snapshot.document)
            .map_err(|_| "Invalid prepared history document")?;
        let mut changes = document
            .get_changes(&[])
            .into_iter()
            .map(|change| (change.hash().to_string(), (change, None)))
            .collect::<BTreeMap<_, _>>();
        for (index, original) in source.pending_change_bytes.iter().enumerate() {
            let change = Change::from_bytes(original.clone())
                .map_err(|_| "Invalid prepared pending history")?;
            changes
                .entry(change.hash().to_string())
                .or_insert((change, Some(index)));
        }
        if decisions.len() != changes.len() {
            return Err("Native history decisions do not cover original changes".into());
        }
        let mut counts = [0u64; 3];
        let mut entity_versions = BTreeMap::<String, BTreeMap<String, String>>::new();
        let mut entity_entry_count = 0usize;
        for (hash, (change, pending_index)) in &changes {
            let observation = decisions
                .get(hash.as_str())
                .ok_or("Missing Native history decision")?;
            counts[match observation {
                CausalAdmissionStatus::Admitted { .. } => 0,
                CausalAdmissionStatus::Pending { .. } => 1,
                CausalAdmissionStatus::Quarantined { .. } => 2,
            }] += 1;
            let original = pending_index.map_or_else(
                || change.raw_bytes(),
                |index| source.pending_change_bytes[index].as_slice(),
            );
            let bytes = writer::bytes(
                writer,
                child(&context, format!("change/{hash}/bytes")),
                original,
            )?;
            let dependencies = change
                .deps()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            let dependency_bytes = writer::canonical(&dependencies)?;
            let dependencies_ref = writer::bytes(
                writer,
                child(&context, format!("change/{hash}/dependencies")),
                &dependency_bytes,
            )?;
            let mut proofs =
                IndexBuilder::new(child(&context, format!("change/{hash}/authorizations")))?;
            if let Some(indices) = by_hash.get(hash.as_str()) {
                for i in indices {
                    proofs.push(format!("{i:016x}"), proof_ids[*i].clone(), writer)?;
                }
            }
            let captured = HistoryCapturedChange {
                kind: "workspace-history-archive-record".into(),
                version: 1,
                workspace_id: context.workspace_id.clone(),
                history_epoch: self.history_epoch,
                hash: hash.clone(),
                bytes,
                dependencies: dependencies_ref,
                dependency_count: dependencies.len() as u64,
                authorizations: proofs.finish(writer)?,
                observation: (*observation).clone(),
                admission_policy: crate::causal_admission::CAUSAL_ADMISSION_POLICY_ID.into(),
                admission_revision: self.preparation.admission_revision().into(),
                authority_revision: self.preparation.authority_digest().into(),
                capture_revision: self.capture_revision.clone(),
                metadata: archive_change_metadata(&mut document, change)?,
            };
            let captured_id = record(writer, &context, &captured)?;
            index.push(format!("change/{hash}"), captured_id.clone(), writer)?;
            if let Some(metadata) = &captured.metadata {
                let descending_time = u64::MAX - ((metadata.time as u64) ^ (1u64 << 63));
                let chronological_key = format!("{descending_time:016x}/{hash}");
                for entity in &metadata.entity_ids {
                    entity_entry_count += 1;
                    if entity_entry_count > 1_048_576 { return Err("Archived entity version index exceeds limit".into()); }
                    entity_versions.entry(entity.clone()).or_default().insert(chronological_key.clone(), captured_id.clone());
                }
            }
        }
        let control = writer::bytes(
            writer,
            child(&context, "source-control".into()),
            &self.originals.control_json,
        )?;
        index.push(
            "control".into(),
            record(writer, &context, &control)?,
            writer,
        )?;
        let document = writer::bytes(
            writer,
            child(&context, "source-document".into()),
            &source.snapshot.document,
        )?;
        index.push(
            "document".into(),
            record(writer, &context, &document)?,
            writer,
        )?;
        let mut entity_records = BTreeMap::<String, String>::new();
        for (entity_id, versions) in entity_versions {
            let digest = history_entity_index_id(&entity_id)?;
            let entity_context = child(&context, format!("entity/{digest}/versions"));
            let mut entity_index = IndexBuilder::new(entity_context.clone())?;
            for (key, id) in versions { entity_index.push(key, id, writer)?; }
            let entity_record = HistoryCapturedEntityIndex { kind: "workspace-history-entity-index".into(), version: 1,
                entity_id, context: entity_context, root: entity_index.finish(writer)? };
            entity_records.insert(format!("entity/{digest}"), record(writer, &context, &entity_record)?);
        }
        for (key, id) in entity_records { index.push(key, id, writer)?; }
        for (i, original) in source.pending_change_bytes.iter().enumerate() {
            let reference = writer::bytes(
                writer,
                child(&context, format!("source-pending/{i:016x}")),
                original,
            )?;
            index.push(
                format!("pending/{i:016x}"),
                record(writer, &context, &reference)?,
                writer,
            )?;
        }
        for (i, id) in proof_ids.into_iter().enumerate() {
            index.push(format!("proof/{i:016x}"), id, writer)?;
        }
        Ok(HistoryArchiveCatalogue {
            kind: "workspace-history-catalogue".into(),
            version: 1,
            context,
            root: index.finish(writer)?,
            admission_revision: self.preparation.admission_revision().into(),
            authority_revision: self.preparation.authority_digest().into(),
            capture_revision: self.capture_revision.clone(),
            change_count: changes.len() as u64,
            authorization_count: source.records.len() as u64,
            pending_original_count: source.pending_change_bytes.len() as u64,
            admitted_count: counts[0],
            pending_count: counts[1],
            quarantined_count: counts[2],
        })
    }
}

fn child(context: &HistoryArchiveTreeContext, index_id: String) -> HistoryArchiveTreeContext {
    HistoryArchiveTreeContext {
        index_id,
        ..context.clone()
    }
}

fn record(
    writer: &mut impl HistoryArchiveWriter,
    context: &HistoryArchiveTreeContext,
    value: &impl Serialize,
) -> Result<String, String> {
    writer::object(writer, context, "record", &writer::canonical(value)?, 0, 1)
}
