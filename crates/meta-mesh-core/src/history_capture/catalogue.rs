use super::{
    VerifiedHistoryArchiveCapture,
    writer::{self, HistoryArchiveBytesReference, HistoryArchiveWriter, IndexBuilder},
};
use crate::{
    causal_admission::CausalAdmissionStatus,
    history_archive::{HistoryArchiveIndexRoot, HistoryArchiveTreeContext},
};
use automerge::{AutoCommit, Change};
use serde::{Deserialize, Serialize};
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
        drop(document);
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
            };
            index.push(
                format!("change/{hash}"),
                record(writer, &context, &captured)?,
                writer,
            )?;
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
