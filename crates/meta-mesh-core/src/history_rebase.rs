//! Current admitted-state preparation only; not original authorship or activation authority.
use crate::history_archive::{MAX_HISTORY_ARCHIVE_INTEGER, history_archive_object_id};
use crate::history_preparation::{HistoryPreparationSigner, VerifiedHistoryPreparation};
use automerge::{
    ActorId, AutoCommit, ObjId, ObjType, Prop, ROOT, ReadDoc, ScalarValue, Span, Value,
    transaction::{CommitOptions, Transactable},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

mod state;

pub struct VerifiedHistoryRebase {
    document: Vec<u8>,
    state_digest: String,
    document_digest: String,
    genesis_hash: String,
    admission_revision: String,
    authority_revision: String,
    history_epoch: u64,
    transition_id: String,
    node_count: u64,
    signer: HistoryPreparationSigner,
}
impl VerifiedHistoryRebase {
    pub fn document(&self) -> &[u8] {
        &self.document
    }
    pub fn state_digest(&self) -> &str {
        &self.state_digest
    }
    pub fn document_digest(&self) -> &str {
        &self.document_digest
    }
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }
    pub fn authority_revision(&self) -> &str {
        &self.authority_revision
    }
    pub fn history_epoch(&self) -> u64 {
        self.history_epoch
    }
    pub fn transition_id(&self) -> &str {
        &self.transition_id
    }
    pub fn node_count(&self) -> u64 {
        self.node_count
    }
    pub fn signer(&self) -> &HistoryPreparationSigner {
        &self.signer
    }
}
impl VerifiedHistoryPreparation {
    pub fn rebase(
        &self,
        history_epoch: u64,
        transition_id: &str,
    ) -> Result<VerifiedHistoryRebase, String> {
        if history_epoch == 0
            || history_epoch > MAX_HISTORY_ARCHIVE_INTEGER
            || !(20..=64).contains(&transition_id.len())
            || !transition_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("Invalid Native rebase epoch or transition".into());
        }
        let source = AutoCommit::load(&self.admission().authorized_document)
            .map_err(|_| "Invalid admitted rebase projection")?;
        let binding = serde_json::json!({"workspaceId":self.source().snapshot.workspace_id,"historyEpoch":history_epoch,"transitionId":transition_id,
            "admissionRevision":self.admission_revision(),"authorityRevision":self.authority_digest(),
            "personId":self.signer().person_id,"deviceId":self.signer().device_id});
        let actor = Sha256::digest(
            format!(
                "MESH-HISTORY/1/basis-actor\0{}",
                crate::canonicalize_json(&binding)?
            )
            .as_bytes(),
        );
        let mut target = AutoCommit::new_with_encoding(source.text_encoding())
            .with_actor(ActorId::from(actor.to_vec()));
        let (state_digest, node_count) = state::walk(&source, Some(&mut target))?;
        let mut message = binding.as_object().unwrap().clone();
        message.insert("kind".into(), "workspace-history-basis".into());
        message.insert("version".into(), 1.into());
        message.insert("stateDigest".into(), state_digest.clone().into());
        let options = CommitOptions::default()
            .with_time(0)
            .with_message(crate::canonicalize_json(&message.into())?);
        let genesis = if target.pending_ops() == 0 {
            target.empty_change(options)
        } else {
            target
                .commit_with(options)
                .ok_or("Native rebase did not commit its basis")?
        };
        let document = target.save();
        if history_current_state_digest(&document)? != state_digest
            || target.get_changes(&[]).len() != 1
        {
            return Err(
                "Native rebase changed current-state content or retained historical changes".into(),
            );
        }
        Ok(VerifiedHistoryRebase {
            document_digest: history_archive_object_id(&document),
            document,
            state_digest,
            genesis_hash: genesis.to_string(),
            admission_revision: self.admission_revision().into(),
            authority_revision: self.authority_digest().into(),
            history_epoch,
            transition_id: transition_id.into(),
            node_count,
            signer: self.signer().clone(),
        })
    }
}

pub fn history_current_state_digest(document: &[u8]) -> Result<String, String> {
    let source = AutoCommit::load(document).map_err(|_| "Invalid current-state digest document")?;
    Ok(state::walk(&source, None)?.0)
}

#[cfg(test)]
mod tests;
