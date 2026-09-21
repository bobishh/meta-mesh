use std::collections::HashMap;

use automerge::{
    AutoCommit,
    sync::{Message, State, SyncDoc},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_MAX_AUTOMERGE_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomergeSyncFrame {
    pub version: u8,
    pub scope_id: String,
    pub document_id: String,
    pub from_device_id: String,
    pub to_device_id: String,
    pub message: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomergeSyncResult {
    pub accepted_changes: usize,
    pub heads: Vec<String>,
    pub document: Vec<u8>,
    pub response: Option<AutomergeSyncFrame>,
}

struct DocumentState {
    scope_id: String,
    document: AutoCommit,
}

pub struct AutomergeSyncEngine {
    local_device_id: String,
    maximum_frame_bytes: usize,
    documents: HashMap<String, DocumentState>,
    peers: HashMap<(String, String), State>,
}

impl AutomergeSyncEngine {
    pub fn new(
        local_device_id: impl Into<String>,
        maximum_frame_bytes: Option<usize>,
    ) -> Result<Self, String> {
        let local_device_id = local_device_id.into();
        if local_device_id.is_empty() {
            return Err("Invalid local device ID".to_string());
        }
        let maximum_frame_bytes = maximum_frame_bytes.unwrap_or(DEFAULT_MAX_AUTOMERGE_FRAME_BYTES);
        if maximum_frame_bytes == 0 {
            return Err("Invalid Automerge frame limit".to_string());
        }
        Ok(Self {
            local_device_id,
            maximum_frame_bytes,
            documents: HashMap::new(),
            peers: HashMap::new(),
        })
    }

    pub fn load_document(
        &mut self,
        scope_id: impl Into<String>,
        document_id: impl Into<String>,
        bytes: &[u8],
    ) -> Result<(), String> {
        let scope_id = scope_id.into();
        let document_id = document_id.into();
        if scope_id.is_empty() || document_id.is_empty() {
            return Err("Invalid Automerge document identity".to_string());
        }
        let document = AutoCommit::load(bytes)
            .map_err(|error| format!("Invalid Automerge document: {error}"))?;
        self.documents
            .insert(document_id, DocumentState { scope_id, document });
        Ok(())
    }

    pub fn save_document(&mut self, document_id: &str) -> Result<Vec<u8>, String> {
        Ok(self.document_mut(document_id)?.document.save())
    }

    pub fn heads(&mut self, document_id: &str) -> Result<Vec<String>, String> {
        Ok(self
            .document_mut(document_id)?
            .document
            .get_heads()
            .into_iter()
            .map(|head| head.to_string())
            .collect())
    }

    pub fn reset(&mut self, document_id: &str, remote_device_id: &str) {
        self.peers
            .remove(&(document_id.to_string(), remote_device_id.to_string()));
    }

    pub fn generate(
        &mut self,
        document_id: &str,
        remote_device_id: &str,
        authorized: bool,
        proof: Option<Value>,
    ) -> Result<Option<AutomergeSyncFrame>, String> {
        if !authorized {
            return Err("Unauthorized Automerge sync".to_string());
        }
        if remote_device_id.is_empty() {
            return Err("Invalid remote device ID".to_string());
        }
        let key = (document_id.to_string(), remote_device_id.to_string());
        let mut state = self.peers.remove(&key).unwrap_or_else(State::new);
        let local_device_id = self.local_device_id.clone();
        let maximum_frame_bytes = self.maximum_frame_bytes;
        let document = self.document_mut(document_id)?;
        let message = document.document.sync().generate_sync_message(&mut state);
        let scope_id = document.scope_id.clone();
        self.peers.insert(key, state);
        let Some(message) = message else {
            return Ok(None);
        };
        let message = message.encode();
        validate_message(&message, maximum_frame_bytes)?;
        Ok(Some(AutomergeSyncFrame {
            version: 1,
            scope_id,
            document_id: document_id.to_string(),
            from_device_id: local_device_id,
            to_device_id: remote_device_id.to_string(),
            message,
            proof,
        }))
    }

    pub fn receive(
        &mut self,
        remote_device_id: &str,
        frame: AutomergeSyncFrame,
        authorized: bool,
        response_proof: Option<Value>,
    ) -> Result<AutomergeSyncResult, String> {
        if !authorized {
            return Err("Unauthorized Automerge sync".to_string());
        }
        self.validate_frame(remote_device_id, &frame)?;
        let key = (frame.document_id.clone(), remote_device_id.to_string());
        let mut state = self.peers.remove(&key).unwrap_or_else(State::new);
        let message = Message::decode(&frame.message)
            .map_err(|error| format!("Invalid Automerge sync message: {error}"))?;
        let maximum_frame_bytes = self.maximum_frame_bytes;
        let local_device_id = self.local_device_id.clone();
        let document = self.document_mut(&frame.document_id)?;
        let before_heads = document.document.get_heads();
        document
            .document
            .sync()
            .receive_sync_message(&mut state, message)
            .map_err(|error| format!("Automerge sync failed: {error}"))?;
        let accepted_changes = document.document.get_changes(&before_heads).len();
        let heads = document
            .document
            .get_heads()
            .into_iter()
            .map(|head| head.to_string())
            .collect::<Vec<_>>();
        let response = document.document.sync().generate_sync_message(&mut state);
        let scope_id = document.scope_id.clone();
        let document_bytes = document.document.save();
        self.peers.insert(key, state);
        let response = response
            .map(|message| -> Result<AutomergeSyncFrame, String> {
                let message = message.encode();
                validate_message(&message, maximum_frame_bytes)?;
                Ok(AutomergeSyncFrame {
                    version: 1,
                    scope_id,
                    document_id: frame.document_id,
                    from_device_id: local_device_id,
                    to_device_id: remote_device_id.to_string(),
                    message,
                    proof: response_proof,
                })
            })
            .transpose()?;
        Ok(AutomergeSyncResult {
            accepted_changes,
            heads,
            document: document_bytes,
            response,
        })
    }

    fn validate_frame(
        &self,
        remote_device_id: &str,
        frame: &AutomergeSyncFrame,
    ) -> Result<(), String> {
        let document = self
            .documents
            .get(&frame.document_id)
            .ok_or_else(|| "Automerge document is not loaded".to_string())?;
        if frame.version != 1
            || frame.scope_id != document.scope_id
            || frame.from_device_id != remote_device_id
            || frame.to_device_id != self.local_device_id
        {
            return Err("Invalid Automerge sync frame".to_string());
        }
        validate_message(&frame.message, self.maximum_frame_bytes)
    }

    fn document_mut(&mut self, document_id: &str) -> Result<&mut DocumentState, String> {
        self.documents
            .get_mut(document_id)
            .ok_or_else(|| "Automerge document is not loaded".to_string())
    }
}

fn validate_message(message: &[u8], maximum: usize) -> Result<(), String> {
    if message.is_empty() || message.len() > maximum {
        Err("Automerge sync frame exceeds size limit".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use automerge::{ROOT, transaction::Transactable};

    use super::*;

    #[test]
    fn rust_automerge_engines_converge_and_reject_wrong_recipient() {
        let mut source = AutoCommit::new();
        source.put(ROOT, "title", "from-rust").unwrap();
        let source_bytes = source.save();
        let mut empty = AutoCommit::new();
        let empty_bytes = empty.save();

        let mut left = AutomergeSyncEngine::new("left", None).unwrap();
        let mut right = AutomergeSyncEngine::new("right", None).unwrap();
        left.load_document("scope", "doc", &source_bytes).unwrap();
        right.load_document("scope", "doc", &empty_bytes).unwrap();

        let mut frame = left.generate("doc", "right", true, None).unwrap().unwrap();
        let mut rejected = frame.clone();
        rejected.to_device_id = "someone-else".into();
        assert!(right.receive("left", rejected, true, None).is_err());
        let mut unsupported = frame.clone();
        unsupported.version = 2;
        assert_eq!(
            right.receive("left", unsupported, true, None).unwrap_err(),
            "Invalid Automerge sync frame"
        );

        for _ in 0..20 {
            let result = right.receive("left", frame, true, None).unwrap();
            let Some(response) = result.response else {
                break;
            };
            let result = left.receive("right", response, true, None).unwrap();
            match result.response {
                Some(response) => frame = response,
                None => break,
            }
        }
        assert_eq!(left.heads("doc").unwrap(), right.heads("doc").unwrap());
        assert_eq!(
            left.save_document("doc").unwrap(),
            right.save_document("doc").unwrap()
        );
    }
}
