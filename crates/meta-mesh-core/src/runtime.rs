use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

pub const MAX_CONTROL_FRAME_BYTES: usize = 256 * 1024;
pub const CONTROL_CHUNK_BYTES: usize = 128 * 1024;
pub const MAX_CONTROL_SNAPSHOT_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionKey {
    pub workspace_id: String,
    pub device_id: String,
    pub instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCandidate {
    pub key: SessionKey,
    pub connection_id: String,
    pub remote_issued_at: String,
    pub remote_route_sequence: Option<u64>,
    pub direction: SessionDirection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSession {
    pub key: SessionKey,
    pub connection_id: String,
    pub remote_issued_at: String,
    pub remote_route_sequence: Option<u64>,
    pub direction: SessionDirection,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "decision",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SessionAdmission {
    Accepted {
        generation: u64,
        replaced_connection_id: Option<String>,
    },
    Rejected {
        retained_connection_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteAttempt {
    pub route_key: String,
    pub token: u64,
    pub started_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconnectState {
    pub failures: u32,
    pub retry_at_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshRuntimeState {
    running: bool,
    generation: u64,
    attempt_sequence: u64,
    sessions: BTreeMap<SessionKey, RuntimeSession>,
    attempts: BTreeMap<String, RouteAttempt>,
    reconnects: BTreeMap<String, ReconnectState>,
}

impl MeshRuntimeState {
    pub fn start(&mut self) {
        self.running = true;
    }

    pub fn stop(&mut self) -> Vec<String> {
        self.running = false;
        self.attempts.clear();
        self.reconnects.clear();
        let connections = self
            .sessions
            .values()
            .map(|session| session.connection_id.clone())
            .collect();
        self.sessions.clear();
        connections
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn sessions(&self) -> impl Iterator<Item = &RuntimeSession> {
        self.sessions.values()
    }

    pub fn begin_route_attempt(&mut self, route_key: String, now_ms: u64) -> RouteAttempt {
        self.attempt_sequence = self.attempt_sequence.saturating_add(1);
        let attempt = RouteAttempt {
            route_key: route_key.clone(),
            token: self.attempt_sequence,
            started_at_ms: now_ms,
        };
        self.attempts.insert(route_key, attempt.clone());
        attempt
    }

    pub fn finish_route_attempt(&mut self, route_key: &str, token: u64) -> bool {
        if self
            .attempts
            .get(route_key)
            .is_some_and(|attempt| attempt.token == token)
        {
            self.attempts.remove(route_key);
            true
        } else {
            false
        }
    }

    pub fn schedule_reconnect(
        &mut self,
        route_key: String,
        now_ms: u64,
        base_delay_ms: u64,
        maximum_delay_ms: u64,
    ) -> ReconnectState {
        let failures = self
            .reconnects
            .get(&route_key)
            .map_or(1, |state| state.failures.saturating_add(1));
        let exponent = failures.saturating_sub(1).min(31);
        let delay = base_delay_ms
            .saturating_mul(1_u64 << exponent)
            .min(maximum_delay_ms);
        let state = ReconnectState {
            failures,
            retry_at_ms: now_ms.saturating_add(delay),
        };
        self.reconnects.insert(route_key, state.clone());
        state
    }

    pub fn clear_reconnect(&mut self, route_key: &str) {
        self.reconnects.remove(route_key);
    }

    pub fn due_reconnects(&self, now_ms: u64) -> Vec<String> {
        self.reconnects
            .iter()
            .filter(|(_, state)| state.retry_at_ms <= now_ms)
            .map(|(route, _)| route.clone())
            .collect()
    }

    pub fn admit_session(
        &mut self,
        candidate: SessionCandidate,
        preferred: SessionDirection,
    ) -> SessionAdmission {
        if let Some(previous) = self.sessions.get(&candidate.key) {
            if !should_replace_session(previous, &candidate, preferred) {
                return SessionAdmission::Rejected {
                    retained_connection_id: previous.connection_id.clone(),
                };
            }
        }
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        let previous = self.sessions.insert(
            candidate.key.clone(),
            RuntimeSession {
                key: candidate.key,
                connection_id: candidate.connection_id,
                remote_issued_at: candidate.remote_issued_at,
                remote_route_sequence: candidate.remote_route_sequence,
                direction: candidate.direction,
                generation,
            },
        );
        SessionAdmission::Accepted {
            generation,
            replaced_connection_id: previous.map(|session| session.connection_id),
        }
    }

    pub fn remove_session(&mut self, key: &SessionKey, generation: u64) -> Option<String> {
        if self
            .sessions
            .get(key)
            .is_some_and(|session| session.generation == generation)
        {
            self.sessions
                .remove(key)
                .map(|session| session.connection_id)
        } else {
            None
        }
    }

    pub fn connected_devices(&self, workspace_id: &str) -> BTreeSet<String> {
        self.sessions
            .keys()
            .filter(|key| key.workspace_id == workspace_id)
            .map(|key| key.device_id.clone())
            .collect()
    }
}

fn should_replace_session(
    previous: &RuntimeSession,
    candidate: &SessionCandidate,
    preferred: SessionDirection,
) -> bool {
    if candidate.remote_route_sequence != previous.remote_route_sequence {
        return match (
            candidate.remote_route_sequence,
            previous.remote_route_sequence,
        ) {
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (Some(candidate), Some(previous)) => candidate > previous,
            (None, None) => false,
        };
    }
    candidate.direction != previous.direction && candidate.direction == preferred
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlChunk {
    pub version: u8,
    pub workspace_id: String,
    pub transfer_id: String,
    pub index: usize,
    pub total_bytes: usize,
    pub data: String,
}

pub fn control_frames(
    workspace_id: &str,
    transfer_id: &str,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if bytes.len() > MAX_CONTROL_SNAPSHOT_BYTES {
        return Err("Mesh control snapshot exceeds size limit".to_string());
    }
    if bytes.len() <= MAX_CONTROL_FRAME_BYTES {
        return Ok(vec![bytes.to_vec()]);
    }
    bytes
        .chunks(CONTROL_CHUNK_BYTES)
        .enumerate()
        .map(|(index, part)| {
            serde_json::to_vec(&ControlChunk {
                version: 2,
                workspace_id: workspace_id.to_string(),
                transfer_id: transfer_id.to_string(),
                index,
                total_bytes: bytes.len(),
                data: URL_SAFE_NO_PAD.encode(part),
            })
            .map_err(|_| "Could not encode mesh control chunk".to_string())
        })
        .collect()
}

#[derive(Debug)]
struct PendingControlTransfer {
    id: String,
    total_bytes: usize,
    parts: BTreeMap<usize, Vec<u8>>,
}

#[derive(Debug)]
pub struct ControlFrameReceiver {
    workspace_id: String,
    pending: Option<PendingControlTransfer>,
}

impl ControlFrameReceiver {
    pub fn new(workspace_id: impl Into<String>) -> Self {
        Self {
            workspace_id: workspace_id.into(),
            pending: None,
        }
    }

    pub fn receive(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if frame.len() > MAX_CONTROL_FRAME_BYTES {
            return Err("Mesh control frame exceeds size limit".to_string());
        }
        let value: serde_json::Value =
            serde_json::from_slice(frame).map_err(|_| "Invalid mesh control frame".to_string())?;
        if value.get("version").and_then(serde_json::Value::as_u64) != Some(2) {
            if self.pending.is_some() {
                return Err("Incomplete mesh control snapshot".to_string());
            }
            return Ok(Some(frame.to_vec()));
        }
        let chunk: ControlChunk =
            serde_json::from_value(value).map_err(|_| "Invalid mesh control chunk".to_string())?;
        validate_chunk(&chunk, &self.workspace_id)?;
        let part = URL_SAFE_NO_PAD
            .decode(&chunk.data)
            .map_err(|_| "Invalid mesh control chunk".to_string())?;
        let expected_parts = chunk.total_bytes.div_ceil(CONTROL_CHUNK_BYTES);
        let expected_size = if chunk.index + 1 == expected_parts {
            chunk.total_bytes - chunk.index * CONTROL_CHUNK_BYTES
        } else {
            CONTROL_CHUNK_BYTES
        };
        if part.len() != expected_size {
            return Err("Invalid mesh control chunk length".to_string());
        }
        match &self.pending {
            Some(pending)
                if pending.id != chunk.transfer_id || pending.total_bytes != chunk.total_bytes =>
            {
                return Err("Conflicting mesh control transfer".to_string());
            }
            None => {
                self.pending = Some(PendingControlTransfer {
                    id: chunk.transfer_id.clone(),
                    total_bytes: chunk.total_bytes,
                    parts: BTreeMap::new(),
                });
            }
            _ => {}
        }
        let pending = self.pending.as_mut().expect("pending transfer initialized");
        if pending.parts.insert(chunk.index, part).is_some() {
            return Err("Conflicting mesh control chunk".to_string());
        }
        if pending.parts.len() != expected_parts {
            return Ok(None);
        }
        let mut value = Vec::with_capacity(pending.total_bytes);
        for index in 0..expected_parts {
            value.extend(
                pending
                    .parts
                    .get(&index)
                    .ok_or_else(|| "Incomplete mesh control transfer".to_string())?,
            );
        }
        if value.len() != pending.total_bytes {
            return Err("Invalid mesh control snapshot length".to_string());
        }
        self.pending = None;
        Ok(Some(value))
    }
}

fn validate_chunk(chunk: &ControlChunk, workspace_id: &str) -> Result<(), String> {
    let parts = chunk.total_bytes.div_ceil(CONTROL_CHUNK_BYTES);
    if chunk.version != 2
        || chunk.workspace_id != workspace_id
        || chunk.transfer_id.is_empty()
        || chunk.total_bytes <= MAX_CONTROL_FRAME_BYTES
        || chunk.total_bytes > MAX_CONTROL_SNAPSHOT_BYTES
        || chunk.index >= parts
    {
        Err("Invalid mesh control chunk".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        instance: &str,
        connection: &str,
        sequence: u64,
        direction: SessionDirection,
    ) -> SessionCandidate {
        SessionCandidate {
            key: SessionKey {
                workspace_id: "workspace".into(),
                device_id: "device".into(),
                instance_id: instance.into(),
            },
            connection_id: connection.into(),
            remote_issued_at: "2026-09-21T00:00:00Z".into(),
            remote_route_sequence: Some(sequence),
            direction,
        }
    }

    #[test]
    fn sibling_instances_coexist_and_stale_cleanup_cannot_remove_replacement() {
        let mut runtime = MeshRuntimeState::default();
        let first = runtime.admit_session(
            candidate("one", "first", 1, SessionDirection::Incoming),
            SessionDirection::Incoming,
        );
        let sibling = runtime.admit_session(
            candidate("two", "sibling", 99, SessionDirection::Outgoing),
            SessionDirection::Incoming,
        );
        let replacement = runtime.admit_session(
            candidate("one", "replacement", 2, SessionDirection::Outgoing),
            SessionDirection::Incoming,
        );
        let SessionAdmission::Accepted {
            generation: old_generation,
            ..
        } = first
        else {
            panic!()
        };
        assert!(matches!(sibling, SessionAdmission::Accepted { .. }));
        assert!(
            matches!(replacement, SessionAdmission::Accepted { replaced_connection_id: Some(value), .. } if value == "first")
        );
        assert_eq!(
            runtime.remove_session(
                &candidate("one", "", 0, SessionDirection::Incoming).key,
                old_generation
            ),
            None
        );
        assert_eq!(runtime.sessions().count(), 2);
    }

    #[test]
    fn route_attempt_tokens_and_reconnects_ignore_stale_work() {
        let mut runtime = MeshRuntimeState::default();
        let first = runtime.begin_route_attempt("route".into(), 10);
        let second = runtime.begin_route_attempt("route".into(), 20);
        assert!(!runtime.finish_route_attempt("route", first.token));
        assert!(runtime.finish_route_attempt("route", second.token));
        assert_eq!(
            runtime
                .schedule_reconnect("route".into(), 100, 50, 1_000)
                .retry_at_ms,
            150
        );
        assert_eq!(
            runtime
                .schedule_reconnect("route".into(), 200, 50, 1_000)
                .retry_at_ms,
            300
        );
        assert!(runtime.due_reconnects(299).is_empty());
        assert_eq!(runtime.due_reconnects(300), vec!["route"]);
    }

    #[test]
    fn large_control_snapshot_reassembles_out_of_order() {
        let bytes = vec![7_u8; MAX_CONTROL_FRAME_BYTES + 17];
        let mut frames = control_frames("workspace", "transfer", &bytes).unwrap();
        frames.reverse();
        let mut receiver = ControlFrameReceiver::new("workspace");
        let mut result = None;
        for frame in frames {
            if let Some(value) = receiver.receive(&frame).unwrap() {
                result = Some(value);
            }
        }
        assert_eq!(result, Some(bytes));
    }
}
