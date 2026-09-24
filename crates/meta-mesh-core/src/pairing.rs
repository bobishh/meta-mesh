use serde::{Deserialize, Serialize};

pub const PAIRING_VERSION: &str = "0.0.1";

const PAIRING_FRAME_TYPES: &[&str] = &[
    "sync-request",
    "sync-response",
    "sync-ack",
    "sync-update",
    "sync-heartbeat",
    "sync-heartbeat-ack",
    "enroll-request",
    "enroll-approved",
    "enroll-rejected",
    "enroll-rejected-ack",
    "enroll-ack",
    "enroll-complete",
    "workspace-join-request",
    "workspace-join-response",
    "workspace-join-rejected-ack",
    "mesh-handshake-request",
    "mesh-handshake-response",
    "mesh-handoff-request",
    "mesh-handoff-ready",
    "mesh-handoff-confirmed",
    "mesh-automerge-sync",
    "mesh-control-sync",
    "mesh-owner-workspace-offer",
    "mesh-iroh-gossip",
    "mesh-durable-batch",
    "mesh-durable-ack",
    "mesh-blob-request-v1",
    "mesh-blob-response-v1",
    "mesh-blob-error-v1",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingFrameHeader {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub version: String,
    pub secret: String,
}

pub struct PairingCodec;

impl PairingCodec {
    pub fn encode(frame_type: &str, secret: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        if !is_pairing_frame_type(frame_type) || secret.is_empty() {
            return Err("Pairing frame invalid".to_string());
        }
        let header = PairingFrameHeader {
            frame_type: frame_type.to_string(),
            version: PAIRING_VERSION.to_string(),
            secret: secret.to_string(),
        };
        let mut frame =
            serde_json::to_vec(&header).map_err(|_| "Pairing frame invalid".to_string())?;
        frame.push(b'\n');
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    pub fn inspect(frame: &[u8]) -> Result<PairingFrameHeader, String> {
        let separator = frame
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| "Pairing frame missing".to_string())?;
        let header: PairingFrameHeader = serde_json::from_slice(&frame[..separator])
            .map_err(|_| "Pairing frame invalid".to_string())?;
        if header.version != PAIRING_VERSION
            || header.secret.is_empty()
            || !is_pairing_frame_type(&header.frame_type)
        {
            return Err("Pairing frame invalid".to_string());
        }
        Ok(header)
    }

    pub fn decode(
        frame: &[u8],
        expected_type: &str,
        expected_secret: &str,
    ) -> Result<Vec<u8>, String> {
        let separator = frame
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| "Pairing frame missing".to_string())?;
        let header: PairingFrameHeader = serde_json::from_slice(&frame[..separator])
            .map_err(|_| "Pairing frame invalid".to_string())?;
        if header.frame_type != expected_type
            || header.version != PAIRING_VERSION
            || header.secret != expected_secret
        {
            return Err("Pairing authorization failed".to_string());
        }
        Ok(frame[separator + 1..].to_vec())
    }
}

const MAX_WORKSPACE_JOIN_ERROR_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceJoinSide {
    Host,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceJoinPhase {
    ReadyRequest,
    AwaitingRequest,
    AwaitingResponse,
    AwaitingAck,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceJoinResponse {
    Accepted(Vec<u8>),
    Rejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceJoinAck {
    Accepted(Vec<u8>),
    Rejected(String),
}

/// Owns the workspace invitation response and acknowledgement transitions.
/// Application code supplies the prepared workspace payload; this machine
/// validates phase, authentication, response envelope, and acknowledgement.
pub struct WorkspaceJoinHandshake {
    secret: String,
    side: WorkspaceJoinSide,
    phase: WorkspaceJoinPhase,
    response: Option<WorkspaceJoinResponse>,
}

impl WorkspaceJoinHandshake {
    pub fn host(secret: &str) -> Result<Self, String> {
        Self::new(secret, WorkspaceJoinSide::Host)
    }

    pub fn guest(secret: &str) -> Result<Self, String> {
        Self::new(secret, WorkspaceJoinSide::Guest)
    }

    fn new(secret: &str, side: WorkspaceJoinSide) -> Result<Self, String> {
        if secret.is_empty() {
            return Err("Pairing frame invalid".to_string());
        }
        Ok(Self {
            secret: secret.to_string(),
            side,
            phase: match side {
                WorkspaceJoinSide::Host => WorkspaceJoinPhase::AwaitingRequest,
                WorkspaceJoinSide::Guest => WorkspaceJoinPhase::ReadyRequest,
            },
            response: None,
        })
    }

    /// Guest transition: authenticate and send its invitation request.
    pub fn send_request(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.require(WorkspaceJoinSide::Guest, WorkspaceJoinPhase::ReadyRequest)?;
        let value: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|_| "Workspace join request invalid".to_string())?;
        if !value.is_object() {
            return Err("Workspace join request invalid".to_string());
        }
        let frame = PairingCodec::encode("workspace-join-request", &self.secret, payload)?;
        self.phase = WorkspaceJoinPhase::AwaitingResponse;
        Ok(frame)
    }

    /// Host transition: authenticate the guest request before application approval logic runs.
    pub fn receive_request(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        self.require(WorkspaceJoinSide::Host, WorkspaceJoinPhase::AwaitingRequest)?;
        let payload = PairingCodec::decode(frame, "workspace-join-request", &self.secret)?;
        let value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| "Workspace join request invalid".to_string())?;
        if !value.is_object() {
            return Err("Workspace join request invalid".to_string());
        }
        self.phase = WorkspaceJoinPhase::AwaitingResponse;
        Ok(payload)
    }

    /// Host transition: prepare the authenticated response, successful or rejected.
    pub fn respond(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.require(
            WorkspaceJoinSide::Host,
            WorkspaceJoinPhase::AwaitingResponse,
        )?;
        let value: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|_| "Workspace join response invalid".to_string())?;
        if !value.is_object() {
            return Err("Workspace join response invalid".to_string());
        }
        let frame = PairingCodec::encode("workspace-join-response", &self.secret, payload)?;
        self.response = Some(WorkspaceJoinResponse::Accepted(payload.to_vec()));
        self.phase = WorkspaceJoinPhase::AwaitingAck;
        Ok(frame)
    }

    pub fn reject(&mut self, message: &str) -> Result<Vec<u8>, String> {
        self.require(
            WorkspaceJoinSide::Host,
            WorkspaceJoinPhase::AwaitingResponse,
        )?;
        let error = bounded_join_error(message);
        let payload = serde_json::to_vec(&serde_json::json!({ "error": error }))
            .map_err(|_| "Workspace join response invalid".to_string())?;
        let frame = PairingCodec::encode("workspace-join-response", &self.secret, &payload)?;
        self.response = Some(WorkspaceJoinResponse::Rejected(error));
        self.phase = WorkspaceJoinPhase::AwaitingAck;
        Ok(frame)
    }

    /// Guest transition: accept only a valid response envelope under this invite secret.
    pub fn receive_response(&mut self, frame: &[u8]) -> Result<WorkspaceJoinResponse, String> {
        self.require(
            WorkspaceJoinSide::Guest,
            WorkspaceJoinPhase::AwaitingResponse,
        )?;
        let payload = PairingCodec::decode(frame, "workspace-join-response", &self.secret)?;
        let value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| "Workspace join response invalid".to_string())?;
        let object = value
            .as_object()
            .ok_or_else(|| "Workspace join response invalid".to_string())?;
        let response = match object.get("error") {
            Some(error) => {
                let message = error
                    .as_str()
                    .filter(|message| !message.is_empty())
                    .ok_or_else(|| "Workspace join response invalid".to_string())?;
                WorkspaceJoinResponse::Rejected(bounded_join_error(message))
            }
            None => WorkspaceJoinResponse::Accepted(payload),
        };
        self.response = Some(response.clone());
        self.phase = WorkspaceJoinPhase::AwaitingAck;
        Ok(response)
    }

    /// Guest transition after rejecting an application-level failure.
    pub fn acknowledge_rejection(&mut self) -> Result<Vec<u8>, String> {
        self.require(WorkspaceJoinSide::Guest, WorkspaceJoinPhase::AwaitingAck)?;
        if !matches!(self.response, Some(WorkspaceJoinResponse::Rejected(_))) {
            return Err("Workspace join acknowledgement out of sequence".to_string());
        }
        self.finish_guest_ack(&[])
    }

    /// Guest transition after validating and installing the successful payload.
    pub fn acknowledge_success(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.require(WorkspaceJoinSide::Guest, WorkspaceJoinPhase::AwaitingAck)?;
        if !matches!(self.response, Some(WorkspaceJoinResponse::Accepted(_))) {
            return Err("Workspace join acknowledgement out of sequence".to_string());
        }
        self.finish_guest_ack(payload)
    }

    /// Guest transition after accepting a response but failing application validation or install.
    pub fn reject_accepted_response(&mut self, message: &str) -> Result<Vec<u8>, String> {
        self.require(WorkspaceJoinSide::Guest, WorkspaceJoinPhase::AwaitingAck)?;
        if !matches!(self.response, Some(WorkspaceJoinResponse::Accepted(_))) {
            return Err("Workspace join acknowledgement out of sequence".to_string());
        }
        let error = bounded_join_error(message);
        let payload = serde_json::to_vec(&serde_json::json!({ "error": error }))
            .map_err(|_| "Workspace join acknowledgement invalid".to_string())?;
        let frame = PairingCodec::encode("workspace-join-rejected-ack", &self.secret, &payload)?;
        self.phase = WorkspaceJoinPhase::Complete;
        Ok(frame)
    }

    /// Host transition: authenticate and consume the guest acknowledgement.
    pub fn receive_ack(&mut self, frame: &[u8]) -> Result<WorkspaceJoinAck, String> {
        self.require(WorkspaceJoinSide::Host, WorkspaceJoinPhase::AwaitingAck)?;
        let header = PairingCodec::inspect(frame)?;
        if header.secret != self.secret {
            return Err("Pairing authorization failed".to_string());
        }
        let response = self
            .response
            .as_ref()
            .ok_or_else(|| "Workspace join handshake out of sequence".to_string())?;
        let result = match response {
            WorkspaceJoinResponse::Rejected(_) => {
                let payload = PairingCodec::decode(frame, "sync-ack", &self.secret)?;
                if !payload.is_empty() {
                    return Err("Workspace join acknowledgement invalid".to_string());
                }
                WorkspaceJoinAck::Accepted(payload)
            }
            WorkspaceJoinResponse::Accepted(_)
                if header.frame_type == "workspace-join-rejected-ack" =>
            {
                let payload =
                    PairingCodec::decode(frame, "workspace-join-rejected-ack", &self.secret)?;
                let error = serde_json::from_slice::<serde_json::Value>(&payload)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("error")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    })
                    .filter(|error| !error.is_empty())
                    .ok_or_else(|| "Workspace join acknowledgement invalid".to_string())?;
                WorkspaceJoinAck::Rejected(bounded_join_error(&error))
            }
            WorkspaceJoinResponse::Accepted(_) => {
                let payload = PairingCodec::decode(frame, "sync-ack", &self.secret)?;
                WorkspaceJoinAck::Accepted(payload)
            }
        };
        self.phase = WorkspaceJoinPhase::Complete;
        Ok(result)
    }

    fn finish_guest_ack(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let frame = PairingCodec::encode("sync-ack", &self.secret, payload)?;
        self.phase = WorkspaceJoinPhase::Complete;
        Ok(frame)
    }

    fn require(&self, side: WorkspaceJoinSide, phase: WorkspaceJoinPhase) -> Result<(), String> {
        if self.side != side || self.phase != phase {
            return Err("Workspace join handshake out of sequence".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceJoinHandoffSide {
    Host,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceJoinHandoffPhase {
    Ready,
    AwaitingReady,
    AwaitingConfirmation,
    Resuming,
    Resumed,
    Confirming,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceJoinHandoffOutcome {
    Retry,
    Failed,
    Adopted,
    Complete,
}

/// Authenticated host/guest handoff transitions after workspace snapshot sync.
/// Browser code performs streams and mesh lifecycle effects; this machine owns
/// legal sequencing and whether an error permits retry or preserves adoption.
pub struct WorkspaceJoinHandoff {
    secret: String,
    side: WorkspaceJoinHandoffSide,
    phase: WorkspaceJoinHandoffPhase,
}

impl WorkspaceJoinHandoff {
    pub fn host(secret: &str) -> Result<Self, String> {
        Self::new(secret, WorkspaceJoinHandoffSide::Host)
    }

    pub fn guest(secret: &str) -> Result<Self, String> {
        Self::new(secret, WorkspaceJoinHandoffSide::Guest)
    }

    fn new(secret: &str, side: WorkspaceJoinHandoffSide) -> Result<Self, String> {
        if secret.is_empty() {
            return Err("Pairing frame invalid".to_string());
        }
        Ok(Self {
            secret: secret.to_string(),
            side,
            phase: match side {
                WorkspaceJoinHandoffSide::Host => WorkspaceJoinHandoffPhase::Ready,
                WorkspaceJoinHandoffSide::Guest => WorkspaceJoinHandoffPhase::Ready,
            },
        })
    }

    pub fn guest_request(&mut self) -> Result<Vec<u8>, String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::Ready,
        )?;
        let frame = PairingCodec::encode("mesh-handoff-request", &self.secret, &[])?;
        self.phase = WorkspaceJoinHandoffPhase::AwaitingReady;
        Ok(frame)
    }

    pub fn host_receive_request(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        self.require(
            WorkspaceJoinHandoffSide::Host,
            WorkspaceJoinHandoffPhase::Ready,
        )?;
        let payload = PairingCodec::decode(frame, "mesh-handoff-request", &self.secret)?;
        if !payload.is_empty() {
            return Err("Workspace handoff request invalid".to_string());
        }
        let response = PairingCodec::encode("mesh-handoff-ready", &self.secret, &[])?;
        self.phase = WorkspaceJoinHandoffPhase::AwaitingConfirmation;
        Ok(response)
    }

    pub fn guest_receive_ready(&mut self, frame: &[u8]) -> Result<(), String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::AwaitingReady,
        )?;
        let payload = PairingCodec::decode(frame, "mesh-handoff-ready", &self.secret)?;
        if !payload.is_empty() {
            return Err("Workspace handoff response invalid".to_string());
        }
        self.phase = WorkspaceJoinHandoffPhase::Resuming;
        Ok(())
    }

    pub fn guest_transport_failed(
        &mut self,
        retryable: bool,
    ) -> Result<WorkspaceJoinHandoffOutcome, String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::AwaitingReady,
        )?;
        self.phase = WorkspaceJoinHandoffPhase::Complete;
        Ok(if retryable {
            WorkspaceJoinHandoffOutcome::Retry
        } else {
            WorkspaceJoinHandoffOutcome::Failed
        })
    }

    pub fn guest_resume_succeeded(&mut self) -> Result<(), String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::Resuming,
        )?;
        self.phase = WorkspaceJoinHandoffPhase::Resumed;
        Ok(())
    }

    /// Rust decides retry only while adoption has not completed.
    pub fn guest_resume_failed(
        &mut self,
        retryable: bool,
    ) -> Result<WorkspaceJoinHandoffOutcome, String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::Resuming,
        )?;
        self.phase = WorkspaceJoinHandoffPhase::Complete;
        Ok(if retryable {
            WorkspaceJoinHandoffOutcome::Retry
        } else {
            WorkspaceJoinHandoffOutcome::Failed
        })
    }

    pub fn guest_begin_confirmation(&mut self) -> Result<Vec<u8>, String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::Resumed,
        )?;
        let frame = PairingCodec::encode("mesh-handoff-confirmed", &self.secret, &[])?;
        self.phase = WorkspaceJoinHandoffPhase::Confirming;
        Ok(frame)
    }

    pub fn guest_confirmation_sent(&mut self) -> Result<WorkspaceJoinHandoffOutcome, String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::Confirming,
        )?;
        self.phase = WorkspaceJoinHandoffPhase::Complete;
        Ok(WorkspaceJoinHandoffOutcome::Complete)
    }

    /// The mesh owns the node after resume succeeds; failed confirmation must preserve it.
    pub fn guest_confirmation_failed(&mut self) -> Result<WorkspaceJoinHandoffOutcome, String> {
        self.require(
            WorkspaceJoinHandoffSide::Guest,
            WorkspaceJoinHandoffPhase::Confirming,
        )?;
        self.phase = WorkspaceJoinHandoffPhase::Complete;
        Ok(WorkspaceJoinHandoffOutcome::Adopted)
    }

    pub fn host_receive_confirmation(&mut self, frame: &[u8]) -> Result<(), String> {
        self.require(
            WorkspaceJoinHandoffSide::Host,
            WorkspaceJoinHandoffPhase::AwaitingConfirmation,
        )?;
        let payload = PairingCodec::decode(frame, "mesh-handoff-confirmed", &self.secret)?;
        if !payload.is_empty() {
            return Err("Workspace handoff confirmation invalid".to_string());
        }
        self.phase = WorkspaceJoinHandoffPhase::Complete;
        Ok(())
    }

    fn require(
        &self,
        side: WorkspaceJoinHandoffSide,
        phase: WorkspaceJoinHandoffPhase,
    ) -> Result<(), String> {
        if self.side != side || self.phase != phase {
            return Err("Workspace handoff out of sequence".to_string());
        }
        Ok(())
    }
}

fn bounded_join_error(message: &str) -> String {
    let mut end = message.len().min(MAX_WORKSPACE_JOIN_ERROR_BYTES);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_string()
}

fn is_pairing_frame_type(frame_type: &str) -> bool {
    PAIRING_FRAME_TYPES.contains(&frame_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_frame_round_trips_binary_payload() {
        let frame =
            PairingCodec::encode("mesh-control-sync", "workspace-secret", &[0, 1, 255]).unwrap();
        assert_eq!(
            PairingCodec::inspect(&frame).unwrap(),
            PairingFrameHeader {
                frame_type: "mesh-control-sync".to_string(),
                version: PAIRING_VERSION.to_string(),
                secret: "workspace-secret".to_string(),
            }
        );
        assert_eq!(
            PairingCodec::decode(&frame, "mesh-control-sync", "workspace-secret").unwrap(),
            vec![0, 1, 255]
        );
    }

    #[test]
    fn enrollment_rejection_preserves_reason_and_authenticates_ack() {
        let reason = br#"{"reason":"Workspace storage is unavailable"}"#;
        let rejection = PairingCodec::encode("enroll-rejected", "secret", reason).unwrap();
        assert_eq!(
            PairingCodec::decode(&rejection, "enroll-rejected", "secret").unwrap(),
            reason
        );
        let ack = PairingCodec::encode("enroll-rejected-ack", "secret", &[]).unwrap();
        assert!(
            PairingCodec::decode(&ack, "enroll-rejected-ack", "secret")
                .unwrap()
                .is_empty()
        );
        assert!(PairingCodec::decode(&ack, "enroll-rejected-ack", "wrong-secret").is_err());
    }

    #[test]
    fn pairing_frame_rejects_wrong_secret() {
        let frame = PairingCodec::encode("sync-request", "wrong-secret", &[1]).unwrap();
        assert_eq!(
            PairingCodec::decode(&frame, "sync-request", "expected-secret").unwrap_err(),
            "Pairing authorization failed"
        );
    }

    #[test]
    fn iroh_gossip_frame_round_trips_binary_packet() {
        let packet = [0, 1, 2, 255];
        let frame = PairingCodec::encode("mesh-iroh-gossip", "workspace-secret", &packet).unwrap();
        assert_eq!(
            PairingCodec::decode(&frame, "mesh-iroh-gossip", "workspace-secret").unwrap(),
            packet
        );
    }

    #[test]
    fn owner_workspace_offer_uses_the_distinct_frame_name() {
        let frame =
            PairingCodec::encode("mesh-owner-workspace-offer", "workspace-secret", &[1]).unwrap();
        assert_eq!(
            PairingCodec::inspect(&frame).unwrap().frame_type,
            "mesh-owner-workspace-offer"
        );
        assert_eq!(
            PairingCodec::encode("mesh-gossip", "workspace-secret", &[]).unwrap_err(),
            "Pairing frame invalid"
        );
    }

    #[test]
    fn pairing_frame_rejects_unknown_type() {
        assert_eq!(
            PairingCodec::encode("unknown", "secret", &[]).unwrap_err(),
            "Pairing frame invalid"
        );
    }

    #[test]
    fn workspace_join_success_moves_from_response_to_authenticated_ack() {
        let payload = br#"{"grants":[],"snapshot":"AQ","meshWorkspaces":[]}"#;
        let mut host = WorkspaceJoinHandshake::host("join-secret").unwrap();
        let mut guest = WorkspaceJoinHandshake::guest("join-secret").unwrap();
        let request = guest.send_request(br#"{"personId":"guest"}"#).unwrap();
        host.receive_request(&request).unwrap();
        let response = host.respond(payload).unwrap();

        assert_eq!(
            guest.receive_response(&response).unwrap(),
            WorkspaceJoinResponse::Accepted(payload.to_vec())
        );
        let acknowledgement = guest.acknowledge_success(b"guest snapshot").unwrap();
        assert_eq!(
            host.receive_ack(&acknowledgement).unwrap(),
            WorkspaceJoinAck::Accepted(b"guest snapshot".to_vec())
        );
        assert_eq!(
            host.receive_ack(&acknowledgement).unwrap_err(),
            "Workspace join handshake out of sequence"
        );
    }

    #[test]
    fn workspace_join_rejection_is_bounded_and_acknowledged_once() {
        let mut host = WorkspaceJoinHandshake::host("join-secret").unwrap();
        let mut guest = WorkspaceJoinHandshake::guest("join-secret").unwrap();
        let request = guest.send_request(br#"{"personId":"guest"}"#).unwrap();
        host.receive_request(&request).unwrap();
        let response = host.reject(&format!("{} tail", "é".repeat(300))).unwrap();

        let WorkspaceJoinResponse::Rejected(reason) = guest.receive_response(&response).unwrap()
        else {
            panic!("rejection response expected")
        };
        assert_eq!(reason.len(), MAX_WORKSPACE_JOIN_ERROR_BYTES);
        assert!(reason.is_char_boundary(reason.len()));
        let acknowledgement = guest.acknowledge_rejection().unwrap();
        assert_eq!(
            host.receive_ack(&acknowledgement).unwrap(),
            WorkspaceJoinAck::Accepted(Vec::new())
        );
        assert_eq!(
            guest.acknowledge_rejection().unwrap_err(),
            "Workspace join handshake out of sequence"
        );
    }

    #[test]
    fn workspace_join_requires_authenticated_response_and_correct_transition() {
        let mut guest = WorkspaceJoinHandshake::guest("join-secret").unwrap();
        guest.send_request(br#"{"personId":"guest"}"#).unwrap();
        let wrong_secret =
            PairingCodec::encode("workspace-join-response", "other-secret", br#"{}"#).unwrap();
        assert_eq!(
            guest.receive_response(&wrong_secret).unwrap_err(),
            "Pairing authorization failed"
        );
        assert_eq!(
            guest.acknowledge_success(&[]).unwrap_err(),
            "Workspace join handshake out of sequence"
        );

        let mut host = WorkspaceJoinHandshake::host("join-secret").unwrap();
        let mut right_guest = WorkspaceJoinHandshake::guest("join-secret").unwrap();
        let request = right_guest
            .send_request(br#"{"personId":"guest"}"#)
            .unwrap();
        host.receive_request(&request).unwrap();
        assert_eq!(
            host.receive_ack(&[]).unwrap_err(),
            "Workspace join handshake out of sequence"
        );
    }

    #[test]
    fn workspace_join_guest_install_failure_is_a_typed_terminal_host_rejection() {
        let mut host = WorkspaceJoinHandshake::host("join-secret").unwrap();
        let mut guest = WorkspaceJoinHandshake::guest("join-secret").unwrap();
        let request = guest.send_request(br#"{"personId":"guest"}"#).unwrap();
        host.receive_request(&request).unwrap();
        let response = host.respond(br#"{"grants":[],"snapshot":"AQ"}"#).unwrap();
        guest.receive_response(&response).unwrap();
        let acknowledgement = guest
            .reject_accepted_response("Storage failure: network unavailable")
            .unwrap();

        assert_eq!(
            host.receive_ack(&acknowledgement).unwrap(),
            WorkspaceJoinAck::Rejected("Storage failure: network unavailable".to_string())
        );
    }

    #[test]
    fn host_rejection_requires_an_empty_acknowledgement() {
        let mut host = WorkspaceJoinHandshake::host("join-secret").unwrap();
        let mut guest = WorkspaceJoinHandshake::guest("join-secret").unwrap();
        let request = guest.send_request(br#"{"personId":"guest"}"#).unwrap();
        host.receive_request(&request).unwrap();
        let response = host.reject("approval failed").unwrap();
        guest.receive_response(&response).unwrap();
        let invalid_ack = PairingCodec::encode("sync-ack", "join-secret", b"not empty").unwrap();

        assert_eq!(
            host.receive_ack(&invalid_ack).unwrap_err(),
            "Workspace join acknowledgement invalid"
        );
    }

    #[test]
    fn workspace_join_request_is_authenticated_and_starts_host_response_phase() {
        let mut host = WorkspaceJoinHandshake::host("join-secret").unwrap();
        let mut guest = WorkspaceJoinHandshake::guest("join-secret").unwrap();
        let wrong_secret =
            PairingCodec::encode("workspace-join-request", "other-secret", br#"{}"#).unwrap();
        assert_eq!(
            host.receive_request(&wrong_secret).unwrap_err(),
            "Pairing authorization failed"
        );
        assert_eq!(
            host.respond(br#"{}"#).unwrap_err(),
            "Workspace join handshake out of sequence"
        );
        let request = guest.send_request(br#"{"personId":"guest"}"#).unwrap();
        assert_eq!(
            guest.send_request(br#"{}"#).unwrap_err(),
            "Workspace join handshake out of sequence"
        );
        assert_eq!(
            host.receive_request(&request).unwrap(),
            br#"{"personId":"guest"}"#
        );
    }

    #[test]
    fn workspace_handoff_resume_failure_retries_only_before_adoption() {
        let mut guest = WorkspaceJoinHandoff::guest("join-secret").unwrap();
        let mut host = WorkspaceJoinHandoff::host("join-secret").unwrap();
        let request = guest.guest_request().unwrap();
        let ready = host.host_receive_request(&request).unwrap();
        guest.guest_receive_ready(&ready).unwrap();

        assert_eq!(
            guest.guest_resume_failed(true).unwrap(),
            WorkspaceJoinHandoffOutcome::Retry
        );
        assert_eq!(
            guest.guest_resume_succeeded().unwrap_err(),
            "Workspace handoff out of sequence"
        );
    }

    #[test]
    fn workspace_handoff_transport_failure_can_retry_only_before_resume() {
        let mut guest = WorkspaceJoinHandoff::guest("join-secret").unwrap();
        guest.guest_request().unwrap();
        assert_eq!(
            guest.guest_transport_failed(true).unwrap(),
            WorkspaceJoinHandoffOutcome::Retry
        );
        assert_eq!(
            guest.guest_transport_failed(true).unwrap_err(),
            "Workspace handoff out of sequence"
        );
    }

    #[test]
    fn workspace_handoff_confirmation_failure_preserves_adopted_node() {
        let mut guest = WorkspaceJoinHandoff::guest("join-secret").unwrap();
        let mut host = WorkspaceJoinHandoff::host("join-secret").unwrap();
        let request = guest.guest_request().unwrap();
        let ready = host.host_receive_request(&request).unwrap();
        guest.guest_receive_ready(&ready).unwrap();
        guest.guest_resume_succeeded().unwrap();
        guest.guest_begin_confirmation().unwrap();

        assert_eq!(
            guest.guest_confirmation_failed().unwrap(),
            WorkspaceJoinHandoffOutcome::Adopted
        );
        assert_eq!(
            guest.guest_confirmation_sent().unwrap_err(),
            "Workspace handoff out of sequence"
        );
        assert_eq!(
            host.host_receive_confirmation(
                &PairingCodec::encode("mesh-handoff-confirmed", "other-secret", &[],).unwrap()
            )
            .unwrap_err(),
            "Pairing authorization failed"
        );
    }

    #[test]
    fn workspace_handoff_success_authenticates_each_stage_once() {
        let mut guest = WorkspaceJoinHandoff::guest("join-secret").unwrap();
        let mut host = WorkspaceJoinHandoff::host("join-secret").unwrap();
        let request = guest.guest_request().unwrap();
        let ready = host.host_receive_request(&request).unwrap();
        guest.guest_receive_ready(&ready).unwrap();
        guest.guest_resume_succeeded().unwrap();
        let confirmation = guest.guest_begin_confirmation().unwrap();

        assert_eq!(
            guest.guest_confirmation_sent().unwrap(),
            WorkspaceJoinHandoffOutcome::Complete
        );
        host.host_receive_confirmation(&confirmation).unwrap();
        assert_eq!(
            host.host_receive_confirmation(&confirmation).unwrap_err(),
            "Workspace handoff out of sequence"
        );
    }
}
