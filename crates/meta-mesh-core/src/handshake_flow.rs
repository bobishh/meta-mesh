use crate::SessionDirection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStep {
    ReadRequest,
    SendRequest,
    ReadResponse,
    MergeAuthority,
    VerifyPeer,
    CheckRevocation,
    CheckExpectedPeer,
    PersistPeer,
    InstallSession,
    SendResponse,
    SendRevocation,
    AfterInstalled,
    Complete,
    Revoked,
    SessionRejected,
    PeerMismatch,
}

impl HandshakeStep {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadRequest => "readRequest",
            Self::SendRequest => "sendRequest",
            Self::ReadResponse => "readResponse",
            Self::MergeAuthority => "mergeAuthority",
            Self::VerifyPeer => "verifyPeer",
            Self::CheckRevocation => "checkRevocation",
            Self::CheckExpectedPeer => "checkExpectedPeer",
            Self::PersistPeer => "persistPeer",
            Self::InstallSession => "installSession",
            Self::SendResponse => "sendResponse",
            Self::SendRevocation => "sendRevocation",
            Self::AfterInstalled => "afterInstalled",
            Self::Complete => "complete",
            Self::Revoked => "revoked",
            Self::SessionRejected => "sessionRejected",
            Self::PeerMismatch => "peerMismatch",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MeshHandshakeFlow {
    direction: SessionDirection,
    step: HandshakeStep,
}

impl MeshHandshakeFlow {
    pub fn new(direction: SessionDirection) -> Self {
        let step = match direction {
            SessionDirection::Incoming => HandshakeStep::ReadRequest,
            SessionDirection::Outgoing => HandshakeStep::SendRequest,
        };
        Self { direction, step }
    }

    pub fn step(&self) -> HandshakeStep {
        self.step
    }

    /// Advance only after the host completed the current I/O action. A decision
    /// is required for access, peer identity, and session admission branches.
    pub fn advance(
        &mut self,
        completed: &str,
        decision: Option<bool>,
    ) -> Result<HandshakeStep, String> {
        if completed != self.step.as_str() {
            return Err("Out-of-order mesh handshake step".into());
        }
        let next = match (self.direction, self.step, decision) {
            (SessionDirection::Incoming, HandshakeStep::ReadRequest, None) => {
                HandshakeStep::MergeAuthority
            }
            (SessionDirection::Outgoing, HandshakeStep::SendRequest, None) => {
                HandshakeStep::ReadResponse
            }
            (SessionDirection::Outgoing, HandshakeStep::ReadResponse, None) => {
                HandshakeStep::MergeAuthority
            }
            (_, HandshakeStep::MergeAuthority, None) => HandshakeStep::VerifyPeer,
            (SessionDirection::Incoming, HandshakeStep::VerifyPeer, None) => {
                HandshakeStep::CheckRevocation
            }
            (SessionDirection::Outgoing, HandshakeStep::VerifyPeer, None) => {
                HandshakeStep::CheckExpectedPeer
            }
            (SessionDirection::Incoming, HandshakeStep::CheckRevocation, Some(true)) => {
                HandshakeStep::SendRevocation
            }
            (SessionDirection::Incoming, HandshakeStep::CheckRevocation, Some(false)) => {
                HandshakeStep::PersistPeer
            }
            (SessionDirection::Outgoing, HandshakeStep::CheckExpectedPeer, Some(true)) => {
                HandshakeStep::PersistPeer
            }
            (SessionDirection::Outgoing, HandshakeStep::CheckExpectedPeer, Some(false)) => {
                HandshakeStep::PeerMismatch
            }
            (SessionDirection::Incoming, HandshakeStep::PersistPeer, None) => {
                HandshakeStep::InstallSession
            }
            (SessionDirection::Outgoing, HandshakeStep::PersistPeer, None) => {
                HandshakeStep::Complete
            }
            (SessionDirection::Incoming, HandshakeStep::InstallSession, Some(true)) => {
                HandshakeStep::SendResponse
            }
            (SessionDirection::Incoming, HandshakeStep::InstallSession, Some(false)) => {
                HandshakeStep::SessionRejected
            }
            (SessionDirection::Incoming, HandshakeStep::SendResponse, None) => {
                HandshakeStep::AfterInstalled
            }
            (SessionDirection::Incoming, HandshakeStep::AfterInstalled, None) => {
                HandshakeStep::Complete
            }
            (SessionDirection::Incoming, HandshakeStep::SendRevocation, None) => {
                HandshakeStep::Revoked
            }
            _ => return Err("Invalid mesh handshake transition".into()),
        };
        self.step = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_rejection_cannot_install_or_persist_peer() {
        let mut flow = MeshHandshakeFlow::new(SessionDirection::Incoming);
        assert_eq!(flow.step(), HandshakeStep::ReadRequest);
        assert!(flow.advance("verifyPeer", None).is_err());
        for (current, next) in [
            ("readRequest", HandshakeStep::MergeAuthority),
            ("mergeAuthority", HandshakeStep::VerifyPeer),
            ("verifyPeer", HandshakeStep::CheckRevocation),
        ] {
            assert_eq!(flow.advance(current, None).unwrap(), next);
        }
        assert_eq!(
            flow.advance("checkRevocation", Some(true)).unwrap(),
            HandshakeStep::SendRevocation
        );
        assert_eq!(
            flow.advance("sendRevocation", None).unwrap(),
            HandshakeStep::Revoked
        );
        assert!(flow.advance("persistPeer", None).is_err());
    }

    #[test]
    fn incoming_install_and_outgoing_identity_have_separate_terminal_branches() {
        let mut inbound = MeshHandshakeFlow::new(SessionDirection::Incoming);
        for step in ["readRequest", "mergeAuthority", "verifyPeer"] {
            inbound.advance(step, None).unwrap();
        }
        inbound.advance("checkRevocation", Some(false)).unwrap();
        inbound.advance("persistPeer", None).unwrap();
        assert_eq!(
            inbound.advance("installSession", Some(false)).unwrap(),
            HandshakeStep::SessionRejected
        );

        let mut outbound = MeshHandshakeFlow::new(SessionDirection::Outgoing);
        for step in [
            "sendRequest",
            "readResponse",
            "mergeAuthority",
            "verifyPeer",
        ] {
            outbound.advance(step, None).unwrap();
        }
        assert_eq!(
            outbound.advance("checkExpectedPeer", Some(false)).unwrap(),
            HandshakeStep::PeerMismatch
        );
        assert!(outbound.advance("persistPeer", None).is_err());
    }

    #[test]
    fn successful_incoming_flow_requires_response_after_install() {
        let mut flow = MeshHandshakeFlow::new(SessionDirection::Incoming);
        for step in ["readRequest", "mergeAuthority", "verifyPeer"] {
            flow.advance(step, None).unwrap();
        }
        flow.advance("checkRevocation", Some(false)).unwrap();
        flow.advance("persistPeer", None).unwrap();
        assert_eq!(
            flow.advance("installSession", Some(true)).unwrap(),
            HandshakeStep::SendResponse
        );
        assert_eq!(
            flow.advance("sendResponse", None).unwrap(),
            HandshakeStep::AfterInstalled
        );
        assert_eq!(
            flow.advance("afterInstalled", None).unwrap(),
            HandshakeStep::Complete
        );
    }
}
