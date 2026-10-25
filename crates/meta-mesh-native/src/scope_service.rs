use meta_mesh_core::{
    LiveSessionPublishPlan, MeshHandshake, MeshInstant, MeshPeerAdmission, PairingCodec,
    WorkspaceWriteAuthorizationSnapshot, encode_mesh_handshake,
};
use serde_json::Value;
use std::collections::HashMap;

use crate::{NativeScopeAdmission, NativeScopeHost, NativeScopePeer};

pub struct NativeScopeCredential {
    pub workspace_id: String,
    pub secret: String,
}

/// Product boundary for a native mesh participant. Implementations must load
/// signed authority from durable storage and validate writes in ScopeHost.
pub trait NativeScopeServiceHost {
    type ScopeHost: NativeScopeHost;

    fn local_device_id(&self) -> &str;
    fn credential(&mut self, secret: &str) -> Result<Option<NativeScopeCredential>, String>;
    fn prepare_handshake(
        &mut self,
        workspace_id: &str,
        request: &MeshHandshake,
    ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String>;
    fn authority(
        &mut self,
        workspace_id: &str,
    ) -> Result<WorkspaceWriteAuthorizationSnapshot, String>;
    fn outgoing_handshake(&mut self, workspace_id: &str) -> Result<Value, String>;
    fn open_scope(&mut self, peer: &MeshPeerAdmission) -> Result<Self::ScopeHost, String>;
}

/// Serial RPC driver over NativeNode's browser-compatible Iroh ALPN. A scope
/// frame is considered only after the endpoint passes signed admission.
pub struct NativeScopeService<H: NativeScopeServiceHost> {
    admission: NativeScopeAdmission,
    peers: HashMap<(String, String), NativeScopePeer<H::ScopeHost>>,
    host: H,
}

impl<H: NativeScopeServiceHost> NativeScopeService<H> {
    pub fn new(host: H) -> Self {
        Self {
            admission: NativeScopeAdmission::default(),
            peers: HashMap::new(),
            host,
        }
    }

    pub fn host(&self) -> &H {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    pub fn has_peer(&self, workspace_id: &str, remote_endpoint: &str) -> bool {
        self.admission.peer(workspace_id, remote_endpoint).is_some()
    }

    pub fn forget_peer(&mut self, workspace_id: &str, remote_endpoint: &str) {
        self.admission.remove(workspace_id, remote_endpoint);
        self.peers
            .remove(&(workspace_id.to_string(), remote_endpoint.to_string()));
    }

    /// Release expired partial control transfers without dropping authenticated peers.
    pub fn expire_pending_transfers(&mut self) -> usize {
        self.expire_pending_transfers_at(MeshInstant::now())
    }

    pub fn expire_pending_transfers_at(&mut self, now: MeshInstant) -> usize {
        self.peers
            .values_mut()
            .map(|peer| peer.expire_pending_transfers_at(now))
            .filter(|expired| *expired)
            .count()
    }

    pub fn prepare_connect(&mut self, workspace_id: &str, secret: &str) -> Result<Vec<u8>, String> {
        let credential = self
            .host
            .credential(secret)?
            .ok_or("Unknown mesh credential")?;
        if credential.workspace_id != workspace_id {
            return Err("Mesh credential targets another workspace".into());
        }
        let handshake = self.host.outgoing_handshake(workspace_id)?;
        encode_mesh_handshake("mesh-handshake-request", secret, handshake)
    }

    pub fn complete_connect(
        &mut self,
        workspace_id: &str,
        secret: &str,
        remote_endpoint: &str,
        response: &[u8],
        now_ms: i128,
    ) -> Result<MeshPeerAdmission, String> {
        let credential = self
            .host
            .credential(secret)?
            .ok_or("Unknown mesh credential")?;
        if credential.workspace_id != workspace_id {
            return Err("Mesh credential targets another workspace".into());
        }
        let authority = self.host.authority(workspace_id)?;
        let peer = self.admission.admit_response(
            response,
            secret,
            workspace_id,
            remote_endpoint,
            &authority,
            now_ms,
        )?;
        let scope = match self.host.open_scope(&peer) {
            Ok(scope) => scope,
            Err(error) => {
                self.admission.remove(workspace_id, remote_endpoint);
                return Err(error);
            }
        };
        let native = match NativeScopePeer::new(
            workspace_id,
            secret,
            self.host.local_device_id(),
            &peer.device_id,
            scope,
        ) {
            Ok(native) => native,
            Err(error) => {
                self.admission.remove(workspace_id, remote_endpoint);
                return Err(error);
            }
        };
        self.peers.insert(
            (workspace_id.to_string(), remote_endpoint.to_string()),
            native,
        );
        Ok(peer)
    }

    pub fn receive(
        &mut self,
        remote_endpoint: &str,
        frame: &[u8],
        now_ms: i128,
    ) -> Result<Option<Vec<u8>>, String> {
        let header = PairingCodec::inspect(frame)?;
        let credential = self
            .host
            .credential(&header.secret)?
            .ok_or("Unknown mesh credential")?;
        let key = (credential.workspace_id.clone(), remote_endpoint.to_string());
        if header.frame_type == "mesh-handshake-request" {
            let workspace_id = credential.workspace_id.clone();
            let (peer, response) = self.admission.accept(
                frame,
                &credential.secret,
                &workspace_id,
                remote_endpoint,
                now_ms,
                |request| self.host.prepare_handshake(&workspace_id, request),
            )?;
            let scope = match self.host.open_scope(&peer) {
                Ok(scope) => scope,
                Err(error) => {
                    self.admission.remove(&workspace_id, remote_endpoint);
                    return Err(error);
                }
            };
            let peer = match NativeScopePeer::new(
                &workspace_id,
                &credential.secret,
                self.host.local_device_id(),
                &peer.device_id,
                scope,
            ) {
                Ok(peer) => peer,
                Err(error) => {
                    self.admission.remove(&workspace_id, remote_endpoint);
                    return Err(error);
                }
            };
            self.peers.insert(key, peer);
            return Ok(Some(response));
        }
        self.admission
            .peer(&credential.workspace_id, remote_endpoint)
            .ok_or("Unauthenticated mesh peer")?;
        self.refresh_authority(&credential.workspace_id, now_ms)?;
        self.admission
            .peer(&credential.workspace_id, remote_endpoint)
            .ok_or("Unauthenticated mesh peer")?;
        self.peers
            .get_mut(&key)
            .ok_or("Mesh scope session is missing")?
            .receive(frame)
    }

    pub fn prepare_publish(
        &mut self,
        workspace_id: &str,
        remote_endpoint: &str,
        now_ms: i128,
    ) -> Result<LiveSessionPublishPlan, String> {
        self.refresh_authority(workspace_id, now_ms)?;
        self.admission
            .peer(workspace_id, remote_endpoint)
            .ok_or("Unauthenticated mesh peer")?;
        self.peers
            .get_mut(&(workspace_id.to_string(), remote_endpoint.to_string()))
            .ok_or("Mesh scope session is missing")?
            .prepare_publish()
    }

    pub fn finish_publish(
        &mut self,
        workspace_id: &str,
        remote_endpoint: &str,
        control_snapshot: &[u8],
        all_frames_sent: bool,
    ) -> Result<(), String> {
        self.peers
            .get_mut(&(workspace_id.to_string(), remote_endpoint.to_string()))
            .ok_or("Mesh scope session is missing")?
            .finish_publish(control_snapshot, all_frames_sent);
        Ok(())
    }

    /// Reset only an incomplete document/proof receive after its response
    /// exchange timed out. Product storage and the untrusted page cache remain.
    pub fn abort_incomplete_document_receive(
        &mut self,
        workspace_id: &str,
        remote_endpoint: &str,
    ) -> Result<bool, String> {
        self.peers
            .get_mut(&(workspace_id.to_string(), remote_endpoint.to_string()))
            .map(NativeScopePeer::abort_incomplete_document_receive)
            .ok_or_else(|| "Mesh scope session is missing".into())
    }

    fn refresh_authority(&mut self, workspace_id: &str, now_ms: i128) -> Result<(), String> {
        let authority = self.host.authority(workspace_id)?;
        for endpoint in self.admission.refresh(&authority, now_ms)? {
            self.peers.remove(&(workspace_id.to_string(), endpoint));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeScopeSnapshot;
    use meta_mesh_core::{MAX_CONTROL_FRAME_BYTES, control_frames};
    use std::time::Duration;

    struct Scope;
    impl NativeScopeHost for Scope {
        fn snapshot(&mut self) -> Result<NativeScopeSnapshot, String> {
            panic!("not admitted")
        }
        fn persist_document(
            &mut self,
            _: &[u8],
            _: Option<&Value>,
            _: &[String],
        ) -> Result<(), String> {
            panic!("not admitted")
        }
        fn merge_authorization(&mut self, _: &Value) -> Result<(), String> {
            panic!("not admitted")
        }
        fn merge_chat(&mut self, _: &Value) -> Result<(), String> {
            panic!("not admitted")
        }
        fn merge_mesh(&mut self, _: &Value) -> Result<(), String> {
            panic!("not admitted")
        }
        fn merge_durable_batch(&mut self, _: &[u8]) -> Result<(), String> {
            panic!("not admitted")
        }
        fn merge_owner_offer(&mut self, _: &[u8]) -> Result<(), String> {
            panic!("not admitted")
        }
        fn receive_gossip(&mut self, _: &[u8]) -> Result<(), String> {
            panic!("not admitted")
        }
    }

    struct Host;
    impl NativeScopeServiceHost for Host {
        type ScopeHost = Scope;
        fn local_device_id(&self) -> &str {
            "local"
        }
        fn credential(&mut self, secret: &str) -> Result<Option<NativeScopeCredential>, String> {
            Ok((secret == "secret").then(|| NativeScopeCredential {
                workspace_id: "board".into(),
                secret: secret.into(),
            }))
        }
        fn prepare_handshake(
            &mut self,
            _: &str,
            _: &MeshHandshake,
        ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String> {
            panic!("not admitted")
        }
        fn authority(&mut self, _: &str) -> Result<WorkspaceWriteAuthorizationSnapshot, String> {
            panic!("not admitted")
        }
        fn outgoing_handshake(&mut self, _: &str) -> Result<Value, String> {
            Ok(serde_json::json!({
                "workspaceId": "board", "peer": {},
                "capabilities": ["iroh-gossip-v1", "automerge-sync-v1", "device-revocation-v1"],
            }))
        }
        fn open_scope(&mut self, _: &MeshPeerAdmission) -> Result<Scope, String> {
            panic!("not admitted")
        }
    }

    #[test]
    fn scope_frame_cannot_read_authority_before_signed_handshake() {
        let frame = PairingCodec::encode("sync-heartbeat", "secret", &[]).unwrap();
        let mut service = NativeScopeService::new(Host);
        assert_eq!(
            service.receive("remote", &frame, 0).unwrap_err(),
            "Unauthenticated mesh peer"
        );
    }

    #[test]
    fn outbound_handshake_uses_the_same_credential_bound_frame_as_browser() {
        let mut service = NativeScopeService::new(Host);
        let request = service.prepare_connect("board", "secret").unwrap();
        let decoded = meta_mesh_core::decode_mesh_handshake(
            &request,
            "mesh-handshake-request",
            "secret",
            "board",
        )
        .unwrap();
        assert_eq!(decoded.workspace_id, "board");
        assert!(service.prepare_connect("board", "wrong").is_err());
    }

    #[test]
    fn pending_transfer_sweep_keeps_other_authenticated_peers_live() {
        let mut service = NativeScopeService::new(Host);
        for remote in ["remote-a", "remote-b"] {
            let peer = NativeScopePeer::new("board", "secret", "local", remote, Scope).unwrap();
            service.peers.insert(("board".into(), remote.into()), peer);
        }

        let bytes = vec![7; MAX_CONTROL_FRAME_BYTES + 1];
        let pages = control_frames("board", "expired-transfer", &bytes).unwrap();
        let first_page = PairingCodec::encode("mesh-control-sync", "secret", &pages[0]).unwrap();
        assert!(
            service
                .peers
                .get_mut(&("board".into(), "remote-a".into()))
                .unwrap()
                .receive(&first_page)
                .unwrap()
                .is_none()
        );

        let future = MeshInstant::now()
            + Duration::from_millis(u64::from(meta_mesh_core::MAX_TRANSFER_DEADLINE_MS) + 1);
        assert_eq!(service.expire_pending_transfers_at(future), 1);
        assert_eq!(service.peers.len(), 2);
        let heartbeat = PairingCodec::encode("sync-heartbeat", "secret", &[]).unwrap();
        for peer in service.peers.values_mut() {
            let acknowledgement = peer.receive(&heartbeat).unwrap().unwrap();
            assert_eq!(
                PairingCodec::inspect(&acknowledgement).unwrap().frame_type,
                "sync-heartbeat-ack"
            );
        }
    }
}
