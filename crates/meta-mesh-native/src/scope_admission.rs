use serde_json::Value;

use meta_mesh_core::{
    MeshAuthenticatedSessions, MeshHandshake, MeshPeerAdmission, PairingFrameHeader,
    WorkspaceWriteAuthorizationSnapshot, decode_mesh_handshake, encode_mesh_handshake,
    inspect_mesh_handshake,
};

/// Native counterpart to the browser's credential-bound scope handshake.
/// Product code supplies current signed authority and its own signed response.
#[derive(Default)]
pub struct NativeScopeAdmission {
    sessions: MeshAuthenticatedSessions,
}

impl NativeScopeAdmission {
    pub fn inspect(frame: &[u8]) -> Result<PairingFrameHeader, String> {
        inspect_mesh_handshake(frame)
    }

    pub fn accept(
        &mut self,
        frame: &[u8],
        secret: &str,
        workspace_id: &str,
        remote_endpoint: &str,
        now_ms: i128,
        prepare: impl FnOnce(
            &MeshHandshake,
        ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String>,
    ) -> Result<(MeshPeerAdmission, Vec<u8>), String> {
        let request = decode_mesh_handshake(frame, "mesh-handshake-request", secret, workspace_id)?;
        let (snapshot, response) = prepare(&request)?;
        if snapshot.workspace_id != workspace_id {
            return Err("Native scope authority does not match handshake workspace".into());
        }
        // Encode before admitting so an invalid local response never opens a
        // session that cannot complete its handshake.
        let response = encode_mesh_handshake("mesh-handshake-response", secret, response)?;
        let peer = self.sessions.admit(
            serde_json::to_value(request).map_err(|error| error.to_string())?,
            &snapshot,
            remote_endpoint,
            now_ms,
        )?;
        Ok((peer, response))
    }

    pub fn peer(&self, workspace_id: &str, remote_endpoint: &str) -> Option<&MeshPeerAdmission> {
        self.sessions.peer(workspace_id, remote_endpoint)
    }

    pub fn refresh(
        &mut self,
        snapshot: &WorkspaceWriteAuthorizationSnapshot,
        now_ms: i128,
    ) -> Result<Vec<String>, String> {
        self.sessions.refresh(snapshot, now_ms)
    }

    pub fn remove(&mut self, workspace_id: &str, remote_endpoint: &str) -> bool {
        self.sessions.remove(workspace_id, remote_endpoint)
    }
}
