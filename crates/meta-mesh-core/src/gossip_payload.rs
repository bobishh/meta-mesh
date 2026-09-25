use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceUpdate<'a> {
    version: u8,
    kind: &'static str,
    workspace_id: &'a str,
    nonce: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncomingWorkspaceUpdate {
    version: u8,
    kind: String,
    workspace_id: String,
}

pub fn encode_workspace_update(workspace_id: &str, nonce: &str) -> Vec<u8> {
    serde_json::to_vec(&WorkspaceUpdate {
        version: 1,
        kind: "workspace-update",
        workspace_id,
        nonce,
    })
    .expect("workspace update contains only strings")
}

pub fn is_workspace_update(payload: &[u8], workspace_id: &str) -> bool {
    serde_json::from_slice::<IncomingWorkspaceUpdate>(payload).is_ok_and(|message| {
        message.version == 1
            && message.kind == "workspace-update"
            && message.workspace_id == workspace_id
    })
}
