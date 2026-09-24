use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const INVALID_SET: &str = "The peer sent a different set of workspaces than the invitation allows.";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSetEntry {
    pub id: String,
    pub bytes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh: Option<Value>,
}

pub fn encode_workspace_set(entries: &[WorkspaceSetEntry]) -> Result<Vec<u8>, String> {
    serde_json::to_vec(entries).map_err(|_| "Invalid workspace set".into())
}

pub fn decode_workspace_set(
    bytes: &[u8],
    allowed_ids: &[String],
) -> Result<Vec<WorkspaceSetEntry>, String> {
    let entries: Vec<WorkspaceSetEntry> =
        serde_json::from_slice(bytes).map_err(|_| INVALID_SET.to_string())?;
    let allowed: HashSet<&str> = allowed_ids.iter().map(String::as_str).collect();
    let actual: HashSet<&str> = entries.iter().map(|entry| entry.id.as_str()).collect();
    if entries.len() != allowed_ids.len() || actual.len() != allowed_ids.len() || actual != allowed
    {
        return Err(INVALID_SET.into());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_set_requires_exact_invited_scope() {
        let allowed = vec!["a".into(), "b".into()];
        let entries = br#"[{"id":"a","bytes":"AA"},{"id":"b","bytes":"BB"}]"#;
        assert_eq!(decode_workspace_set(entries, &allowed).unwrap().len(), 2);
        assert!(
            decode_workspace_set(
                br#"[{"id":"a","bytes":"AA"},{"id":"a","bytes":"BB"}]"#,
                &allowed
            )
            .is_err()
        );
        assert!(
            decode_workspace_set(
                br#"[{"id":"a","bytes":"AA"},{"id":"c","bytes":"BB"}]"#,
                &allowed
            )
            .is_err()
        );
        assert!(
            decode_workspace_set(
                br#"[{"id":"a","bytes":1},{"id":"b","bytes":"BB"}]"#,
                &allowed
            )
            .is_err()
        );
    }
}
