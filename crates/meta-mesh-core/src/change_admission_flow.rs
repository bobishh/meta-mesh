use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AuthorizedWorkspaceChange, IncomingWorkspaceChangeAuthorization, WorkspaceRole,
    WorkspaceWriteAuthorizationSnapshot, admit_workspace_change_authorizations,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAdmissionChange {
    pub hash: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    pub actor: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAdmissionFlowInput {
    pub records: Vec<Value>,
    pub known_hashes: Vec<String>,
    pub changes: Vec<ChangeAdmissionChange>,
    pub snapshot: WorkspaceWriteAuthorizationSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAdmissionFlowPlan {
    pub needed_hashes: Vec<String>,
    pub incoming_changes: Vec<ChangeAdmissionChange>,
    pub verified_authorizations: Vec<Value>,
    pub admitted_changes: Vec<AuthorizedWorkspaceChange>,
    pub editor_changes: Vec<ChangeAdmissionChange>,
    pub unsigned_changes: Vec<ChangeAdmissionChange>,
    pub unsigned_error: Option<String>,
}

/// Resolve incoming change coverage and authorization in one core policy pass.
/// Browser hosts may decode Automerge changes, but must not decide which
/// authorization records matter, which role wins for duplicate proofs, or
/// which incoming changes remain unsigned.
pub fn plan_change_admission_flow(
    input: ChangeAdmissionFlowInput,
    now_ms: i128,
) -> Result<ChangeAdmissionFlowPlan, String> {
    if input.changes.len() > 1_000_000
        || input.known_hashes.len() > 1_000_000
        || input.records.len() > 20_000
    {
        return Err("Workspace change admission exceeds size limit".into());
    }

    let mut needed_hashes = Vec::with_capacity(input.changes.len());
    let mut needed = HashSet::with_capacity(input.changes.len());
    for change in &input.changes {
        if change.hash.is_empty() || !needed.insert(change.hash.as_str()) {
            return Err("Invalid workspace change history".into());
        }
        needed_hashes.push(change.hash.clone());
    }
    let known = input
        .known_hashes
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();

    // Match historically ignored unrelated records, then required every
    // relevant one to pass Rust signature and authority verification.
    let verified_authorizations = input
        .records
        .into_iter()
        .filter(|record| record_covers_any(record, &needed))
        .collect::<Vec<_>>();
    let typed_authorizations = verified_authorizations
        .iter()
        .cloned()
        .map(serde_json::from_value::<IncomingWorkspaceChangeAuthorization>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid workspace change authorization".to_string())?;
    let admitted_changes = admit_workspace_change_authorizations(
        &typed_authorizations,
        &input.snapshot,
        &needed_hashes,
        now_ms,
    )?;
    let (incoming_changes, editor_changes, unsigned_changes, unsigned_error) =
        classify_changes(&input.changes, &known, &admitted_changes)?;

    Ok(ChangeAdmissionFlowPlan {
        needed_hashes,
        incoming_changes,
        verified_authorizations,
        admitted_changes,
        editor_changes,
        unsigned_changes,
        unsigned_error,
    })
}

fn classify_changes(
    changes: &[ChangeAdmissionChange],
    known: &HashSet<&str>,
    admitted: &[AuthorizedWorkspaceChange],
) -> Result<
    (
        Vec<ChangeAdmissionChange>,
        Vec<ChangeAdmissionChange>,
        Vec<ChangeAdmissionChange>,
        Option<String>,
    ),
    String,
> {
    // When duplicate records prove the same hash, owner proof takes
    // precedence. This matches Match's recordAllowedHashes rule.
    let mut roles = BTreeMap::<String, WorkspaceRole>::new();
    for entry in admitted {
        if roles.get(&entry.hash) != Some(&WorkspaceRole::Owner) {
            roles.insert(entry.hash.clone(), entry.role);
        }
    }
    let incoming = changes
        .iter()
        .filter(|change| !known.contains(change.hash.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let editor_changes = incoming
        .iter()
        .filter(|change| roles.get(&change.hash) == Some(&WorkspaceRole::Editor))
        .cloned()
        .collect::<Vec<_>>();
    if editor_changes
        .iter()
        .any(|change| change.dependencies.is_empty())
    {
        return Err("Only the owner can create a workspace".into());
    }
    let unsigned = incoming
        .iter()
        .filter(|change| !roles.contains_key(&change.hash))
        .cloned()
        .collect::<Vec<_>>();
    let unsigned_error = unsigned.first().map(unsigned_change_error);
    Ok((incoming, editor_changes, unsigned, unsigned_error))
}

fn record_covers_any(record: &Value, needed: &HashSet<&str>) -> bool {
    record
        .pointer("/signed/payload/hashes")
        .and_then(Value::as_array)
        .is_some_and(|hashes| {
            hashes
                .iter()
                .filter_map(Value::as_str)
                .any(|hash| needed.contains(hash))
        })
}

pub fn unsigned_change_error(change: &ChangeAdmissionChange) -> String {
    format!(
        "Unsigned workspace change rejected: {} (actor {}, {})",
        change.hash,
        change.actor,
        if change.message.is_empty() {
            "no change message"
        } else {
            &change.message
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_error_preserves_match_diagnostic_shape() {
        assert_eq!(
            unsigned_change_error(&ChangeAdmissionChange {
                hash: "hash-1".into(),
                dependencies: vec!["parent".into()],
                actor: "actor-1".into(),
                message: String::new(),
            }),
            "Unsigned workspace change rejected: hash-1 (actor actor-1, no change message)"
        );
    }

    #[test]
    fn unrelated_or_malformed_record_is_not_selected_for_verification() {
        let needed = ["needed"].into_iter().collect::<HashSet<_>>();
        assert!(!record_covers_any(
            &serde_json::json!({ "broken": true }),
            &needed
        ));
        assert!(!record_covers_any(
            &serde_json::json!({ "signed": { "payload": { "hashes": ["unrelated"] } } }),
            &needed
        ));
        assert!(record_covers_any(
            &serde_json::json!({ "signed": { "payload": { "hashes": ["needed"] } } }),
            &needed
        ));
    }

    #[test]
    fn owner_proof_wins_duplicate_hash_and_unsigned_changes_are_reported() {
        let changes = vec![
            ChangeAdmissionChange {
                hash: "owned".into(),
                dependencies: vec!["parent".into()],
                actor: "actor".into(),
                message: "owner edit".into(),
            },
            ChangeAdmissionChange {
                hash: "unsigned".into(),
                dependencies: vec!["parent".into()],
                actor: "actor".into(),
                message: String::new(),
            },
        ];
        let admitted = vec![
            AuthorizedWorkspaceChange {
                hash: "owned".into(),
                role: WorkspaceRole::Owner,
            },
            AuthorizedWorkspaceChange {
                hash: "owned".into(),
                role: WorkspaceRole::Editor,
            },
        ];
        let (incoming, editor, unsigned, error) =
            classify_changes(&changes, &HashSet::new(), &admitted).unwrap();
        assert_eq!(incoming.len(), 2);
        assert!(editor.is_empty());
        assert_eq!(
            unsigned
                .iter()
                .map(|change| change.hash.as_str())
                .collect::<Vec<_>>(),
            ["unsigned"]
        );
        assert_eq!(
            error.as_deref(),
            Some("Unsigned workspace change rejected: unsigned (actor actor, no change message)")
        );
    }

    #[test]
    fn editor_cannot_create_initial_workspace_change() {
        let root = ChangeAdmissionChange {
            hash: "root".into(),
            dependencies: vec![],
            actor: "actor".into(),
            message: String::new(),
        };
        let admitted = [AuthorizedWorkspaceChange {
            hash: "root".into(),
            role: WorkspaceRole::Editor,
        }];
        assert_eq!(
            classify_changes(&[root], &HashSet::new(), &admitted).unwrap_err(),
            "Only the owner can create a workspace"
        );
    }
}
