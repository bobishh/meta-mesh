use serde::{Deserialize, Serialize};

/// Authority command decisions and side-effect ordering shared by hosts.
/// Hosts read credentials, sign records, persist them, and publish frames.
#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AuthorityCommandInput {
    Revoke {
        local_person_id: String,
        owner_person_id: Option<String>,
    },
    Leave {
        workspace_id: String,
    },
    Promote {
        local_person_id: String,
        owner_person_id: Option<String>,
        target_person_id: String,
        has_active_membership: bool,
    },
    SetSuccessor {
        local_person_id: String,
        owner_person_id: Option<String>,
        successor_person_id: Option<String>,
        eligible_editor_person_ids: Vec<String>,
    },
    Vote {
        local_person_id: String,
        has_credential: bool,
        has_policy: bool,
        grant_role: Option<String>,
        eligible_editor_person_ids: Vec<String>,
        successor_person_id: Option<String>,
        candidate_person_id: String,
        existing_vote_for: Option<String>,
    },
    Claim {
        local_person_id: String,
        has_credential: bool,
        has_policy: bool,
        grant_role: Option<String>,
        grant_person_id: Option<String>,
    },
    Transfer {
        local_person_id: String,
        owner_person_id: Option<String>,
        target_person_id: String,
        active_peer_count: usize,
        target_online: bool,
        confirmation_session_count: usize,
        has_advertisement: bool,
        pending_target_person_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorityAction {
    CreateRevocation,
    MergeRevocation,
    RefreshSuccessionPolicy,
    Publish,
    ReloadCredential,
    DisconnectRevoked,
    Notify,
    Leave,
    CreatePolicy,
    SetPolicy,
    CreateVote,
    MergeVote,
    CreateClaim,
    MergeClaim,
    VerifyTarget,
    CreateTransfer,
    PersistProposal,
    ConfirmDelivery,
    MergeTransfer,
    CreateGrant,
    PersistGrant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CatalogMergeAction {
    Ownership,
    Revocations,
    RefreshCredential,
    Succession,
    Peers,
    Notify,
}

pub fn plan_catalog_merge() -> Vec<CatalogMergeAction> {
    use CatalogMergeAction as C;
    vec![
        C::Ownership,
        C::Revocations,
        C::RefreshCredential,
        C::Succession,
        C::RefreshCredential,
        C::Peers,
        C::Notify,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorityImportAction {
    ValidateCapabilities,
    DeviceRevocations,
    Departures,
    Revocations,
    OwnershipTransfers,
    Succession,
    RefreshCredential,
    Peers,
}

pub fn plan_authority_import(
    kind: &str,
    has_revocations: bool,
    has_transfers: bool,
) -> Result<Vec<AuthorityImportAction>, String> {
    use AuthorityImportAction as I;
    let mut actions = Vec::new();
    match kind {
        "invitation" => {}
        "handshake" => actions.push(I::ValidateCapabilities),
        _ => return Err("Invalid authority import".into()),
    }
    actions.extend([
        I::DeviceRevocations,
        I::RefreshCredential,
        I::Departures,
        I::RefreshCredential,
    ]);
    if kind == "invitation" && has_revocations {
        actions.extend([I::Revocations, I::RefreshCredential]);
    }
    if kind == "handshake" && has_transfers {
        actions.push(I::OwnershipTransfers);
    }
    actions.extend([I::Succession, I::RefreshCredential]);
    if kind == "invitation" {
        actions.push(I::Peers);
    }
    Ok(actions)
}

pub fn plan_authority_command(
    input: AuthorityCommandInput,
) -> Result<Vec<AuthorityAction>, String> {
    use AuthorityAction as A;
    match input {
        AuthorityCommandInput::Revoke {
            local_person_id,
            owner_person_id,
        } => {
            if owner_person_id.as_deref() != Some(&local_person_id) {
                return Err("Only the workspace owner can revoke access".into());
            }
            Ok(vec![
                A::CreateRevocation,
                A::MergeRevocation,
                A::RefreshSuccessionPolicy,
                A::Publish,
                A::ReloadCredential,
                A::DisconnectRevoked,
                A::Notify,
            ])
        }
        AuthorityCommandInput::Leave { workspace_id } => {
            if workspace_id.is_empty() {
                return Err("No active workspace".into());
            }
            Ok(vec![A::Leave, A::Notify])
        }
        AuthorityCommandInput::Promote {
            local_person_id,
            owner_person_id,
            target_person_id,
            has_active_membership,
        } => {
            if owner_person_id.as_deref() != Some(&local_person_id) {
                return Err("Only the workspace owner can change roles".into());
            }
            if target_person_id == local_person_id {
                return Err("The owner is already authorized".into());
            }
            if !has_active_membership {
                return Err("No active membership found for this person".into());
            }
            Ok(vec![
                A::CreateGrant,
                A::PersistGrant,
                A::RefreshSuccessionPolicy,
                A::Notify,
                A::Publish,
            ])
        }
        AuthorityCommandInput::SetSuccessor {
            local_person_id,
            owner_person_id,
            successor_person_id,
            eligible_editor_person_ids,
        } => {
            if owner_person_id.as_deref() != Some(&local_person_id) {
                return Err("Only the workspace owner can set succession".into());
            }
            if successor_person_id
                .as_ref()
                .is_some_and(|person_id| !eligible_editor_person_ids.contains(person_id))
            {
                return Err("Successor must be an editor".into());
            }
            Ok(vec![A::CreatePolicy, A::SetPolicy, A::Notify, A::Publish])
        }
        AuthorityCommandInput::Vote {
            local_person_id,
            has_credential,
            has_policy,
            grant_role,
            eligible_editor_person_ids,
            successor_person_id,
            candidate_person_id,
            existing_vote_for,
        } => {
            if !has_credential {
                return Err("Workspace membership is unavailable".into());
            }
            if !has_policy {
                return Err("The owner has not enabled ownership recovery".into());
            }
            if grant_role.as_deref() != Some("editor")
                || !eligible_editor_person_ids.contains(&local_person_id)
            {
                return Err("You are not an eligible editor in the current recovery policy".into());
            }
            if successor_person_id.is_some() {
                return Err("This workspace uses a named successor, not editor voting".into());
            }
            if let Some(existing) = existing_vote_for {
                if existing == candidate_person_id {
                    return Ok(vec![]);
                }
                return Err("Your vote is already recorded for this policy".into());
            }
            Ok(vec![A::CreateVote, A::MergeVote, A::Notify, A::Publish])
        }
        AuthorityCommandInput::Claim {
            local_person_id,
            has_credential,
            has_policy,
            grant_role,
            grant_person_id,
        } => {
            if !has_credential
                || !has_policy
                || grant_role.as_deref() != Some("editor")
                || grant_person_id.as_deref() != Some(&local_person_id)
            {
                return Err("Only an eligible editor can claim ownership".into());
            }
            Ok(vec![A::CreateClaim, A::MergeClaim, A::Notify, A::Publish])
        }
        AuthorityCommandInput::Transfer {
            local_person_id,
            owner_person_id,
            target_person_id,
            active_peer_count,
            target_online,
            confirmation_session_count,
            has_advertisement,
            pending_target_person_id,
        } => {
            if owner_person_id.as_deref() != Some(&local_person_id) {
                return Err("Only the workspace owner can transfer ownership".into());
            }
            if target_person_id == local_person_id {
                return Err("You already own this workspace".into());
            }
            if active_peer_count == 0 {
                return Err("Select an active mesh member".into());
            }
            if !target_online {
                return Err("Member must be online to receive ownership".into());
            }
            if confirmation_session_count == 0 {
                return Err("The recipient must reload Match before receiving ownership".into());
            }
            if !has_advertisement {
                return Err("Member identity is unavailable".into());
            }
            if pending_target_person_id
                .as_ref()
                .is_some_and(|person_id| person_id != &target_person_id)
            {
                return Err("An ownership transfer is pending for another member. Reconnect that member to finish it.".into());
            }
            let mut actions = vec![A::VerifyTarget];
            if pending_target_person_id.is_none() {
                actions.extend([A::CreateTransfer, A::PersistProposal]);
            }
            actions.extend([
                A::ConfirmDelivery,
                A::ReloadCredential,
                A::MergeTransfer,
                A::Notify,
                A::Publish,
            ]);
            Ok(actions)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_publishes_before_disconnecting() {
        let plan = plan_authority_command(AuthorityCommandInput::Revoke {
            local_person_id: "owner".into(),
            owner_person_id: Some("owner".into()),
        })
        .unwrap();
        assert!(
            plan.iter()
                .position(|step| *step == AuthorityAction::Publish)
                .unwrap()
                < plan
                    .iter()
                    .position(|step| *step == AuthorityAction::DisconnectRevoked)
                    .unwrap()
        );
    }

    #[test]
    fn recovery_vote_is_idempotent_but_cannot_change_candidate() {
        let make = |existing_vote_for| AuthorityCommandInput::Vote {
            local_person_id: "editor".into(),
            has_credential: true,
            has_policy: true,
            grant_role: Some("editor".into()),
            eligible_editor_person_ids: vec!["editor".into()],
            successor_person_id: None,
            candidate_person_id: "candidate".into(),
            existing_vote_for,
        };
        assert!(plan_authority_command(make(Some("candidate".into())))
            .unwrap()
            .is_empty());
        assert_eq!(
            plan_authority_command(make(Some("other".into()))).unwrap_err(),
            "Your vote is already recorded for this policy"
        );
    }

    #[test]
    fn pending_transfer_reuses_signed_proposal() {
        let plan = plan_authority_command(AuthorityCommandInput::Transfer {
            local_person_id: "owner".into(),
            owner_person_id: Some("owner".into()),
            target_person_id: "editor".into(),
            active_peer_count: 1,
            target_online: true,
            confirmation_session_count: 1,
            has_advertisement: true,
            pending_target_person_id: Some("editor".into()),
        })
        .unwrap();
        assert!(!plan.contains(&AuthorityAction::CreateTransfer));
        assert_eq!(plan[0], AuthorityAction::VerifyTarget);
        assert!(plan.contains(&AuthorityAction::ConfirmDelivery));
    }

    #[test]
    fn promotion_requires_owner_and_active_membership() {
        let input = AuthorityCommandInput::Promote {
            local_person_id: "owner".into(),
            owner_person_id: Some("owner".into()),
            target_person_id: "editor".into(),
            has_active_membership: true,
        };
        let plan = plan_authority_command(input).unwrap();
        assert_eq!(plan[0], AuthorityAction::CreateGrant);
        assert!(plan.contains(&AuthorityAction::PersistGrant));
        assert!(plan.contains(&AuthorityAction::RefreshSuccessionPolicy));
        assert!(plan_authority_command(AuthorityCommandInput::Promote {
            local_person_id: "editor".into(),
            owner_person_id: Some("owner".into()),
            target_person_id: "other".into(),
            has_active_membership: true,
        })
        .is_err());
    }
}
