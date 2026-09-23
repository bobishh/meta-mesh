//! Aggregate authority plans. Hosts only perform storage, signing and network callbacks.

use serde::Serialize;

use crate::{
    AuthorityAction, AuthorityCommandInput, TransferSelectionInput, TransferSelectionPlan,
    plan_authority_command, select_ownership_transfer,
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipAuthorityFlowInput {
    #[serde(flatten)]
    pub selection: TransferSelectionInput,
    pub confirmation_session_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipAuthorityFlowPlan {
    pub selection: TransferSelectionPlan,
    pub actions: Vec<AuthorityAction>,
}

/// Builds the complete ownership-operation decision from explicit peer facts.
/// It never selects a recipient from product document content or local cache.
pub fn plan_ownership_authority_flow(
    input: OwnershipAuthorityFlowInput,
) -> Result<OwnershipAuthorityFlowPlan, String> {
    let selection_input = input.selection.clone();
    let selection = select_ownership_transfer(selection_input)?;
    let pending_target_person_id = selection
        .pending_index
        .and_then(|index| input.selection.transfers.get(index))
        .map(|record| record.to_owner_person_id.clone());
    let actions = plan_authority_command(AuthorityCommandInput::Transfer {
        local_person_id: input.selection.local_person_id,
        owner_person_id: input.selection.owner_person_id,
        target_person_id: input.selection.target_person_id,
        active_peer_count: selection.peer_indices.len(),
        target_online: selection.target_online,
        confirmation_session_count: input.confirmation_session_count,
        has_advertisement: selection.advertisement_index.is_some(),
        pending_target_person_id,
    })?;
    Ok(OwnershipAuthorityFlowPlan { selection, actions })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TransferPeerInput, TransferRecordInput};

    #[test]
    fn ownership_flow_selects_only_verified_target_facts_then_requires_receipt() {
        let plan = plan_ownership_authority_flow(OwnershipAuthorityFlowInput {
            selection: TransferSelectionInput {
                local_person_id: "owner".into(),
                owner_person_id: Some("owner".into()),
                credential_epoch: Some(1),
                target_person_id: "editor".into(),
                peers: vec![TransferPeerInput {
                    person_id: "editor".into(),
                    revoked: false,
                    online: true,
                    has_advertisement: true,
                }],
                transfers: vec![],
            },
            confirmation_session_count: 1,
        })
        .unwrap();
        assert!(plan.actions.contains(&AuthorityAction::VerifyTarget));
        assert!(plan.actions.contains(&AuthorityAction::ConfirmDelivery));
        assert!(plan.actions.contains(&AuthorityAction::MergeTransfer));
    }

    #[test]
    fn ownership_flow_rejects_stale_or_revoked_recipient_before_callbacks() {
        let result = plan_ownership_authority_flow(OwnershipAuthorityFlowInput {
            selection: TransferSelectionInput {
                local_person_id: "owner".into(),
                owner_person_id: Some("owner".into()),
                credential_epoch: Some(1),
                target_person_id: "editor".into(),
                peers: vec![TransferPeerInput {
                    person_id: "editor".into(),
                    revoked: true,
                    online: true,
                    has_advertisement: true,
                }],
                transfers: vec![TransferRecordInput {
                    epoch: 2,
                    from_owner_person_id: "owner".into(),
                    to_owner_person_id: "editor".into(),
                }],
            },
            confirmation_session_count: 1,
        });
        assert!(result.is_err());
    }
}
