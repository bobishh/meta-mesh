use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransferPeerInput {
    pub person_id: String,
    pub revoked: bool,
    pub online: bool,
    pub has_advertisement: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransferRecordInput {
    pub epoch: u64,
    pub from_owner_person_id: String,
    pub to_owner_person_id: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransferSelectionInput {
    pub local_person_id: String,
    pub owner_person_id: Option<String>,
    pub credential_epoch: Option<u64>,
    pub target_person_id: String,
    pub peers: Vec<TransferPeerInput>,
    pub transfers: Vec<TransferRecordInput>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSelectionPlan {
    pub peer_indices: Vec<usize>,
    pub advertisement_index: Option<usize>,
    pub pending_index: Option<usize>,
    pub target_online: bool,
}

pub fn select_ownership_transfer(
    input: TransferSelectionInput,
) -> Result<TransferSelectionPlan, String> {
    if input.owner_person_id.as_deref() != Some(&input.local_person_id) {
        return Err("Only the workspace owner can transfer ownership".into());
    }
    if input.target_person_id == input.local_person_id {
        return Err("You already own this workspace".into());
    }
    let peer_indices = input
        .peers
        .iter()
        .enumerate()
        .filter_map(|(index, peer)| {
            (peer.person_id == input.target_person_id && !peer.revoked).then_some(index)
        })
        .collect::<Vec<_>>();
    let target_online = peer_indices.iter().any(|index| input.peers[*index].online);
    let advertisement_index = peer_indices
        .iter()
        .copied()
        .find(|index| input.peers[*index].has_advertisement);
    let pending_index = input.credential_epoch.and_then(|epoch| {
        input.transfers.iter().position(|record| {
            record.epoch == epoch + 1 && record.from_owner_person_id == input.local_person_id
        })
    });
    Ok(TransferSelectionPlan {
        peer_indices,
        advertisement_index,
        pending_index,
        target_online,
    })
}
