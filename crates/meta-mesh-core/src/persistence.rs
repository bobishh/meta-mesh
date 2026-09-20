use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingDocumentChange {
    pub hash: String,
    pub bytes: Vec<u8>,
    pub proof: Value,
    pub verified: bool,
    #[serde(default)]
    pub existing_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredDocumentChange {
    pub version: u8,
    pub document_id: String,
    pub hash: String,
    pub bytes: Vec<u8>,
    pub proof: Value,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAdmissionPlan {
    pub accepted_hashes: Vec<String>,
    pub duplicate_hashes: Vec<String>,
    pub accepted: Vec<StoredDocumentChange>,
}

pub fn plan_change_admission(
    document_id: &str,
    changes: Vec<IncomingDocumentChange>,
    verified_at: &str,
) -> Result<ChangeAdmissionPlan, String> {
    if document_id.is_empty() || changes.is_empty() || verified_at.is_empty() {
        return Err("Invalid document change batch".to_string());
    }
    let mut seen = std::collections::HashSet::with_capacity(changes.len());
    let mut plan = ChangeAdmissionPlan {
        accepted_hashes: Vec::new(),
        duplicate_hashes: Vec::new(),
        accepted: Vec::new(),
    };
    for change in changes {
        if change.hash.is_empty() || !change.verified || !seen.insert(change.hash.clone()) {
            return Err("Document change verification failed".to_string());
        }
        if let Some(existing) = change.existing_bytes {
            if existing != change.bytes {
                return Err("Change hash collision".to_string());
            }
            plan.duplicate_hashes.push(change.hash);
            continue;
        }
        plan.accepted_hashes.push(change.hash.clone());
        plan.accepted.push(StoredDocumentChange {
            version: 1,
            document_id: document_id.to_string(),
            hash: change.hash,
            bytes: change.bytes,
            proof: change.proof,
            verified_at: verified_at.to_string(),
        });
    }
    Ok(plan)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxClaim {
    pub version: u8,
    pub document_id: String,
    pub target_device_id: String,
    pub batch_id: String,
    pub owner_instance_id: String,
    pub claimed_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxClaimInput {
    pub document_id: String,
    pub target_device_id: String,
    pub batch_id: String,
    pub owner_instance_id: String,
    pub now: i64,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxClaimTransition {
    pub claim: OutboxClaim,
    pub acquired: bool,
}

pub fn transition_outbox_claim(
    current: Option<OutboxClaim>,
    input: OutboxClaimInput,
) -> Result<OutboxClaimTransition, String> {
    if input.document_id.is_empty()
        || input.target_device_id.is_empty()
        || input.batch_id.is_empty()
        || input.owner_instance_id.is_empty()
        || input.ttl_ms <= 0
    {
        return Err("Invalid outbox claim lifetime".to_string());
    }
    if let Some(current) = current {
        if current.expires_at > input.now && current.owner_instance_id != input.owner_instance_id {
            return Ok(OutboxClaimTransition {
                claim: current,
                acquired: false,
            });
        }
    }
    let expires_at = input
        .now
        .checked_add(input.ttl_ms)
        .ok_or_else(|| "Invalid outbox claim lifetime".to_string())?;
    Ok(OutboxClaimTransition {
        claim: OutboxClaim {
            version: 1,
            document_id: input.document_id,
            target_device_id: input.target_device_id,
            batch_id: input.batch_id,
            owner_instance_id: input.owner_instance_id,
            claimed_at: input.now,
            expires_at,
        },
        acquired: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_is_idempotent_and_rejects_collisions() {
        let duplicate = IncomingDocumentChange {
            hash: "same".into(),
            bytes: vec![1],
            proof: Value::Null,
            verified: true,
            existing_bytes: Some(vec![1]),
        };
        let plan = plan_change_admission("doc", vec![duplicate.clone()], "now").unwrap();
        assert_eq!(plan.duplicate_hashes, vec!["same"]);
        let mut collision = duplicate;
        collision.bytes = vec![2];
        assert_eq!(
            plan_change_admission("doc", vec![collision], "now").unwrap_err(),
            "Change hash collision"
        );
    }

    #[test]
    fn outbox_claim_only_moves_after_expiry() {
        let input = OutboxClaimInput {
            document_id: "doc".into(),
            target_device_id: "device".into(),
            batch_id: "batch".into(),
            owner_instance_id: "tab-b".into(),
            now: 50,
            ttl_ms: 100,
        };
        let current = OutboxClaim {
            version: 1,
            document_id: "doc".into(),
            target_device_id: "device".into(),
            batch_id: "batch".into(),
            owner_instance_id: "tab-a".into(),
            claimed_at: 0,
            expires_at: 100,
        };
        assert!(
            !transition_outbox_claim(Some(current.clone()), input.clone())
                .unwrap()
                .acquired
        );
        let mut expired = input;
        expired.now = 101;
        assert!(
            transition_outbox_claim(Some(current), expired)
                .unwrap()
                .acquired
        );
    }
}
