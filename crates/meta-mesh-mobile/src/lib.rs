use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::{EndpointAddr, EndpointId};
use iroh_blobs::{Hash, ticket::BlobTicket};
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, IdentityPassphraseEnvelope, IdentityRecoveryEnvelope,
    IdentitySecurity, SignedEnvelope, derive_device_seed, identity_security_for_recovery,
    legacy_recovery_from_samples, open_identity_seed, open_identity_seed_with_passphrase,
    parse_invitation, public_key_from_seed, public_key_id, recovery_phrase_from_entropy,
    recovery_phrase_to_entropy, seal_identity_seed, seal_identity_seed_with_passphrase,
    sign_json_envelope, verify_signed_envelope,
};
use meta_mesh_native::{GossipTopicReceiver, GossipTopicSender, NativeNode, NativeNodeOptions};
use serde_json::Value;
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileMeshError {
    #[error("{message}")]
    Failure { message: String },
}

impl MobileMeshError {
    fn from_display(error: impl std::fmt::Display) -> Self {
        Self::Failure {
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum MobileIdentitySecurity {
    Legacy,
    Better,
    Insane,
}

impl From<MobileIdentitySecurity> for IdentitySecurity {
    fn from(value: MobileIdentitySecurity) -> Self {
        match value {
            MobileIdentitySecurity::Legacy => IdentitySecurity::Legacy,
            MobileIdentitySecurity::Better => IdentitySecurity::Better,
            MobileIdentitySecurity::Insane => IdentitySecurity::Insane,
        }
    }
}

impl From<IdentitySecurity> for MobileIdentitySecurity {
    fn from(value: IdentitySecurity) -> Self {
        match value {
            IdentitySecurity::Legacy => MobileIdentitySecurity::Legacy,
            IdentitySecurity::Better => MobileIdentitySecurity::Better,
            IdentitySecurity::Insane => MobileIdentitySecurity::Insane,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileGossipMessage {
    pub content: Vec<u8>,
    pub delivered_from: String,
}

#[uniffi::export]
pub fn mesh_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[uniffi::export]
pub fn mesh_public_key_from_seed(seed: Vec<u8>) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Identity root must contain 32 bytes")?;
    public_key_from_seed(&seed).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_public_key_id(public_key: String) -> Result<String, MobileMeshError> {
    public_key_id(&public_key).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_derive_device_seed(entropy: Vec<u8>) -> Result<Vec<u8>, MobileMeshError> {
    let entropy = exact_bytes::<32>(&entropy, "Device entropy must contain 32 bytes")?;
    derive_device_seed(&entropy)
        .map(|seed| seed.to_vec())
        .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_recovery_phrase_from_entropy(entropy: Vec<u8>) -> Result<String, MobileMeshError> {
    recovery_phrase_from_entropy(&entropy).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_recovery_phrase_to_entropy(phrase: String) -> Result<Vec<u8>, MobileMeshError> {
    recovery_phrase_to_entropy(&phrase).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_legacy_recovery_from_samples(samples: Vec<u16>) -> Result<String, MobileMeshError> {
    legacy_recovery_from_samples(&samples).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_identity_security_for_recovery(recovery_key: String) -> Option<MobileIdentitySecurity> {
    identity_security_for_recovery(&recovery_key).map(Into::into)
}

#[uniffi::export]
pub fn mesh_sign_envelope_json(
    seed: Vec<u8>,
    payload_json: String,
    signer_key_id: String,
    domain: Option<String>,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Private key seed must contain 32 bytes")?;
    let payload: Value =
        serde_json::from_str(&payload_json).map_err(MobileMeshError::from_display)?;
    let envelope = sign_json_envelope(
        &seed,
        payload,
        signer_key_id,
        domain.as_deref().unwrap_or(DEFAULT_SIGNATURE_DOMAIN),
    )
    .map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&envelope).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_verify_envelope_json(
    envelope_json: String,
    public_key: String,
    domain: Option<String>,
) -> Result<bool, MobileMeshError> {
    let envelope: SignedEnvelope<Value> =
        serde_json::from_str(&envelope_json).map_err(MobileMeshError::from_display)?;
    verify_signed_envelope(
        &envelope,
        &public_key,
        domain.as_deref().unwrap_or(DEFAULT_SIGNATURE_DOMAIN),
    )
    .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_seal_identity_seed(
    seed: Vec<u8>,
    person_id: String,
    recovery_key: String,
    security: MobileIdentitySecurity,
    salt: Vec<u8>,
    iv: Vec<u8>,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Identity root must contain 32 bytes")?;
    let salt = exact_bytes::<16>(&salt, "Recovery salt must contain 16 bytes")?;
    let iv = exact_bytes::<12>(&iv, "Recovery IV must contain 12 bytes")?;
    let envelope = seal_identity_seed(
        &seed,
        &person_id,
        &recovery_key,
        security.into(),
        &salt,
        &iv,
    )
    .map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&envelope).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_open_identity_seed(
    envelope_json: String,
    recovery_key: String,
) -> Result<Vec<u8>, MobileMeshError> {
    let envelope: IdentityRecoveryEnvelope =
        serde_json::from_str(&envelope_json).map_err(MobileMeshError::from_display)?;
    open_identity_seed(&envelope, &recovery_key)
        .map(|seed| seed.to_vec())
        .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_seal_identity_seed_with_passphrase(
    seed: Vec<u8>,
    person_id: String,
    passphrase: String,
    salt: Vec<u8>,
    iv: Vec<u8>,
) -> Result<String, MobileMeshError> {
    let seed = exact_bytes::<32>(&seed, "Identity root must contain 32 bytes")?;
    let salt = exact_bytes::<16>(&salt, "Passphrase salt must contain 16 bytes")?;
    let iv = exact_bytes::<12>(&iv, "Passphrase IV must contain 12 bytes")?;
    let envelope = seal_identity_seed_with_passphrase(&seed, &person_id, &passphrase, &salt, &iv)
        .map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&envelope).map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_open_identity_seed_with_passphrase(
    envelope_json: String,
    passphrase: String,
) -> Result<Vec<u8>, MobileMeshError> {
    let envelope: IdentityPassphraseEnvelope =
        serde_json::from_str(&envelope_json).map_err(MobileMeshError::from_display)?;
    open_identity_seed_with_passphrase(&envelope, &passphrase)
        .map(|seed| seed.to_vec())
        .map_err(MobileMeshError::from_display)
}

#[uniffi::export]
pub fn mesh_parse_invitation_json(
    invitation_url: String,
    now_ms: i64,
) -> Result<String, MobileMeshError> {
    let invitation =
        parse_invitation(&invitation_url, now_ms).map_err(MobileMeshError::from_display)?;
    serde_json::to_string(&invitation).map_err(MobileMeshError::from_display)
}

#[derive(uniffi::Object)]
pub struct MobileMeshNode {
    runtime: Arc<Runtime>,
    node: Mutex<Option<NativeNode>>,
}

#[uniffi::export]
impl MobileMeshNode {
    #[uniffi::constructor]
    pub fn start(
        secret: Option<Vec<u8>>,
        allowed_peer_ids: Vec<String>,
        storage_path: Option<String>,
    ) -> Result<Arc<Self>, MobileMeshError> {
        let secret = secret
            .map(|value| exact_bytes::<32>(&value, "Node secret must contain 32 bytes"))
            .transpose()?;
        let allowed_peers = allowed_peer_ids
            .iter()
            .map(|value| EndpointId::from_str(value).map_err(MobileMeshError::from_display))
            .collect::<Result<Vec<_>, _>>()?;
        let runtime = Arc::new(Runtime::new().map_err(MobileMeshError::from_display)?);
        let node = runtime
            .block_on(NativeNode::start_with_options(NativeNodeOptions {
                secret,
                allowed_peers,
                storage_path: storage_path.map(PathBuf::from),
                ..NativeNodeOptions::default()
            }))
            .map_err(MobileMeshError::from_display)?;
        Ok(Arc::new(Self {
            runtime,
            node: Mutex::new(Some(node)),
        }))
    }

    pub fn endpoint_id(&self) -> Result<String, MobileMeshError> {
        self.with_node(|node| Ok(node.endpoint_id().to_string()))
    }

    pub fn endpoint_addr_json(&self) -> Result<String, MobileMeshError> {
        self.with_node(|node| {
            serde_json::to_string(&node.addr()).map_err(MobileMeshError::from_display)
        })
    }

    pub fn authorize_peer(&self, peer_id: String) -> Result<(), MobileMeshError> {
        let peer = EndpointId::from_str(&peer_id).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            node.authorize_peer(peer);
            Ok(())
        })
    }

    pub fn revoke_peer(&self, peer_id: String) -> Result<(), MobileMeshError> {
        let peer = EndpointId::from_str(&peer_id).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            node.revoke_peer(&peer);
            Ok(())
        })
    }

    pub fn add_blob(&self, data: Vec<u8>) -> Result<String, MobileMeshError> {
        self.with_node(|node| {
            self.runtime
                .block_on(node.add_blob(&data))
                .map(|ticket| ticket.to_string())
                .map_err(MobileMeshError::from_display)
        })
    }

    pub fn get_blob(&self, hash: String) -> Result<Option<Vec<u8>>, MobileMeshError> {
        let hash = Hash::from_str(&hash).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            self.runtime
                .block_on(node.get_blob(hash))
                .map_err(MobileMeshError::from_display)
        })
    }

    pub fn fetch_blob(&self, ticket: String) -> Result<Vec<u8>, MobileMeshError> {
        let ticket = BlobTicket::from_str(&ticket).map_err(MobileMeshError::from_display)?;
        self.with_node(|node| {
            self.runtime
                .block_on(node.fetch_blob(&ticket))
                .map_err(MobileMeshError::from_display)
        })
    }

    pub fn join_gossip(
        &self,
        topic: String,
        bootstrap_peer_addrs_json: Vec<String>,
    ) -> Result<Arc<MobileGossipTopic>, MobileMeshError> {
        let peers = bootstrap_peer_addrs_json
            .iter()
            .map(|value| {
                serde_json::from_str::<EndpointAddr>(value).map_err(MobileMeshError::from_display)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.with_node(|node| {
            let (sender, receiver) = self
                .runtime
                .block_on(node.join_gossip(&topic, peers))
                .map_err(MobileMeshError::from_display)?;
            Ok(Arc::new(MobileGossipTopic {
                runtime: self.runtime.clone(),
                sender,
                receiver: Mutex::new(receiver),
            }))
        })
    }

    pub fn close(&self) -> Result<(), MobileMeshError> {
        let node = self
            .node
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile node lock poisoned"))?
            .take();
        if let Some(node) = node {
            self.runtime
                .block_on(node.close())
                .map_err(MobileMeshError::from_display)?;
        }
        Ok(())
    }
}

impl MobileMeshNode {
    fn with_node<T>(
        &self,
        action: impl FnOnce(&NativeNode) -> Result<T, MobileMeshError>,
    ) -> Result<T, MobileMeshError> {
        let guard = self
            .node
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile node lock poisoned"))?;
        let node = guard
            .as_ref()
            .ok_or_else(|| MobileMeshError::from_display("Mobile node is closed"))?;
        action(node)
    }
}

impl Drop for MobileMeshNode {
    fn drop(&mut self) {
        let Some(node) = self.node.get_mut().ok().and_then(Option::take) else {
            return;
        };
        let _ = self.runtime.block_on(node.close());
    }
}

#[derive(uniffi::Object)]
pub struct MobileGossipTopic {
    runtime: Arc<Runtime>,
    sender: GossipTopicSender,
    receiver: Mutex<GossipTopicReceiver>,
}

#[uniffi::export]
impl MobileGossipTopic {
    pub fn broadcast(&self, content: Vec<u8>) -> Result<(), MobileMeshError> {
        self.runtime
            .block_on(self.sender.broadcast(content))
            .map_err(MobileMeshError::from_display)
    }

    pub fn receive(&self, timeout_ms: u64) -> Result<Option<MobileGossipMessage>, MobileMeshError> {
        let mut receiver = self
            .receiver
            .lock()
            .map_err(|_| MobileMeshError::from_display("Mobile gossip lock poisoned"))?;
        let received = self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(timeout_ms), receiver.recv()).await
        });
        match received {
            Ok(Ok(Some(message))) => Ok(Some(MobileGossipMessage {
                content: message.content.to_vec(),
                delivered_from: message.delivered_from.to_string(),
            })),
            Ok(Ok(None)) => Ok(None),
            Ok(Err(error)) => Err(MobileMeshError::from_display(error)),
            Err(_) => Ok(None),
        }
    }
}

fn exact_bytes<const N: usize>(value: &[u8], error: &str) -> Result<[u8; N], MobileMeshError> {
    value
        .try_into()
        .map_err(|_| MobileMeshError::from_display(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_identity_api_matches_core() {
        let seed = vec![7; 32];
        let public_key = mesh_public_key_from_seed(seed.clone()).unwrap();
        let person_id = mesh_public_key_id(public_key).unwrap();
        let envelope = mesh_sign_envelope_json(
            seed,
            r#"{"kind":"mobile-test","version":1}"#.to_string(),
            person_id,
            None,
        )
        .unwrap();
        assert!(
            mesh_verify_envelope_json(
                envelope,
                mesh_public_key_from_seed(vec![7; 32]).unwrap(),
                None
            )
            .unwrap()
        );
    }

    #[test]
    fn mobile_native_nodes_exchange_blob_and_gossip() {
        let node_1 = MobileMeshNode::start(Some(vec![1; 32]), vec![], None).unwrap();
        let node_2 =
            MobileMeshNode::start(Some(vec![2; 32]), vec![node_1.endpoint_id().unwrap()], None)
                .unwrap();
        node_1
            .authorize_peer(node_2.endpoint_id().unwrap())
            .unwrap();

        let ticket = node_1.add_blob(b"mobile-blob".to_vec()).unwrap();
        assert_eq!(node_2.fetch_blob(ticket).unwrap(), b"mobile-blob");

        let topic_1 = node_1
            .join_gossip("mobile-topic".to_string(), vec![])
            .unwrap();
        let topic_2 = node_2
            .join_gossip(
                "mobile-topic".to_string(),
                vec![node_1.endpoint_addr_json().unwrap()],
            )
            .unwrap();
        topic_1.broadcast(b"hello-mobile".to_vec()).unwrap();
        let message = topic_2.receive(5_000).unwrap().unwrap();
        assert_eq!(message.content, b"hello-mobile");

        node_1.close().unwrap();
        node_2.close().unwrap();
    }
}
