use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use futures_lite::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, presets},
};
use iroh_blobs::{
    ALPN as BLOBS_ALPN, BlobsProtocol,
    api::Store,
    store::{fs::FsStore, mem::MemStore},
    ticket::BlobTicket,
};
use iroh_gossip::{
    TopicId,
    api::{Event, GossipReceiver, GossipSender},
    net::{GOSSIP_ALPN, Gossip},
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub struct NativeNodeOptions {
    pub secret: Option<[u8; 32]>,
    pub allowed_peers: Vec<EndpointId>,
    pub allow_any: bool,
    pub storage_path: Option<PathBuf>,
    pub bind_addr: SocketAddr,
    pub relay_mode: RelayMode,
}

impl Default for NativeNodeOptions {
    fn default() -> Self {
        Self {
            secret: None,
            allowed_peers: Vec::new(),
            allow_any: false,
            storage_path: None,
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            relay_mode: RelayMode::Default,
        }
    }
}

#[derive(Debug)]
struct AccessHook {
    allowed_remotes: Arc<RwLock<HashSet<EndpointId>>>,
    allow_any: bool,
}

impl EndpointHooks for AccessHook {
    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        if connection.side().is_client() || self.allow_any {
            return AfterHandshakeOutcome::Accept;
        }
        if self
            .allowed_remotes
            .read()
            .expect("native peer allowlist poisoned")
            .contains(&connection.remote_id())
        {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"unauthorized".to_vec(),
            }
        }
    }
}

pub struct NativeNode {
    endpoint: Endpoint,
    router: iroh::protocol::Router,
    gossip: Gossip,
    store: Store,
    allowed_peers: Arc<RwLock<HashSet<EndpointId>>>,
    allow_any: bool,
}

pub struct GossipTopicSender {
    inner: GossipSender,
}

impl GossipTopicSender {
    pub async fn broadcast(&self, message: impl Into<bytes::Bytes>) -> Result<(), BoxError> {
        self.inner
            .broadcast(message.into())
            .await
            .map_err(|error| Box::new(error) as _)
    }

    pub async fn broadcast_neighbors(
        &self,
        message: impl Into<bytes::Bytes>,
    ) -> Result<(), BoxError> {
        self.inner
            .broadcast_neighbors(message.into())
            .await
            .map_err(|error| Box::new(error) as _)
    }
}

pub struct GossipTopicReceiver {
    inner: GossipReceiver,
}

#[derive(Debug, Clone)]
pub struct GossipReceivedMessage {
    pub content: bytes::Bytes,
    pub delivered_from: EndpointId,
}

impl GossipTopicReceiver {
    pub async fn recv(&mut self) -> Result<Option<GossipReceivedMessage>, BoxError> {
        while let Some(result) = self.inner.next().await {
            match result {
                Ok(Event::Received(message)) => {
                    return Ok(Some(GossipReceivedMessage {
                        content: message.content,
                        delivered_from: message.delivered_from,
                    }));
                }
                Ok(_) => {}
                Err(error) => return Err(Box::new(error)),
            }
        }
        Ok(None)
    }

    pub async fn next_event(&mut self) -> Option<Result<Event, iroh_gossip::api::ApiError>> {
        self.inner.next().await
    }
}

impl NativeNode {
    pub async fn start(
        secret: Option<[u8; 32]>,
        allowed_peers: Vec<EndpointId>,
    ) -> Result<Self, BoxError> {
        Self::start_with_options(NativeNodeOptions {
            secret,
            allowed_peers,
            allow_any: false,
            storage_path: None,
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            relay_mode: RelayMode::Disabled,
        })
        .await
    }

    pub async fn start_with_options(options: NativeNodeOptions) -> Result<Self, BoxError> {
        let secret_key = options
            .secret
            .map(|bytes| SecretKey::from_bytes(&bytes))
            .unwrap_or_else(SecretKey::generate);
        let allowed_peers = Arc::new(RwLock::new(options.allowed_peers.into_iter().collect()));
        let endpoint = Endpoint::builder(presets::Minimal)
            .relay_mode(options.relay_mode)
            .bind_addr(options.bind_addr)?
            .secret_key(secret_key)
            .hooks(AccessHook {
                allowed_remotes: allowed_peers.clone(),
                allow_any: options.allow_any,
            })
            .bind()
            .await?;

        let gossip = Gossip::builder().spawn(endpoint.clone());
        let store: Store = match options.storage_path {
            Some(path) => FsStore::load(path).await?.into(),
            None => MemStore::new().into(),
        };
        let blobs = BlobsProtocol::new(&store, None);
        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .accept(BLOBS_ALPN, blobs)
            .spawn();

        Ok(Self {
            endpoint,
            router,
            gossip,
            store,
            allowed_peers,
            allow_any: options.allow_any,
        })
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    pub fn authorize_peer(&self, peer: EndpointId) {
        self.allowed_peers
            .write()
            .expect("native peer allowlist poisoned")
            .insert(peer);
    }

    pub fn revoke_peer(&self, peer: &EndpointId) {
        self.allowed_peers
            .write()
            .expect("native peer allowlist poisoned")
            .remove(peer);
    }

    pub fn is_peer_authorized(&self, peer: &EndpointId) -> bool {
        self.allow_any
            || self
                .allowed_peers
                .read()
                .expect("native peer allowlist poisoned")
                .contains(peer)
    }

    pub async fn join_gossip(
        &self,
        topic_name: &str,
        bootstrap_peers: Vec<EndpointAddr>,
    ) -> Result<(GossipTopicSender, GossipTopicReceiver), BoxError> {
        let digest = blake3::hash(topic_name.as_bytes());
        let topic_id = TopicId::from_bytes(*digest.as_bytes());
        let mut bootstrap_ids = Vec::with_capacity(bootstrap_peers.len());

        for peer_addr in bootstrap_peers {
            bootstrap_ids.push(peer_addr.id);
            let connection = self.endpoint.connect(peer_addr, GOSSIP_ALPN).await?;
            let gossip = self.gossip.clone();
            tokio::spawn(async move {
                let _ = gossip.handle_connection(connection).await;
            });
        }

        let topic = if bootstrap_ids.is_empty() {
            self.gossip.subscribe(topic_id, vec![]).await?
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            self.gossip
                .subscribe_and_join(topic_id, bootstrap_ids)
                .await?
        };
        let (sender, receiver) = topic.split();
        Ok((
            GossipTopicSender { inner: sender },
            GossipTopicReceiver { inner: receiver },
        ))
    }

    pub async fn add_blob(&self, data: &[u8]) -> Result<BlobTicket, BoxError> {
        let tag = self.store.add_bytes(data.to_vec()).await?;
        Ok(BlobTicket::new(self.addr(), tag.hash, tag.format))
    }

    pub async fn get_blob(&self, hash: iroh_blobs::Hash) -> Result<Option<Vec<u8>>, BoxError> {
        match self.store.get_bytes(hash).await {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(error) => {
                let message = error.to_string();
                if message.contains("not found") || message.contains("NotFound") {
                    Ok(None)
                } else {
                    Err(Box::new(error))
                }
            }
        }
    }

    pub async fn fetch_blob(&self, ticket: &BlobTicket) -> Result<Vec<u8>, BoxError> {
        let connection = self
            .endpoint
            .connect(ticket.addr().clone(), BLOBS_ALPN)
            .await?;
        self.store
            .remote()
            .fetch(connection, ticket.hash_and_format())
            .await?;
        let bytes = self.store.get_bytes(ticket.hash()).await?;
        Ok(bytes.to_vec())
    }

    pub async fn close(self) -> Result<(), BoxError> {
        self.router.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn current_iroh_node_has_stable_identity_and_mutable_allowlist() {
        let secret = [42u8; 32];
        let peer = NativeNode::start(Some([7u8; 32]), vec![]).await.unwrap();
        let peer_id = peer.endpoint_id();
        let node = NativeNode::start(Some(secret), vec![]).await.unwrap();
        let endpoint_id = node.endpoint_id();
        assert!(!node.is_peer_authorized(&peer_id));
        node.authorize_peer(peer_id);
        assert!(node.is_peer_authorized(&peer_id));
        node.revoke_peer(&peer_id);
        assert!(!node.is_peer_authorized(&peer_id));
        node.close().await.unwrap();
        peer.close().await.unwrap();

        let restarted = NativeNode::start(Some(secret), vec![]).await.unwrap();
        assert_eq!(restarted.endpoint_id(), endpoint_id);
        restarted.close().await.unwrap();
    }
}
