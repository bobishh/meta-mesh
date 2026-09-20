use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, presets},
};

#[derive(Debug, Clone)]
pub struct NativeNodeOptions {
    pub secret: Option<[u8; 32]>,
    pub allowed_peers: Vec<EndpointId>,
    pub allow_any: bool,
    pub bind_addr: SocketAddr,
    pub relay_mode: RelayMode,
}

impl Default for NativeNodeOptions {
    fn default() -> Self {
        Self {
            secret: None,
            allowed_peers: Vec::new(),
            allow_any: false,
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
    allowed_peers: Arc<RwLock<HashSet<EndpointId>>>,
    allow_any: bool,
}

impl NativeNode {
    pub async fn start(
        secret: Option<[u8; 32]>,
        allowed_peers: Vec<EndpointId>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_options(NativeNodeOptions {
            secret,
            allowed_peers,
            allow_any: false,
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            relay_mode: RelayMode::Disabled,
        })
        .await
    }

    pub async fn start_with_options(
        options: NativeNodeOptions,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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
        Ok(Self {
            endpoint,
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

    pub async fn close(self) {
        self.endpoint.close().await;
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
        node.close().await;
        peer.close().await;

        let restarted = NativeNode::start(Some(secret), vec![]).await.unwrap();
        assert_eq!(restarted.endpoint_id(), endpoint_id);
        restarted.close().await;
    }
}
