use wasm_bindgen::prelude::*;

#[allow(dead_code)]
const ALPN: &[u8] = b"match/sync/0";

#[cfg(target_family = "wasm")]
use iroh::SecretKey;
#[cfg(target_family = "wasm")]
use iroh_webrtc_transport::browser::{
    BrowserDialOptions, BrowserWebRtcAcceptor, BrowserWebRtcConnection, BrowserWebRtcNode,
    BrowserWebRtcNodeConfig, BrowserWebRtcStream,
};

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub struct BrowserNode {
    inner: BrowserWebRtcNode,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl BrowserNode {
    #[wasm_bindgen(js_name = start)]
    pub async fn start(secret: Option<Vec<u8>>) -> Result<BrowserNode, JsValue> {
        let secret_key = match secret {
            Some(mut bytes) => {
                if bytes.len() != 32 {
                    return Err(JsError::new("secret key must be exactly 32 bytes").into());
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&bytes);
                bytes.fill(0);
                let key = SecretKey::from_bytes(&key_bytes);
                key_bytes.fill(0);
                key
            }
            None => SecretKey::generate(),
        };
        let inner = BrowserWebRtcNode::builder(BrowserWebRtcNodeConfig::default(), secret_key)
            .accept_facade(ALPN)
            .spawn()
            .await?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(getter, js_name = endpointId)]
    pub fn endpoint_id(&self) -> String {
        self.inner.endpoint_id().to_owned()
    }

    #[wasm_bindgen(js_name = dial)]
    pub async fn dial(&self, remote_endpoint: String) -> Result<BrowserConnection, JsValue> {
        let connection = self
            .inner
            .dial(
                &remote_endpoint,
                ALPN,
                BrowserDialOptions::webrtc_preferred(),
            )
            .await?;
        Ok(BrowserConnection { inner: connection })
    }

    #[wasm_bindgen(js_name = dialRelay)]
    pub async fn dial_relay(&self, remote_endpoint: String) -> Result<BrowserConnection, JsValue> {
        let connection = self
            .inner
            .dial(&remote_endpoint, ALPN, BrowserDialOptions::iroh_relay())
            .await?;
        Ok(BrowserConnection { inner: connection })
    }

    #[wasm_bindgen(js_name = accept)]
    pub async fn accept(&self) -> Result<BrowserAcceptor, JsValue> {
        Ok(BrowserAcceptor {
            inner: self.inner.accept(ALPN).await?,
        })
    }

    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self, reason: Option<String>) -> Result<(), JsValue> {
        self.inner
            .close(reason.as_deref().unwrap_or("Mesh node closed"))
            .await
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub struct BrowserAcceptor {
    inner: BrowserWebRtcAcceptor,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl BrowserAcceptor {
    #[wasm_bindgen(js_name = accept)]
    pub async fn accept(&self) -> Result<Option<BrowserConnection>, JsValue> {
        Ok(self
            .inner
            .accept()
            .await?
            .map(|inner| BrowserConnection { inner }))
    }

    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self) -> Result<(), JsValue> {
        self.inner.close("Mesh acceptor closed").await
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub struct BrowserConnection {
    inner: BrowserWebRtcConnection,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl BrowserConnection {
    #[wasm_bindgen(getter, js_name = remoteEndpointId)]
    pub fn remote_endpoint_id(&self) -> String {
        self.inner.remote_endpoint_id().to_owned()
    }

    #[wasm_bindgen(js_name = openStream)]
    pub async fn open_stream(&self) -> Result<BrowserStream, JsValue> {
        Ok(BrowserStream {
            inner: self.inner.open_bi().await?,
        })
    }

    #[wasm_bindgen(js_name = acceptStream)]
    pub async fn accept_stream(&self) -> Result<BrowserStream, JsValue> {
        Ok(BrowserStream {
            inner: self.inner.accept_bi().await?,
        })
    }

    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self) -> Result<(), JsValue> {
        self.inner.close("Mesh connection closed").await
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub struct BrowserStream {
    inner: BrowserWebRtcStream,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl BrowserStream {
    #[wasm_bindgen(js_name = send)]
    pub async fn send(&self, bytes: &[u8]) -> Result<(), JsValue> {
        self.inner.send_all(bytes).await
    }

    #[wasm_bindgen(js_name = read)]
    pub async fn read(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.read_to_end().await
    }

    #[wasm_bindgen(js_name = closeSend)]
    pub async fn close_send(&self) -> Result<(), JsValue> {
        self.inner.close_send().await
    }
}

#[cfg(not(target_family = "wasm"))]
pub use native::*;

#[cfg(not(target_family = "wasm"))]
mod native {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::{Arc, RwLock},
    };
    use futures_lite::StreamExt;
    use iroh::{
        endpoint::{presets, AfterHandshakeOutcome, ConnectionInfo, EndpointHooks, RelayMode},
        Endpoint, EndpointAddr, EndpointId, SecretKey,
    };
    use iroh_blobs::{
        store::mem::MemStore,
        ticket::BlobTicket,
        BlobsProtocol,
        ALPN as BLOBS_ALPN,
    };
    use iroh_gossip::{
        api::{Event, GossipReceiver, GossipSender},
        net::{Gossip, GOSSIP_ALPN},
    };
    use wasm_bindgen::prelude::*;

    use crate::gossip::GossipEngine;

    #[derive(Debug, Clone)]
    pub struct NativeNodeOptions {
        pub secret: Option<[u8; 32]>,
        pub allowed_peers: Vec<EndpointId>,
        pub allow_any: bool,
        pub storage_path: Option<PathBuf>,
        pub bind_addr: Option<SocketAddr>,
        pub relay_mode: RelayMode,
    }

    impl Default for NativeNodeOptions {
        fn default() -> Self {
            Self {
                secret: None,
                allowed_peers: Vec::new(),
                allow_any: false,
                storage_path: None,
                bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
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
        async fn after_handshake<'a>(&'a self, conn: &'a ConnectionInfo) -> AfterHandshakeOutcome {
            // Outbound connections initiated by this node are permitted
            if conn.side().is_client() {
                return AfterHandshakeOutcome::Accept;
            }
            if self.allow_any {
                return AfterHandshakeOutcome::Accept;
            }
            let allowed = self.allowed_remotes.read().unwrap();
            if allowed.contains(&conn.remote_id()) {
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
        store: iroh_blobs::api::Store,
        allowed_peers: Arc<RwLock<HashSet<EndpointId>>>,
        allow_any: bool,
    }

    pub struct GossipTopicSender {
        inner: GossipSender,
    }

    impl GossipTopicSender {
        pub async fn broadcast(&self, message: impl Into<bytes::Bytes>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.inner.broadcast(message.into()).await.map_err(|e| Box::new(e) as _)
        }

        pub async fn broadcast_neighbors(&self, message: impl Into<bytes::Bytes>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.inner.broadcast_neighbors(message.into()).await.map_err(|e| Box::new(e) as _)
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
        pub async fn recv(&mut self) -> Result<Option<GossipReceivedMessage>, Box<dyn std::error::Error + Send + Sync>> {
            while let Some(res) = self.inner.next().await {
                match res {
                    Ok(Event::Received(msg)) => {
                        return Ok(Some(GossipReceivedMessage {
                            content: msg.content,
                            delivered_from: msg.delivered_from,
                        }));
                    }
                    Ok(_) => {}
                    Err(e) => return Err(Box::new(e)),
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
        ) -> Result<NativeNode, Box<dyn std::error::Error + Send + Sync>> {
            Self::start_with_options(NativeNodeOptions {
                secret,
                allowed_peers,
                allow_any: false,
                storage_path: None,
                bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
                relay_mode: RelayMode::Disabled,
            })
            .await
        }

        pub async fn start_with_options(
            options: NativeNodeOptions,
        ) -> Result<NativeNode, Box<dyn std::error::Error + Send + Sync>> {
            let secret_key = match options.secret {
                Some(bytes) => SecretKey::from_bytes(&bytes),
                None => SecretKey::generate(),
            };

            let allowed_set = Arc::new(RwLock::new(options.allowed_peers.into_iter().collect()));
            let hook = AccessHook {
                allowed_remotes: allowed_set.clone(),
                allow_any: options.allow_any,
            };

            let bind_addr = options.bind_addr.unwrap_or_else(|| {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            });

            let endpoint = Endpoint::builder(presets::Minimal)
                .clear_addr_filter()
                .relay_mode(options.relay_mode)
                .bind_addr(bind_addr)?
                .secret_key(secret_key)
                .hooks(hook)
                .bind()
                .await?;

            let gossip = Gossip::builder().spawn(endpoint.clone());

            let store: iroh_blobs::api::Store = match options.storage_path {
                Some(ref path) => {
                    let fs_store = iroh_blobs::store::fs::FsStore::load(path).await?;
                    fs_store.into()
                }
                None => {
                    let mem_store = MemStore::new();
                    mem_store.into()
                }
            };

            let blobs = BlobsProtocol::new(&store, None);

            let router = iroh::protocol::Router::builder(endpoint.clone())
                .accept(GOSSIP_ALPN, gossip.clone())
                .accept(BLOBS_ALPN, blobs)
                .spawn();

            Ok(NativeNode {
                endpoint,
                router,
                gossip,
                store,
                allowed_peers: allowed_set,
                allow_any: options.allow_any,
            })
        }

        pub fn endpoint_id(&self) -> EndpointId {
            self.endpoint.id()
        }

        pub fn addr(&self) -> EndpointAddr {
            let sockets = self.endpoint.bound_sockets();
            let mut addr = EndpointAddr::new(self.endpoint.id());
            if !sockets.is_empty() {
                addr = addr.with_ip_addr(sockets[0]);
            }
            addr
        }

        pub fn authorize_peer(&self, peer: EndpointId) {
            self.allowed_peers.write().unwrap().insert(peer);
        }

        pub fn revoke_peer(&self, peer: &EndpointId) {
            self.allowed_peers.write().unwrap().remove(peer);
        }

        pub fn is_peer_authorized(&self, peer: &EndpointId) -> bool {
            if self.allow_any {
                return true;
            }
            let allowed = self.allowed_peers.read().unwrap();
            allowed.contains(peer)
        }

        pub async fn join_gossip(
            &self,
            topic_name: &str,
            bootstrap_peers: Vec<EndpointAddr>,
        ) -> Result<(GossipTopicSender, GossipTopicReceiver), Box<dyn std::error::Error + Send + Sync>> {
            let topic_id = GossipEngine::topic_id_for_name(topic_name);

            let mut bootstrap_ids = Vec::new();
            for peer_addr in bootstrap_peers {
                bootstrap_ids.push(peer_addr.id);
                if let Ok(conn) = self.endpoint.connect(peer_addr, GOSSIP_ALPN).await {
                    let gossip = self.gossip.clone();
                    tokio::spawn(async move {
                        let _ = gossip.handle_connection(conn).await;
                    });
                }
            }

            let topic = if bootstrap_ids.is_empty() {
                self.gossip.subscribe(topic_id, vec![]).await?
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                self.gossip.subscribe_and_join(topic_id, bootstrap_ids).await?
            };

            let (sender, receiver) = topic.split();
            Ok((
                GossipTopicSender { inner: sender },
                GossipTopicReceiver { inner: receiver },
            ))
        }

        pub async fn add_blob(
            &self,
            data: &[u8],
        ) -> Result<BlobTicket, Box<dyn std::error::Error + Send + Sync>> {
            let tag = self.store.add_bytes(data.to_vec()).await?;
            let addr = self.addr();
            let ticket = BlobTicket::new(addr, tag.hash, tag.format);
            Ok(ticket)
        }

        pub async fn get_blob(
            &self,
            hash: iroh_blobs::Hash,
        ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
            match self.store.get_bytes(hash).await {
                Ok(bytes) => Ok(Some(bytes.to_vec())),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("not found") || msg.contains("NotFound") {
                        Ok(None)
                    } else {
                        Err(Box::new(e))
                    }
                }
            }
        }

        pub async fn fetch_blob(
            &self,
            ticket: &BlobTicket,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let conn = self
                .endpoint
                .connect(ticket.addr().clone(), BLOBS_ALPN)
                .await?;
            self.store
                .remote()
                .fetch(conn, ticket.hash_and_format())
                .await?;
            let bytes = self.store.get_bytes(ticket.hash()).await?;
            Ok(bytes.to_vec())
        }

        pub async fn close(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let _ = self.router.shutdown().await;
            self.endpoint.close().await;
            let _ = self.store.shutdown().await;
            Ok(())
        }
    }

    #[wasm_bindgen]
    pub struct BrowserNode {
        endpoint_id: String,
        inner: Arc<tokio::sync::Mutex<Option<NativeNode>>>,
    }

    #[wasm_bindgen]
    impl BrowserNode {
        #[wasm_bindgen(js_name = start)]
        pub async fn start(secret: Option<Vec<u8>>) -> Result<BrowserNode, JsValue> {
            let key = secret.and_then(|s| {
                if s.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&s);
                    Some(arr)
                } else {
                    None
                }
            });
            let node = NativeNode::start_with_options(NativeNodeOptions {
                secret: key,
                allowed_peers: vec![],
                allow_any: true,
                storage_path: None,
                bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
                relay_mode: RelayMode::Disabled,
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

            let endpoint_id = node.endpoint_id().to_string();
            Ok(Self {
                endpoint_id,
                inner: Arc::new(tokio::sync::Mutex::new(Some(node))),
            })
        }

        #[wasm_bindgen(getter, js_name = endpointId)]
        pub fn endpoint_id(&self) -> String {
            self.endpoint_id.clone()
        }

        #[wasm_bindgen(js_name = close)]
        pub async fn close(&self, _reason: Option<String>) -> Result<(), JsValue> {
            let mut guard = self.inner.lock().await;
            if let Some(node) = guard.take() {
                let _ = node.close().await;
            }
            Ok(())
        }
    }
}

#[wasm_bindgen]
pub async fn start_browser_node(secret: Option<Vec<u8>>) -> Result<BrowserNode, JsValue> {
    BrowserNode::start(secret).await
}
