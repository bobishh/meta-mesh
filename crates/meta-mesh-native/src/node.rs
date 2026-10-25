use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex, RwLock, Weak},
    time::Duration,
};

use futures_lite::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, presets},
    protocol::{AcceptError, ProtocolHandler},
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
use meta_mesh_core::{
    MAX_CONCURRENT_FRAMES_PER_CONNECTION, MAX_CONCURRENT_HEADERS_PER_CONNECTION,
    MAX_PAIRING_HEADER_BYTES, MAX_RPC_FRAME_BYTES, MAX_TRANSFER_DEADLINE_MS, PairingCodec,
    pairing_frame_budget,
};
#[cfg(test)]
use tokio::sync::Barrier;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub const RPC_ALPN: &[u8] = b"meta-mesh/rpc/1";
const BROWSER_RPC_ALPN: &[u8] = b"match/sync/0";
pub const MAX_RPC_BYTES: usize = MAX_RPC_FRAME_BYTES;
const RPC_QUEUE_CAPACITY: usize = 64;
const MAX_PEER_READ_SLOT_ENTRIES: usize = 1024;

#[derive(Debug)]
struct PeerStreamBudgets {
    inbound: Arc<Semaphore>,
    inbound_waiters: Arc<Semaphore>,
    outbound: Arc<Semaphore>,
}

impl PeerStreamBudgets {
    fn new() -> Self {
        Self {
            inbound: Arc::new(Semaphore::new(MAX_CONCURRENT_FRAMES_PER_CONNECTION)),
            inbound_waiters: Arc::new(Semaphore::new(MAX_CONCURRENT_HEADERS_PER_CONNECTION)),
            outbound: Arc::new(Semaphore::new(MAX_CONCURRENT_FRAMES_PER_CONNECTION)),
        }
    }
}

#[derive(Debug, Default)]
struct PeerStreamBudgetRegistry {
    peers: StdMutex<HashMap<EndpointId, Weak<PeerStreamBudgets>>>,
}

impl PeerStreamBudgetRegistry {
    fn budgets_for(&self, peer: EndpointId) -> Option<Arc<PeerStreamBudgets>> {
        let mut peers = self.peers.lock().ok()?;
        peers.retain(|_, budgets| budgets.strong_count() > 0);
        if let Some(budgets) = peers.get(&peer).and_then(Weak::upgrade) {
            return Some(budgets);
        }
        if peers.len() >= MAX_PEER_READ_SLOT_ENTRIES {
            return None;
        }
        let budgets = Arc::new(PeerStreamBudgets::new());
        peers.insert(peer, Arc::downgrade(&budgets));
        Some(budgets)
    }
}

#[derive(Debug, Clone)]
pub struct NativeNodeOptions {
    pub secret: Option<[u8; 32]>,
    pub allowed_peers: Vec<EndpointId>,
    pub allow_any: bool,
    pub accept_unlisted_browser_rpc: bool,
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
            accept_unlisted_browser_rpc: false,
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
    accept_unlisted_browser_rpc: bool,
    #[cfg(test)]
    decisions: Arc<Mutex<Option<mpsc::UnboundedSender<AccessDecision>>>>,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct AccessDecision {
    remote: EndpointId,
    alpn: Vec<u8>,
    accepted: bool,
}

impl EndpointHooks for AccessHook {
    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        let accepted = connection.side().is_client()
            || self.allow_any
            || (self.accept_unlisted_browser_rpc && connection.alpn() == BROWSER_RPC_ALPN)
            || self
                .allowed_remotes
                .read()
                .expect("native peer allowlist poisoned")
                .contains(&connection.remote_id());

        #[cfg(test)]
        if connection.side().is_server() {
            if let Some(decisions) = self.decisions.lock().await.as_ref() {
                let _ = decisions.send(AccessDecision {
                    remote: connection.remote_id(),
                    alpn: connection.alpn().to_vec(),
                    accepted,
                });
            }
        }

        if accepted {
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
    rpc_inbox: Arc<NativeRpcInbox>,
    peer_budgets: Arc<PeerStreamBudgetRegistry>,
    #[cfg(test)]
    access_decisions: Arc<Mutex<Option<mpsc::UnboundedSender<AccessDecision>>>>,
}

/// One browser-compatible Iroh connection for multi-stream protocols such as
/// workspace invitation and handoff. A normal `request` opens a new connection
/// for every frame, which the browser invitation host cannot accept.
/// Inbound and outbound streams use separate peer budgets to avoid reciprocal
/// requests consuming each other's capacity. Inbound waits are bounded by the
/// peer queue limit and share the transfer deadline with body reads.
pub struct NativeBrowserConnection {
    connection: Connection,
    peer_budgets: Arc<PeerStreamBudgets>,
}

pub struct NativeBrowserRequest {
    payload: Vec<u8>,
    send: iroh::endpoint::SendStream,
}

impl NativeBrowserRequest {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub async fn respond(mut self, response: &[u8]) -> Result<(), BoxError> {
        if response.len() > MAX_RPC_BYTES {
            return Err(io_error("RPC response exceeds size limit"));
        }
        self.send.write_all(response).await?;
        self.send.finish()?;
        Ok(())
    }
}

impl NativeBrowserConnection {
    pub async fn accept(&self) -> Result<NativeBrowserRequest, BoxError> {
        let (mut send, mut receive) = self.connection.accept_bi().await?;
        let timeout = Duration::from_millis(u64::from(MAX_TRANSFER_DEADLINE_MS));
        let deadline = tokio::time::Instant::now() + timeout;
        let _permit = match acquire_inbound_frame_slot(
            &self.peer_budgets,
            &self.connection,
            deadline,
        )
        .await
        {
            Ok(permit) => permit,
            Err(error) => {
                send.reset(0u32.into()).ok();
                receive.stop(0u32.into()).ok();
                return Err(error);
            }
        };
        match tokio::time::timeout_at(deadline, receive.read_to_end(MAX_RPC_BYTES)).await {
            Ok(Ok(payload)) => Ok(NativeBrowserRequest { payload, send }),
            Ok(Err(error)) => {
                receive.stop(0u32.into()).ok();
                Err(Box::new(error))
            }
            Err(_) => {
                receive.stop(0u32.into()).ok();
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Browser RPC stream timed out",
                )))
            }
        }
    }

    pub async fn accept_pairing(&self) -> Result<NativeBrowserRequest, BoxError> {
        let (mut send, mut receive) = self.connection.accept_bi().await?;
        let timeout = Duration::from_millis(u64::from(MAX_TRANSFER_DEADLINE_MS));
        let deadline = tokio::time::Instant::now() + timeout;
        let _permit = match acquire_inbound_frame_slot(
            &self.peer_budgets,
            &self.connection,
            deadline,
        )
        .await
        {
            Ok(permit) => permit,
            Err(error) => {
                send.reset(0u32.into()).ok();
                receive.stop(0u32.into()).ok();
                return Err(error);
            }
        };
        let result =
            tokio::time::timeout_at(deadline, read_pairing_frame(&mut receive, false)).await;
        match result {
            Ok(Ok(payload)) => Ok(NativeBrowserRequest { payload, send }),
            Ok(Err(error)) => {
                trace_peer_stream_error("browser.accept_pairing.failed", &self.connection, &error);
                receive.stop(0u32.into()).ok();
                Err(error)
            }
            Err(_) => {
                trace_peer_stream(
                    "browser.accept_pairing.timed_out",
                    &self.connection,
                    "phase=read",
                );
                receive.stop(0u32.into()).ok();
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Pairing stream timed out",
                )))
            }
        }
    }

    pub async fn exchange(&self, payload: &[u8], timeout: Duration) -> Result<Vec<u8>, BoxError> {
        if payload.len() > MAX_RPC_BYTES {
            return Err(io_error("RPC request exceeds size limit"));
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let _permit = acquire_peer_outbound_slot(
            self.peer_budgets.outbound.clone(),
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
        let (mut send, mut receive) = tokio::time::timeout_at(deadline, self.connection.open_bi())
            .await
            .map_err(|_| io_error("Browser RPC stream open timed out"))??;
        match tokio::time::timeout_at(deadline, async {
            send.write_all(payload).await?;
            send.finish()?;
            let response = receive.read_to_end(MAX_RPC_BYTES).await?;
            Ok::<Vec<u8>, BoxError>(response)
        })
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => {
                trace_peer_stream_error("browser.exchange.failed", &self.connection, &error);
                let _ = send.reset(0u32.into());
                let _ = receive.stop(0u32.into());
                Err(error)
            }
            Err(_) => {
                trace_peer_stream(
                    "browser.exchange.timed_out",
                    &self.connection,
                    "phase=exchange",
                );
                let _ = send.reset(0u32.into());
                let _ = receive.stop(0u32.into());
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Browser RPC request timed out",
                )))
            }
        }
    }

    pub async fn exchange_pairing(
        &self,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, BoxError> {
        if payload.len() > MAX_RPC_BYTES {
            return Err(io_error("Pairing frame exceeds ingress limit: stage=send"));
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let _permit = acquire_peer_outbound_slot(
            self.peer_budgets.outbound.clone(),
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
        let (mut send, mut receive) = tokio::time::timeout_at(deadline, self.connection.open_bi())
            .await
            .map_err(|_| io_error("Pairing stream open timed out"))??;
        let result = tokio::time::timeout_at(deadline, async {
            send.write_all(payload).await?;
            send.finish()?;
            read_pairing_frame(&mut receive, true).await
        })
        .await;
        match result {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(error)) => {
                trace_peer_stream_error(
                    "browser.exchange_pairing.failed",
                    &self.connection,
                    &error,
                );
                let _ = send.reset(0u32.into());
                let _ = receive.stop(0u32.into());
                Err(error)
            }
            Err(_) => {
                trace_peer_stream(
                    "browser.exchange_pairing.timed_out",
                    &self.connection,
                    "phase=exchange",
                );
                let _ = send.reset(0u32.into());
                let _ = receive.stop(0u32.into());
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Pairing stream timed out",
                )))
            }
        }
    }

    pub fn close(&self) {
        trace_peer_stream(
            "browser.connection.close",
            &self.connection,
            "reason=browser_session_complete",
        );
        self.connection
            .close(0u32.into(), b"browser session complete");
    }
}

async fn read_pairing_frame(
    receive: &mut iroh::endpoint::RecvStream,
    allow_empty_response: bool,
) -> Result<Vec<u8>, BoxError> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    let header = loop {
        let remaining = MAX_PAIRING_HEADER_BYTES.saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(io_error(
                "Pairing header exceeds ingress limit: stage=stream",
            ));
        }
        let read_limit = remaining.min(buffer.len());
        let Some(length) = receive.read(&mut buffer[..read_limit]).await? else {
            if allow_empty_response && bytes.is_empty() {
                return Ok(bytes);
            }
            return Err(io_error("Pairing header incomplete: stage=stream"));
        };
        let chunk = &buffer[..length];
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        bytes.extend_from_slice(chunk);
        if let Some(position) = newline {
            let header_end = bytes.len() - length + position + 1;
            let header = PairingCodec::inspect(&bytes[..header_end])
                .map_err(|_| io_error("Pairing frame invalid: stage=header"))?;
            break header;
        }
        if bytes.len() >= MAX_PAIRING_HEADER_BYTES {
            return Err(io_error(
                "Pairing header exceeds ingress limit: stage=stream",
            ));
        }
    };
    let budget = pairing_frame_budget(&header.frame_type)
        .ok_or_else(|| io_error("Pairing frame invalid: stage=kind"))?;
    let header_bytes = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len())
        + 1;
    let frame_limit = budget
        .max_wire_bytes
        .min(MAX_RPC_FRAME_BYTES)
        .min(header_bytes.saturating_add(budget.max_payload_bytes));
    if bytes.len() > frame_limit {
        return Err(io_error(
            "Pairing frame exceeds ingress limit: stage=header",
        ));
    }
    loop {
        let remaining = frame_limit.saturating_sub(bytes.len());
        let read_limit = remaining.saturating_add(1).min(buffer.len());
        let Some(length) = receive.read(&mut buffer[..read_limit]).await? else {
            return Ok(bytes);
        };
        if length > remaining {
            return Err(io_error(
                "Pairing frame exceeds ingress limit: stage=stream",
            ));
        }
        bytes.extend_from_slice(&buffer[..length]);
    }
}

#[derive(Debug)]
pub struct NativeRpcRequest {
    remote_endpoint_id: EndpointId,
    payload: Vec<u8>,
    response: Option<oneshot::Sender<Vec<u8>>>,
}

impl NativeRpcRequest {
    pub fn remote_endpoint_id(&self) -> EndpointId {
        self.remote_endpoint_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn respond(mut self, response: Vec<u8>) -> Result<(), BoxError> {
        if response.len() > MAX_RPC_BYTES {
            return Err(io_error("RPC response exceeds size limit"));
        }
        self.response
            .take()
            .ok_or_else(|| io_error("RPC request already answered"))?
            .send(response)
            .map_err(|_| io_error("RPC requester disconnected"))
    }
}

#[derive(Debug)]
pub struct NativeRpcInbox {
    receiver: Mutex<mpsc::Receiver<NativeRpcRequest>>,
}

impl NativeRpcInbox {
    pub async fn receive(&self) -> Option<NativeRpcRequest> {
        self.receiver.lock().await.recv().await
    }
}

#[derive(Debug, Clone)]
struct RpcProtocol {
    sender: mpsc::Sender<NativeRpcRequest>,
    peer_budgets: Arc<PeerStreamBudgetRegistry>,
}

impl ProtocolHandler for RpcProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote_endpoint_id = connection.remote_id();
        let peer_budgets = self.peer_budgets.budgets_for(remote_endpoint_id);
        let connection_id = connection.stable_id();
        while let Ok((mut send, mut receive)) = connection.accept_bi().await {
            let deadline = tokio::time::Instant::now()
                + Duration::from_millis(u64::from(MAX_TRANSFER_DEADLINE_MS));
            let Some(peer_budgets) = peer_budgets.as_ref() else {
                send.reset(1u32.into()).ok();
                receive.stop(1u32.into()).ok();
                continue;
            };
            let permit = match acquire_inbound_frame_slot(peer_budgets, &connection, deadline).await
            {
                Ok(permit) => permit,
                Err(error) => {
                    trace_rpc_slot_reset(connection_id, remote_endpoint_id, Some(0));
                    if peer_stream_trace_enabled() {
                        eprintln!(
                            "trace.peer_stream event=rpc.stream.admission_rejected error={error}"
                        );
                    }
                    send.reset(1u32.into()).ok();
                    receive.stop(1u32.into()).ok();
                    continue;
                }
            };
            if peer_stream_trace_enabled() {
                let available_after = peer_budgets.inbound.available_permits();
                eprintln!(
                    "trace.peer_stream event=rpc.stream.started connection_id={connection_id} peer={} active_slots={}",
                    short_endpoint_id(remote_endpoint_id),
                    MAX_CONCURRENT_FRAMES_PER_CONNECTION.saturating_sub(available_after)
                );
            }
            let sender = self.sender.clone();
            let stream_connection_id = connection_id;
            let stream_peer_id = remote_endpoint_id;
            let stream_budgets = peer_budgets.clone();
            tokio::spawn(async move {
                let _budget_guard = stream_budgets;
                let _permit = permit;
                let result = tokio::time::timeout_at(deadline, async {
                    let payload = receive.read_to_end(MAX_RPC_BYTES).await?;
                    let (response, response_receiver) = oneshot::channel();
                    sender
                        .send(NativeRpcRequest {
                            remote_endpoint_id,
                            payload,
                            response: Some(response),
                        })
                        .await
                        .map_err(|_| io_error("RPC listener stopped"))?;
                    let response = response_receiver
                        .await
                        .map_err(|_| io_error("RPC request dropped without response"))?;
                    send.write_all(&response).await?;
                    send.finish()?;
                    Ok::<(), BoxError>(())
                })
                .await;
                if !matches!(&result, Ok(Ok(()))) {
                    if peer_stream_trace_enabled() {
                        eprintln!(
                            "trace.peer_stream event=rpc.stream.failed connection_id={stream_connection_id} peer={} outcome={}",
                            short_endpoint_id(stream_peer_id),
                            if matches!(&result, Err(_)) {
                                "deadline"
                            } else {
                                "io"
                            }
                        );
                    }
                    send.reset(1u32.into()).ok();
                    receive.stop(1u32.into()).ok();
                } else if peer_stream_trace_enabled() {
                    eprintln!(
                        "trace.peer_stream event=rpc.stream.completed connection_id={stream_connection_id} peer={}",
                        short_endpoint_id(stream_peer_id)
                    );
                }
            });
        }
        if peer_stream_trace_enabled() {
            eprintln!(
                "trace.peer_stream event=rpc.connection.accept_ended connection_id={connection_id} peer={} reason={}",
                short_endpoint_id(remote_endpoint_id),
                connection
                    .close_reason()
                    .map_or_else(|| "none".to_string(), |reason| reason.to_string())
            );
        }
        Ok(())
    }
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
            accept_unlisted_browser_rpc: false,
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
        #[cfg(test)]
        let access_decisions = Arc::new(Mutex::new(None));
        let endpoint = Endpoint::builder(presets::N0)
            .relay_mode(options.relay_mode)
            .bind_addr(options.bind_addr)?
            .secret_key(secret_key)
            .hooks(AccessHook {
                allowed_remotes: allowed_peers.clone(),
                allow_any: options.allow_any,
                accept_unlisted_browser_rpc: options.accept_unlisted_browser_rpc,
                #[cfg(test)]
                decisions: access_decisions.clone(),
            })
            .bind()
            .await?;

        let gossip = Gossip::builder().spawn(endpoint.clone());
        let store: Store = match options.storage_path {
            Some(path) => FsStore::load(path).await?.into(),
            None => MemStore::new().into(),
        };
        let blobs = BlobsProtocol::new(&store, None);
        let (rpc_sender, rpc_receiver) = mpsc::channel(RPC_QUEUE_CAPACITY);
        let rpc_inbox = Arc::new(NativeRpcInbox {
            receiver: Mutex::new(rpc_receiver),
        });
        let peer_budgets = Arc::new(PeerStreamBudgetRegistry::default());
        let rpc = RpcProtocol {
            sender: rpc_sender,
            peer_budgets: peer_budgets.clone(),
        };
        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .accept(BLOBS_ALPN, blobs)
            .accept(RPC_ALPN, rpc.clone())
            .accept(BROWSER_RPC_ALPN, rpc)
            .spawn();

        Ok(Self {
            endpoint,
            router,
            gossip,
            store,
            allowed_peers,
            allow_any: options.allow_any,
            rpc_inbox,
            peer_budgets,
            #[cfg(test)]
            access_decisions,
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

    pub fn rpc_inbox(&self) -> Arc<NativeRpcInbox> {
        self.rpc_inbox.clone()
    }

    pub async fn connect_browser(
        &self,
        endpoint_addr: EndpointAddr,
        timeout: Duration,
    ) -> Result<NativeBrowserConnection, BoxError> {
        let connection = tokio::time::timeout(
            timeout,
            self.endpoint.connect(endpoint_addr, BROWSER_RPC_ALPN),
        )
        .await
        .map_err(|_| io_error("Browser RPC connection timed out"))??;
        let peer_budgets = self
            .peer_budgets
            .budgets_for(connection.remote_id())
            .ok_or_else(|| io_error("Peer read-slot registry is full"))?;
        Ok(NativeBrowserConnection {
            connection,
            peer_budgets,
        })
    }

    pub async fn request(
        &self,
        endpoint_addr: EndpointAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, BoxError> {
        if payload.len() > MAX_RPC_BYTES {
            return Err(io_error("RPC request exceeds size limit"));
        }
        let peer_budgets = self
            .peer_budgets
            .budgets_for(endpoint_addr.id.clone())
            .ok_or_else(|| io_error("Peer read-slot registry is full"))?;
        let _permit = peer_budgets
            .outbound
            .clone()
            .try_acquire_owned()
            .map_err(|_| io_error("Peer outbound stream concurrency limit exceeded"))?;
        tokio::time::timeout(timeout, async {
            let mut last_error = None;
            for alpn in [RPC_ALPN, BROWSER_RPC_ALPN] {
                match rpc_roundtrip(&self.endpoint, endpoint_addr.clone(), alpn, payload).await {
                    Ok(response) => return Ok(response),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| io_error("RPC negotiation failed")))
        })
        .await
        .map_err(|_| io_error("RPC request timed out"))?
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

async fn rpc_roundtrip(
    endpoint: &Endpoint,
    endpoint_addr: EndpointAddr,
    alpn: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    let connection = endpoint.connect(endpoint_addr, alpn).await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    send.write_all(payload).await?;
    send.finish()?;
    let response = receive.read_to_end(MAX_RPC_BYTES).await?;
    connection.close(0u32.into(), b"request complete");
    Ok(response)
}

fn io_error(message: &'static str) -> BoxError {
    Box::new(std::io::Error::other(message))
}

fn peer_stream_trace_enabled() -> bool {
    std::env::var_os("META_MESH_TRACE_PEER_STREAMS").is_some()
}

fn short_endpoint_id(endpoint: EndpointId) -> String {
    endpoint.to_string().chars().take(8).collect()
}

fn trace_peer_stream(event: &str, connection: &Connection, detail: &str) {
    if peer_stream_trace_enabled() {
        eprintln!(
            "trace.peer_stream event={event} connection_id={} peer={} detail={detail}",
            connection.stable_id(),
            short_endpoint_id(connection.remote_id())
        );
    }
}

fn trace_peer_stream_error(event: &str, connection: &Connection, error: &dyn std::fmt::Display) {
    if peer_stream_trace_enabled() {
        eprintln!(
            "trace.peer_stream event={event} connection_id={} peer={} error={}",
            connection.stable_id(),
            short_endpoint_id(connection.remote_id()),
            error
        );
    }
}

fn trace_rpc_slot_reset(connection_id: usize, peer: EndpointId, available_before: Option<usize>) {
    if peer_stream_trace_enabled() {
        eprintln!(
            "trace.peer_stream event=rpc.stream.slot_reset connection_id={connection_id} peer={} available_slots={}",
            short_endpoint_id(peer),
            available_before.map_or_else(|| "registry_full".to_string(), |slots| slots.to_string())
        );
    }
}

async fn acquire_peer_outbound_slot(
    slots: Arc<Semaphore>,
    timeout: Duration,
) -> Result<OwnedSemaphorePermit, BoxError> {
    tokio::time::timeout(timeout, slots.acquire_owned())
        .await
        .map_err(|_| io_error("Peer outbound stream wait timed out"))?
        .map_err(|error| Box::new(error) as BoxError)
}

async fn acquire_inbound_frame_slot(
    budgets: &PeerStreamBudgets,
    connection: &Connection,
    deadline: tokio::time::Instant,
) -> Result<OwnedSemaphorePermit, BoxError> {
    let _queue_permit = budgets
        .inbound_waiters
        .clone()
        .try_acquire_owned()
        .map_err(|_| io_error("Peer inbound stream queue is full"))?;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    tokio::select! {
        permit = tokio::time::timeout(remaining, budgets.inbound.clone().acquire_owned()) => {
            permit
                .map_err(|_| io_error("Peer inbound stream capacity wait timed out"))?
                .map_err(|error| Box::new(error) as BoxError)
        }
        _ = connection.closed() => Err(io_error("Peer connection closed while waiting for inbound stream capacity")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn browser_incoming_stream_waits_for_read_capacity_without_closing_connection() {
        for pairing in [false, true] {
            let remote = Endpoint::builder(presets::N0)
                .alpns(vec![BROWSER_RPC_ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap()
                .bind()
                .await
                .unwrap();
            let node = NativeNode::start_with_options(NativeNodeOptions {
                relay_mode: RelayMode::Disabled,
                bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                ..Default::default()
            })
            .await
            .unwrap();
            let (session, peer) = tokio::join!(
                node.connect_browser(remote.addr(), Duration::from_secs(5)),
                async { remote.accept().await.unwrap().await.unwrap() }
            );
            let session = session.unwrap();
            let first_slot = session
                .peer_budgets
                .inbound
                .clone()
                .acquire_owned()
                .await
                .unwrap();
            let second_slot = session
                .peer_budgets
                .inbound
                .clone()
                .acquire_owned()
                .await
                .unwrap();
            assert_eq!(session.peer_budgets.inbound.available_permits(), 0);
            let payload = if pairing {
                PairingCodec::encode("sync-heartbeat", "secret", &[]).unwrap()
            } else {
                b"incoming request".to_vec()
            };
            let (mut send, mut receive) = peer.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let accepting = async {
                if pairing {
                    session.accept_pairing().await
                } else {
                    session.accept().await
                }
            };
            tokio::pin!(accepting);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut accepting)
                    .await
                    .is_err(),
                "an excess incoming stream must wait instead of failing the admitted connection"
            );
            assert_eq!(session.peer_budgets.inbound.available_permits(), 0);
            drop(first_slot);
            let request = tokio::time::timeout(Duration::from_secs(1), &mut accepting)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request.payload(), payload);
            request.respond(b"ack").await.unwrap();
            assert_eq!(receive.read_to_end(32).await.unwrap(), b"ack");
            drop(second_slot);

            let (mut send, mut receive) = peer.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let request = if pairing {
                session.accept_pairing().await
            } else {
                session.accept().await
            }
            .unwrap();
            request.respond(b"next ack").await.unwrap();
            assert_eq!(receive.read_to_end(32).await.unwrap(), b"next ack");
            session.close();
            node.close().await.unwrap();
            remote.close().await;
        }
    }

    #[tokio::test]
    async fn pairing_exchange_waits_for_a_peer_stream_slot() {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let waiting_slots = slots.clone();
        let waiter = tokio::spawn(async move {
            acquire_peer_outbound_slot(waiting_slots, Duration::from_secs(1)).await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "saturated peer slot must queue outbound work"
        );
        drop(held);

        assert!(waiter.await.unwrap().is_ok());
    }

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

    #[tokio::test]
    async fn browser_session_exchanges_invitation_and_ack_on_one_connection() {
        let guest = NativeNode::start(Some([17; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(Some([18; 32]), vec![guest.endpoint_id()])
            .await
            .unwrap();
        let session = guest
            .connect_browser(host.addr(), Duration::from_secs(5))
            .await
            .unwrap();
        let inbox = host.rpc_inbox();
        let responder = tokio::spawn(async move {
            let first = inbox.receive().await.unwrap();
            assert_eq!(first.payload(), b"workspace-join-request");
            first.respond(b"workspace-join-response".to_vec()).unwrap();
            let second = inbox.receive().await.unwrap();
            assert_eq!(second.payload(), b"sync-ack");
            second.respond(Vec::new()).unwrap();
        });
        assert_eq!(
            session
                .exchange(b"workspace-join-request", Duration::from_secs(5))
                .await
                .unwrap(),
            b"workspace-join-response"
        );
        assert!(
            session
                .exchange(b"sync-ack", Duration::from_secs(5))
                .await
                .unwrap()
                .is_empty()
        );
        responder.await.unwrap();
        session.close();
        guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn timed_out_browser_stream_does_not_close_the_peer_connection() {
        let guest = NativeNode::start(Some([41; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(Some([42; 32]), vec![guest.endpoint_id()])
            .await
            .unwrap();
        let session = guest
            .connect_browser(host.addr(), Duration::from_secs(5))
            .await
            .unwrap();
        let inbox = host.rpc_inbox();
        let responder = tokio::spawn(async move {
            let delayed = inbox.receive().await.unwrap();
            assert_eq!(delayed.payload(), b"slow-scope-frame");
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = delayed.respond(b"late-response".to_vec());

            let heartbeat = inbox.receive().await.unwrap();
            assert_eq!(heartbeat.payload(), b"sync-heartbeat");
            heartbeat.respond(b"sync-heartbeat-ack".to_vec()).unwrap();
        });

        let timed_out = session
            .exchange(b"slow-scope-frame", Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(
            timed_out
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::TimedOut)
        );
        assert_eq!(
            session
                .exchange(b"sync-heartbeat", Duration::from_secs(2))
                .await
                .unwrap(),
            b"sync-heartbeat-ack"
        );

        responder.await.unwrap();
        session.close();
        guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn rpc_inbound_queue_waits_for_capacity_and_keeps_other_peers_live() {
        let guest = NativeNode::start(Some([61; 32]), vec![]).await.unwrap();
        let other_guest = NativeNode::start(Some([62; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(
            Some([63; 32]),
            vec![guest.endpoint_id(), other_guest.endpoint_id()],
        )
        .await
        .unwrap();
        let inbox = host.rpc_inbox();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let expected_peer = guest.endpoint_id();
        let responder = tokio::spawn(async move {
            let first = inbox.receive().await.unwrap();
            let second = inbox.receive().await.unwrap();
            assert_eq!(first.remote_endpoint_id(), expected_peer);
            assert_eq!(second.remote_endpoint_id(), expected_peer);
            assert!([first.payload(), second.payload()].contains(&b"same-peer-one".as_slice()));
            assert!([first.payload(), second.payload()].contains(&b"same-peer-two".as_slice()));
            ready_tx.send(()).unwrap();

            let healthy = inbox.receive().await.unwrap();
            assert_eq!(healthy.payload(), b"different-peer");
            healthy.respond(b"healthy-response".to_vec()).unwrap();

            release_rx.await.unwrap();
            first.respond(b"response-one".to_vec()).unwrap();
            second.respond(b"response-two".to_vec()).unwrap();
            let first_queued = inbox.receive().await.unwrap();
            assert_eq!(first_queued.payload(), b"same-peer-queued-one");
            first_queued
                .respond(b"queued-response-one".to_vec())
                .unwrap();
            let second_queued = inbox.receive().await.unwrap();
            assert_eq!(second_queued.payload(), b"same-peer-queued-two");
            second_queued
                .respond(b"queued-response-two".to_vec())
                .unwrap();
        });

        {
            let first = guest.request(host.addr(), b"same-peer-one", Duration::from_secs(5));
            let second = guest.request(host.addr(), b"same-peer-two", Duration::from_secs(5));
            tokio::pin!(first);
            tokio::pin!(second);
            let ready = ready_rx;
            tokio::pin!(ready);
            tokio::select! {
                _ = &mut ready => {}
                result = &mut first => panic!("first request completed before release: {result:?}"),
                result = &mut second => panic!("second request completed before release: {result:?}"),
            }

            let mut first_queued = tokio::spawn({
                let endpoint = guest.endpoint.clone();
                let address = host.addr();
                async move { rpc_roundtrip(&endpoint, address, RPC_ALPN, b"same-peer-queued-one").await }
            });
            let budgets = host.peer_budgets.budgets_for(guest.endpoint_id()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while budgets.inbound_waiters.available_permits()
                    == MAX_CONCURRENT_HEADERS_PER_CONNECTION
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("first request should claim the queue head");
            let mut second_queued = tokio::spawn({
                let endpoint = guest.endpoint.clone();
                let address = host.addr();
                async move { rpc_roundtrip(&endpoint, address, RPC_ALPN, b"same-peer-queued-two").await }
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while budgets.inbound_waiters.available_permits()
                    != MAX_CONCURRENT_HEADERS_PER_CONNECTION - 2
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("second request should queue behind the first");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut first_queued)
                    .await
                    .is_err(),
                "queued same-peer stream must wait for an inbound slot"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut second_queued)
                    .await
                    .is_err(),
                "later same-peer stream must remain behind the queue head"
            );
            assert_eq!(
                other_guest
                    .request(host.addr(), b"different-peer", Duration::from_secs(2))
                    .await
                    .unwrap(),
                b"healthy-response"
            );

            release_tx.send(()).unwrap();
            let (first, second) = tokio::join!(first, second);
            assert!(first.is_ok());
            assert!(second.is_ok());
            assert_eq!(first_queued.await.unwrap().unwrap(), b"queued-response-one");
            assert_eq!(
                second_queued.await.unwrap().unwrap(),
                b"queued-response-two"
            );
        }
        responder.await.unwrap();
        guest.close().await.unwrap();
        other_guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn reciprocal_outbound_requests_do_not_consume_inbound_capacity() {
        let first = NativeNode::start(Some([71; 32]), vec![]).await.unwrap();
        let second = NativeNode::start(Some([72; 32]), vec![first.endpoint_id()])
            .await
            .unwrap();
        first.authorize_peer(second.endpoint_id());

        let first_inbox = first.rpc_inbox();
        let second_inbox = second.rpc_inbox();
        let both_sides_ready = Arc::new(Barrier::new(2));
        let first_ready = both_sides_ready.clone();
        let first_responder = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(2);
            for _ in 0..2 {
                requests.push(first_inbox.receive().await.unwrap());
            }
            first_ready.wait().await;
            for request in requests {
                let response = [request.payload(), b"-reply"].concat();
                request.respond(response).unwrap();
            }
        });
        let second_responder = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(2);
            for _ in 0..2 {
                requests.push(second_inbox.receive().await.unwrap());
            }
            both_sides_ready.wait().await;
            for request in requests {
                let response = [request.payload(), b"-reply"].concat();
                request.respond(response).unwrap();
            }
        });

        let requests = async {
            tokio::join!(
                first.request(second.addr(), b"first-one", Duration::from_secs(5)),
                first.request(second.addr(), b"first-two", Duration::from_secs(5)),
                second.request(first.addr(), b"second-one", Duration::from_secs(5)),
                second.request(first.addr(), b"second-two", Duration::from_secs(5)),
            )
        };
        let (first_one, first_two, second_one, second_two) =
            tokio::time::timeout(Duration::from_secs(8), requests)
                .await
                .expect("reciprocal requests must not deadlock");
        assert_eq!(first_one.unwrap(), b"first-one-reply");
        assert_eq!(first_two.unwrap(), b"first-two-reply");
        assert_eq!(second_one.unwrap(), b"second-one-reply");
        assert_eq!(second_two.unwrap(), b"second-two-reply");

        first_responder.await.unwrap();
        second_responder.await.unwrap();
        first.close().await.unwrap();
        second.close().await.unwrap();
    }

    #[tokio::test]
    async fn rpc_inbound_queue_rejects_overflow_without_reading_queued_payloads() {
        let guest = NativeNode::start(Some([73; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(Some([74; 32]), vec![guest.endpoint_id()])
            .await
            .unwrap();
        let inbox = host.rpc_inbox();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let expected_peer = guest.endpoint_id();
        let responder = tokio::spawn(async move {
            let first = inbox.receive().await.unwrap();
            let second = inbox.receive().await.unwrap();
            assert_eq!(first.remote_endpoint_id(), expected_peer);
            assert_eq!(second.remote_endpoint_id(), expected_peer);
            ready_tx.send(()).unwrap();
            release_rx.await.unwrap();
            for request in [first, second] {
                let response = [request.payload(), b"-reply"].concat();
                request.respond(response).unwrap();
            }

            let expected_payloads: HashSet<Vec<u8>> = (0..MAX_CONCURRENT_HEADERS_PER_CONNECTION)
                .map(|index| format!("queued-{index}").into_bytes())
                .collect();
            let mut received_payloads = HashSet::new();
            for _ in 0..MAX_CONCURRENT_HEADERS_PER_CONNECTION {
                let request = inbox.receive().await.unwrap();
                assert_eq!(request.remote_endpoint_id(), expected_peer);
                assert!(expected_payloads.contains(request.payload()));
                assert!(received_payloads.insert(request.payload().to_vec()));
                let response = request.payload().to_vec();
                request.respond(response).unwrap();
            }
            assert_eq!(received_payloads, expected_payloads);
        });

        {
            let first = guest.request(host.addr(), b"active-one", Duration::from_secs(8));
            let second = guest.request(host.addr(), b"active-two", Duration::from_secs(8));
            tokio::pin!(first);
            tokio::pin!(second);
            let ready = ready_rx;
            tokio::pin!(ready);
            tokio::select! {
                _ = &mut ready => {}
                result = &mut first => panic!("first request completed before release: {result:?}"),
                result = &mut second => panic!("second request completed before release: {result:?}"),
            }

            let outbound_overflow = tokio::time::timeout(
                Duration::from_millis(100),
                guest.request(host.addr(), b"third-outbound", Duration::from_secs(2)),
            )
            .await
            .expect("NativeNode.request must reject outbound overflow promptly")
            .unwrap_err();
            assert!(
                outbound_overflow
                    .to_string()
                    .contains("Peer outbound stream concurrency limit exceeded")
            );

            let mut queued = Vec::with_capacity(MAX_CONCURRENT_HEADERS_PER_CONNECTION);
            for index in 0..MAX_CONCURRENT_HEADERS_PER_CONNECTION {
                let endpoint = guest.endpoint.clone();
                let address = host.addr();
                queued.push(tokio::spawn(async move {
                    rpc_roundtrip(
                        &endpoint,
                        address,
                        RPC_ALPN,
                        format!("queued-{index}").as_bytes(),
                    )
                    .await
                }));
            }
            let budgets = host.peer_budgets.budgets_for(guest.endpoint_id()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while budgets.inbound_waiters.available_permits() != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("all bounded inbound queue entries should be reserved");

            let overflow_endpoint = guest.endpoint.clone();
            let overflow_address = host.addr();
            let overflow = tokio::time::timeout(
                Duration::from_secs(2),
                rpc_roundtrip(
                    &overflow_endpoint,
                    overflow_address,
                    RPC_ALPN,
                    b"overflow-must-not-be-read",
                ),
            )
            .await
            .expect("overflow should be rejected promptly");
            assert!(overflow.is_err(), "queue overflow must reset the stream");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), host.rpc_inbox().receive())
                    .await
                    .is_err(),
                "queued payloads must not enter the application inbox before capacity"
            );

            release_tx.send(()).unwrap();
            assert_eq!(first.await.unwrap(), b"active-one-reply");
            assert_eq!(second.await.unwrap(), b"active-two-reply");
            for (index, queued) in queued.into_iter().enumerate() {
                assert_eq!(
                    queued.await.unwrap().unwrap(),
                    format!("queued-{index}").as_bytes()
                );
            }
        }
        responder.await.unwrap();
        guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn rpc_queued_stream_releases_queue_reservation_when_connection_closes() {
        let guest = NativeNode::start(Some([75; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(Some([76; 32]), vec![guest.endpoint_id()])
            .await
            .unwrap();
        let budgets = host.peer_budgets.budgets_for(guest.endpoint_id()).unwrap();
        let first = budgets.inbound.clone().acquire_owned().await.unwrap();
        let second = budgets.inbound.clone().acquire_owned().await.unwrap();

        let connection = guest.endpoint.connect(host.addr(), RPC_ALPN).await.unwrap();
        let (mut send, _receive) = connection.open_bi().await.unwrap();
        send.write_all(b"queued-until-close").await.unwrap();
        send.finish().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while budgets.inbound_waiters.available_permits()
                == MAX_CONCURRENT_HEADERS_PER_CONNECTION
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("stream should enter bounded queue");

        connection.close(0u32.into(), b"cancel queued request");
        tokio::time::timeout(Duration::from_secs(2), async {
            while budgets.inbound_waiters.available_permits()
                != MAX_CONCURRENT_HEADERS_PER_CONNECTION
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("closing the connection should release its queue reservation");

        drop(first);
        drop(second);
        guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn rpc_stream_keeps_peer_budget_alive_after_connection_handler_closes() {
        let guest = NativeNode::start(Some([77; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(Some([78; 32]), vec![guest.endpoint_id()])
            .await
            .unwrap();
        let connection = guest.endpoint.connect(host.addr(), RPC_ALPN).await.unwrap();
        let (mut send, _receive) = connection.open_bi().await.unwrap();
        send.write_all(b"held-application-request").await.unwrap();
        send.finish().unwrap();
        let request = tokio::time::timeout(Duration::from_secs(2), host.rpc_inbox().receive())
            .await
            .unwrap()
            .unwrap();
        let budgets = host.peer_budgets.budgets_for(guest.endpoint_id()).unwrap();
        assert_eq!(budgets.inbound.available_permits(), 1);
        let weak_budgets = Arc::downgrade(&budgets);
        drop(budgets);

        connection.close(0u32.into(), b"disconnect while request is handled");
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_budgets.strong_count() >= 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("connection handler should end after peer disconnect");
        assert_eq!(
            weak_budgets.strong_count(),
            1,
            "the in-flight application response must retain the peer budget"
        );

        let reconnected_budgets = host.peer_budgets.budgets_for(guest.endpoint_id()).unwrap();
        assert!(
            Weak::ptr_eq(&weak_budgets, &Arc::downgrade(&reconnected_budgets)),
            "a reconnect must reuse the budget still held by the in-flight request"
        );
        assert_eq!(reconnected_budgets.inbound.available_permits(), 1);
        drop(reconnected_budgets);
        drop(request);
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_budgets.strong_count() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("completed stream should let the idle peer budget expire");

        guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn pairing_stream_resets_at_header_and_kind_limits_without_harming_another_peer() {
        let first_guest = NativeNode::start(Some([51; 32]), vec![]).await.unwrap();
        let second_guest = NativeNode::start(Some([52; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(
            Some([53; 32]),
            vec![first_guest.endpoint_id(), second_guest.endpoint_id()],
        )
        .await
        .unwrap();
        let first_session = first_guest
            .connect_browser(host.addr(), Duration::from_secs(5))
            .await
            .unwrap();
        let second_session = second_guest
            .connect_browser(host.addr(), Duration::from_secs(5))
            .await
            .unwrap();
        let inbox = host.rpc_inbox();
        let responder = tokio::spawn(async move {
            let header_probe = inbox.receive().await.unwrap();
            assert_eq!(header_probe.payload(), b"oversized-header");
            header_probe
                .respond(vec![b'{'; MAX_PAIRING_HEADER_BYTES + 1])
                .unwrap();

            let kind_probe = inbox.receive().await.unwrap();
            assert_eq!(kind_probe.payload(), b"oversized-proof-frame");
            let proof_wire_limit = pairing_frame_budget("mesh-proof-page-v1")
                .unwrap()
                .max_wire_bytes;
            let mut oversized_proof =
                PairingCodec::encode("mesh-proof-page-v1", "secret", &[]).unwrap();
            oversized_proof.resize(proof_wire_limit + 1, 0);
            kind_probe.respond(oversized_proof).unwrap();

            let healthy = inbox.receive().await.unwrap();
            assert_eq!(healthy.payload(), b"healthy-peer");
            healthy
                .respond(PairingCodec::encode("sync-heartbeat-ack", "secret", &[]).unwrap())
                .unwrap();
        });

        let header_error = first_session
            .exchange_pairing(b"oversized-header", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            header_error
                .to_string()
                .contains("Pairing header exceeds ingress limit")
        );
        let kind_error = first_session
            .exchange_pairing(b"oversized-proof-frame", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            kind_error
                .to_string()
                .contains("Pairing frame exceeds ingress limit")
        );
        let healthy_ack = second_session
            .exchange_pairing(b"healthy-peer", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            PairingCodec::inspect(&healthy_ack).unwrap().frame_type,
            "sync-heartbeat-ack"
        );

        responder.await.unwrap();
        first_session.close();
        second_session.close();
        first_guest.close().await.unwrap();
        second_guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn pairing_exchange_accepts_empty_noop_ack_but_rejects_truncated_header() {
        let guest = NativeNode::start(Some([61; 32]), vec![]).await.unwrap();
        let host = NativeNode::start(Some([62; 32]), vec![guest.endpoint_id()])
            .await
            .unwrap();
        let session = guest
            .connect_browser(host.addr(), Duration::from_secs(5))
            .await
            .unwrap();
        let inbox = host.rpc_inbox();
        let responder = tokio::spawn(async move {
            let noop = inbox.receive().await.unwrap();
            assert_eq!(noop.payload(), b"noop");
            noop.respond(Vec::new()).unwrap();

            let truncated = inbox.receive().await.unwrap();
            assert_eq!(truncated.payload(), b"truncated");
            truncated.respond(b"{\"header\"".to_vec()).unwrap();

            let valid = inbox.receive().await.unwrap();
            assert_eq!(valid.payload(), b"valid");
            valid
                .respond(PairingCodec::encode("sync-heartbeat-ack", "secret", &[]).unwrap())
                .unwrap();
        });

        assert!(
            session
                .exchange_pairing(b"noop", Duration::from_secs(5))
                .await
                .unwrap()
                .is_empty()
        );
        let truncated = session
            .exchange_pairing(b"truncated", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(truncated.to_string().contains("Pairing header incomplete"));
        let valid = session
            .exchange_pairing(b"valid", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            PairingCodec::inspect(&valid).unwrap().frame_type,
            "sync-heartbeat-ack"
        );

        responder.await.unwrap();
        session.close();
        guest.close().await.unwrap();
        host.close().await.unwrap();
    }

    #[tokio::test]
    async fn unlisted_browser_sync_can_reach_signed_admission_without_blob_access() {
        let guest = NativeNode::start(Some([31; 32]), vec![]).await.unwrap();
        let host = NativeNode::start_with_options(NativeNodeOptions {
            secret: Some([32; 32]),
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            relay_mode: RelayMode::Disabled,
            accept_unlisted_browser_rpc: true,
            ..NativeNodeOptions::default()
        })
        .await
        .unwrap();
        assert!(!host.is_peer_authorized(&guest.endpoint_id()));
        let (decision_sender, mut decisions) = mpsc::unbounded_channel();
        *host.access_decisions.lock().await = Some(decision_sender);

        let inbox = host.rpc_inbox();
        let responder = tokio::spawn(async move {
            let request = tokio::time::timeout(Duration::from_secs(5), inbox.receive())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request.payload(), b"signed-admission");
            request.respond(b"admitted".to_vec()).unwrap();
        });
        let browser = guest
            .connect_browser(host.addr(), Duration::from_secs(5))
            .await
            .unwrap();
        let browser_decision = tokio::time::timeout(Duration::from_secs(5), decisions.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            browser_decision,
            AccessDecision {
                remote: guest.endpoint_id(),
                alpn: BROWSER_RPC_ALPN.to_vec(),
                accepted: true,
            }
        );
        assert_eq!(
            browser
                .exchange(b"signed-admission", Duration::from_secs(5))
                .await
                .unwrap(),
            b"admitted"
        );
        responder.await.unwrap();
        let blobs = guest
            .endpoint
            .connect(host.addr(), BLOBS_ALPN)
            .await
            .unwrap();
        if let Ok((mut send, _receive)) = blobs.open_bi().await {
            send.write_all(b"unauthorized blob request").await.unwrap();
            send.finish().unwrap();
        }
        let blobs_decision = tokio::time::timeout(Duration::from_secs(5), decisions.recv())
            .await
            .unwrap();
        assert_eq!(
            blobs_decision.unwrap(),
            AccessDecision {
                remote: guest.endpoint_id(),
                alpn: BLOBS_ALPN.to_vec(),
                accepted: false,
            }
        );
        drop(blobs);
        browser.close();
        guest.close().await.unwrap();
        host.close().await.unwrap();
    }
}
