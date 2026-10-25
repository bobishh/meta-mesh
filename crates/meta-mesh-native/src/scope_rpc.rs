use std::{
    error::Error,
    fmt, io,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use tokio::sync::Mutex;

use crate::{NativeBrowserConnection, NativeNode, NativeScopeService, NativeScopeServiceHost};

const MAX_SYNC_REPLY_ROUNDS: usize = 128;
const MAX_PROOF_REPLY_ROUNDS: usize = 4096;
const OUTBOUND_HANDSHAKE_ADMISSION_WAIT: Duration = Duration::from_secs(12);
static NEXT_PUBLISH_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopePublishFailureKind {
    Prepare,
    ExchangeTimeout,
    Exchange,
    Receive,
    ReplyLimit,
}

#[derive(Debug)]
pub struct ScopePublishError {
    pub kind: ScopePublishFailureKind,
    pub stage: &'static str,
    message: String,
}

impl ScopePublishError {
    fn new(kind: ScopePublishFailureKind, stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            stage,
            message: message.into(),
        }
    }

    pub fn is_exchange_timeout(&self) -> bool {
        self.kind == ScopePublishFailureKind::ExchangeTimeout
    }
}

impl fmt::Display for ScopePublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.stage, self.message)
    }
}

impl Error for ScopePublishError {}

/// Serve one browser-compatible Iroh stream through signed native admission.
/// A rejected frame drops the request, causing the transport to reset it.
pub async fn serve_scope_request<H: NativeScopeServiceHost>(
    node: &NativeNode,
    service: &Mutex<NativeScopeService<H>>,
    now_ms: i128,
) -> Result<bool, String> {
    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    let inbox = node.rpc_inbox();
    let request = inbox.receive();
    tokio::pin!(request);
    let request = loop {
        tokio::select! {
            request = &mut request => break request,
            _ = maintenance.tick() => {
                service.lock().await.expire_pending_transfers();
            }
        }
    };
    let Some(request) = request else {
        return Ok(false);
    };
    let remote_endpoint = request.remote_endpoint_id().to_string();
    let response =
        receive_scope_request_frame(service, &remote_endpoint, request.payload(), now_ms).await?;
    request
        .respond(response.unwrap_or_default())
        .map_err(|error| format!("Send native scope response: {error}"))?;
    Ok(true)
}

async fn receive_scope_request_frame<H: NativeScopeServiceHost>(
    service: &Mutex<NativeScopeService<H>>,
    remote_endpoint: &str,
    frame: &[u8],
    now_ms: i128,
) -> Result<Option<Vec<u8>>, String> {
    let received_at = std::time::Instant::now();
    let first = service.lock().await.receive(remote_endpoint, frame, now_ms);
    let Err(error) = first else {
        return first;
    };
    if error != "Unauthenticated mesh peer" {
        return Err(error);
    }

    let trace = std::env::var_os("LIGHTHOUSE_TRACE_SYNC").is_some();
    let completion = service
        .lock()
        .await
        .pending_outbound_handshake_for_frame(frame, remote_endpoint);
    if trace {
        eprintln!(
            "trace.sync event=rpc.unauthenticated route={} pending={}",
            short(remote_endpoint),
            completion.is_some()
        );
    }

    if let Some(mut completion) = completion {
        if !*completion.borrow() {
            let waited =
                tokio::time::timeout(OUTBOUND_HANDSHAKE_ADMISSION_WAIT, completion.changed()).await;
            if trace {
                eprintln!(
                    "trace.sync event=rpc.handshake_wait route={} result={}",
                    short(remote_endpoint),
                    if waited.is_ok() {
                        "completed"
                    } else {
                        "timeout"
                    }
                );
            }
        }
    }

    // Retry once after completion, cancellation, or timeout. This also closes
    // the narrow race where admission lands between the first error and lookup.
    let elapsed_ms = i128::try_from(received_at.elapsed().as_millis()).unwrap_or(i128::MAX);
    let retry_now_ms = now_ms.saturating_add(elapsed_ms);
    let retry = service
        .lock()
        .await
        .receive(remote_endpoint, frame, retry_now_ms);
    if trace {
        eprintln!(
            "trace.sync event=rpc.admission_retry route={} result={}",
            short(remote_endpoint),
            if retry.is_ok() {
                "admitted"
            } else {
                "rejected"
            }
        );
    }
    retry
}

/// Serve frames opened by a browser on the already authenticated outbound
/// connection. The browser associates scope admission with this connection.
pub async fn serve_scope_connection<H: NativeScopeServiceHost>(
    connection: &NativeBrowserConnection,
    service: &Mutex<NativeScopeService<H>>,
    remote_id: &str,
    clock: impl Fn() -> Result<i128, String>,
) -> Result<(), String> {
    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    loop {
        let request = connection.accept_pairing();
        tokio::pin!(request);
        let request = loop {
            tokio::select! {
                request = &mut request => break request
                    .map_err(|error| format!("Receive native scope frame: {error}"))?,
                _ = maintenance.tick() => {
                    service.lock().await.expire_pending_transfers();
                }
            }
        };
        let response = service
            .lock()
            .await
            .receive(remote_id, request.payload(), clock()?)?;
        request
            .respond(response.as_deref().unwrap_or_default())
            .await
            .map_err(|error| format!("Send native scope response: {error}"))?;
    }
}

/// Publish the Rust scope plan over the same Iroh RPC streams as Match.
/// Automerge replies may produce another frame; drain that bounded exchange
/// before claiming the publish completed.
pub async fn publish_scope_to<H: NativeScopeServiceHost>(
    connection: &NativeBrowserConnection,
    service: &Mutex<NativeScopeService<H>>,
    workspace_id: &str,
    remote_id: &str,
    now_ms: i128,
    timeout: Duration,
) -> Result<(), ScopePublishError> {
    let trace = std::env::var_os("LIGHTHOUSE_TRACE_SYNC").is_some();
    let publish_id = NEXT_PUBLISH_ID.fetch_add(1, Ordering::Relaxed);
    let started = std::time::Instant::now();
    let plan_started = std::time::Instant::now();
    let plan = service
        .lock()
        .await
        .prepare_publish(workspace_id, remote_id, now_ms)
        .map_err(|error| {
            ScopePublishError::new(ScopePublishFailureKind::Prepare, "prepare", error)
        })?;
    if trace {
        eprintln!(
            "trace.sync event=publish.plan id={publish_id} workspace={} route={} elapsed_ms={} document={} control_frames={} deadline_ms={}",
            short(workspace_id),
            short(remote_id),
            plan_started.elapsed().as_millis(),
            plan.document_frame.is_some(),
            plan.control_frames.len(),
            timeout.as_millis()
        );
    }
    let mut frames = Vec::with_capacity(plan.control_frames.len() + 1);
    if let Some(document) = plan.document_frame {
        frames.push(document);
    }
    frames.extend(plan.control_frames);
    let sent = async {
        for (frame_index, frame) in frames.into_iter().enumerate() {
            let mut next = Some(frame);
            let mut sync_rounds = 0;
            let mut proof_rounds = 0;
            for round in 0..MAX_SYNC_REPLY_ROUNDS + MAX_PROOF_REPLY_ROUNDS {
                let Some(frame) = next.take() else { break };
                let kind = frame_kind(&frame);
                consume_reply_budget(&kind, &mut sync_rounds, &mut proof_rounds)?;
                let exchange_started = std::time::Instant::now();
                if trace {
                    eprintln!("trace.sync event=publish.frame.start id={publish_id} workspace={} route={} index={frame_index} round={round} kind={kind} bytes={} deadline_ms={}", short(workspace_id), short(remote_id), frame.len(), timeout.as_millis());
                }
        let reply = connection.exchange_pairing(&frame, timeout).await.map_err(|error| {
                    let kind = if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::TimedOut) {
                        ScopePublishFailureKind::ExchangeTimeout
                    } else {
                        ScopePublishFailureKind::Exchange
                    };
                    if trace {
                        let failure_kind = frame_kind_name(kind);
                        eprintln!("trace.sync event=publish.frame.failed id={publish_id} workspace={} route={} index={frame_index} round={round} kind={failure_kind} stage=exchange elapsed_ms={} deadline_ms={}", short(workspace_id), short(remote_id), exchange_started.elapsed().as_millis(), timeout.as_millis());
                    }
                    ScopePublishError::new(kind, "exchange", error.to_string())
                })?;
                if trace {
                    eprintln!("trace.sync event=publish.frame.response id={publish_id} workspace={} route={} index={frame_index} round={round} kind={kind} response_bytes={} elapsed_ms={}", short(workspace_id), short(remote_id), reply.len(), exchange_started.elapsed().as_millis());
                }
                if reply.is_empty() {
                    break;
                }
                next = service.lock().await.receive(remote_id, &reply, now_ms)
                    .map_err(|error| ScopePublishError::new(ScopePublishFailureKind::Receive, "reply_receive", error))?;
            }
            if next.is_some() {
                return Err(ScopePublishError::new(ScopePublishFailureKind::ReplyLimit, "reply_limit", "Native scope sync exceeded reply limit"));
            }
        }
        Ok(())
    }
    .await;
    let aborted_incomplete_receive = if sent
        .as_ref()
        .is_err_and(ScopePublishError::is_exchange_timeout)
    {
        service
            .lock()
            .await
            .abort_incomplete_document_receive(workspace_id, remote_id)
            .unwrap_or(false)
    } else {
        false
    };
    service
        .lock()
        .await
        .finish_publish(
            workspace_id,
            remote_id,
            &plan.control_snapshot,
            sent.is_ok(),
        )
        .map_err(|error| {
            ScopePublishError::new(ScopePublishFailureKind::Prepare, "finish", error)
        })?;
    if trace {
        eprintln!(
            "trace.sync event=publish.end id={publish_id} workspace={} route={} result={} aborted_incomplete_receive={aborted_incomplete_receive} elapsed_ms={}",
            short(workspace_id),
            short(remote_id),
            if sent.is_ok() { "ok" } else { "failed" },
            started.elapsed().as_millis()
        );
    }
    sent
}

fn short(value: &str) -> &str {
    value.get(..8).unwrap_or(value)
}

fn frame_kind(frame: &[u8]) -> String {
    crate::PairingCodec::inspect(frame)
        .map(|header| header.frame_type)
        .unwrap_or_else(|_| "invalid".into())
}

fn frame_kind_name(kind: ScopePublishFailureKind) -> &'static str {
    match kind {
        ScopePublishFailureKind::ExchangeTimeout => "exchange_timeout",
        ScopePublishFailureKind::Exchange => "exchange_error",
        ScopePublishFailureKind::Prepare => "prepare_error",
        ScopePublishFailureKind::Receive => "receive_error",
        ScopePublishFailureKind::ReplyLimit => "reply_limit",
    }
}

fn consume_reply_budget(
    kind: &str,
    sync: &mut usize,
    proof: &mut usize,
) -> Result<(), ScopePublishError> {
    if kind == "mesh-proof-request-v1" || kind == "mesh-proof-page-v1" {
        *proof += 1;
        if *proof > MAX_PROOF_REPLY_ROUNDS {
            return Err(ScopePublishError::new(
                ScopePublishFailureKind::ReplyLimit,
                "proof_reply_limit",
                "Native authorization transfer exceeded reply limit",
            ));
        }
    } else {
        *sync += 1;
        if *sync > MAX_SYNC_REPLY_ROUNDS {
            return Err(ScopePublishError::new(
                ScopePublishFailureKind::ReplyLimit,
                "reply_limit",
                "Native scope sync exceeded reply limit",
            ));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeScopeCredential, NativeScopeSnapshot};
    use automerge::AutoCommit;
    use meta_mesh_core::{
        DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, PeerAdvertisementPayload,
        WorkspaceAuthority, WorkspaceWriteAuthorizationSnapshot, encode_mesh_handshake,
        public_key_from_seed, public_key_id, sign_device_certificate, sign_json_envelope,
    };
    use serde_json::{Value, json};
    use std::future::Future;

    struct Scope;

    impl crate::NativeScopeHost for Scope {
        fn snapshot(&mut self) -> Result<NativeScopeSnapshot, String> {
            panic!("heartbeat does not read scope")
        }
        fn persist_document(
            &mut self,
            _: &[u8],
            _: Option<&Value>,
            _: &[String],
        ) -> Result<(), String> {
            panic!("heartbeat does not persist a document")
        }
        fn merge_authorization(&mut self, _: &Value) -> Result<(), String> {
            panic!("heartbeat does not merge authorization")
        }
        fn merge_chat(&mut self, _: &Value) -> Result<(), String> {
            panic!("heartbeat does not merge chat")
        }
        fn merge_mesh(&mut self, _: &Value) -> Result<(), String> {
            panic!("heartbeat does not merge mesh")
        }
        fn merge_durable_batch(&mut self, _: &[u8]) -> Result<(), String> {
            panic!("heartbeat does not merge a durable batch")
        }
        fn merge_owner_offer(&mut self, _: &[u8]) -> Result<(), String> {
            panic!("heartbeat does not merge an owner offer")
        }
        fn receive_gossip(&mut self, _: &[u8]) -> Result<(), String> {
            panic!("heartbeat does not receive gossip")
        }
    }

    struct Host {
        snapshot: WorkspaceWriteAuthorizationSnapshot,
    }

    impl NativeScopeServiceHost for Host {
        type ScopeHost = Scope;

        fn local_device_id(&self) -> &str {
            "local-device"
        }
        fn credential(&mut self, secret: &str) -> Result<Option<NativeScopeCredential>, String> {
            Ok((secret == "secret").then(|| NativeScopeCredential {
                workspace_id: "board".into(),
                secret: secret.into(),
            }))
        }
        fn prepare_handshake(
            &mut self,
            _: &str,
            _: &meta_mesh_core::MeshHandshake,
        ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String> {
            unreachable!("this test only completes an outbound handshake")
        }
        fn authority(&mut self, _: &str) -> Result<WorkspaceWriteAuthorizationSnapshot, String> {
            Ok(self.snapshot.clone())
        }
        fn outgoing_handshake(&mut self, _: &str) -> Result<Value, String> {
            unreachable!("this test supplies a response directly")
        }
        fn open_scope(&mut self, _: &meta_mesh_core::MeshPeerAdmission) -> Result<Scope, String> {
            Ok(Scope)
        }
    }

    fn owner_handshake_response(issued_at: &str) -> (WorkspaceWriteAuthorizationSnapshot, Vec<u8>) {
        let person_public_key = public_key_from_seed(&[1; 32]).unwrap();
        let person_id = public_key_id(&person_public_key).unwrap();
        let device_public_key = public_key_from_seed(&[2; 32]).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &[1; 32],
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let owner = WorkspaceAuthority {
            person_id: person_id.clone(),
            public_key: person_public_key,
            certificates: vec![certificate.clone()],
        };
        let advertisement_payload = PeerAdvertisementPayload {
            kind: "peer-advertisement".into(),
            version: 1,
            workspace_id: "board".into(),
            person_id,
            device_id: device_id.clone(),
            instance_id: Some("slot-1".into()),
            endpoint: "remote-endpoint".into(),
            issued_at: issued_at.into(),
            route_sequence: None,
            expires_at: None,
            device_name: None,
            user_agent: None,
        };
        let advertisement = sign_json_envelope(
            &[2; 32],
            serde_json::to_value(advertisement_payload).unwrap(),
            &device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let handshake = json!({
            "workspaceId": "board",
            "peer": {
                "advertisement": advertisement,
                "publicKey": owner.public_key,
                "certificates": owner.certificates,
            },
            "capabilities": ["iroh-gossip-v1", "automerge-sync-v1", "device-revocation-v1"],
        });
        let snapshot = WorkspaceWriteAuthorizationSnapshot {
            workspace_id: "board".into(),
            genesis_owner: owner.clone(),
            genesis_epoch: 1,
            expected_current_owner: owner,
            document: AutoCommit::new().save(),
            ownership_transfers: vec![],
            succession_claims: vec![],
            revocations: vec![],
            device_revocations: vec![],
            departures: vec![],
        };
        let response =
            encode_mesh_handshake("mesh-handshake-response", "secret", handshake).unwrap();
        (snapshot, response)
    }

    #[test]
    fn proof_pages_exceed_legacy_rounds_without_weakening_either_bound() {
        let (mut sync, mut proof) = (0, 0);
        for _ in 0..MAX_PROOF_REPLY_ROUNDS {
            consume_reply_budget("mesh-proof-page-v1", &mut sync, &mut proof).unwrap();
        }
        for _ in 0..MAX_SYNC_REPLY_ROUNDS {
            consume_reply_budget("mesh-automerge-sync", &mut sync, &mut proof).unwrap();
        }
        assert_eq!((sync, proof), (128, 4096));
        assert!(consume_reply_budget("mesh-proof-request-v1", &mut sync, &mut proof).is_err());
        assert!(consume_reply_budget("mesh-control-sync", &mut sync, &mut proof).is_err());
    }

    #[tokio::test]
    async fn first_scope_rpc_waits_for_exact_handshake_admission() {
        let (snapshot, response) = owner_handshake_response("1970-01-01T00:00:00Z");
        let service = Mutex::new(NativeScopeService::new(Host { snapshot }));
        let pending = service
            .lock()
            .await
            .begin_outbound_handshake("board", "remote-endpoint")
            .unwrap();
        let frame = crate::PairingCodec::encode("sync-heartbeat", "secret", &[]).unwrap();
        let waiter = receive_scope_request_frame(&service, "remote-endpoint", &frame, 0);
        tokio::pin!(waiter);
        let is_waiting = std::future::poll_fn(|context| {
            std::task::Poll::Ready(waiter.as_mut().poll(context).is_pending())
        })
        .await;
        assert!(
            is_waiting,
            "first RPC should wait while its exact handshake is pending"
        );

        service
            .lock()
            .await
            .complete_connect("board", "secret", "remote-endpoint", &response, 0)
            .unwrap();
        assert!(
            service
                .lock()
                .await
                .pending_outbound_handshake("board", "remote-endpoint")
                .is_none()
        );
        let acknowledgement = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        let acknowledgement = acknowledgement.expect("heartbeat must be acknowledged");
        assert_eq!(
            crate::PairingCodec::inspect(&acknowledgement)
                .unwrap()
                .frame_type,
            "sync-heartbeat-ack"
        );
        drop(pending);
    }

    #[tokio::test]
    async fn admission_retry_advances_time_before_refreshing_route_freshness() {
        let (snapshot, response) = owner_handshake_response("1969-12-02T00:00:00.001Z");
        let service = Mutex::new(NativeScopeService::new(Host { snapshot }));
        let pending = service
            .lock()
            .await
            .begin_outbound_handshake("board", "remote-endpoint")
            .unwrap();
        let frame = crate::PairingCodec::encode("sync-heartbeat", "secret", &[]).unwrap();
        let waiter = receive_scope_request_frame(&service, "remote-endpoint", &frame, 0);
        tokio::pin!(waiter);
        let is_waiting = std::future::poll_fn(|context| {
            std::task::Poll::Ready(waiter.as_mut().poll(context).is_pending())
        })
        .await;
        assert!(is_waiting);

        service
            .lock()
            .await
            .complete_connect("board", "secret", "remote-endpoint", &response, 0)
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap();
        assert_eq!(result.unwrap_err(), "Unauthenticated mesh peer");
        drop(pending);
    }

    #[tokio::test]
    async fn unknown_peer_scope_rpc_is_rejected_without_waiting() {
        let (snapshot, _) = owner_handshake_response("1970-01-01T00:00:00Z");
        let service = Mutex::new(NativeScopeService::new(Host { snapshot }));
        let frame = crate::PairingCodec::encode("sync-heartbeat", "secret", &[]).unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            receive_scope_request_frame(&service, "unknown-endpoint", &frame, 0),
        )
        .await
        .expect("unknown peers must not use the handshake wait");
        assert_eq!(result.unwrap_err(), "Unauthenticated mesh peer");
    }

    #[tokio::test]
    async fn failed_outbound_handshake_releases_waiting_rpc_as_unauthenticated() {
        let (snapshot, _) = owner_handshake_response("1970-01-01T00:00:00Z");
        let service = Mutex::new(NativeScopeService::new(Host { snapshot }));
        let pending = service
            .lock()
            .await
            .begin_outbound_handshake("board", "remote-endpoint")
            .unwrap();
        let frame = crate::PairingCodec::encode("sync-heartbeat", "secret", &[]).unwrap();
        let waiter = receive_scope_request_frame(&service, "remote-endpoint", &frame, 0);
        tokio::pin!(waiter);
        let is_waiting = std::future::poll_fn(|context| {
            std::task::Poll::Ready(waiter.as_mut().poll(context).is_pending())
        })
        .await;
        assert!(
            is_waiting,
            "RPC should wait only while handshake is pending"
        );

        drop(pending);
        let result = tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("failed handshake must release the pending RPC");
        assert_eq!(result.unwrap_err(), "Unauthenticated mesh peer");
    }
}
