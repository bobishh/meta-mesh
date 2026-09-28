use std::{
    error::Error,
    fmt, io,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use tokio::sync::Mutex;

use crate::{NativeBrowserConnection, NativeNode, NativeScopeService, NativeScopeServiceHost};

const MAX_SYNC_REPLY_ROUNDS: usize = 128;
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
    let Some(request) = node.rpc_inbox().receive().await else {
        return Ok(false);
    };
    let response = service.lock().await.receive(
        &request.remote_endpoint_id().to_string(),
        request.payload(),
        now_ms,
    )?;
    request
        .respond(response.unwrap_or_default())
        .map_err(|error| format!("Send native scope response: {error}"))?;
    Ok(true)
}

/// Serve frames opened by a browser on the already authenticated outbound
/// connection. The browser associates scope admission with this connection.
pub async fn serve_scope_connection<H: NativeScopeServiceHost>(
    connection: &NativeBrowserConnection,
    service: &Mutex<NativeScopeService<H>>,
    remote_id: &str,
    clock: impl Fn() -> Result<i128, String>,
) -> Result<(), String> {
    loop {
        let request = connection
            .accept()
            .await
            .map_err(|error| format!("Receive native scope frame: {error}"))?;
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
            for round in 0..MAX_SYNC_REPLY_ROUNDS {
                let Some(frame) = next.take() else { break };
                let kind = frame_kind(&frame);
                let exchange_started = std::time::Instant::now();
                if trace {
                    eprintln!("trace.sync event=publish.frame.start id={publish_id} workspace={} route={} index={frame_index} round={round} kind={kind} bytes={} deadline_ms={}", short(workspace_id), short(remote_id), frame.len(), timeout.as_millis());
                }
                let reply = connection.exchange(&frame, timeout).await.map_err(|error| {
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
            "trace.sync event=publish.end id={publish_id} workspace={} route={} result={} elapsed_ms={}",
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
