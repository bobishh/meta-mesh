use std::time::Duration;

use iroh::EndpointAddr;
use tokio::sync::Mutex;

use crate::{NativeNode, NativeScopeService, NativeScopeServiceHost};

const MAX_SYNC_REPLY_ROUNDS: usize = 128;

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

/// Publish the Rust scope plan over the same Iroh RPC streams as Match.
/// Automerge replies may produce another frame; drain that bounded exchange
/// before claiming the publish completed.
pub async fn publish_scope_to<H: NativeScopeServiceHost>(
    node: &NativeNode,
    service: &Mutex<NativeScopeService<H>>,
    workspace_id: &str,
    remote: EndpointAddr,
    now_ms: i128,
    timeout: Duration,
) -> Result<(), String> {
    let remote_id = remote.id.to_string();
    let plan = service
        .lock()
        .await
        .prepare_publish(workspace_id, &remote_id, now_ms)?;
    let mut frames = Vec::with_capacity(plan.control_frames.len() + 1);
    if let Some(document) = plan.document_frame {
        frames.push(document);
    }
    frames.extend(plan.control_frames);
    let sent = async {
        for frame in frames {
            let mut next = Some(frame);
            for _ in 0..MAX_SYNC_REPLY_ROUNDS {
                let Some(frame) = next.take() else { break };
                let reply = node
                    .request(remote.clone(), &frame, timeout)
                    .await
                    .map_err(|error| format!("Publish native scope frame: {error}"))?;
                if reply.is_empty() {
                    break;
                }
                next = service.lock().await.receive(&remote_id, &reply, now_ms)?;
            }
            if next.is_some() {
                return Err("Native scope sync exceeded reply limit".to_string());
            }
        }
        Ok(())
    }
    .await;
    service.lock().await.finish_publish(
        workspace_id,
        &remote_id,
        &plan.control_snapshot,
        sent.is_ok(),
    )?;
    sent
}
