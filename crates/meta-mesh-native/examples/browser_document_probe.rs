use std::io::{BufRead, Write};

use meta_mesh_core::{
    AutomergeSyncEngine, AutomergeSyncFrame, MeshAuthenticatedSessions, PairingCodec,
    WorkspaceWriteAuthorizationSnapshot,
};
use meta_mesh_native::{NativeNode, NativeNodeOptions};
use serde_json::{Value, json};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeConfig {
    secret: String,
    snapshot: WorkspaceWriteAuthorizationSnapshot,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Transport accepts connections; document RPC requires a signed, endpoint-bound
    // workspace handshake before it can read or change state.
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let mut config: ProbeConfig = serde_json::from_str(&line)?;
    let node = NativeNode::start_with_options(NativeNodeOptions {
        allow_any: true,
        ..NativeNodeOptions::default()
    })
    .await?;
    let local_device_id = node.endpoint_id().to_string();
    let mut engine = AutomergeSyncEngine::new(&local_device_id, None)?;
    engine.load_document(
        &config.snapshot.workspace_id,
        "document",
        &config.snapshot.document,
    )?;
    let mut admitted = MeshAuthenticatedSessions::default();
    let (authority_tx, mut authority_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            let Ok(snapshot) = serde_json::from_str::<WorkspaceWriteAuthorizationSnapshot>(&line)
            else {
                break;
            };
            if authority_tx.send(snapshot).is_err() {
                break;
            }
        }
    });
    println!("{local_device_id}");
    std::io::stdout().flush()?;

    let inbox = node.rpc_inbox();
    loop {
        let request = tokio::select! {
            Some(snapshot) = authority_rx.recv() => {
                admitted.refresh(&snapshot,
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)?;
                config.snapshot = snapshot;
                println!("authority-updated");
                std::io::stdout().flush()?;
                continue;
            }
            Some(request) = inbox.receive() => request,
            else => break,
        };
        let remote_device_id = request.remote_endpoint_id().to_string();
        let response = (|| -> Result<Value, String> {
            let value: Value = serde_json::from_slice(request.payload())
                .map_err(|error| format!("Invalid request: {error}"))?;
            match value.get("kind").and_then(Value::as_str) {
                Some("handshake") => {
                    let frame: Vec<u8> = serde_json::from_value(
                        value.get("frame").cloned().ok_or("Missing handshake")?,
                    )
                    .map_err(|error| format!("Invalid handshake frame: {error}"))?;
                    let payload =
                        PairingCodec::decode(&frame, "mesh-handshake-request", &config.secret)?;
                    let raw: Value = serde_json::from_slice(&payload)
                        .map_err(|error| format!("Invalid handshake payload: {error}"))?;
                    let peer = admitted.admit(
                        raw,
                        &config.snapshot,
                        &remote_device_id,
                        time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
                    )?;
                    let device_id = peer.device_id.clone();
                    Ok(json!({ "deviceId": device_id }))
                }
                Some("sync") => {
                    let peer = admitted
                        .peer(&remote_device_id)
                        .ok_or("Unauthenticated mesh peer")?;
                    let frame: AutomergeSyncFrame =
                        serde_json::from_value(value.get("frame").cloned().ok_or("Missing frame")?)
                            .map_err(|error| format!("Invalid frame: {error}"))?;
                    if frame.scope_id != peer.workspace_id || frame.from_device_id != peer.device_id
                    {
                        return Err("Mesh document sender does not match admitted peer".into());
                    }
                    let result = engine.receive(&peer.device_id, frame, true, None)?;
                    serde_json::to_value(result).map_err(|error| error.to_string())
                }
                Some("read") => {
                    if admitted.peer(&remote_device_id).is_none() {
                        return Err("Unauthenticated mesh peer".into());
                    }
                    Ok(json!({ "document": engine.save_document("document")? }))
                }
                _ => Err("Unsupported request".into()),
            }
        })()
        .unwrap_or_else(|error| json!({ "error": error }));
        request.respond(serde_json::to_vec(&response)?)?;
    }
    node.close().await?;
    Ok(())
}
