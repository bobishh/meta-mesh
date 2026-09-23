use automerge::{AutoCommit, ROOT, transaction::Transactable};
use meta_mesh_core::{AutomergeSyncEngine, AutomergeSyncFrame};
use meta_mesh_native::{NativeNode, NativeNodeOptions};
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // E2E fixture only. Production admission must verify a signed workspace grant.
    let node = NativeNode::start_with_options(NativeNodeOptions {
        allow_any: true,
        ..NativeNodeOptions::default()
    })
    .await?;
    let local_device_id = node.endpoint_id().to_string();
    let mut source = AutoCommit::new();
    source.put(ROOT, "native", "from-rust")?;
    let mut engine = AutomergeSyncEngine::new(&local_device_id, None)?;
    engine.load_document("browser-native-e2e", "document", &source.save())?;
    println!("{local_device_id}");

    let inbox = node.rpc_inbox();
    while let Some(request) = inbox.receive().await {
        let remote_device_id = request.remote_endpoint_id().to_string();
        let response = (|| -> Result<Value, String> {
            let value: Value = serde_json::from_slice(request.payload())
                .map_err(|error| format!("Invalid request: {error}"))?;
            match value.get("kind").and_then(Value::as_str) {
                Some("sync") => {
                    let frame: AutomergeSyncFrame =
                        serde_json::from_value(value.get("frame").cloned().ok_or("Missing frame")?)
                            .map_err(|error| format!("Invalid frame: {error}"))?;
                    let result = engine.receive(&remote_device_id, frame, true, None)?;
                    serde_json::to_value(result).map_err(|error| error.to_string())
                }
                Some("read") => Ok(json!({ "document": engine.save_document("document")? })),
                _ => Err("Unsupported request".into()),
            }
        })()
        .unwrap_or_else(|error| json!({ "error": error }));
        request.respond(serde_json::to_vec(&response)?)?;
    }
    node.close().await?;
    Ok(())
}
