#[path = "support/tlc_graph.rs"]
mod tlc_graph;
use meta_mesh_core::{
    BatchDeliveryAction, DeviceBatch, DeviceChange, DurableBatchAckPayload, MeshBatchDeliveryFlow,
    durable_ack_matches, public_key_from_seed, public_key_id, sign_durable_batch_ack,
    verify_durable_batch_ack,
};
use tlc_graph::Graph;

#[test]
#[ignore = "requires freshly generated TLC graph; executed by formal/check.sh"]
fn tlc_delivery_edges_conform_to_rust() {
    let graph = Graph::load("MESH_TLC_DELIVERY_GRAPH");
    let batch = DeviceBatch {
        protocol_version: 1,
        scope_id: "scope".into(),
        document_id: "doc".into(),
        batch_id: "batch".into(),
        changes: ["h1", "h2"]
            .into_iter()
            .map(|h| DeviceChange {
                hash: h.into(),
                bytes: vec![1],
            })
            .collect(),
    };
    let seed = [93; 32];
    let public_key = public_key_from_seed(&seed).unwrap();
    let receiver = public_key_id(&public_key).unwrap();
    for trace in graph.traces() {
        let mut flow = MeshBatchDeliveryFlow::new(
            receiver.clone(),
            vec!["route".into()],
            0.0,
            vec![0.0; trace.len() + 1],
        )
        .unwrap();
        flow.start().unwrap();
        let mut complete = false;
        let mut round = 0;
        for edge in &trace {
            if edge.action.starts_with("ReceiveAck(") {
                // TLC owns expected completion; the driver only translates its input ACK set.
                let arg = edge
                    .action
                    .strip_prefix("ReceiveAck(")
                    .unwrap()
                    .strip_suffix(')')
                    .unwrap()
                    .trim();
                let values = arg.strip_prefix('{').unwrap().strip_suffix('}').unwrap();
                let hashes: Vec<String> = values
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                let signed = sign_durable_batch_ack(
                    &seed,
                    &receiver,
                    DurableBatchAckPayload {
                        kind: "mesh-durable-batch-ack".into(),
                        version: 1,
                        scope_id: "scope".into(),
                        document_id: "doc".into(),
                        batch_id: "batch".into(),
                        receiver_device_id: receiver.clone(),
                        accepted_hashes: hashes,
                        accepted_heads: vec![],
                        committed_at: "2026-09-25T00:00:00Z".into(),
                    },
                )
                .unwrap();
                let ack = verify_durable_batch_ack(&signed, &public_key).unwrap();
                let accepted = durable_ack_matches(&ack, &batch, &receiver);
                let result = flow.route_result(round, 0, accepted, "incomplete ACK".into());
                for action in result.actions {
                    match action {
                        BatchDeliveryAction::Completed { .. } => complete = true,
                        BatchDeliveryAction::ArmRetry {
                            round: retry_round, ..
                        } => {
                            // Internal scheduling step, stuttering at the batch abstraction.
                            let retry = flow.retry_elapsed(retry_round);
                            assert!(
                                retry
                                    .actions
                                    .iter()
                                    .any(|a| matches!(a, BatchDeliveryAction::LaunchRoute { .. }))
                            );
                            round += 1;
                        }
                        BatchDeliveryAction::CancelOtherRoutes { .. } => {}
                        other => panic!("Unexpected batch effect {other:?}; trace={trace:?}"),
                    }
                }
            } else {
                assert!(
                    edge.action.starts_with("Persist(") || edge.action == "Retry",
                    "Unmapped TLC action {}",
                    edge.action
                );
            }
            assert_eq!(
                complete,
                graph.states[&edge.to]["complete"].as_bool().unwrap(),
                "Rust delivery mismatch; trace={trace:?}; edge={edge:?}"
            );
        }
    }
    println!(
        "Rust delivery: {} TLC states, {} edges replayed",
        graph.states.len(),
        graph.edges.len()
    );
}
