#[path = "support/tlc_graph.rs"]
mod tlc_graph;
use meta_mesh_core::{
    MeshRuntimeState, MeshSessionLifecycleState, SessionAdmission, SessionCandidate,
    SessionDirection, SessionKey,
};
use std::collections::{BTreeMap, BTreeSet};
use tlc_graph::{Graph, action};

#[test]
#[ignore = "requires freshly generated TLC graph; executed by formal/check.sh"]
fn tlc_session_edges_conform_to_rust() {
    let graph = Graph::load("MESH_TLC_SESSION_GRAPH");
    for trace in graph.traces() {
        let mut lifecycle = MeshSessionLifecycleState::default();
        let mut runtime = MeshRuntimeState::default();
        let mut generations = BTreeMap::new();
        let mut open = BTreeSet::new(); // host effects returned by Rust
        for edge in &trace {
            let (name, args) = action(&edge.action);
            let key = SessionKey {
                workspace_id: "board".into(),
                device_id: "same-device".into(),
                instance_id: args[0].into(),
            };
            let generation: u64 = args[1].parse().unwrap();
            let id = format!("{}:{generation}", args[0]);
            match name {
                "Register" => {
                    let admission = runtime.admit_session(
                        SessionCandidate {
                            key: key.clone(),
                            connection_id: id.clone(),
                            remote_issued_at: "2026-09-25T00:00:00Z".into(),
                            remote_route_sequence: Some(generation),
                            direction: SessionDirection::Outgoing,
                        },
                        SessionDirection::Outgoing,
                    );
                    let SessionAdmission::Accepted {
                        generation: actual, ..
                    } = admission
                    else {
                        panic!("rejected {:?}", edge)
                    };
                    generations.insert(generation, actual);
                    lifecycle
                        .register(key.clone(), id.clone(), actual, 0)
                        .unwrap();
                    open.insert(id);
                }
                "CleanupOlder" => {
                    let actual = generations[&generation];
                    let decision = lifecycle.evict(&key, actual);
                    if decision.should_close {
                        open.remove(decision.connection_id.as_ref().unwrap());
                    }
                    // Exercise the runtime generation guard even on delayed/repeated cleanup.
                    runtime.remove_session(&key, actual);
                }
                _ => panic!("Unmapped TLC action: {}", edge.action),
            }
            let state = &graph.states[&edge.to];
            let expected: BTreeSet<_> = state["current"]
                .as_object()
                .unwrap()
                .iter()
                .filter_map(|(key, g)| {
                    (g.as_u64().unwrap() != 0).then(|| format!("{key}:{}", g.as_u64().unwrap()))
                })
                .collect();
            let actual: BTreeSet<_> = lifecycle
                .publish_plan()
                .into_iter()
                .flat_map(|p| p.connection_ids)
                .collect();
            assert_eq!(
                actual, expected,
                "lifecycle mismatch; trace={trace:?}; edge={edge:?}"
            );
            let actual: BTreeSet<_> = runtime
                .sessions()
                .map(|s| s.connection_id.clone())
                .collect();
            assert_eq!(
                actual, expected,
                "runtime mismatch; trace={trace:?}; edge={edge:?}"
            );
            let expected_open: BTreeSet<_> = state["open"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    format!(
                        "{}:{}",
                        pair[0].as_str().unwrap(),
                        pair[1].as_u64().unwrap()
                    )
                })
                .collect();
            assert_eq!(
                open, expected_open,
                "transport effects mismatch; trace={trace:?}"
            );
        }
    }
    println!(
        "Rust sessions: {} TLC states, {} edges replayed",
        graph.states.len(),
        graph.edges.len()
    );
}
