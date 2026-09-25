use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum BatchDeliveryAction {
    LaunchRoute {
        round: u32,
        route_index: u32,
    },
    ArmFallback {
        round: u32,
        delay_ms: f64,
    },
    ArmRetry {
        round: u32,
        delay_ms: f64,
    },
    CancelOtherRoutes {
        round: u32,
        route_index: u32,
    },
    CancelAllRoutes {
        round: u32,
    },
    Completed {
        round: u32,
        route_index: u32,
        attempted_route_ids: Vec<String>,
    },
    Exhausted {
        attempted_route_ids: Vec<String>,
        message: String,
    },
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeliveryUpdate {
    pub actions: Vec<BatchDeliveryAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Hash))]
enum DeliveryState {
    Ready,
    Running,
    WaitingRetry,
    Complete,
    Failed,
    Aborted,
}

/// Platform-neutral route fallback, retry, and acknowledgement state.
/// Hosts own timers, abort controllers, and route I/O.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct MeshBatchDeliveryFlow {
    target_device_id: String,
    route_ids: Vec<String>,
    fallback_delay_ms: f64,
    retry_delays_ms: Vec<f64>,
    retry_index: usize,
    round: u32,
    next_route_index: usize,
    pending: BTreeSet<usize>,
    fallback_armed: bool,
    attempted_route_ids: Vec<String>,
    failures: Vec<String>,
    state: DeliveryState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, HashMap, VecDeque};

    #[derive(Debug, Deserialize)]
    struct ExplorerEdge {
        from: String,
        to: String,
        action: String,
    }

    #[derive(Deserialize)]
    struct ExplorerGraph {
        initial: String,
        states: BTreeMap<String, Value>,
        edges: Vec<ExplorerEdge>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct DeliveryKey {
        target_device_id: String,
        route_ids: Vec<String>,
        fallback_delay_bits: u64,
        retry_delay_bits: Vec<u64>,
        retry_index: usize,
        round: u32,
        next_route_index: usize,
        pending: Vec<usize>,
        fallback_armed: bool,
        attempted_route_ids: Vec<String>,
        failures: Vec<String>,
        state: DeliveryState,
    }

    impl MeshBatchDeliveryFlow {
        fn exploration_key(&self) -> DeliveryKey {
            let Self {
                target_device_id,
                route_ids,
                fallback_delay_ms,
                retry_delays_ms,
                retry_index,
                round,
                next_route_index,
                pending,
                fallback_armed,
                attempted_route_ids,
                failures,
                state,
            } = self;
            DeliveryKey {
                target_device_id: target_device_id.clone(),
                route_ids: route_ids.clone(),
                fallback_delay_bits: fallback_delay_ms.to_bits(),
                retry_delay_bits: retry_delays_ms
                    .iter()
                    .map(|value| value.to_bits())
                    .collect(),
                retry_index: *retry_index,
                round: *round,
                next_route_index: *next_route_index,
                pending: pending.iter().copied().collect(),
                fallback_armed: *fallback_armed,
                attempted_route_ids: attempted_route_ids.clone(),
                failures: failures.clone(),
                state: *state,
            }
        }
    }

    #[derive(Debug, Clone)]
    enum ExplorerAction {
        Start,
        Fallback(u32),
        Retry(u32),
        RouteAccepted { round: u32, route: u32 },
        RouteRejected { round: u32, route: u32 },
        Abort,
    }

    impl ExplorerAction {
        fn label(&self) -> String {
            match self {
                Self::Start => "Start".into(),
                Self::Fallback(round) => format!("FallbackElapsed({round})"),
                Self::Retry(round) => format!("RetryElapsed({round})"),
                Self::RouteAccepted { round, route } => {
                    format!("RouteAccepted({round},{route})")
                }
                Self::RouteRejected { round, route } => {
                    format!("RouteRejected({round},{route})")
                }
                Self::Abort => "Abort".into(),
            }
        }
    }

    #[derive(Clone)]
    struct ExplorerNode {
        flow: MeshBatchDeliveryFlow,
        model_state: String,
        trace: Vec<String>,
    }

    fn normalized_label(label: &str) -> String {
        label.split_whitespace().collect()
    }

    fn route_number(route: &str) -> usize {
        match route {
            "route-a" => 0,
            "route-b" => 1,
            other => panic!("unexpected route {other}"),
        }
    }

    fn failure_index(failure: &str) -> usize {
        if failure.starts_with("route-a: ") {
            0
        } else if failure.starts_with("route-b: ") {
            1
        } else {
            panic!("unexpected failure {failure}")
        }
    }

    fn normalize_update(
        update: BatchDeliveryUpdate,
        flow: &MeshBatchDeliveryFlow,
        trace: &[String],
    ) -> Value {
        Value::Array(
            update
                .actions
                .into_iter()
                .map(|action| match action {
                    BatchDeliveryAction::LaunchRoute { round, route_index } => {
                        json!(["Launch", round, route_index])
                    }
                    BatchDeliveryAction::ArmFallback { round, delay_ms } => {
                        assert_eq!(delay_ms.to_bits(), 5.0f64.to_bits(), "trace={trace:?}");
                        json!(["ArmFallback", round])
                    }
                    BatchDeliveryAction::ArmRetry { round, delay_ms } => {
                        assert_eq!(delay_ms.to_bits(), 7.0f64.to_bits(), "trace={trace:?}");
                        json!(["ArmRetry", round])
                    }
                    BatchDeliveryAction::CancelOtherRoutes { round, route_index } => {
                        json!(["CancelOther", round, route_index])
                    }
                    BatchDeliveryAction::CancelAllRoutes { round } => {
                        json!(["CancelAll", round])
                    }
                    BatchDeliveryAction::Completed {
                        round,
                        route_index,
                        attempted_route_ids,
                    } => json!([
                        "Completed",
                        round,
                        route_index,
                        attempted_route_ids
                            .iter()
                            .map(|route| route_number(route))
                            .collect::<Vec<_>>()
                    ]),
                    BatchDeliveryAction::Exhausted {
                        attempted_route_ids,
                        message,
                    } => {
                        let expected = format!(
                            "Delivery retries exhausted for device receiver: {}",
                            flow.failures.join("; ")
                        );
                        assert_eq!(
                            message, expected,
                            "exhaustion message mismatch; trace={trace:?}"
                        );
                        json!([
                            "Exhausted",
                            attempted_route_ids
                                .iter()
                                .map(|route| route_number(route))
                                .collect::<Vec<_>>(),
                            flow.failures
                                .iter()
                                .map(|failure| failure_index(failure))
                                .collect::<Vec<_>>()
                        ])
                    }
                    BatchDeliveryAction::Aborted => json!(["Aborted"]),
                })
                .collect(),
        )
    }

    fn number_sequence(model: &Value, field: &str) -> Vec<usize> {
        model[field]
            .as_array()
            .unwrap_or_else(|| panic!("{field} is not a sequence"))
            .iter()
            .map(|value| value.as_u64().expect("sequence number") as usize)
            .collect()
    }

    fn expected_state(model: &Value) -> DeliveryKey {
        DeliveryKey {
            target_device_id: "receiver".into(),
            route_ids: vec!["route-a".into(), "route-b".into()],
            fallback_delay_bits: 5.0f64.to_bits(),
            retry_delay_bits: vec![7.0f64.to_bits()],
            retry_index: model["retryIndex"].as_u64().expect("retryIndex") as usize,
            round: model["round"].as_u64().expect("round") as u32,
            next_route_index: model["nextRoute"].as_u64().expect("nextRoute") as usize,
            pending: number_sequence(model, "pending"),
            fallback_armed: model["fallbackArmed"].as_bool().expect("fallbackArmed"),
            attempted_route_ids: number_sequence(model, "attempted")
                .into_iter()
                .map(|index| format!("route-{}", if index == 0 { 'a' } else { 'b' }))
                .collect(),
            failures: number_sequence(model, "failures")
                .into_iter()
                .map(|index| format!("route-{}: failed", if index == 0 { 'a' } else { 'b' }))
                .collect(),
            state: match model["state"].as_str().expect("state") {
                "Ready" => DeliveryState::Ready,
                "Running" => DeliveryState::Running,
                "WaitingRetry" => DeliveryState::WaitingRetry,
                "Complete" => DeliveryState::Complete,
                "Failed" => DeliveryState::Failed,
                "Aborted" => DeliveryState::Aborted,
                state => panic!("unexpected model state {state}"),
            },
        }
    }

    fn abstract_state(model: &Value) -> String {
        serde_json::to_string(&json!({
            "state": model["state"],
            "retryIndex": model["retryIndex"],
            "round": model["round"],
            "nextRoute": model["nextRoute"],
            "pending": model["pending"],
            "fallbackArmed": model["fallbackArmed"],
            "attempted": model["attempted"],
            "failures": model["failures"],
        }))
        .unwrap()
    }

    fn enabled_actions(flow: &MeshBatchDeliveryFlow) -> Vec<ExplorerAction> {
        let mut actions = vec![ExplorerAction::Abort];
        if flow.state == DeliveryState::Ready {
            actions.push(ExplorerAction::Start);
        }
        for round in 0..=2 {
            actions.push(ExplorerAction::Fallback(round));
            actions.push(ExplorerAction::Retry(round));
            for route in 0..=2 {
                actions.push(ExplorerAction::RouteAccepted { round, route });
                actions.push(ExplorerAction::RouteRejected { round, route });
            }
        }
        actions
    }

    fn apply_action(
        source: &MeshBatchDeliveryFlow,
        action: &ExplorerAction,
        trace: &[String],
    ) -> (MeshBatchDeliveryFlow, Value) {
        let mut flow = source.clone();
        let update = match action {
            ExplorerAction::Start => flow.start().expect("start is enabled only from Ready"),
            ExplorerAction::Fallback(round) => flow.fallback_elapsed(*round),
            ExplorerAction::Retry(round) => flow.retry_elapsed(*round),
            ExplorerAction::RouteAccepted { round, route } => {
                flow.route_result(*round, *route, true, "failed".into())
            }
            ExplorerAction::RouteRejected { round, route } => {
                flow.route_result(*round, *route, false, "failed".into())
            }
            ExplorerAction::Abort => flow.abort(),
        };
        let actions = normalize_update(update, &flow, trace);
        (flow, actions)
    }

    #[test]
    #[ignore = "requires a freshly generated TLC graph; executed by formal/check.sh"]
    fn bounded_actual_delivery_states_conform_to_tla_transitions() {
        let path = std::env::var("MESH_TLC_DELIVERY_IMPLEMENTATION_GRAPH")
            .expect("MESH_TLC_DELIVERY_IMPLEMENTATION_GRAPH missing: run ./formal/check.sh");
        let graph: ExplorerGraph =
            serde_json::from_slice(&std::fs::read(path).expect("read TLC graph"))
                .expect("decode TLC graph");
        let mut transitions = HashMap::with_capacity(graph.edges.len());
        for edge in graph.edges {
            let key = (edge.from, normalized_label(&edge.action));
            assert!(transitions.insert(key, edge.to).is_none());
        }

        let initial = MeshBatchDeliveryFlow::new(
            "receiver".into(),
            vec!["route-a".into(), "route-b".into()],
            5.0,
            vec![7.0],
        )
        .unwrap();
        assert_eq!(
            initial.exploration_key(),
            expected_state(&graph.states[&graph.initial])
        );

        let initial_key = initial.exploration_key();
        let mut known =
            HashMap::from([(initial_key, abstract_state(&graph.states[&graph.initial]))]);
        let mut queue = VecDeque::from([ExplorerNode {
            flow: initial,
            model_state: graph.initial,
            trace: Vec::new(),
        }]);
        let mut edges = 0usize;

        while let Some(node) = queue.pop_front() {
            for action in enabled_actions(&node.flow) {
                let label = action.label();
                let mut trace = node.trace.clone();
                trace.push(label.clone());
                let target_id = transitions
                    .get(&(node.model_state.clone(), label.clone()))
                    .unwrap_or_else(|| panic!("unmapped delivery event {label}; trace={trace:?}"))
                    .clone();
                let (target, actual_actions) = apply_action(&node.flow, &action, &trace);
                let model = &graph.states[&target_id];
                assert_eq!(
                    actual_actions, model["lastActions"],
                    "effect mismatch; trace={trace:?}"
                );
                let key = target.exploration_key();
                assert_eq!(
                    key,
                    expected_state(model),
                    "state mismatch; trace={trace:?}"
                );
                edges += 1;

                let abstraction = abstract_state(model);
                if let Some(previous) = known.get(&key) {
                    assert_eq!(
                        previous, &abstraction,
                        "equal concrete states mapped to unequal model states; trace={trace:?}"
                    );
                } else {
                    known.insert(key, abstraction);
                    queue.push_back(ExplorerNode {
                        flow: target,
                        model_state: target_id,
                        trace,
                    });
                }
            }
        }

        println!(
            "Rust delivery exploration: {} unique concrete states, {} enabled edges",
            known.len(),
            edges
        );
    }
}

impl MeshBatchDeliveryFlow {
    pub fn new(
        target_device_id: String,
        route_ids: Vec<String>,
        fallback_delay_ms: f64,
        retry_delays_ms: Vec<f64>,
    ) -> Result<Self, String> {
        if target_device_id.is_empty()
            || route_ids.is_empty()
            || route_ids.iter().any(String::is_empty)
        {
            return Err("Invalid durable batch delivery routes".into());
        }
        if !fallback_delay_ms.is_finite()
            || fallback_delay_ms < 0.0
            || retry_delays_ms
                .iter()
                .any(|delay| !delay.is_finite() || *delay < 0.0)
        {
            return Err("Invalid durable batch delivery delay".into());
        }
        Ok(Self {
            target_device_id,
            route_ids,
            fallback_delay_ms,
            retry_delays_ms,
            retry_index: 0,
            round: 0,
            next_route_index: 0,
            pending: BTreeSet::new(),
            fallback_armed: false,
            attempted_route_ids: Vec::new(),
            failures: Vec::new(),
            state: DeliveryState::Ready,
        })
    }

    pub fn start(&mut self) -> Result<BatchDeliveryUpdate, String> {
        if self.state != DeliveryState::Ready {
            return Err("Durable batch delivery already started".into());
        }
        self.state = DeliveryState::Running;
        Ok(self.launch_next())
    }

    pub fn route_result(
        &mut self,
        round: u32,
        route_index: u32,
        accepted: bool,
        failure: String,
    ) -> BatchDeliveryUpdate {
        let index = route_index as usize;
        if self.state != DeliveryState::Running
            || round != self.round
            || !self.pending.remove(&index)
        {
            return BatchDeliveryUpdate {
                actions: Vec::new(),
            };
        }
        if accepted {
            self.state = DeliveryState::Complete;
            return BatchDeliveryUpdate {
                actions: vec![
                    BatchDeliveryAction::CancelOtherRoutes { round, route_index },
                    BatchDeliveryAction::Completed {
                        round,
                        route_index,
                        attempted_route_ids: self.attempted_route_ids.clone(),
                    },
                ],
            };
        }
        let route_id = self
            .route_ids
            .get(index)
            .map(String::as_str)
            .unwrap_or("unknown route");
        self.failures.push(format!("{route_id}: {failure}"));
        let mut actions = Vec::new();
        if self.next_route_index < self.route_ids.len() {
            actions.extend(self.launch_next().actions);
        } else if self.pending.is_empty() {
            actions.extend(self.finish_round().actions);
        }
        BatchDeliveryUpdate { actions }
    }

    pub fn fallback_elapsed(&mut self, round: u32) -> BatchDeliveryUpdate {
        if self.state != DeliveryState::Running || round != self.round || !self.fallback_armed {
            return BatchDeliveryUpdate {
                actions: Vec::new(),
            };
        }
        self.fallback_armed = false;
        if self.next_route_index < self.route_ids.len() {
            self.launch_next()
        } else {
            BatchDeliveryUpdate {
                actions: Vec::new(),
            }
        }
    }

    pub fn retry_elapsed(&mut self, round: u32) -> BatchDeliveryUpdate {
        if self.state != DeliveryState::WaitingRetry || round != self.round {
            return BatchDeliveryUpdate {
                actions: Vec::new(),
            };
        }
        self.round = self.round.saturating_add(1);
        self.next_route_index = 0;
        self.pending.clear();
        self.fallback_armed = false;
        self.state = DeliveryState::Running;
        self.launch_next()
    }

    pub fn abort(&mut self) -> BatchDeliveryUpdate {
        if matches!(
            self.state,
            DeliveryState::Complete | DeliveryState::Failed | DeliveryState::Aborted
        ) {
            return BatchDeliveryUpdate {
                actions: Vec::new(),
            };
        }
        self.state = DeliveryState::Aborted;
        BatchDeliveryUpdate {
            actions: vec![
                BatchDeliveryAction::CancelAllRoutes { round: self.round },
                BatchDeliveryAction::Aborted,
            ],
        }
    }

    fn launch_next(&mut self) -> BatchDeliveryUpdate {
        if self.next_route_index >= self.route_ids.len() {
            return self.finish_round();
        }
        let index = self.next_route_index;
        self.next_route_index += 1;
        self.pending.insert(index);
        self.attempted_route_ids.push(self.route_ids[index].clone());
        let mut actions = vec![BatchDeliveryAction::LaunchRoute {
            round: self.round,
            route_index: index as u32,
        }];
        if self.next_route_index < self.route_ids.len() && !self.fallback_armed {
            self.fallback_armed = true;
            actions.push(BatchDeliveryAction::ArmFallback {
                round: self.round,
                delay_ms: self.fallback_delay_ms,
            });
        }
        BatchDeliveryUpdate { actions }
    }

    fn finish_round(&mut self) -> BatchDeliveryUpdate {
        if !self.pending.is_empty() {
            return BatchDeliveryUpdate {
                actions: Vec::new(),
            };
        }
        if let Some(delay_ms) = self.retry_delays_ms.get(self.retry_index).copied() {
            self.retry_index += 1;
            self.state = DeliveryState::WaitingRetry;
            return BatchDeliveryUpdate {
                actions: vec![BatchDeliveryAction::ArmRetry {
                    round: self.round,
                    delay_ms,
                }],
            };
        }
        self.state = DeliveryState::Failed;
        let details = if self.failures.is_empty() {
            "all routes failed".to_string()
        } else {
            self.failures.join("; ")
        };
        BatchDeliveryUpdate {
            actions: vec![BatchDeliveryAction::Exhausted {
                attempted_route_ids: self.attempted_route_ids.clone(),
                message: format!(
                    "Delivery retries exhausted for device {}: {details}",
                    self.target_device_id
                ),
            }],
        }
    }
}
