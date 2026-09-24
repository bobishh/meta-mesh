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
