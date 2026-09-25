//! Gossip lifecycle decisions independent of browser transports and timers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const DEFAULT_GOSSIP_TOPIC_PREFIX: &str = "mesh-workspace-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipRebuildInput {
    pub workspace_id: String,
    pub endpoints: Vec<String>,
    pub stopped: bool,
    pub engine_available: bool,
    pub transport_secret_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GossipRebuildAction {
    Reuse,
    Start,
    Close,
    Idle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipRebuildPlan {
    pub action: GossipRebuildAction,
    pub close_previous: bool,
    pub topic: String,
    pub endpoints: Vec<String>,
    pub topology_changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GossipReceiveAction {
    Refresh,
    Handle,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GossipDeliveryAction {
    Publish,
    IgnoreTopic,
    RejectSession,
    IgnorePayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GossipLifecycleNeighborChange {
    Up,
    Down,
    Same,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipNeighborPlan {
    pub change: GossipLifecycleNeighborChange,
    pub publish_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipBroadcastPlan {
    pub broadcast: bool,
    pub topic: String,
}

#[derive(Debug)]
pub struct GossipLifecycleState {
    topic_prefix: String,
    workspaces: BTreeMap<String, GossipWorkspaceState>,
}

#[derive(Debug, Default)]
struct GossipWorkspaceState {
    endpoints: Vec<String>,
    active: bool,
    neighbors: usize,
}

impl GossipLifecycleState {
    pub fn new(topic_prefix: impl Into<String>) -> Result<Self, String> {
        let topic_prefix = topic_prefix.into();
        if topic_prefix.is_empty() || topic_prefix.len() > 512 {
            return Err("Invalid gossip topic prefix".into());
        }
        Ok(Self {
            topic_prefix,
            workspaces: BTreeMap::new(),
        })
    }

    pub fn topic(&self, workspace_id: &str) -> Result<String, String> {
        validate_workspace_id(workspace_id)?;
        Ok(format!("{}{workspace_id}", self.topic_prefix))
    }

    /// Plans only state transitions. Hosts perform engine construction, secret
    /// lookup, stream I/O and timer scheduling after receiving this plan.
    pub fn plan_rebuild(&mut self, input: GossipRebuildInput) -> Result<GossipRebuildPlan, String> {
        validate_workspace_id(&input.workspace_id)?;
        let topic = self.topic(&input.workspace_id)?;
        let mut endpoints = input.endpoints;
        endpoints.retain(|endpoint| !endpoint.is_empty());
        endpoints.sort();
        endpoints.dedup();
        let state = self.workspaces.entry(input.workspace_id).or_default();
        let topology_changed = state.endpoints != endpoints;
        let must_close =
            state.active && (input.stopped || endpoints.is_empty() || topology_changed);
        state.endpoints = endpoints.clone();
        if must_close {
            state.active = false;
            state.neighbors = 0;
        }
        let action = if input.stopped
            || endpoints.is_empty()
            || !input.engine_available
            || !input.transport_secret_available
        {
            if must_close {
                GossipRebuildAction::Close
            } else {
                GossipRebuildAction::Idle
            }
        } else if state.active && !topology_changed {
            GossipRebuildAction::Reuse
        } else {
            GossipRebuildAction::Start
        };
        Ok(GossipRebuildPlan {
            action,
            close_previous: must_close,
            topic,
            endpoints,
            topology_changed,
        })
    }

    pub fn started(&mut self, workspace_id: &str) -> Result<(), String> {
        validate_workspace_id(workspace_id)?;
        let state = self
            .workspaces
            .get_mut(workspace_id)
            .ok_or("Gossip workspace is unknown")?;
        if state.endpoints.is_empty() {
            return Err("Gossip workspace has no endpoints".into());
        }
        state.active = true;
        Ok(())
    }

    pub fn start_failed(&mut self, workspace_id: &str) -> Result<(), String> {
        validate_workspace_id(workspace_id)?;
        if let Some(state) = self.workspaces.get_mut(workspace_id) {
            state.active = false;
            state.neighbors = 0;
        }
        Ok(())
    }

    pub fn close(&mut self, workspace_id: &str) -> Result<(), String> {
        validate_workspace_id(workspace_id)?;
        self.workspaces.remove(workspace_id);
        Ok(())
    }

    pub fn close_all(&mut self) {
        self.workspaces.clear();
    }

    pub fn receive_action(
        &self,
        workspace_id: &str,
        driver_available: bool,
        session_available: bool,
    ) -> Result<GossipReceiveAction, String> {
        validate_workspace_id(workspace_id)?;
        if !driver_available {
            Ok(GossipReceiveAction::Refresh)
        } else if !session_available {
            Ok(GossipReceiveAction::Drop)
        } else {
            Ok(GossipReceiveAction::Handle)
        }
    }

    pub fn delivery_action(
        &self,
        workspace_id: &str,
        topic: &str,
        session_available: bool,
        packet_valid: bool,
    ) -> Result<GossipDeliveryAction, String> {
        if topic != self.topic(workspace_id)? {
            Ok(GossipDeliveryAction::IgnoreTopic)
        } else if !session_available {
            Ok(GossipDeliveryAction::RejectSession)
        } else if !packet_valid {
            Ok(GossipDeliveryAction::IgnorePayload)
        } else {
            Ok(GossipDeliveryAction::Publish)
        }
    }

    pub fn observe_neighbors(
        &mut self,
        workspace_id: &str,
        count: usize,
    ) -> Result<GossipNeighborPlan, String> {
        validate_workspace_id(workspace_id)?;
        let state = self
            .workspaces
            .get_mut(workspace_id)
            .ok_or("Gossip workspace is inactive")?;
        let change = if count > state.neighbors {
            GossipLifecycleNeighborChange::Up
        } else if count < state.neighbors {
            GossipLifecycleNeighborChange::Down
        } else {
            GossipLifecycleNeighborChange::Same
        };
        state.neighbors = count;
        Ok(GossipNeighborPlan {
            change,
            publish_all: change == GossipLifecycleNeighborChange::Up,
        })
    }

    pub fn broadcast_plan(
        &self,
        workspace_id: &str,
        driver_available: bool,
    ) -> Result<GossipBroadcastPlan, String> {
        let topic = self.topic(workspace_id)?;
        let active = self
            .workspaces
            .get(workspace_id)
            .is_some_and(|state| state.active);
        Ok(GossipBroadcastPlan {
            broadcast: active && driver_available,
            topic,
        })
    }
}

impl Default for GossipLifecycleState {
    fn default() -> Self {
        Self::new(DEFAULT_GOSSIP_TOPIC_PREFIX).expect("valid default gossip prefix")
    }
}

fn validate_workspace_id(workspace_id: &str) -> Result<(), String> {
    if workspace_id.is_empty() || workspace_id.len() > 512 {
        Err("Invalid gossip workspace id".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rebuild(endpoints: &[&str]) -> GossipRebuildInput {
        GossipRebuildInput {
            workspace_id: "scope".into(),
            endpoints: endpoints.iter().map(ToString::to_string).collect(),
            stopped: false,
            engine_available: true,
            transport_secret_available: true,
        }
    }

    #[test]
    fn rebuild_is_canonical_and_owns_reuse_close_start_decisions() {
        let mut state = GossipLifecycleState::default();
        let first = state.plan_rebuild(rebuild(&["b", "a", "a"])).unwrap();
        assert_eq!(first.action, GossipRebuildAction::Start);
        assert_eq!(first.topic, "mesh-workspace-scope");
        assert_eq!(first.endpoints, ["a", "b"]);
        state.started("scope").unwrap();
        assert_eq!(
            state.plan_rebuild(rebuild(&["a", "b"])).unwrap().action,
            GossipRebuildAction::Reuse
        );
        let changed = state.plan_rebuild(rebuild(&["new"])).unwrap();
        assert_eq!(changed.action, GossipRebuildAction::Start);
        assert!(changed.close_previous);
        state.started("scope").unwrap();
        let mut stopped = rebuild(&["new"]);
        stopped.stopped = true;
        assert_eq!(
            state.plan_rebuild(stopped).unwrap().action,
            GossipRebuildAction::Close
        );
    }

    #[test]
    fn receive_delivery_neighbor_and_broadcast_are_explicit_plans() {
        let mut state = GossipLifecycleState::default();
        assert_eq!(
            state.receive_action("scope", false, true).unwrap(),
            GossipReceiveAction::Refresh
        );
        assert_eq!(
            state.delivery_action("scope", "other", true, true).unwrap(),
            GossipDeliveryAction::IgnoreTopic
        );
        assert_eq!(
            state
                .delivery_action("scope", "mesh-workspace-scope", false, true)
                .unwrap(),
            GossipDeliveryAction::RejectSession
        );
        state.plan_rebuild(rebuild(&["remote"])).unwrap();
        state.started("scope").unwrap();
        assert_eq!(
            state.receive_action("scope", true, false).unwrap(),
            GossipReceiveAction::Drop
        );
        assert_eq!(
            state.receive_action("scope", true, true).unwrap(),
            GossipReceiveAction::Handle
        );
        assert!(state.observe_neighbors("scope", 1).unwrap().publish_all);
        assert_eq!(
            state.observe_neighbors("scope", 1).unwrap().change,
            GossipLifecycleNeighborChange::Same
        );
        assert_eq!(
            state.observe_neighbors("scope", 0).unwrap().change,
            GossipLifecycleNeighborChange::Down
        );
        assert!(state.broadcast_plan("scope", true).unwrap().broadcast);
    }
}
