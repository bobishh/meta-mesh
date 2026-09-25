use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::SessionKey;

pub const DEFAULT_SESSION_STABLE_AFTER_MS: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInstallDecision {
    pub generation: u64,
    pub replaced_generation: Option<u64>,
    pub replaced_connection_id: Option<String>,
    pub stable_after_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEvictionDecision {
    pub should_close: bool,
    pub was_current: bool,
    pub connection_id: Option<String>,
}

/// One asynchronous host callback. Rust chooses which callback effects are
/// still valid for the generation; hosts only schedule timers and perform I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionCallbackEvent {
    Recovery,
    Stable,
    HeartbeatFailed,
    ReceiveSucceeded,
    ReceiveFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionCallbackPlan {
    pub publish_recovery: bool,
    pub stable: bool,
    pub report_failure: bool,
    pub evict: bool,
}

/// Host publication order. Every active session in a workspace publishes
/// before that workspace's gossip broadcast; workspaces may run independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionWorkspacePublishPlan {
    pub workspace_id: String,
    pub connection_ids: Vec<String>,
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq, Hash))]
struct SessionLifecycleEntry {
    connection_id: String,
    stable_at_ms: u64,
    stable: bool,
    failure_reported: bool,
    recovery_published: bool,
    evicted: bool,
}

/// Owns decisions that span session installation and asynchronous callbacks.
/// Generation checks make replaced-session callbacks harmless while still
/// allowing their host resources to close exactly once.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq, Hash))]
pub struct MeshSessionLifecycleState {
    stable_after_ms: u64,
    current: BTreeMap<SessionKey, u64>,
    entries: BTreeMap<(SessionKey, u64), SessionLifecycleEntry>,
    last_generation: u64,
}

impl Default for MeshSessionLifecycleState {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_STABLE_AFTER_MS)
    }
}

impl MeshSessionLifecycleState {
    pub fn new(stable_after_ms: u64) -> Self {
        Self {
            stable_after_ms,
            current: BTreeMap::new(),
            entries: BTreeMap::new(),
            last_generation: 0,
        }
    }

    pub fn register(
        &mut self,
        key: SessionKey,
        connection_id: String,
        generation: u64,
        now_ms: u64,
    ) -> Result<SessionInstallDecision, String> {
        if key.workspace_id.is_empty()
            || key.device_id.is_empty()
            || key.instance_id.is_empty()
            || connection_id.is_empty()
            || generation == 0
            || self.entries.contains_key(&(key.clone(), generation))
        {
            return Err("Invalid mesh session lifecycle registration".into());
        }
        let replaced_generation = self.current.get(&key).copied();
        if self.last_generation >= generation {
            return Err("Stale mesh session generation".into());
        }
        let replaced_connection_id = replaced_generation
            .and_then(|previous| self.entries.get(&(key.clone(), previous)))
            .map(|entry| entry.connection_id.clone());
        let stable_at_ms = now_ms.saturating_add(self.stable_after_ms);
        self.last_generation = generation;
        self.current.insert(key.clone(), generation);
        self.entries.insert(
            (key, generation),
            SessionLifecycleEntry {
                connection_id,
                stable_at_ms,
                ..Default::default()
            },
        );
        Ok(SessionInstallDecision {
            generation,
            replaced_generation,
            replaced_connection_id,
            stable_after_ms: self.stable_after_ms,
        })
    }

    /// Completes the stability timer only for the still-current generation.
    pub fn mark_stable(&mut self, key: &SessionKey, generation: u64, now_ms: u64) -> bool {
        if self.current.get(key) != Some(&generation) {
            return false;
        }
        let Some(entry) = self.entries.get_mut(&(key.clone(), generation)) else {
            return false;
        };
        if entry.evicted || entry.stable || now_ms < entry.stable_at_ms {
            return false;
        }
        entry.stable = true;
        true
    }

    /// Reports each active generation's first connection failure once.
    pub fn report_failure(&mut self, key: &SessionKey, generation: u64) -> bool {
        if self.current.get(key) != Some(&generation) {
            return false;
        }
        let Some(entry) = self.entries.get_mut(&(key.clone(), generation)) else {
            return false;
        };
        if entry.evicted || entry.failure_reported {
            return false;
        }
        entry.failure_reported = true;
        true
    }

    /// Recovered-state publication runs once, and only while generation stays current.
    pub fn publish_recovery(&mut self, key: &SessionKey, generation: u64) -> bool {
        if self.current.get(key) != Some(&generation) {
            return false;
        }
        let Some(entry) = self.entries.get_mut(&(key.clone(), generation)) else {
            return false;
        };
        if entry.evicted || entry.recovery_published {
            return false;
        }
        entry.recovery_published = true;
        true
    }

    /// Plans callback effects atomically. In particular, a replaced session
    /// may still need transport cleanup, but cannot publish recovery, become
    /// stable, or report a new failure for the current session.
    pub fn callback_plan(
        &mut self,
        key: &SessionKey,
        generation: u64,
        event: SessionCallbackEvent,
        now_ms: u64,
    ) -> SessionCallbackPlan {
        let is_current = self.current.get(key) == Some(&generation);
        let Some(entry) = self.entries.get_mut(&(key.clone(), generation)) else {
            return SessionCallbackPlan::default();
        };
        if entry.evicted {
            return SessionCallbackPlan::default();
        }
        match event {
            SessionCallbackEvent::Recovery if is_current && !entry.recovery_published => {
                entry.recovery_published = true;
                SessionCallbackPlan {
                    publish_recovery: true,
                    ..Default::default()
                }
            }
            SessionCallbackEvent::Stable
                if is_current && !entry.stable && now_ms >= entry.stable_at_ms =>
            {
                entry.stable = true;
                SessionCallbackPlan {
                    stable: true,
                    ..Default::default()
                }
            }
            SessionCallbackEvent::HeartbeatFailed if is_current && !entry.failure_reported => {
                entry.failure_reported = true;
                SessionCallbackPlan {
                    report_failure: true,
                    evict: true,
                    ..Default::default()
                }
            }
            SessionCallbackEvent::ReceiveFailed => {
                let report_failure = is_current && !entry.failure_reported;
                entry.failure_reported |= report_failure;
                SessionCallbackPlan {
                    report_failure,
                    evict: true,
                    ..Default::default()
                }
            }
            SessionCallbackEvent::ReceiveSucceeded => SessionCallbackPlan {
                evict: true,
                ..Default::default()
            },
            _ => SessionCallbackPlan::default(),
        }
    }

    pub fn publish_plan(&self) -> Vec<SessionWorkspacePublishPlan> {
        let mut workspaces = BTreeMap::<String, Vec<String>>::new();
        for ((key, generation), entry) in &self.entries {
            if !entry.evicted && self.current.get(key) == Some(generation) {
                workspaces
                    .entry(key.workspace_id.clone())
                    .or_default()
                    .push(entry.connection_id.clone());
            }
        }
        workspaces
            .into_iter()
            .map(
                |(workspace_id, connection_ids)| SessionWorkspacePublishPlan {
                    workspace_id,
                    connection_ids,
                },
            )
            .collect()
    }

    /// Eviction closes each registered transport once and removes runtime
    /// session state only when this generation is still current.
    pub fn evict(&mut self, key: &SessionKey, generation: u64) -> SessionEvictionDecision {
        let entry_key = (key.clone(), generation);
        let Some(entry) = self.entries.get_mut(&entry_key) else {
            return SessionEvictionDecision {
                should_close: false,
                was_current: false,
                connection_id: None,
            };
        };
        if entry.evicted {
            return SessionEvictionDecision {
                should_close: false,
                was_current: false,
                connection_id: Some(entry.connection_id.clone()),
            };
        }
        entry.evicted = true;
        let connection_id = entry.connection_id.clone();
        let was_current = self.current.get(key) == Some(&generation);
        if was_current {
            self.current.remove(key);
        }
        self.entries.remove(&entry_key);
        SessionEvictionDecision {
            should_close: true,
            was_current,
            connection_id: Some(connection_id),
        }
    }

    /// Drop live lifecycle state on host shutdown. Keep the global generation
    /// watermark so callbacks from before restart cannot register as current.
    pub fn clear(&mut self) {
        self.current.clear();
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MeshRuntimeState, RuntimeSession, SessionAdmission, SessionCandidate, SessionDirection,
    };
    use serde::Deserialize;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque, hash_map::DefaultHasher};
    use std::hash::{Hash, Hasher};

    fn key() -> SessionKey {
        SessionKey {
            workspace_id: "workspace".into(),
            device_id: "device".into(),
            instance_id: "instance".into(),
        }
    }

    #[test]
    fn replacement_closes_old_generation_without_removing_new_session() {
        let key = key();
        let mut lifecycle = MeshSessionLifecycleState::new(10);
        lifecycle.register(key.clone(), "old".into(), 1, 0).unwrap();
        let replacement = lifecycle.register(key.clone(), "new".into(), 2, 5).unwrap();
        assert_eq!(replacement.replaced_generation, Some(1));
        assert_eq!(replacement.replaced_connection_id.as_deref(), Some("old"));
        assert!(!lifecycle.report_failure(&key, 1));

        let stale_close = lifecycle.evict(&key, 1);
        assert!(stale_close.should_close);
        assert!(!stale_close.was_current);
        assert_eq!(stale_close.connection_id.as_deref(), Some("old"));
        assert!(!lifecycle.evict(&key, 1).should_close);

        let current_close = lifecycle.evict(&key, 2);
        assert!(current_close.should_close);
        assert!(current_close.was_current);
        assert_eq!(current_close.connection_id.as_deref(), Some("new"));
    }

    #[test]
    fn stable_notification_waits_for_delay_and_is_one_shot() {
        let key = key();
        let mut lifecycle = MeshSessionLifecycleState::new(10);
        lifecycle
            .register(key.clone(), "conn".into(), 3, 100)
            .unwrap();
        assert!(!lifecycle.mark_stable(&key, 3, 109));
        assert!(lifecycle.mark_stable(&key, 3, 110));
        assert!(!lifecycle.mark_stable(&key, 3, 111));
    }

    #[test]
    fn stale_failure_and_recovery_callbacks_are_ignored() {
        let key = key();
        let mut lifecycle = MeshSessionLifecycleState::new(10);
        lifecycle
            .register(key.clone(), "first".into(), 4, 0)
            .unwrap();
        lifecycle
            .register(key.clone(), "second".into(), 5, 1)
            .unwrap();
        assert!(!lifecycle.report_failure(&key, 4));
        assert!(!lifecycle.publish_recovery(&key, 4));
        assert!(lifecycle.report_failure(&key, 5));
        assert!(!lifecycle.report_failure(&key, 5));
        assert!(lifecycle.publish_recovery(&key, 5));
        assert!(!lifecycle.publish_recovery(&key, 5));
    }

    #[test]
    fn cannot_register_a_older_generation_over_the_current_entry() {
        let key = key();
        let mut lifecycle = MeshSessionLifecycleState::default();
        lifecycle.register(key.clone(), "new".into(), 8, 0).unwrap();
        assert_eq!(
            lifecycle.register(key, "stale".into(), 7, 1).unwrap_err(),
            "Stale mesh session generation"
        );
    }

    #[test]
    fn clear_drops_session_entries_and_keeps_constant_generation_watermark() {
        let key = key();
        let mut lifecycle = MeshSessionLifecycleState::default();
        lifecycle.register(key.clone(), "old".into(), 8, 0).unwrap();
        lifecycle.clear();
        assert!(!lifecycle.publish_recovery(&key, 8));
        assert_eq!(
            lifecycle
                .register(key.clone(), "stale".into(), 7, 1)
                .unwrap_err(),
            "Stale mesh session generation"
        );
        assert!(lifecycle.register(key, "new".into(), 9, 2).is_ok());
    }

    #[test]
    fn callback_plan_owns_recovery_stability_failure_and_cleanup_ordering() {
        let key = key();
        let mut lifecycle = MeshSessionLifecycleState::new(10);
        lifecycle.register(key.clone(), "old".into(), 1, 0).unwrap();
        lifecycle
            .register(key.clone(), "current".into(), 2, 1)
            .unwrap();

        assert_eq!(
            lifecycle.callback_plan(&key, 1, SessionCallbackEvent::Recovery, 1),
            SessionCallbackPlan::default()
        );
        assert_eq!(
            lifecycle.callback_plan(&key, 1, SessionCallbackEvent::ReceiveFailed, 1),
            SessionCallbackPlan {
                evict: true,
                ..Default::default()
            }
        );
        assert_eq!(
            lifecycle.callback_plan(&key, 2, SessionCallbackEvent::Stable, 10),
            SessionCallbackPlan::default()
        );
        assert_eq!(
            lifecycle.callback_plan(&key, 2, SessionCallbackEvent::Stable, 11),
            SessionCallbackPlan {
                stable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            lifecycle.callback_plan(&key, 2, SessionCallbackEvent::Recovery, 11),
            SessionCallbackPlan {
                publish_recovery: true,
                ..Default::default()
            }
        );
        assert_eq!(
            lifecycle.callback_plan(&key, 2, SessionCallbackEvent::HeartbeatFailed, 11),
            SessionCallbackPlan {
                report_failure: true,
                evict: true,
                ..Default::default()
            }
        );
        assert_eq!(
            lifecycle.callback_plan(&key, 2, SessionCallbackEvent::ReceiveFailed, 11),
            SessionCallbackPlan {
                evict: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn publish_plan_groups_current_sessions_before_workspace_broadcast() {
        let mut lifecycle = MeshSessionLifecycleState::default();
        lifecycle
            .register(
                SessionKey {
                    workspace_id: "b".into(),
                    device_id: "z".into(),
                    instance_id: "one".into(),
                },
                "b-z".into(),
                1,
                0,
            )
            .unwrap();
        lifecycle
            .register(
                SessionKey {
                    workspace_id: "a".into(),
                    device_id: "y".into(),
                    instance_id: "one".into(),
                },
                "a-y".into(),
                2,
                0,
            )
            .unwrap();
        lifecycle
            .register(
                SessionKey {
                    workspace_id: "a".into(),
                    device_id: "x".into(),
                    instance_id: "one".into(),
                },
                "a-x".into(),
                3,
                0,
            )
            .unwrap();

        assert_eq!(
            lifecycle.publish_plan(),
            vec![
                SessionWorkspacePublishPlan {
                    workspace_id: "a".into(),
                    connection_ids: vec!["a-x".into(), "a-y".into()]
                },
                SessionWorkspacePublishPlan {
                    workspace_id: "b".into(),
                    connection_ids: vec!["b-z".into()]
                },
            ]
        );
    }

    const EXPLORER_GENERATIONS: u64 = 3;

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

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct CallbackHandle {
        key: SessionKey,
        generation: u64,
        connection_id: String,
        stable_at_ms: u64,
    }

    /// Equality is the exploration key. In particular, the derived equality
    /// on both Rust state machines includes private counters, maps, and every
    /// lifecycle-entry flag; the model projection is deliberately not the key.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct ConcreteSessionState {
        runtime: MeshRuntimeState,
        lifecycle: MeshSessionLifecycleState,
        callbacks: Vec<CallbackHandle>,
        open: BTreeSet<String>,
        stable_notifications: BTreeSet<(String, u64)>,
        failure_reports: BTreeSet<(String, u64)>,
        recovery_publications: BTreeSet<(String, u64)>,
    }

    #[derive(Debug, Clone)]
    enum ExplorerAction {
        Register {
            instance: &'static str,
            generation: u64,
        },
        CleanupOlder(CallbackHandle),
        Callback {
            name: &'static str,
            event: SessionCallbackEvent,
            handle: CallbackHandle,
            now_ms: u64,
        },
    }

    impl ExplorerAction {
        fn model_label(&self) -> String {
            match self {
                Self::Register {
                    instance,
                    generation,
                } => format!("Register({instance},{generation})"),
                Self::CleanupOlder(handle) => format!(
                    "CleanupOlder({},{})",
                    handle.key.instance_id, handle.generation
                ),
                Self::Callback { name, handle, .. } => {
                    format!("{name}({},{})", handle.key.instance_id, handle.generation)
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ExplorerNode {
        concrete: ConcreteSessionState,
        model_state: String,
        trace: Vec<String>,
    }

    fn concrete_fingerprint(state: &ConcreteSessionState) -> u64 {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        hasher.finish()
    }

    fn session_key(instance: &str) -> SessionKey {
        SessionKey {
            workspace_id: "board".into(),
            device_id: "same-device".into(),
            instance_id: instance.into(),
        }
    }

    fn normalized_action(label: &str) -> String {
        label.split_whitespace().collect()
    }

    fn pair_set(state: &Value, field: &str) -> BTreeSet<(String, u64)> {
        state[field]
            .as_array()
            .unwrap_or_else(|| panic!("{field} is not a TLC set"))
            .iter()
            .map(|pair| {
                let pair = pair.as_array().expect("TLC pair");
                (
                    pair[0].as_str().expect("TLC key").to_string(),
                    pair[1].as_u64().expect("TLC generation"),
                )
            })
            .collect()
    }

    fn expected_connections(state: &Value) -> BTreeSet<String> {
        state["current"]
            .as_object()
            .expect("TLC current function")
            .iter()
            .filter_map(|(instance, generation)| {
                let generation = generation.as_u64().expect("TLC generation");
                (generation != 0).then(|| format!("{instance}:{generation}"))
            })
            .collect()
    }

    fn assert_matches_model(concrete: &ConcreteSessionState, model: &Value, trace: &[String]) {
        let expected = expected_connections(model);
        let runtime: BTreeSet<_> = concrete
            .runtime
            .sessions()
            .map(|session| session.connection_id.clone())
            .collect();
        assert_eq!(runtime, expected, "runtime mismatch; trace={trace:?}");

        let lifecycle: BTreeSet<_> = concrete
            .lifecycle
            .publish_plan()
            .into_iter()
            .flat_map(|plan| plan.connection_ids)
            .collect();
        assert_eq!(lifecycle, expected, "lifecycle mismatch; trace={trace:?}");

        let expected_open: BTreeSet<_> = pair_set(model, "open")
            .into_iter()
            .map(|(instance, generation)| format!("{instance}:{generation}"))
            .collect();
        assert_eq!(
            concrete.open, expected_open,
            "transport effects mismatch; trace={trace:?}"
        );

        let registered: BTreeSet<_> = concrete
            .callbacks
            .iter()
            .map(|handle| (handle.key.instance_id.clone(), handle.generation))
            .collect();
        assert_eq!(
            registered,
            pair_set(model, "registered"),
            "registered callback mismatch; trace={trace:?}"
        );
        assert_eq!(
            concrete.stable_notifications,
            pair_set(model, "stable"),
            "stable callback mismatch; trace={trace:?}"
        );
        assert_eq!(
            concrete.failure_reports,
            pair_set(model, "failureReported"),
            "failure callback mismatch; trace={trace:?}"
        );
        assert_eq!(
            concrete.recovery_publications,
            pair_set(model, "recoveryPublished"),
            "recovery callback mismatch; trace={trace:?}"
        );
        assert_eq!(
            concrete.callbacks.len() as u64,
            model["lastGeneration"].as_u64().expect("lastGeneration"),
            "generation bound mismatch; trace={trace:?}"
        );

        let requested = model["requestedCurrent"]
            .as_object()
            .expect("TLC requestedCurrent function");
        for instance in ["tabA", "tabB"] {
            let actual = concrete
                .callbacks
                .iter()
                .rev()
                .find(|handle| handle.key.instance_id == instance)
                .map_or(0, |handle| handle.generation);
            assert_eq!(
                actual,
                requested[instance].as_u64().expect("requested generation"),
                "requested-session history mismatch; trace={trace:?}"
            );
        }
    }

    fn enabled_actions(state: &ConcreteSessionState) -> Vec<ExplorerAction> {
        let mut actions = Vec::new();
        let next_generation = state.callbacks.len() as u64 + 1;
        if next_generation <= EXPLORER_GENERATIONS {
            for instance in ["tabA", "tabB"] {
                actions.push(ExplorerAction::Register {
                    instance,
                    generation: next_generation,
                });
            }
        }

        let current: BTreeMap<_, _> = state
            .runtime
            .sessions()
            .map(|session: &RuntimeSession| (session.key.clone(), session.generation))
            .collect();
        for handle in &state.callbacks {
            if current
                .get(&handle.key)
                .is_some_and(|generation| handle.generation < *generation)
            {
                actions.push(ExplorerAction::CleanupOlder(handle.clone()));
            }
            for (name, event, now_ms) in [
                ("Recovery", SessionCallbackEvent::Recovery, 0),
                (
                    "StableEarly",
                    SessionCallbackEvent::Stable,
                    handle.stable_at_ms - 1,
                ),
                (
                    "StableDue",
                    SessionCallbackEvent::Stable,
                    handle.stable_at_ms,
                ),
                ("HeartbeatFailed", SessionCallbackEvent::HeartbeatFailed, 0),
                (
                    "ReceiveSucceeded",
                    SessionCallbackEvent::ReceiveSucceeded,
                    0,
                ),
                ("ReceiveFailed", SessionCallbackEvent::ReceiveFailed, 0),
            ] {
                actions.push(ExplorerAction::Callback {
                    name,
                    event,
                    handle: handle.clone(),
                    now_ms,
                });
            }
        }
        actions
    }

    fn cleanup_generation(
        state: &mut ConcreteSessionState,
        handle: &CallbackHandle,
        trace: &[String],
    ) {
        let was_open = state.open.contains(&handle.connection_id);
        let decision = state.lifecycle.evict(&handle.key, handle.generation);
        assert_eq!(
            decision.should_close, was_open,
            "cleanup close cardinality mismatch; trace={trace:?}"
        );
        if decision.should_close {
            assert_eq!(
                decision.connection_id.as_deref(),
                Some(handle.connection_id.as_str()),
                "cleanup chose another connection; trace={trace:?}"
            );
            assert!(
                state.open.remove(&handle.connection_id),
                "transport closed twice; trace={trace:?}"
            );
        }
        let removed = state.runtime.remove_session(&handle.key, handle.generation);
        if decision.was_current {
            assert_eq!(
                removed.as_deref(),
                Some(handle.connection_id.as_str()),
                "runtime mismatch while removing current generation; trace={trace:?}"
            );
        } else {
            assert_eq!(
                removed, None,
                "runtime mismatch: stale cleanup removed current generation; trace={trace:?}"
            );
        }
    }

    fn apply_action(
        source: &ConcreteSessionState,
        action: &ExplorerAction,
        trace: &[String],
    ) -> ConcreteSessionState {
        let mut state = source.clone();
        match action {
            ExplorerAction::Register {
                instance,
                generation,
            } => {
                let key = session_key(instance);
                let connection_id = format!("{instance}:{generation}");
                let replaced = state
                    .runtime
                    .sessions()
                    .find(|session| session.key == key)
                    .map(|session| session.connection_id.clone());
                let admission = state.runtime.admit_session(
                    SessionCandidate {
                        key: key.clone(),
                        connection_id: connection_id.clone(),
                        remote_issued_at: "2026-09-25T00:00:00Z".into(),
                        remote_route_sequence: Some(*generation),
                        direction: SessionDirection::Outgoing,
                    },
                    SessionDirection::Outgoing,
                );
                let SessionAdmission::Accepted {
                    generation: actual,
                    replaced_connection_id,
                } = admission
                else {
                    panic!("new bounded generation was rejected; trace={trace:?}")
                };
                assert_eq!(
                    actual, *generation,
                    "runtime generation mismatch; trace={trace:?}"
                );
                assert_eq!(
                    replaced_connection_id, replaced,
                    "replacement effect mismatch; trace={trace:?}"
                );
                let installed = state
                    .lifecycle
                    .register(key.clone(), connection_id.clone(), actual, *generation)
                    .unwrap_or_else(|error| {
                        panic!("registration failed: {error}; trace={trace:?}")
                    });
                assert_eq!(installed.stable_after_ms, 10_000);
                state.open.insert(connection_id.clone());
                state.callbacks.push(CallbackHandle {
                    key,
                    generation: actual,
                    connection_id,
                    stable_at_ms: generation + 10_000,
                });
            }
            ExplorerAction::CleanupOlder(handle) => {
                cleanup_generation(&mut state, handle, trace);
            }
            ExplorerAction::Callback {
                event,
                handle,
                now_ms,
                ..
            } => {
                let plan =
                    state
                        .lifecycle
                        .callback_plan(&handle.key, handle.generation, *event, *now_ms);
                let pair = (handle.key.instance_id.clone(), handle.generation);
                if plan.publish_recovery {
                    assert!(state.recovery_publications.insert(pair.clone()));
                }
                if plan.stable {
                    assert!(state.stable_notifications.insert(pair.clone()));
                }
                if plan.report_failure {
                    assert!(state.failure_reports.insert(pair));
                }
                if plan.evict {
                    cleanup_generation(&mut state, handle, trace);
                }
            }
        }
        state
    }

    fn session_projection(model: &Value) -> String {
        serde_json::to_string(&serde_json::json!({
            "current": model["current"],
            "requestedCurrent": model["requestedCurrent"],
            "registered": model["registered"],
            "open": model["open"],
            "lastGeneration": model["lastGeneration"],
        }))
        .unwrap()
    }

    #[test]
    #[ignore = "requires a freshly generated TLC graph; executed by formal/check.sh"]
    fn bounded_actual_session_states_conform_to_tla_transitions() {
        let path = std::env::var("MESH_TLC_SESSION_IMPLEMENTATION_GRAPH")
            .expect("MESH_TLC_SESSION_IMPLEMENTATION_GRAPH missing: run ./formal/check.sh");
        let graph: ExplorerGraph =
            serde_json::from_slice(&std::fs::read(path).expect("read TLC graph"))
                .expect("decode TLC graph");
        let mut transitions = HashMap::with_capacity(graph.edges.len());
        for edge in graph.edges {
            let key = (edge.from, normalized_action(&edge.action));
            assert!(
                transitions.insert(key, edge.to).is_none(),
                "nondeterministic model edge for one labeled action"
            );
        }

        let initial = ConcreteSessionState {
            runtime: MeshRuntimeState::default(),
            lifecycle: MeshSessionLifecycleState::new(10_000),
            callbacks: Vec::new(),
            open: BTreeSet::new(),
            stable_notifications: BTreeSet::new(),
            failure_reports: BTreeSet::new(),
            recovery_publications: BTreeSet::new(),
        };
        assert_matches_model(&initial, &graph.states[&graph.initial], &[]);

        let mut states = vec![initial.clone()];
        let mut model_states = vec![graph.initial.clone()];
        let mut states_by_fingerprint =
            HashMap::from([(concrete_fingerprint(&initial), vec![0usize])]);
        let mut queue = VecDeque::from([ExplorerNode {
            concrete: initial,
            model_state: graph.initial,
            trace: Vec::new(),
        }]);
        let mut explored_edges = 0usize;
        let mut projections = BTreeMap::<String, usize>::new();

        while let Some(node) = queue.pop_front() {
            *projections
                .entry(session_projection(&graph.states[&node.model_state]))
                .or_default() += 1;
            for action in enabled_actions(&node.concrete) {
                let label = action.model_label();
                let mut trace = node.trace.clone();
                trace.push(label.clone());
                let target_id = transitions
                    .get(&(node.model_state.clone(), label.clone()))
                    .unwrap_or_else(|| {
                        panic!("unmapped implementation event {label}; trace={trace:?}")
                    })
                    .clone();
                let target = apply_action(&node.concrete, &action, &trace);
                assert_matches_model(&target, &graph.states[&target_id], &trace);
                explored_edges += 1;

                let fingerprint = concrete_fingerprint(&target);
                let known_index = states_by_fingerprint.get(&fingerprint).and_then(|indices| {
                    indices
                        .iter()
                        .copied()
                        .find(|index| states[*index] == target)
                });
                if let Some(index) = known_index {
                    // Concrete equality must imply equal abstract state. Only
                    // TLC's instrumentation bit may differ between histories.
                    let mut previous = graph.states[&model_states[index]].clone();
                    let mut candidate = graph.states[&target_id].clone();
                    previous.as_object_mut().unwrap().remove("parity");
                    candidate.as_object_mut().unwrap().remove("parity");
                    assert_eq!(
                        previous, candidate,
                        "one concrete state has incompatible abstractions; trace={trace:?}"
                    );
                } else {
                    let index = states.len();
                    states.push(target.clone());
                    model_states.push(target_id.clone());
                    states_by_fingerprint
                        .entry(fingerprint)
                        .or_default()
                        .push(index);
                    queue.push_back(ExplorerNode {
                        concrete: target,
                        model_state: target_id,
                        trace,
                    });
                }
            }
        }

        let same_projection_states = projections.values().copied().max().unwrap_or_default();
        assert!(
            same_projection_states > 1,
            "exploration did not retain hidden implementation-state distinctions"
        );
        println!(
            "Rust session exploration: {} unique concrete states, {} enabled edges, up to {} concrete states per session projection",
            states.len(),
            explored_edges,
            same_projection_states
        );
    }
}
