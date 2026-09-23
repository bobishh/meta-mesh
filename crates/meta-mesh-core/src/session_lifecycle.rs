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

#[derive(Debug, Default)]
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
}
