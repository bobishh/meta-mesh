use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{GossipBounds, GossipCandidate, select_scoped_neighbors};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialRouteInput {
    pub workspace_id: String,
    pub device_id: String,
    pub revoked: bool,
    pub health: i64,
    pub retry_at_ms: u64,
    pub has_session: bool,
    pub attempt_active: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialScheduleInput {
    pub local_device_id: String,
    pub now_ms: u64,
    pub routes: Vec<DialRouteInput>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DialSchedulePlan {
    pub ready_groups: Vec<Vec<usize>>,
    pub retries: BTreeMap<String, u64>,
}

pub fn plan_dial_schedule(input: DialScheduleInput) -> Result<DialSchedulePlan, String> {
    let mut candidates = BTreeMap::<String, Vec<(usize, &DialRouteInput)>>::new();
    for (index, route) in input.routes.iter().enumerate() {
        // Each pair has one dialer. Simultaneous Iroh dials can alias the
        // same underlying connection; closing a rejected duplicate then
        // closes the accepted session as well.
        if route.revoked || route.device_id <= input.local_device_id {
            continue;
        }
        candidates
            .entry(route.workspace_id.clone())
            .or_default()
            .push((index, route));
    }
    let mut selected = HashSet::<(String, String)>::new();
    for (workspace_id, routes) in &candidates {
        let people = routes
            .iter()
            .map(|(_, route)| GossipCandidate {
                device_id: route.device_id.clone(),
                health: route.health,
                backed_off_until: 0,
            })
            .collect::<Vec<_>>();
        for device_id in select_scoped_neighbors(
            &input.local_device_id,
            &people,
            &GossipBounds::default(),
            input.now_ms as i64,
            0,
        )? {
            selected.insert((workspace_id.clone(), device_id));
        }
    }
    let mut groups = BTreeMap::<(String, String), Vec<(usize, &DialRouteInput)>>::new();
    for (workspace_id, routes) in candidates {
        for (index, route) in routes {
            if selected.contains(&(workspace_id.clone(), route.device_id.clone())) {
                groups
                    .entry((workspace_id.clone(), route.device_id.clone()))
                    .or_default()
                    .push((index, route));
            }
        }
    }
    let mut ready_groups = Vec::new();
    let mut retries = BTreeMap::<String, u64>::new();
    for ((workspace_id, _), routes) in groups {
        if routes[0].1.has_session {
            continue;
        }
        if routes[0].1.attempt_active {
            retry(
                &mut retries,
                &workspace_id,
                input.now_ms.saturating_add(1_000),
            );
            continue;
        }
        let ready = routes
            .iter()
            .filter(|(_, route)| input.now_ms >= route.retry_at_ms)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        if !ready.is_empty() {
            ready_groups.push(ready);
        } else if let Some(at) = routes.iter().map(|(_, route)| route.retry_at_ms).min() {
            retry(&mut retries, &workspace_id, at);
        }
    }
    Ok(DialSchedulePlan {
        ready_groups,
        retries,
    })
}

fn retry(retries: &mut BTreeMap<String, u64>, workspace_id: &str, at: u64) {
    let prior = retries.entry(workspace_id.to_string()).or_insert(at);
    *prior = (*prior).min(at);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_side_of_a_device_pair_dials() {
        let route = |device_id: &str| DialRouteInput {
            workspace_id: "board".into(), device_id: device_id.into(), revoked: false,
            health: 0, retry_at_ms: 0, has_session: false, attempt_active: false,
        };
        let lower = plan_dial_schedule(DialScheduleInput {
            local_device_id: "device-a".into(), now_ms: 1, routes: vec![route("device-b")],
        }).unwrap();
        let upper = plan_dial_schedule(DialScheduleInput {
            local_device_id: "device-b".into(), now_ms: 1, routes: vec![route("device-a")],
        }).unwrap();
        assert_eq!(lower.ready_groups, vec![vec![0]]);
        assert!(upper.ready_groups.is_empty());
    }
}
