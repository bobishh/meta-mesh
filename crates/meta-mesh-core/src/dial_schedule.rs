use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{GossipBounds, GossipCandidate, select_scoped_neighbors};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialRouteInput {
    pub workspace_id: String,
    pub device_id: String,
    pub instance_id: String,
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
    pub local_instance_id: String,
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
        // Each endpoint pair has one dialer. Keeping this tie-break at the
        // instance level lets every browser tab own a session while avoiding
        // simultaneous dials to the same Iroh endpoint.
        if route.revoked
            || !local_endpoint_dials(
                &input.local_device_id,
                &input.local_instance_id,
                &route.device_id,
                &route.instance_id,
            )
        {
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
    let mut groups = BTreeMap::<(String, String, String), Vec<(usize, &DialRouteInput)>>::new();
    for (workspace_id, routes) in candidates {
        for (index, route) in routes {
            if selected.contains(&(workspace_id.clone(), route.device_id.clone())) {
                groups
                    .entry((
                        workspace_id.clone(),
                        route.device_id.clone(),
                        route.instance_id.clone(),
                    ))
                    .or_default()
                    .push((index, route));
            }
        }
    }
    let mut ready_groups = Vec::new();
    let mut retries = BTreeMap::<String, u64>::new();
    for ((workspace_id, _, _), routes) in groups {
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

fn local_endpoint_dials(
    local_device_id: &str,
    local_instance_id: &str,
    remote_device_id: &str,
    remote_instance_id: &str,
) -> bool {
    (local_device_id, local_instance_id) < (remote_device_id, remote_instance_id)
}

fn retry(retries: &mut BTreeMap<String, u64>, workspace_id: &str, at: u64) {
    let prior = retries.entry(workspace_id.to_string()).or_insert(at);
    *prior = (*prior).min(at);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_side_of_an_endpoint_pair_dials() {
        let route = |device_id: &str, instance_id: &str| DialRouteInput {
            workspace_id: "board".into(),
            device_id: device_id.into(),
            instance_id: instance_id.into(),
            revoked: false,
            health: 0,
            retry_at_ms: 0,
            has_session: false,
            attempt_active: false,
        };
        let lower = plan_dial_schedule(DialScheduleInput {
            local_device_id: "device-a".into(),
            local_instance_id: "tab-a".into(),
            now_ms: 1,
            routes: vec![route("device-b", "tab-b")],
        })
        .unwrap();
        let upper = plan_dial_schedule(DialScheduleInput {
            local_device_id: "device-b".into(),
            local_instance_id: "tab-b".into(),
            now_ms: 1,
            routes: vec![route("device-a", "tab-a")],
        })
        .unwrap();
        assert_eq!(lower.ready_groups, vec![vec![0]]);
        assert!(upper.ready_groups.is_empty());
    }

    #[test]
    fn schedules_each_reachable_remote_instance_independently() {
        let route = |instance_id: &str| DialRouteInput {
            workspace_id: "board".into(),
            device_id: "device-b".into(),
            instance_id: instance_id.into(),
            revoked: false,
            health: 0,
            retry_at_ms: 0,
            has_session: false,
            attempt_active: false,
        };
        let plan = plan_dial_schedule(DialScheduleInput {
            local_device_id: "device-a".into(),
            local_instance_id: "tab-a".into(),
            now_ms: 1,
            routes: vec![route("tab-b1"), route("tab-b2")],
        })
        .unwrap();
        assert_eq!(plan.ready_groups, vec![vec![0], vec![1]]);
    }
}
