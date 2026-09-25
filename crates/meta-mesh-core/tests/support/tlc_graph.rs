use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub action: String,
}
#[derive(Deserialize)]
pub struct Graph {
    pub initial: String,
    pub states: BTreeMap<String, Value>,
    pub edges: Vec<Edge>,
}
impl Graph {
    pub fn load(env: &str) -> Self {
        let path =
            std::env::var(env).unwrap_or_else(|_| panic!("{env} missing: run ./formal/check.sh"));
        let graph: Self = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(!graph.states.is_empty() && !graph.edges.is_empty());
        graph
    }

    /// Every TLC edge is exercised after a shortest initial-to-source trace.
    /// Model state is never injected into implementation state.
    pub fn traces(&self) -> Vec<Vec<&Edge>> {
        let mut paths: BTreeMap<String, Vec<usize>> =
            BTreeMap::from([(self.initial.clone(), vec![])]);
        let mut outgoing: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (i, edge) in self.edges.iter().enumerate() {
            outgoing.entry(&edge.from).or_default().push(i);
        }
        let mut queue = VecDeque::from([self.initial.clone()]);
        while let Some(source) = queue.pop_front() {
            for &i in outgoing.get(source.as_str()).into_iter().flatten() {
                let edge = &self.edges[i];
                if !paths.contains_key(&edge.to) {
                    let mut path = paths[&source].clone();
                    path.push(i);
                    paths.insert(edge.to.clone(), path);
                    queue.push_back(edge.to.clone());
                }
            }
        }
        assert_eq!(paths.len(), self.states.len(), "Unreachable TLC states");
        self.edges
            .iter()
            .map(|edge| {
                let mut trace = paths[&edge.from]
                    .iter()
                    .map(|&i| &self.edges[i])
                    .collect::<Vec<_>>();
                trace.push(edge);
                trace
            })
            .collect()
    }
}

#[allow(dead_code)]
pub fn action(label: &str) -> (&str, Vec<&str>) {
    match label.split_once('(') {
        Some((name, args)) => (
            name,
            args.strip_suffix(')')
                .unwrap()
                .split(',')
                .map(str::trim)
                .collect(),
        ),
        None => (label, vec![]),
    }
}
