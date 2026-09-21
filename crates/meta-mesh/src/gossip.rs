use bytes::Bytes;
use iroh_gossip::proto::{
    Config, Message, PeerData, Scope, Timer, TopicId,
    state::{InEvent, OutEvent, State},
    topic::{Command, Event},
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPacket {
    pub topic: String,
    pub sender: String,
    pub message_id: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GossipSend {
    pub peer: String,
    #[serde(with = "serde_bytes")]
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GossipDelivery {
    pub topic: String,
    pub delivered_from: String,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GossipScheduledTimer {
    pub timer_id: u64,
    pub delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct GossipStep {
    pub topic_id: Option<String>,
    pub sends: Vec<GossipSend>,
    pub deliveries: Vec<GossipDelivery>,
    pub timers: Vec<GossipScheduledTimer>,
    pub disconnects: Vec<String>,
    pub neighbors_up: Vec<String>,
    pub neighbors_down: Vec<String>,
}

pub fn peer_id_from_str(s: &str) -> [u8; 32] {
    if s.len() == 64 {
        if let Ok(bytes) = hex::decode(s) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return arr;
        }
    }
    *blake3::hash(s.as_bytes()).as_bytes()
}

#[derive(Clone)]
pub struct GossipEngine {
    local_peer_str: String,
    local_peer_id: [u8; 32],
    state: Arc<Mutex<State<[u8; 32], StdRng>>>,
    peer_names: Arc<RwLock<HashMap<[u8; 32], String>>>,
    topic_names: Arc<RwLock<HashMap<TopicId, String>>>,
    active_neighbors: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    timers: Arc<Mutex<HashMap<u64, Timer<[u8; 32]>>>>,
    next_timer_id: Arc<AtomicU64>,
}

impl GossipEngine {
    pub fn local_peer_id(&self) -> [u8; 32] {
        self.local_peer_id
    }
    pub fn new(local_peer_id: &str) -> Self {
        let local_id = peer_id_from_str(local_peer_id);
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&local_id[0..8]);
        let rng = StdRng::seed_from_u64(u64::from_le_bytes(seed_bytes));

        let state = State::new(
            local_id,
            PeerData::new(local_peer_id.as_bytes().to_vec()),
            Config::default(),
            rng,
        );

        let mut peer_names = HashMap::new();
        peer_names.insert(local_id, local_peer_id.to_string());

        Self {
            local_peer_str: local_peer_id.to_string(),
            local_peer_id: local_id,
            state: Arc::new(Mutex::new(state)),
            peer_names: Arc::new(RwLock::new(peer_names)),
            topic_names: Arc::new(RwLock::new(HashMap::new())),
            active_neighbors: Arc::new(RwLock::new(HashMap::new())),
            timers: Arc::new(Mutex::new(HashMap::new())),
            next_timer_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn topic_id_for_name(name: &str) -> TopicId {
        let digest = blake3::hash(name.as_bytes());
        TopicId::from_bytes(*digest.as_bytes())
    }

    pub fn join_topic(
        &mut self,
        topic_name: &str,
        bootstrap_peers: Vec<String>,
    ) -> Result<GossipStep, String> {
        let topic_id = Self::topic_id_for_name(topic_name);
        let topic_hex = hex::encode(topic_id.as_bytes());

        let peer_ids: Vec<[u8; 32]> = {
            let mut names = self.peer_names.write().map_err(|e| e.to_string())?;
            bootstrap_peers
                .iter()
                .filter(|p| p.as_str() != self.local_peer_str.as_str())
                .map(|p| {
                    let pid = peer_id_from_str(p);
                    names.insert(pid, p.clone());
                    pid
                })
                .collect()
        };

        self.topic_names
            .write()
            .map_err(|e| e.to_string())?
            .insert(topic_id, topic_name.to_string());

        let now = n0_future::time::Instant::now();
        let out_events = {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state
                .handle(
                    InEvent::Command(topic_id, Command::Join(peer_ids)),
                    now,
                    None,
                )
                .collect::<Vec<_>>()
        };

        self.active_neighbors
            .write()
            .map_err(|e| e.to_string())?
            .insert(topic_name.to_string(), HashSet::new());

        let mut step = self.process_out_events(out_events)?;
        step.topic_id = Some(topic_hex);
        Ok(step)
    }

    pub fn leave_topic(&mut self, topic_name: &str) -> Result<GossipStep, String> {
        let topic_id = Self::topic_id_for_name(topic_name);
        let now = n0_future::time::Instant::now();
        let out_events = {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state
                .handle(InEvent::Command(topic_id, Command::Quit), now, None)
                .collect::<Vec<_>>()
        };

        self.active_neighbors
            .write()
            .map_err(|e| e.to_string())?
            .remove(topic_name);

        self.topic_names
            .write()
            .map_err(|e| e.to_string())?
            .remove(&topic_id);

        self.process_out_events(out_events)
    }

    pub fn broadcast(&self, topic_name: &str, content: &[u8]) -> Result<GossipStep, String> {
        let topic_id = Self::topic_id_for_name(topic_name);
        let now = n0_future::time::Instant::now();
        let out_events = {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            if state.state(&topic_id).is_none() {
                return Err(format!("Not joined to topic '{}'", topic_name));
            }
            state
                .handle(
                    InEvent::Command(
                        topic_id,
                        Command::Broadcast(Bytes::copy_from_slice(content), Scope::Swarm),
                    ),
                    now,
                    None,
                )
                .collect::<Vec<_>>()
        };
        self.process_out_events(out_events)
    }

    pub fn handle_message(&self, sender: &str, raw_packet: &[u8]) -> Result<GossipStep, String> {
        let sender_id = peer_id_from_str(sender);
        {
            if let Ok(mut names) = self.peer_names.write() {
                names.insert(sender_id, sender.to_string());
            }
        }

        let iroh_msg: Message<[u8; 32]> = postcard::from_bytes(raw_packet)
            .map_err(|_| "Invalid iroh gossip packet".to_string())?;

        let now = n0_future::time::Instant::now();
        let out_events = {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state
                .handle(InEvent::RecvMessage(sender_id, iroh_msg), now, None)
                .collect::<Vec<_>>()
        };
        self.process_out_events(out_events)
    }

    pub fn expire_timer(&self, timer_id: u64) -> Result<GossipStep, String> {
        let timer = self
            .timers
            .lock()
            .map_err(|e| e.to_string())?
            .remove(&timer_id);
        let Some(timer) = timer else {
            return Ok(GossipStep::default());
        };
        let out_events = {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state
                .handle(
                    InEvent::TimerExpired(timer),
                    n0_future::time::Instant::now(),
                    None,
                )
                .collect::<Vec<_>>()
        };
        self.process_out_events(out_events)
    }

    pub fn peer_disconnected(&self, peer: &str) -> Result<GossipStep, String> {
        let peer_id = peer_id_from_str(peer);
        let out_events = {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state
                .handle(
                    InEvent::PeerDisconnected(peer_id),
                    n0_future::time::Instant::now(),
                    None,
                )
                .collect::<Vec<_>>()
        };
        self.process_out_events(out_events)
    }

    fn process_out_events(
        &self,
        out_events: Vec<OutEvent<[u8; 32]>>,
    ) -> Result<GossipStep, String> {
        let mut step = GossipStep::default();
        for event in out_events {
            match event {
                OutEvent::SendMessage(peer, message) => step.sends.push(GossipSend {
                    peer: self.peer_name(peer),
                    packet: postcard::to_stdvec(&message).map_err(|e| e.to_string())?,
                }),
                OutEvent::EmitEvent(topic_id, Event::Received(event)) => {
                    step.deliveries.push(GossipDelivery {
                        topic: self.topic_name(topic_id),
                        delivered_from: self.peer_name(event.delivered_from),
                        content: event.content.to_vec(),
                    });
                }
                OutEvent::EmitEvent(topic_id, Event::NeighborUp(peer)) => {
                    let topic = self.topic_name(topic_id);
                    let peer = self.peer_name(peer);
                    if peer != self.local_peer_str {
                        self.active_neighbors
                            .write()
                            .map_err(|e| e.to_string())?
                            .entry(topic)
                            .or_default()
                            .insert(peer.clone());
                        step.neighbors_up.push(peer);
                    }
                }
                OutEvent::EmitEvent(topic_id, Event::NeighborDown(peer)) => {
                    let topic = self.topic_name(topic_id);
                    let peer = self.peer_name(peer);
                    if let Some(neighbors) = self
                        .active_neighbors
                        .write()
                        .map_err(|e| e.to_string())?
                        .get_mut(&topic)
                    {
                        neighbors.remove(&peer);
                    }
                    step.neighbors_down.push(peer);
                }
                OutEvent::ScheduleTimer(delay, timer) => {
                    let timer_id = self.next_timer_id.fetch_add(1, Ordering::Relaxed);
                    self.timers
                        .lock()
                        .map_err(|e| e.to_string())?
                        .insert(timer_id, timer);
                    step.timers.push(GossipScheduledTimer {
                        timer_id,
                        delay_ms: delay.as_millis().min(u128::from(u64::MAX)) as u64,
                    });
                }
                OutEvent::DisconnectPeer(peer) => step.disconnects.push(self.peer_name(peer)),
                OutEvent::PeerData(peer, data) => {
                    if let Ok(name) = std::str::from_utf8(data.as_bytes()) {
                        if !name.is_empty() {
                            self.peer_names
                                .write()
                                .map_err(|e| e.to_string())?
                                .insert(peer, name.to_string());
                        }
                    }
                }
            }
        }
        Ok(step)
    }

    fn peer_name(&self, peer: [u8; 32]) -> String {
        self.peer_names
            .read()
            .ok()
            .and_then(|names| names.get(&peer).cloned())
            .unwrap_or_else(|| hex::encode(peer))
    }

    fn topic_name(&self, topic: TopicId) -> String {
        self.topic_names
            .read()
            .ok()
            .and_then(|names| names.get(&topic).cloned())
            .unwrap_or_else(|| hex::encode(topic.as_bytes()))
    }

    pub fn active_neighbors(&self, topic_name: &str) -> Vec<String> {
        if let Ok(active) = self.active_neighbors.read() {
            if let Some(set) = active.get(topic_name) {
                return set.iter().cloned().collect();
            }
        }
        Vec::new()
    }
}

// WASM bindings
#[wasm_bindgen]
pub struct WasmGossipEngine {
    inner: GossipEngine,
}

#[wasm_bindgen]
impl WasmGossipEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(local_peer_id: &str) -> Self {
        Self {
            inner: GossipEngine::new(local_peer_id),
        }
    }

    #[wasm_bindgen(js_name = joinTopic)]
    pub fn join_topic(
        &mut self,
        topic_name: &str,
        bootstrap_peers: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        self.inner
            .join_topic(topic_name, bootstrap_peers)
            .and_then(|step| serde_wasm_bindgen::to_value(&step).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = leaveTopic)]
    pub fn leave_topic(&mut self, topic_name: &str) -> Result<JsValue, JsValue> {
        self.inner
            .leave_topic(topic_name)
            .and_then(|step| serde_wasm_bindgen::to_value(&step).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = broadcast)]
    pub fn broadcast(&self, topic_name: &str, content: &[u8]) -> Result<JsValue, JsValue> {
        self.inner
            .broadcast(topic_name, content)
            .and_then(|step| serde_wasm_bindgen::to_value(&step).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = handleMessage)]
    pub fn handle_message(&self, sender: &str, raw_packet: &[u8]) -> Result<JsValue, JsValue> {
        self.inner
            .handle_message(sender, raw_packet)
            .and_then(|step| serde_wasm_bindgen::to_value(&step).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = expireTimer)]
    pub fn expire_timer(&self, timer_id: u64) -> Result<JsValue, JsValue> {
        self.inner
            .expire_timer(timer_id)
            .and_then(|step| serde_wasm_bindgen::to_value(&step).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = peerDisconnected)]
    pub fn peer_disconnected(&self, peer: &str) -> Result<JsValue, JsValue> {
        self.inner
            .peer_disconnected(peer)
            .and_then(|step| serde_wasm_bindgen::to_value(&step).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = activeNeighbors)]
    pub fn active_neighbors(&self, topic_name: &str) -> Vec<String> {
        self.inner.active_neighbors(topic_name)
    }
}
