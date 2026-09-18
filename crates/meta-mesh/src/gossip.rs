use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
};
use bytes::Bytes;
use iroh_gossip::proto::{
    state::{InEvent, OutEvent, State},
    topic::{Command, Event},
    Config, Message, PeerData, Scope, TopicId,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
struct WireGossip {
    id: [u8; 32],
    content: Bytes,
    scope: WireDeliveryScope,
}

#[derive(Serialize, Deserialize)]
enum WireDeliveryScope {
    Swarm(u16),
    Neighbors,
}

#[derive(Serialize, Deserialize)]
enum WirePlumtreeMessage {
    Gossip(WireGossip),
    Prune,
}

#[derive(Serialize, Deserialize)]
enum WireTopicMessage {
    Swarm(()),
    Gossip(WirePlumtreeMessage),
}

#[derive(Serialize, Deserialize)]
struct WireMessage {
    topic: TopicId,
    message: WireTopicMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPacket {
    pub topic: String,
    pub sender: String,
    pub message_id: String,
    pub content: Vec<u8>,
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
            PeerData::default(),
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
        }
    }

    pub fn topic_id_for_name(name: &str) -> TopicId {
        let digest = blake3::hash(name.as_bytes());
        TopicId::from_bytes(*digest.as_bytes())
    }

    pub fn join_topic(&mut self, topic_name: &str, bootstrap_peers: Vec<String>) -> Result<String, String> {
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
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        let out_events: Vec<OutEvent<[u8; 32]>> = state
            .handle(
                InEvent::Command(topic_id, Command::Join(peer_ids)),
                now,
                None,
            )
            .collect();

        // Track neighbors
        let mut neighbors_set = HashSet::new();
        for peer in bootstrap_peers {
            if peer != self.local_peer_str {
                neighbors_set.insert(peer);
            }
        }
        for event in out_events {
            if let OutEvent::EmitEvent(t, Event::NeighborUp(p)) = event {
                if t == topic_id {
                    if let Ok(names) = self.peer_names.read() {
                        if let Some(name) = names.get(&p) {
                            neighbors_set.insert(name.clone());
                        } else {
                            neighbors_set.insert(hex::encode(p));
                        }
                    }
                }
            }
        }

        self.active_neighbors
            .write()
            .map_err(|e| e.to_string())?
            .insert(topic_name.to_string(), neighbors_set);

        Ok(topic_hex)
    }

    pub fn leave_topic(&mut self, topic_name: &str) -> Result<(), String> {
        let topic_id = Self::topic_id_for_name(topic_name);
        let now = n0_future::time::Instant::now();
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        let _ = state
            .handle(InEvent::Command(topic_id, Command::Quit), now, None)
            .collect::<Vec<_>>();

        self.active_neighbors
            .write()
            .map_err(|e| e.to_string())?
            .remove(topic_name);

        self.topic_names
            .write()
            .map_err(|e| e.to_string())?
            .remove(&topic_id);

        Ok(())
    }

    pub fn broadcast(&self, topic_name: &str, content: &[u8]) -> Result<Vec<u8>, String> {
        let topic_id = Self::topic_id_for_name(topic_name);
        let now = n0_future::time::Instant::now();
        let mut state = self.state.lock().map_err(|e| e.to_string())?;

        if state.state(&topic_id).is_none() {
            return Err(format!("Not joined to topic '{}'", topic_name));
        }

        let out_events: Vec<OutEvent<[u8; 32]>> = state
            .handle(
                InEvent::Command(
                    topic_id,
                    Command::Broadcast(Bytes::copy_from_slice(content), Scope::Swarm),
                ),
                now,
                None,
            )
            .collect();

        // If eager push emitted a SendMessage, serialize it
        for event in out_events {
            if let OutEvent::SendMessage(_peer, msg) = event {
                return postcard::to_stdvec(&msg).map_err(|e| e.to_string());
            }
        }

        // Standard wire message format matching iroh-gossip proto
        let msg_id = *blake3::hash(content).as_bytes();
        let wire_msg = WireMessage {
            topic: topic_id,
            message: WireTopicMessage::Gossip(WirePlumtreeMessage::Gossip(WireGossip {
                id: msg_id,
                content: Bytes::copy_from_slice(content),
                scope: WireDeliveryScope::Swarm(0),
            })),
        };
        postcard::to_stdvec(&wire_msg).map_err(|e| e.to_string())
    }

    pub fn handle_message(&self, sender: &str, raw_packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let sender_id = peer_id_from_str(sender);
        {
            if let Ok(mut names) = self.peer_names.write() {
                names.insert(sender_id, sender.to_string());
            }
        }

        let iroh_msg: Message<[u8; 32]> = match postcard::from_bytes(raw_packet) {
            Ok(msg) => msg,
            Err(_) => {
                // Backward-compatibility: JSON GossipPacket
                if let Ok(packet) = serde_json::from_slice::<GossipPacket>(raw_packet) {
                    let topic_id = Self::topic_id_for_name(&packet.topic);
                    let msg_id = *blake3::hash(&packet.content).as_bytes();
                    let wire_msg = WireMessage {
                        topic: topic_id,
                        message: WireTopicMessage::Gossip(WirePlumtreeMessage::Gossip(WireGossip {
                            id: msg_id,
                            content: Bytes::copy_from_slice(&packet.content),
                            scope: WireDeliveryScope::Swarm(0),
                        })),
                    };
                    let encoded = postcard::to_stdvec(&wire_msg).map_err(|e| e.to_string())?;
                    match postcard::from_bytes(&encoded) {
                        Ok(m) => m,
                        Err(_) => return Ok(None),
                    }
                } else {
                    return Ok(None);
                }
            }
        };

        let now = n0_future::time::Instant::now();
        let mut state = self.state.lock().map_err(|e| e.to_string())?;

        let out_events: Vec<OutEvent<[u8; 32]>> = state
            .handle(InEvent::RecvMessage(sender_id, iroh_msg), now, None)
            .collect();

        let mut delivered_content = None;
        for event in out_events {
            match event {
                OutEvent::EmitEvent(topic_id, Event::Received(gossip_ev)) => {
                    delivered_content = Some(gossip_ev.content.to_vec());
                    if let Ok(topic_names) = self.topic_names.read() {
                        if let Some(topic_name) = topic_names.get(&topic_id) {
                            if let Ok(mut active) = self.active_neighbors.write() {
                                if let Some(set) = active.get_mut(topic_name) {
                                    if sender != self.local_peer_str {
                                        set.insert(sender.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                OutEvent::EmitEvent(topic_id, Event::NeighborUp(peer)) => {
                    if let Ok(topic_names) = self.topic_names.read() {
                        if let Some(topic_name) = topic_names.get(&topic_id) {
                            if let Ok(mut active) = self.active_neighbors.write() {
                                if let Some(set) = active.get_mut(topic_name) {
                                    let peer_str = self
                                        .peer_names
                                        .read()
                                        .ok()
                                        .and_then(|names| names.get(&peer).cloned())
                                        .unwrap_or_else(|| hex::encode(peer));
                                    if peer_str != self.local_peer_str {
                                        set.insert(peer_str);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(delivered_content)
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
    pub fn join_topic(&mut self, topic_name: &str, bootstrap_peers: Vec<String>) -> Result<String, JsValue> {
        self.inner.join_topic(topic_name, bootstrap_peers).map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = leaveTopic)]
    pub fn leave_topic(&mut self, topic_name: &str) -> Result<(), JsValue> {
        self.inner.leave_topic(topic_name).map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = broadcast)]
    pub fn broadcast(&self, topic_name: &str, content: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.broadcast(topic_name, content).map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = handleMessage)]
    pub fn handle_message(&self, sender: &str, raw_packet: &[u8]) -> Result<Option<Vec<u8>>, JsValue> {
        self.inner.handle_message(sender, raw_packet).map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = activeNeighbors)]
    pub fn active_neighbors(&self, topic_name: &str) -> Vec<String> {
        self.inner.active_neighbors(topic_name)
    }
}
