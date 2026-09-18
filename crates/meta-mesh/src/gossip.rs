use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, RwLock},
};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

const SEEN_CAPACITY: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPacket {
    pub topic: String,
    pub sender: String,
    pub message_id: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GossipTopicState {
    pub topic_id: TopicId,
    pub topic_name: String,
    pub neighbors: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct GossipEngine {
    local_peer_id: String,
    topics: Arc<RwLock<HashMap<String, GossipTopicState>>>,
    seen: Arc<RwLock<(HashSet<String>, VecDeque<String>)>>,
}

impl GossipEngine {
    pub fn new(local_peer_id: &str) -> Self {
        Self {
            local_peer_id: local_peer_id.to_string(),
            topics: Arc::new(RwLock::new(HashMap::new())),
            seen: Arc::new(RwLock::new((HashSet::new(), VecDeque::new()))),
        }
    }

    pub fn topic_id_for_name(name: &str) -> TopicId {
        let digest = blake3::hash(name.as_bytes());
        TopicId::from_bytes(*digest.as_bytes())
    }

    pub fn join_topic(&mut self, topic_name: &str, bootstrap_peers: Vec<String>) -> Result<String, String> {
        let topic_id = Self::topic_id_for_name(topic_name);
        let topic_hex = hex::encode(topic_id.as_bytes());

        let mut topics = self.topics.write().map_err(|e| e.to_string())?;
        let mut neighbors = HashSet::new();
        for peer in bootstrap_peers {
            if peer != self.local_peer_id {
                neighbors.insert(peer);
            }
        }

        topics.insert(
            topic_name.to_string(),
            GossipTopicState {
                topic_id,
                topic_name: topic_name.to_string(),
                neighbors,
            },
        );

        Ok(topic_hex)
    }

    pub fn leave_topic(&mut self, topic_name: &str) -> Result<(), String> {
        let mut topics = self.topics.write().map_err(|e| e.to_string())?;
        topics.remove(topic_name);
        Ok(())
    }

    pub fn broadcast(&self, topic_name: &str, content: &[u8]) -> Result<Vec<u8>, String> {
        let topics = self.topics.read().map_err(|e| e.to_string())?;
        if !topics.contains_key(topic_name) {
            return Err(format!("Not joined to topic '{}'", topic_name));
        }

        // Derive deterministic message ID
        let mut hasher = blake3::Hasher::new();
        hasher.update(topic_name.as_bytes());
        hasher.update(self.local_peer_id.as_bytes());
        hasher.update(content);
        let message_id = hasher.finalize().to_hex().to_string();

        self.mark_seen(&message_id)?;

        let packet = GossipPacket {
            topic: topic_name.to_string(),
            sender: self.local_peer_id.clone(),
            message_id,
            content: content.to_vec(),
        };

        serde_json::to_vec(&packet).map_err(|e| e.to_string())
    }

    pub fn handle_message(&self, _sender: &str, raw_packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let packet: GossipPacket = match serde_json::from_slice(raw_packet) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };

        if self.is_seen(&packet.message_id)? {
            return Ok(None); // Suppress duplicate message
        }

        self.mark_seen(&packet.message_id)?;

        // Record neighbor if topic is joined
        {
            let mut topics = self.topics.write().map_err(|e| e.to_string())?;
            if let Some(state) = topics.get_mut(&packet.topic) {
                if packet.sender != self.local_peer_id {
                    state.neighbors.insert(packet.sender.clone());
                }
            }
        }

        Ok(Some(packet.content))
    }

    pub fn active_neighbors(&self, topic_name: &str) -> Vec<String> {
        if let Ok(topics) = self.topics.read() {
            if let Some(state) = topics.get(topic_name) {
                return state.neighbors.iter().cloned().collect();
            }
        }
        Vec::new()
    }

    fn is_seen(&self, message_id: &str) -> Result<bool, String> {
        let seen = self.seen.read().map_err(|e| e.to_string())?;
        Ok(seen.0.contains(message_id))
    }

    fn mark_seen(&self, message_id: &str) -> Result<(), String> {
        let mut seen = self.seen.write().map_err(|e| e.to_string())?;
        if seen.0.insert(message_id.to_string()) {
            seen.1.push_back(message_id.to_string());
            if seen.1.len() > SEEN_CAPACITY {
                if let Some(oldest) = seen.1.pop_front() {
                    seen.0.remove(&oldest);
                }
            }
        }
        Ok(())
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
