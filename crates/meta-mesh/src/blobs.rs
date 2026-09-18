use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
};
use bytes::Bytes;
use iroh_blobs::{
    ticket::BlobTicket,
    BlobFormat, Hash,
};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub kind: String,
    pub version: u32,
    #[serde(rename = "blobId")]
    pub blob_id: String,
    pub hash: String,
    pub ticket: String,
    pub name: String,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTicket {
    pub hash: String,
    pub node: String,
}

#[derive(Debug, Default, Clone)]
pub struct BlobEngine {
    storage: Arc<RwLock<HashMap<Hash, Bytes>>>,
}

impl BlobEngine {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn hash_for_data(data: &[u8]) -> Hash {
        Hash::new(data)
    }

    pub fn create_blob(
        &self,
        data: &[u8],
        name: &str,
        media_type: &str,
        node_endpoint: Option<&str>,
    ) -> Result<BlobDescriptor, String> {
        let hash = Self::hash_for_data(data);
        let hash_hex = hash.to_hex().to_string();
        let blob_id = format!("blake3:{}", hash_hex);

        let ticket = if let Some(endpoint) = node_endpoint {
            if let Ok(node_id) = iroh::EndpointId::from_str(endpoint) {
                let addr = EndpointAddr::new(node_id);
                BlobTicket::new(addr, hash, BlobFormat::Raw).to_string()
            } else {
                format!("iroh-blob:{}:{}", endpoint, hash_hex)
            }
        } else {
            format!("iroh-blob:local:{}", hash_hex)
        };

        // Store bytes
        let mut store = self.storage.write().map_err(|e| e.to_string())?;
        store.insert(hash, Bytes::copy_from_slice(data));

        Ok(BlobDescriptor {
            kind: "blob".to_string(),
            version: 1,
            blob_id,
            hash: hash_hex,
            ticket,
            name: name.to_string(),
            media_type: media_type.to_string(),
            size: data.len(),
        })
    }

    pub fn put_blob(&self, hash_str: &str, data: &[u8]) -> Result<(), String> {
        let expected_hash = Self::parse_hash(hash_str)?;
        let actual_hash = Self::hash_for_data(data);
        if actual_hash != expected_hash {
            return Err("Data does not match expected Blake3 hash".to_string());
        }
        let mut store = self.storage.write().map_err(|e| e.to_string())?;
        store.insert(expected_hash, Bytes::copy_from_slice(data));
        Ok(())
    }

    pub fn get_blob(&self, hash_str: &str) -> Result<Option<Vec<u8>>, String> {
        let hash = Self::parse_hash(hash_str)?;
        let store = self.storage.read().map_err(|e| e.to_string())?;
        Ok(store.get(&hash).map(|bytes| bytes.to_vec()))
    }

    pub fn has_blob(&self, hash_str: &str) -> bool {
        if let Ok(hash) = Self::parse_hash(hash_str) {
            if let Ok(store) = self.storage.read() {
                return store.contains_key(&hash);
            }
        }
        false
    }

    pub fn verify_blob(&self, hash_str: &str, data: &[u8]) -> Result<bool, String> {
        let expected_hash = Self::parse_hash(hash_str)?;
        let actual_hash = Self::hash_for_data(data);
        Ok(actual_hash == expected_hash)
    }

    pub fn parse_ticket(ticket_str: &str) -> Result<ParsedTicket, String> {
        if let Ok(ticket) = BlobTicket::from_str(ticket_str) {
            return Ok(ParsedTicket {
                hash: ticket.hash().to_hex().to_string(),
                node: ticket.addr().id.to_string(),
            });
        }
        if let Some(rest) = ticket_str.strip_prefix("iroh-blob:") {
            let parts: Vec<&str> = rest.split(':').collect();
            if parts.len() >= 2 {
                return Ok(ParsedTicket {
                    node: parts[0].to_string(),
                    hash: parts[1].to_string(),
                });
            }
        }
        Err("Invalid blob ticket format".to_string())
    }

    fn parse_hash(input: &str) -> Result<Hash, String> {
        let clean = input.strip_prefix("blake3:").unwrap_or(input);
        Hash::from_str(clean).map_err(|e| format!("Invalid hash: {}", e))
    }
}

// WASM bindings
#[wasm_bindgen]
pub struct WasmBlobEngine {
    inner: BlobEngine,
}

#[wasm_bindgen]
impl WasmBlobEngine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { inner: BlobEngine::new() }
    }

    #[wasm_bindgen(js_name = createBlob)]
    pub fn create_blob(
        &self,
        data: &[u8],
        name: &str,
        media_type: &str,
        node_endpoint: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let desc = self.inner.create_blob(data, name, media_type, node_endpoint.as_deref())
            .map_err(|e| JsError::new(&e))?;
        serde_wasm_bindgen::to_value(&desc).map_err(|e| JsError::new(&e.to_string()).into())
    }

    #[wasm_bindgen(js_name = putBlob)]
    pub fn put_blob(&self, hash: &str, data: &[u8]) -> Result<(), JsValue> {
        self.inner.put_blob(hash, data).map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = getBlob)]
    pub fn get_blob(&self, hash: &str) -> Result<Option<Vec<u8>>, JsValue> {
        self.inner.get_blob(hash).map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = hasBlob)]
    pub fn has_blob(&self, hash: &str) -> bool {
        self.inner.has_blob(hash)
    }

    #[wasm_bindgen(js_name = verifyBlob)]
    pub fn verify_blob(&self, hash: &str, data: &[u8]) -> Result<bool, JsValue> {
        self.inner.verify_blob(hash, data).map_err(|e| JsError::new(&e).into())
    }

    #[wasm_bindgen(js_name = parseTicket)]
    pub fn parse_ticket(ticket: &str) -> Result<JsValue, JsValue> {
        let parsed = BlobEngine::parse_ticket(ticket).map_err(|e| JsError::new(&e))?;
        serde_wasm_bindgen::to_value(&parsed).map_err(|e| JsError::new(&e.to_string()).into())
    }
}
