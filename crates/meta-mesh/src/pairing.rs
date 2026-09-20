use meta_mesh_core::PairingCodec;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmPairingCodec;

#[wasm_bindgen]
impl WasmPairingCodec {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    #[wasm_bindgen(js_name = encode)]
    pub fn encode(
        &self,
        frame_type: &str,
        secret: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        PairingCodec::encode(frame_type, secret, payload)
            .map_err(|message| JsError::new(&message).into())
    }

    #[wasm_bindgen(js_name = inspect)]
    pub fn inspect(&self, frame: &[u8]) -> Result<JsValue, JsValue> {
        let header = PairingCodec::inspect(frame).map_err(|message| JsError::new(&message))?;
        #[derive(Serialize)]
        struct PublicHeader<'a> {
            #[serde(rename = "type")]
            frame_type: &'a str,
            secret: &'a str,
        }
        serde_wasm_bindgen::to_value(&PublicHeader {
            frame_type: &header.frame_type,
            secret: &header.secret,
        })
        .map_err(|error| JsError::new(&error.to_string()).into())
    }

    #[wasm_bindgen(js_name = decode)]
    pub fn decode(
        &self,
        frame: &[u8],
        expected_type: &str,
        expected_secret: &str,
    ) -> Result<Vec<u8>, JsValue> {
        PairingCodec::decode(frame, expected_type, expected_secret)
            .map_err(|message| JsError::new(&message).into())
    }
}

impl Default for WasmPairingCodec {
    fn default() -> Self {
        Self::new()
    }
}
