#![cfg(target_family = "wasm")]

use iroh::SecretKey;
use iroh_webrtc_transport::browser::{
    BrowserDialOptions, BrowserWebRtcAcceptor, BrowserWebRtcConnection, BrowserWebRtcNode,
    BrowserWebRtcNodeConfig, BrowserWebRtcStream,
};
use meta_mesh_core::{
    DEFAULT_STREAM_READ_BYTES, MAX_PAIRING_HEADER_BYTES, MAX_RPC_FRAME_BYTES, PairingCodec,
    effective_read_limit, pairing_frame_budget,
};
use wasm_bindgen::prelude::*;

const ALPN: &[u8] = b"match/sync/0";

#[wasm_bindgen]
pub struct BrowserNode {
    inner: BrowserWebRtcNode,
}

#[wasm_bindgen]
impl BrowserNode {
    #[wasm_bindgen(js_name = start)]
    pub async fn start(secret: Option<Vec<u8>>) -> Result<BrowserNode, JsValue> {
        crate::browser_tracing::install_browser_transport_tracing();
        let secret_key = match secret {
            Some(mut bytes) => {
                if bytes.len() != 32 {
                    return Err(JsError::new("secret key must be exactly 32 bytes").into());
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&bytes);
                bytes.fill(0);
                let key = SecretKey::from_bytes(&key_bytes);
                key_bytes.fill(0);
                key
            }
            None => SecretKey::generate(),
        };
        let inner = BrowserWebRtcNode::builder(BrowserWebRtcNodeConfig::default(), secret_key)
            .accept_facade(ALPN)
            .spawn()
            .await?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(getter, js_name = endpointId)]
    pub fn endpoint_id(&self) -> String {
        self.inner.endpoint_id().to_owned()
    }

    #[wasm_bindgen(js_name = dial)]
    pub async fn dial(&self, remote_endpoint: String) -> Result<BrowserConnection, JsValue> {
        let connection = self
            .inner
            .dial(
                &remote_endpoint,
                ALPN,
                BrowserDialOptions::webrtc_preferred(),
            )
            .await?;
        Ok(BrowserConnection { inner: connection })
    }

    #[wasm_bindgen(js_name = dialRelay)]
    pub async fn dial_relay(&self, remote_endpoint: String) -> Result<BrowserConnection, JsValue> {
        let connection = self
            .inner
            .dial(&remote_endpoint, ALPN, BrowserDialOptions::iroh_relay())
            .await?;
        Ok(BrowserConnection { inner: connection })
    }

    #[wasm_bindgen(js_name = accept)]
    pub async fn accept(&self) -> Result<BrowserAcceptor, JsValue> {
        Ok(BrowserAcceptor {
            inner: self.inner.accept(ALPN).await?,
        })
    }

    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self, reason: Option<String>) -> Result<(), JsValue> {
        self.inner
            .close(reason.as_deref().unwrap_or("Mesh node closed"))
            .await
    }
}

#[wasm_bindgen]
pub struct BrowserAcceptor {
    inner: BrowserWebRtcAcceptor,
}

#[wasm_bindgen]
impl BrowserAcceptor {
    #[wasm_bindgen(js_name = accept)]
    pub async fn accept(&self) -> Result<Option<BrowserConnection>, JsValue> {
        Ok(self
            .inner
            .accept()
            .await?
            .map(|inner| BrowserConnection { inner }))
    }

    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self) -> Result<(), JsValue> {
        self.inner.close("Mesh acceptor closed").await
    }
}

#[wasm_bindgen]
pub struct BrowserConnection {
    inner: BrowserWebRtcConnection,
}

#[wasm_bindgen]
impl BrowserConnection {
    #[wasm_bindgen(getter, js_name = remoteEndpointId)]
    pub fn remote_endpoint_id(&self) -> String {
        self.inner.remote_endpoint_id().to_owned()
    }

    #[wasm_bindgen(js_name = openStream)]
    pub async fn open_stream(&self) -> Result<BrowserStream, JsValue> {
        Ok(BrowserStream {
            inner: self.inner.open_bi().await?,
        })
    }

    #[wasm_bindgen(js_name = acceptStream)]
    pub async fn accept_stream(&self) -> Result<BrowserStream, JsValue> {
        Ok(BrowserStream {
            inner: self.inner.accept_bi().await?,
        })
    }

    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self) -> Result<(), JsValue> {
        self.inner.close("Mesh connection closed").await
    }
}

#[wasm_bindgen]
pub struct BrowserStream {
    inner: BrowserWebRtcStream,
}

#[wasm_bindgen]
impl BrowserStream {
    #[wasm_bindgen(js_name = send)]
    pub async fn send(&self, bytes: &[u8]) -> Result<(), JsValue> {
        if bytes.len() > MAX_RPC_FRAME_BYTES {
            return Err(JsValue::from_str("Stream write exceeds ingress limit"));
        }
        self.inner.send_all(bytes).await
    }

    #[wasm_bindgen(js_name = read)]
    pub async fn read(&self, maximum_bytes: Option<usize>) -> Result<Vec<u8>, JsValue> {
        let maximum_bytes = effective_read_limit(maximum_bytes, DEFAULT_STREAM_READ_BYTES);
        self.inner.read_to_end(maximum_bytes).await
    }

    #[wasm_bindgen(js_name = readPairingFrame)]
    pub async fn read_pairing_frame(
        &self,
        maximum_bytes: Option<usize>,
    ) -> Result<Vec<u8>, JsValue> {
        let maximum_bytes = effective_read_limit(maximum_bytes, DEFAULT_STREAM_READ_BYTES);
        self.read_pairing_frame_after_prefix(Vec::new(), maximum_bytes, None)
            .await
    }

    /// Read only a bounded header before requesting the peer's payload reservation.
    #[wasm_bindgen(js_name = readPairingFrameAdmitted)]
    pub async fn read_pairing_frame_admitted(
        &self,
        maximum_bytes: usize,
        admit: js_sys::Function,
    ) -> Result<Vec<u8>, JsValue> {
        self.read_pairing_frame_after_prefix(
            Vec::new(),
            effective_read_limit(Some(maximum_bytes), DEFAULT_STREAM_READ_BYTES),
            Some(&admit),
        )
        .await
    }

    #[wasm_bindgen(js_name = readPairingOrRawPrefix)]
    pub async fn read_pairing_or_raw_prefix(
        &self,
        raw_prefix: &[u8],
        maximum_raw_bytes: Option<usize>,
    ) -> Result<Vec<u8>, JsValue> {
        self.read_mixed_frame(
            raw_prefix,
            effective_read_limit(maximum_raw_bytes, DEFAULT_STREAM_READ_BYTES),
            DEFAULT_STREAM_READ_BYTES,
            None,
        )
        .await
    }

    #[wasm_bindgen(js_name = readPairingOrRawPrefixAdmitted)]
    pub async fn read_pairing_or_raw_prefix_admitted(
        &self,
        raw_prefix: &[u8],
        maximum_raw_bytes: usize,
        maximum_frame_bytes: usize,
        admit: js_sys::Function,
    ) -> Result<Vec<u8>, JsValue> {
        self.read_mixed_frame(
            raw_prefix,
            effective_read_limit(Some(maximum_raw_bytes), DEFAULT_STREAM_READ_BYTES),
            effective_read_limit(Some(maximum_frame_bytes), DEFAULT_STREAM_READ_BYTES),
            Some(&admit),
        )
        .await
    }

    async fn admit_read(
        admit: Option<&js_sys::Function>,
        maximum_bytes: usize,
    ) -> Result<(), JsValue> {
        if let Some(admit) = admit {
            let result = admit.call1(
                &JsValue::UNDEFINED,
                &JsValue::from_f64(maximum_bytes as f64),
            )?;
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&result)).await?;
        }
        Ok(())
    }

    async fn read_mixed_frame(
        &self,
        raw_prefix: &[u8],
        maximum_raw_bytes: usize,
        maximum_frame_bytes: usize,
        admit: Option<&js_sys::Function>,
    ) -> Result<Vec<u8>, JsValue> {
        let mut prefix = Vec::with_capacity(raw_prefix.len());
        while prefix.len() < raw_prefix.len() {
            let Some(chunk) = self
                .inner
                .read_chunk(raw_prefix.len() - prefix.len())
                .await?
            else {
                break;
            };
            prefix.extend_from_slice(&chunk);
        }
        if prefix.starts_with(raw_prefix) {
            if prefix.len() > maximum_raw_bytes {
                let _ = self.inner.reset().await;
                return Err(JsValue::from_str(
                    "Raw stream exceeds ingress limit: stage=stream",
                ));
            }
            Self::admit_read(admit, maximum_raw_bytes).await?;
            let remaining = self
                .inner
                .read_to_end(maximum_raw_bytes - prefix.len())
                .await;
            return remaining.map(|bytes| {
                prefix.extend_from_slice(&bytes);
                prefix
            });
        }
        self.read_pairing_frame_after_prefix(prefix, maximum_frame_bytes, admit)
            .await
    }

    async fn read_pairing_frame_after_prefix(
        &self,
        mut bytes: Vec<u8>,
        maximum_bytes: usize,
        admit: Option<&js_sys::Function>,
    ) -> Result<Vec<u8>, JsValue> {
        let initial_frame_limit = (|| -> Result<Option<usize>, JsValue> {
            let Some(header_end) = bytes.iter().position(|byte| *byte == b'\n') else {
                return Ok(None);
            };
            if header_end + 1 > MAX_PAIRING_HEADER_BYTES {
                return Err(JsValue::from_str(
                    "Pairing header exceeds ingress limit: stage=stream",
                ));
            }
            let header = PairingCodec::inspect(&bytes[..header_end + 1])
                .map_err(|_| JsValue::from_str("Pairing frame invalid: stage=header"))?;
            let budget = pairing_frame_budget(&header.frame_type)
                .ok_or_else(|| JsValue::from_str("Pairing frame invalid: stage=kind"))?;
            let payload_wire_limit = header_end
                .saturating_add(1)
                .saturating_add(budget.max_payload_bytes);
            let limit = maximum_bytes
                .min(budget.max_wire_bytes)
                .min(payload_wire_limit);
            if bytes.len() > limit {
                return Err(JsValue::from_str(
                    "Pairing frame exceeds ingress limit: stage=stream",
                ));
            }
            Ok(Some(limit))
        })();
        let mut frame_limit = match initial_frame_limit {
            Ok(limit) => limit,
            Err(error) => {
                let _ = self.inner.reset().await;
                return Err(error);
            }
        };
        let result = async {
            if let Some(limit) = frame_limit {
                Self::admit_read(admit, limit).await?;
            }
            loop {
                let read_limit = frame_limit
                    .map_or_else(
                        || MAX_PAIRING_HEADER_BYTES.saturating_sub(bytes.len()),
                        |limit| limit.saturating_sub(bytes.len()).saturating_add(1),
                    )
                    .min(16 * 1024);
                if read_limit == 0 {
                    return Err(JsValue::from_str(
                        "Pairing header exceeds ingress limit: stage=stream",
                    ));
                }
                let Some(chunk) = self.inner.read_chunk(read_limit).await? else {
                    return Ok(bytes);
                };
                let projected = bytes.len().saturating_add(chunk.len());
                if let Some(limit) = frame_limit {
                    if projected > limit {
                        return Err(JsValue::from_str(
                            "Pairing frame exceeds ingress limit: stage=stream",
                        ));
                    }
                } else {
                    let newline = bytes
                        .iter()
                        .chain(chunk.iter())
                        .position(|byte| *byte == b'\n');
                    let Some(header_end) = newline else {
                        if projected >= MAX_PAIRING_HEADER_BYTES {
                            return Err(JsValue::from_str(
                                "Pairing header exceeds ingress limit: stage=stream",
                            ));
                        }
                        bytes.extend_from_slice(&chunk);
                        continue;
                    };
                    if header_end + 1 > MAX_PAIRING_HEADER_BYTES {
                        return Err(JsValue::from_str(
                            "Pairing header exceeds ingress limit: stage=stream",
                        ));
                    }
                    let mut prefix = Vec::with_capacity(header_end + 1);
                    prefix.extend(bytes.iter().chain(chunk.iter()).take(header_end + 1));
                    let header = PairingCodec::inspect(&prefix)
                        .map_err(|_| JsValue::from_str("Pairing frame invalid: stage=header"))?;
                    let budget = pairing_frame_budget(&header.frame_type)
                        .ok_or_else(|| JsValue::from_str("Pairing frame invalid: stage=kind"))?;
                    let payload_wire_limit = prefix.len().saturating_add(budget.max_payload_bytes);
                    frame_limit = Some(
                        maximum_bytes
                            .min(budget.max_wire_bytes)
                            .min(payload_wire_limit),
                    );
                    if projected > frame_limit.unwrap_or(maximum_bytes) {
                        return Err(JsValue::from_str(
                            "Pairing frame exceeds ingress limit: stage=stream",
                        ));
                    }
                    Self::admit_read(admit, frame_limit.unwrap_or(maximum_bytes)).await?;
                }
                bytes.extend_from_slice(&chunk);
            }
        }
        .await;
        match result {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                let _ = self.inner.reset().await;
                Err(error)
            }
        }
    }

    #[wasm_bindgen(js_name = closeSend)]
    pub async fn close_send(&self) -> Result<(), JsValue> {
        self.inner.close_send().await
    }

    #[wasm_bindgen(js_name = reset, unchecked_return_type = "Promise<void>")]
    pub fn reset(&self) -> js_sys::Promise {
        let stream = self.inner.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            stream.reset().await?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

#[wasm_bindgen]
pub async fn start_browser_node(secret: Option<Vec<u8>>) -> Result<BrowserNode, JsValue> {
    BrowserNode::start(secret).await
}
