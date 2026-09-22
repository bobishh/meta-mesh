#![cfg(target_family = "wasm")]

use iroh::SecretKey;
use iroh_webrtc_transport::browser::{
    BrowserDialOptions, BrowserWebRtcAcceptor, BrowserWebRtcConnection, BrowserWebRtcNode,
    BrowserWebRtcNodeConfig, BrowserWebRtcStream,
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
        self.inner.send_all(bytes).await
    }

    #[wasm_bindgen(js_name = read)]
    pub async fn read(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.read_to_end().await
    }

    #[wasm_bindgen(js_name = closeSend)]
    pub async fn close_send(&self) -> Result<(), JsValue> {
        self.inner.close_send().await
    }
}

#[wasm_bindgen]
pub async fn start_browser_node(secret: Option<Vec<u8>>) -> Result<BrowserNode, JsValue> {
    BrowserNode::start(secret).await
}
