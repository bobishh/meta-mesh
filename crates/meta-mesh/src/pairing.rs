use js_sys::{Object, Reflect, Uint8Array};
use meta_mesh_core::{
    PairingCodec, WorkspaceJoinAck, WorkspaceJoinHandshake, WorkspaceJoinHandoff,
    WorkspaceJoinHandoffOutcome, WorkspaceJoinResponse,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}

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

#[wasm_bindgen]
pub struct WasmWorkspaceJoinHandshake {
    inner: WorkspaceJoinHandshake,
}

#[wasm_bindgen]
impl WasmWorkspaceJoinHandshake {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &str, side: &str) -> Result<WasmWorkspaceJoinHandshake, JsValue> {
        let inner = match side {
            "host" => WorkspaceJoinHandshake::host(secret),
            "guest" => WorkspaceJoinHandshake::guest(secret),
            _ => Err("Workspace join handshake side invalid".to_string()),
        }
        .map_err(js_error)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = sendRequest)]
    pub fn send_request(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.send_request(payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = receiveRequest)]
    pub fn receive_request(&mut self, frame: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.receive_request(frame).map_err(js_error)
    }

    #[wasm_bindgen(js_name = respond)]
    pub fn respond(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.respond(payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = reject)]
    pub fn reject(&mut self, message: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.reject(message).map_err(js_error)
    }

    #[wasm_bindgen(js_name = receiveResponse)]
    pub fn receive_response(&mut self, frame: &[u8]) -> Result<JsValue, JsValue> {
        let response = self.inner.receive_response(frame).map_err(js_error)?;
        let value = Object::new();
        match response {
            WorkspaceJoinResponse::Accepted(payload) => {
                Reflect::set(&value, &"kind".into(), &"accepted".into())?;
                Reflect::set(
                    &value,
                    &"payload".into(),
                    &Uint8Array::from(payload.as_slice()),
                )?;
            }
            WorkspaceJoinResponse::Rejected(error) => {
                Reflect::set(&value, &"kind".into(), &"rejected".into())?;
                Reflect::set(&value, &"error".into(), &error.into())?;
            }
        }
        Ok(value.into())
    }

    #[wasm_bindgen(js_name = acknowledgeRejection)]
    pub fn acknowledge_rejection(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.acknowledge_rejection().map_err(js_error)
    }

    #[wasm_bindgen(js_name = acknowledgeSuccess)]
    pub fn acknowledge_success(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.acknowledge_success(payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = rejectAcceptedResponse)]
    pub fn reject_accepted_response(&mut self, message: &str) -> Result<Vec<u8>, JsValue> {
        self.inner
            .reject_accepted_response(message)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = receiveAck)]
    pub fn receive_ack(&mut self, frame: &[u8]) -> Result<JsValue, JsValue> {
        let acknowledgement = self.inner.receive_ack(frame).map_err(js_error)?;
        let value = Object::new();
        match acknowledgement {
            WorkspaceJoinAck::Accepted(payload) => {
                Reflect::set(&value, &"kind".into(), &"accepted".into())?;
                Reflect::set(
                    &value,
                    &"payload".into(),
                    &Uint8Array::from(payload.as_slice()),
                )?;
            }
            WorkspaceJoinAck::Rejected(error) => {
                Reflect::set(&value, &"kind".into(), &"rejected".into())?;
                Reflect::set(&value, &"error".into(), &error.into())?;
            }
        }
        Ok(value.into())
    }
}

fn handoff_outcome_name(outcome: WorkspaceJoinHandoffOutcome) -> String {
    match outcome {
        WorkspaceJoinHandoffOutcome::Retry => "retry",
        WorkspaceJoinHandoffOutcome::Failed => "failed",
        WorkspaceJoinHandoffOutcome::Adopted => "adopted",
        WorkspaceJoinHandoffOutcome::Complete => "complete",
    }
    .to_string()
}

#[wasm_bindgen]
pub struct WasmWorkspaceJoinHandoff {
    inner: WorkspaceJoinHandoff,
}

#[wasm_bindgen]
impl WasmWorkspaceJoinHandoff {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &str, side: &str) -> Result<WasmWorkspaceJoinHandoff, JsValue> {
        let inner = match side {
            "host" => WorkspaceJoinHandoff::host(secret),
            "guest" => WorkspaceJoinHandoff::guest(secret),
            _ => Err("Workspace handoff side invalid".to_string()),
        }
        .map_err(js_error)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = guestRequest)]
    pub fn guest_request(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.guest_request().map_err(js_error)
    }

    #[wasm_bindgen(js_name = hostReceiveRequest)]
    pub fn host_receive_request(&mut self, frame: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.host_receive_request(frame).map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestReceiveReady)]
    pub fn guest_receive_ready(&mut self, frame: &[u8]) -> Result<(), JsValue> {
        self.inner.guest_receive_ready(frame).map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestTransportFailed)]
    pub fn guest_transport_failed(&mut self, retryable: bool) -> Result<String, JsValue> {
        self.inner.guest_transport_failed(retryable).map(handoff_outcome_name).map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestResumeSucceeded)]
    pub fn guest_resume_succeeded(&mut self) -> Result<(), JsValue> {
        self.inner.guest_resume_succeeded().map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestResumeFailed)]
    pub fn guest_resume_failed(&mut self, retryable: bool) -> Result<String, JsValue> {
        self.inner.guest_resume_failed(retryable).map(handoff_outcome_name).map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestBeginConfirmation)]
    pub fn guest_begin_confirmation(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.guest_begin_confirmation().map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestConfirmationSent)]
    pub fn guest_confirmation_sent(&mut self) -> Result<String, JsValue> {
        self.inner.guest_confirmation_sent().map(handoff_outcome_name).map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestConfirmationFailed)]
    pub fn guest_confirmation_failed(&mut self) -> Result<String, JsValue> {
        self.inner.guest_confirmation_failed().map(handoff_outcome_name).map_err(js_error)
    }

    #[wasm_bindgen(js_name = hostReceiveConfirmation)]
    pub fn host_receive_confirmation(&mut self, frame: &[u8]) -> Result<(), JsValue> {
        self.inner.host_receive_confirmation(frame).map_err(js_error)
    }
}
