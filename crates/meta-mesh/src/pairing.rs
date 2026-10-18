use js_sys::{Object, Reflect, Uint8Array};
use meta_mesh_core::{
    MAX_CONCURRENT_FRAMES_PER_CONNECTION, MAX_IN_FLIGHT_BYTES_PER_CONNECTION,
    MAX_LOGICAL_TRANSFER_BYTES, MAX_PAIRING_HEADER_BYTES, MAX_RPC_FRAME_BYTES,
    MAX_TRANSFER_DEADLINE_MS, MAX_TRANSFER_PAGES, PairingCodec, PairingFrameHeader,
    WorkspaceJoinAck, WorkspaceJoinHandoff, WorkspaceJoinHandoffOutcome, WorkspaceJoinHandshake,
    WorkspaceJoinResponse, pairing_frame_budget, pairing_payload_limit,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn js_error(error: impl ToString) -> JsValue {
    JsError::new(&error.to_string()).into()
}

pub(crate) fn preflight_pairing_frame(frame: &Uint8Array) -> Result<PairingFrameHeader, JsValue> {
    let frame_len = frame.length() as usize;
    if frame_len > MAX_RPC_FRAME_BYTES {
        return Err(js_error(format!(
            "Pairing frame exceeds ingress limit: stage=ffi bytes={frame_len} max={MAX_RPC_FRAME_BYTES}"
        )));
    }
    let header_len = frame_len.min(MAX_PAIRING_HEADER_BYTES);
    let header_bytes = frame.subarray(0, header_len as u32).to_vec();
    let header = PairingCodec::inspect(&header_bytes).map_err(js_error)?;
    let budget = pairing_frame_budget(&header.frame_type)
        .ok_or_else(|| js_error("Pairing frame invalid"))?;
    if frame_len > budget.max_wire_bytes {
        return Err(js_error(format!(
            "Pairing frame exceeds ingress limit: kind={} bytes={frame_len} max={}",
            header.frame_type, budget.max_wire_bytes
        )));
    }
    let payload_len = frame_len.saturating_sub(
        header_bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(header_len)
            + 1,
    );
    if payload_len > budget.max_payload_bytes {
        return Err(js_error(format!(
            "Pairing payload exceeds ingress limit: kind={} bytes={payload_len} max={}",
            header.frame_type, budget.max_payload_bytes
        )));
    }
    Ok(header)
}

#[wasm_bindgen]
pub struct WasmPairingCodec;

#[wasm_bindgen]
pub struct WasmIngressBudgetProfile;

#[wasm_bindgen]
impl WasmIngressBudgetProfile {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    #[wasm_bindgen(js_name = maxHeaderBytes)]
    pub fn max_header_bytes(&self) -> usize {
        MAX_PAIRING_HEADER_BYTES
    }

    #[wasm_bindgen(js_name = maxFrameBytes)]
    pub fn max_frame_bytes(&self, frame_type: &str) -> Result<usize, JsValue> {
        pairing_frame_budget(frame_type)
            .map(|budget| budget.max_wire_bytes)
            .ok_or_else(|| JsError::new("Unsupported pairing frame kind").into())
    }

    #[wasm_bindgen(js_name = maxPayloadBytes)]
    pub fn max_payload_bytes(&self, frame_type: &str) -> Result<usize, JsValue> {
        pairing_frame_budget(frame_type)
            .map(|budget| budget.max_payload_bytes)
            .ok_or_else(|| JsError::new("Unsupported pairing frame kind").into())
    }

    #[wasm_bindgen(js_name = maxLogicalTransferBytes)]
    pub fn max_logical_transfer_bytes(&self) -> usize {
        MAX_LOGICAL_TRANSFER_BYTES
    }

    #[wasm_bindgen(js_name = maxTransferPages)]
    pub fn max_transfer_pages(&self) -> usize {
        MAX_TRANSFER_PAGES
    }

    #[wasm_bindgen(js_name = maxTransferDeadlineMs)]
    pub fn max_transfer_deadline_ms(&self) -> u64 {
        MAX_TRANSFER_DEADLINE_MS
    }

    #[wasm_bindgen(js_name = maxInFlightBytesPerConnection)]
    pub fn max_in_flight_bytes_per_connection(&self) -> usize {
        MAX_IN_FLIGHT_BYTES_PER_CONNECTION
    }

    #[wasm_bindgen(js_name = maxConcurrentFramesPerConnection)]
    pub fn max_concurrent_frames_per_connection(&self) -> usize {
        MAX_CONCURRENT_FRAMES_PER_CONNECTION
    }
}

impl Default for WasmIngressBudgetProfile {
    fn default() -> Self {
        Self::new()
    }
}

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
        payload: &Uint8Array,
    ) -> Result<Vec<u8>, JsValue> {
        let payload_limit =
            pairing_payload_limit(frame_type, secret).map_err(|message| JsError::new(&message))?;
        if payload.length() as usize > payload_limit {
            return Err(JsError::new("Pairing payload exceeds ingress limit").into());
        }
        let payload = payload.to_vec();
        PairingCodec::encode(frame_type, secret, &payload)
            .map_err(|message| JsError::new(&message).into())
    }

    #[wasm_bindgen(js_name = inspect)]
    pub fn inspect(&self, frame: &Uint8Array) -> Result<JsValue, JsValue> {
        let header = preflight_pairing_frame(frame)?;
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
        frame: &Uint8Array,
        expected_type: &str,
        expected_secret: &str,
    ) -> Result<Vec<u8>, JsValue> {
        preflight_pairing_frame(frame)?;
        let frame = frame.to_vec();
        PairingCodec::decode(&frame, expected_type, expected_secret)
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
        self.inner
            .guest_transport_failed(retryable)
            .map(handoff_outcome_name)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestResumeSucceeded)]
    pub fn guest_resume_succeeded(&mut self) -> Result<(), JsValue> {
        self.inner.guest_resume_succeeded().map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestResumeFailed)]
    pub fn guest_resume_failed(&mut self, retryable: bool) -> Result<String, JsValue> {
        self.inner
            .guest_resume_failed(retryable)
            .map(handoff_outcome_name)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestBeginConfirmation)]
    pub fn guest_begin_confirmation(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.guest_begin_confirmation().map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestConfirmationSent)]
    pub fn guest_confirmation_sent(&mut self) -> Result<String, JsValue> {
        self.inner
            .guest_confirmation_sent()
            .map(handoff_outcome_name)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = guestConfirmationFailed)]
    pub fn guest_confirmation_failed(&mut self) -> Result<String, JsValue> {
        self.inner
            .guest_confirmation_failed()
            .map(handoff_outcome_name)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = hostReceiveConfirmation)]
    pub fn host_receive_confirmation(&mut self, frame: &[u8]) -> Result<(), JsValue> {
        self.inner
            .host_receive_confirmation(frame)
            .map_err(js_error)
    }
}
