use std::io::{self, BufRead, Read, Write};

use meta_mesh_core::service_login::{verify_service_login, ServiceLoginEvidence};
use serde::{Deserialize, Serialize};

const MAX_REQUEST_BYTES: usize = 128 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    identity: meta_mesh_core::PublicIdentity,
    device_id: String,
    certificates: Vec<meta_mesh_core::DeviceCertificate>,
    proof: meta_mesh_core::SignedEnvelope<meta_mesh_core::service_login::ServiceLoginPayload>,
    expected_origin: String,
    expected_challenge: String,
    expected_expires_at_ms: u64,
    now_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    person_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

fn main() {
    let stdin = io::stdin();
    let mut line = Vec::new();
    let read = stdin
        .lock()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut line);
    let response = match read {
        Ok(length) if length > 0 && length <= MAX_REQUEST_BYTES && line.last() == Some(&b'\n') => {
            verify_line(&line[..line.len() - 1])
        }
        _ => denied("invalid_request"),
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &response).is_ok() {
        let _ = output.write_all(b"\n");
        let _ = output.flush();
    }
}

fn verify_line(bytes: &[u8]) -> Output {
    let Ok(input) = serde_json::from_slice::<Input>(bytes) else {
        return denied("invalid_request");
    };
    let evidence = ServiceLoginEvidence {
        identity: input.identity,
        device_id: input.device_id,
        certificates: input.certificates,
        proof: input.proof,
    };
    match verify_service_login(
        &evidence,
        &input.expected_origin,
        &input.expected_challenge,
        input.expected_expires_at_ms,
        input.now_ms,
    ) {
        Ok(verified) => Output {
            verified: true,
            person_id: Some(verified.person_id),
            device_id: Some(verified.device_id),
            error: None,
        },
        Err(_) => denied("invalid_or_expired_login"),
    }
}

fn denied(code: &'static str) -> Output {
    Output {
        verified: false,
        person_id: None,
        device_id: None,
        error: Some(code),
    }
}
