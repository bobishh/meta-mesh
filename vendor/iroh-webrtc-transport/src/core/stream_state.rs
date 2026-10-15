use std::sync::atomic::AtomicBool;

use iroh::endpoint::{RecvStream, SendStream};

pub(crate) struct StreamState {
    pub(crate) send: tokio::sync::Mutex<SendStream>,
    pub(crate) recv: tokio::sync::Mutex<RecvStream>,
    pub(crate) closed_send: AtomicBool,
    pub(crate) closed_recv: AtomicBool,
    pub(crate) send_cancel: tokio::sync::Notify,
    pub(crate) recv_cancel: tokio::sync::Notify,
}

impl StreamState {
    pub(crate) fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: tokio::sync::Mutex::new(send),
            recv: tokio::sync::Mutex::new(recv),
            closed_send: AtomicBool::new(false),
            closed_recv: AtomicBool::new(false),
            send_cancel: tokio::sync::Notify::new(),
            recv_cancel: tokio::sync::Notify::new(),
        }
    }

    pub(crate) async fn read_to_end(&self, maximum_bytes: usize) -> Result<Vec<u8>, String> {
        let result = {
            let mut recv = self.recv.lock().await;
            if self.closed_recv.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("Stream closed".into());
            }
            let mut output = Vec::new();
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let remaining = maximum_bytes.saturating_sub(output.len());
                let read_limit = remaining.saturating_add(1).min(buffer.len());
                let read = tokio::select! {
                    _ = self.recv_cancel.notified() => break Err("Stream closed".into()),
                    result = recv.read(&mut buffer[..read_limit]) => result,
                };
                match read {
                    Ok(None) => break Ok(output),
                    Ok(Some(length)) if length > remaining => {
                        break Err("Stream read limit exceeded".into());
                    }
                    Ok(Some(length)) => output.extend_from_slice(&buffer[..length]),
                    Err(error) => break Err(error.to_string()),
                }
            }
        };
        if result.is_err() {
            self.reset().await;
        }
        result
    }

    pub(crate) async fn reset(&self) {
        self.closed_send
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.closed_recv
            .store(true, std::sync::atomic::Ordering::SeqCst);
        notify_stream_cancel(&self.send_cancel);
        notify_stream_cancel(&self.recv_cancel);
        // Wake pending I/O before awaiting either mutex; those futures own the guards.
        let _ = self.send.lock().await.reset(0u32.into());
        let _ = self.recv.lock().await.stop(0u32.into());
    }
}

pub(crate) fn notify_stream_cancel(cancel: &tokio::sync::Notify) {
    cancel.notify_waiters();
    cancel.notify_one();
}

#[cfg(not(target_family = "wasm"))]
#[cfg(test)]
#[path = "stream_state/tests.rs"]
mod tests;
