// Exercise the exact stream lifecycle used by the browser adapter over native loopback QUIC.
#[cfg(all(test, not(target_family = "wasm")))]
#[path = "../../../vendor/iroh-webrtc-transport/src/core/stream_state.rs"]
mod stream_state;
