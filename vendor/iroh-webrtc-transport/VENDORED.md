# Vendored iroh-webrtc-transport

This directory contains the published `iroh-webrtc-transport` 0.1.0-alpha.2
source, from `https://crates.io/crates/iroh-webrtc-transport/0.1.0-alpha.2`.
Its upstream repository is `https://github.com/SuddenlyHazel/iroh-webrtc-transport`
at source revision `fdb511da1650600dba5b97e04880b1aa2738a6`.

The package metadata declares the MIT license. Neither the published crate
source nor upstream revision includes a license file or copyright notice, so
this vendored copy does not reconstruct either one.

Local patch: `src/browser_runtime/direct.rs` makes terminal WebRTC signals sent
during `close_node` best effort. A settled direct dial removes its bootstrap
signal writer, so propagating that missing-writer error previously skipped
`BrowserRuntime::close()`. Ordinary live signaling still uses the strict
`send_outbound_signals` result path.
