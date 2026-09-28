# Bounded authorization transfer

Wire v1 keeps its 20,000-record / 16 MiB admission limits. Large outgoing history uses a v2 manifest and requested whole-record pages. No authority/history is deleted. New peers are required for paged transfers; old peers reject the unfamiliar frames instead of admitting unsigned history.

The manifest binds actual source heads, authority evidence, and a canonical digest of signed records. Each request binds its ordered actual candidate-minus-durable-local hashes, transfer identity, and signature cursor. Source verifies requested hashes against the actual frozen document and indexes records once. Proof additions with unchanged heads/authority change the manifest identity. Changes to authority or unavailable frozen history require restart.

Limits: 256 KiB encoded proof frame, 224 KiB page payload, 1,024 requested hashes, 20,000 records per page, 1,000,000 records / 256 MiB aggregate staging. Serialized envelope/authority bytes count. Indivisible oversized signed records and oversized authority manifests fail closed. Native allows 4,096 proof reply rounds separately from unchanged 128 document/control rounds. These are resource limits, not proof that arbitrary histories fit.

Pages remain untrusted. Saved raw page cache is optional; replay and restart recheck identities and structure. Final shared Rust admission validates cryptographic authority and full coverage of actual unknown changes. Missing/forged pages never produce durable document ACK. Host commits document/proofs atomically before engine completion, notification, or receipt. Interrupted transfers can reuse stable page identities; browser pending transfers abort after 20 seconds without page progress. Cache retention/eviction affects retry cost only.

## Repeat checks

```
cargo test -p meta-mesh-core --lib --no-default-features
cargo test --release -p meta-mesh-core --lib signed_initial_and_incremental_history_benchmark -- --ignored --nocapture
cargo check --manifest-path crates/meta-mesh-native/Cargo.toml --lib
sh scripts/build-wasm.sh
```

Deterministic benchmark fixture: one real signed owner proof per actual Automerge change; fixed key seeds; native release build, September 28 2026. It checks baseline rejection, complete initial coverage, one incremental change, absent proof, and forged signature. Source timings use one frozen source index; page generation excludes network/storage. Admission uses shared Rust policy, not Match UI.

| History / proofs | Aggregate bytes | Pages | Source prepare ms | All source pages ms | Full admission ms | One-proof delta ms |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 96,634 | 1 | 2 | 1 | 7 | 1 |
| 1,000 | 960,634 | 5 | 24 | 15 | 73 | 10 |
| 20,001 | 19,201,594 | 98 | 544 | 343 | 1,608 | 243 |

Delta history contains one additional change. Timings are observations on this machine, not CI thresholds or browser estimates. Paging bounds wire size; it does not remove full-history traversal, TS/WASM copying, admission CPU, or unbounded durable history growth. UI animation/connection flapping remain separate investigations. Automerge's existing 256 KiB live message limit remains separate from initial snapshot proof exchange. No authenticated compaction/checkpoint scheme is implemented.
