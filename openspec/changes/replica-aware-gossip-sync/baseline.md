# Baseline

Recorded 2026-09-15 before protocol implementation.

## Verification

| Repository | Tests | Static/build check |
| --- | ---: | --- |
| meta-mesh | 156 passed in 13 files | `npm run check` passed |
| Match | 407 passed in 45 files | `npm run build` passed; Vite emitted existing chunk-size and dependency-comment warnings |
| Twang | 171 passed in 14 files | `npm run check` passed with zero Svelte diagnostics |

## Existing coverage

- Multiple browser instances: `mesh-instance` verifies unique instance slots and endpoint seeds; `mesh-workspace` verifies signed instance routes; `mesh-peer-store` verifies multiple routes under one device and route sequence renewal. Match verifies several catalog and reconnect cases.
- Reconnect: `mesh-transport` verifies direct/relay fallback, relay cooldown, non-stacking heartbeat, and bounded traces. Match verifies reconnect against stored and expired routes.
- Durable storage: `mesh-browser-store` verifies isolated byte storage and deletion. No commit-before-ack, crash-window, idempotent change-batch, or failed-write delivery coverage exists.
- Incremental sync: no native Automerge sync-state or change-hash storage coverage exists. Match and Twang still exchange complete documents.
- Partition healing: workspace ownership conflict tests cover competing authority records. No concurrent document branch, missed gossip, bridge recovery, or equal-head convergence coverage exists.
- Sparse gossip: no bounded-neighbor, forwarding, seen-cache, amplification, or large-topology simulation coverage exists.

This gap inventory defines the failing scenarios added by tasks 1.2 and 1.3.
