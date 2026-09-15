# Verification measurements

Measured 2026-09-15 on the local test fixtures and Chromium real-route suites. Values describe current fixtures, not production latency guarantees.

## Sparse gossip

Default bounds: low 2, target 4, high 6, eager fanout 3.

| Devices | Maximum degree | Processed frames | Rounds | Converged |
| ---: | ---: | ---: | ---: | --- |
| 3 | 2 | 8 | 4 | yes |
| 10 | 4 | 45 | 10 | yes |
| 100 | 4 | 482 | 22 | yes |

The ten-device split-brain fixture admitted one change in each five-device component. After restoring one bridge and republishing availability, all ten stores held both changes. A sleeping tenth device caught up after one repair publication.

## Automerge bytes

| Fixture | Sync frame | Saved document | Ratio |
| --- | ---: | ---: | ---: |
| Fresh one-message bootstrap hello | 48 B | 181 B | 26.5% |
| One change after 500-message convergence | 220 B | 5,314 B | 4.1% |

The bootstrap exchange uses further native request/response frames; the first-frame number is not total bootstrap traffic. Incremental evidence proves the new change does not resend the complete saved document.

## Multiple tabs and reconnect

- Canonical device-delivery fixture: first instance route fails, sibling route commits, one signed durable ACK completes delivery.
- Twang Chromium: two tabs under one durable device, first route closed, sibling receives one message; after every route closes the message remains pending, reopening a tab delivers it once. Scenario wall time: 9.5 s.
- Match Chromium: two tabs remain one device with two routes; closing either route preserves delivery through the sibling. Scenario wall time: 35.8 s including pairing, two writes, UI assertions, tab close, and cleanup.
- Match Chromium: fully closed remote returns, both peers report connected, queued card arrives. Scenario wall time: 26.9 s including offline detection and UI assertions.
- Duplicate visible deliveries in the multi-tab Twang scenario: 0. Canonical outbox-claim fixture allows one offer; a racing sibling emits 0. Duplicate network admission remains legal and idempotent.

These wall times are suite durations, not isolated reconnect latency. Structured `route.*`, `delivery.*`, and `sync.*` events now permit production percentile measurement without guessing from UI state.

## Remaining limits

- Message documents, attachment bytes, and call signaling are authenticated but not end-to-end encrypted against an untrusted future mailbox provider.
- Delivery cannot complete while every authorized holder is offline. Store-and-forward requires a separately trusted or E2EE-capable always-on node.
- Browser suspension and mobile radio policy can delay route publication and repair.
- Presence derives from recent transport activity. It does not prove delivery or Automerge convergence.
