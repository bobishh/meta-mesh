## Why

Coownership conformance covers governance records, not document permission races.
An editor can submit an offline change concurrently with a downgrade/revocation;
one replica can already know that change while another rejects it. Physical clock
skew must not decide which document change or authority wins.

## What Changes

- Model signed revocation frontiers and document-change dependencies separately
  from governance selection, with real Rust/host conformance.
- Specify admission for changes inside/outside a signed revocation frontier,
  newer grants, previously accepted changes, missing dependencies and replay.
- Retain quarantine for concurrent unauthorized changes, including
  dependent changes, rather than silent deletion or automatic authorization.
- Verify clock independence of permission decisions and card conflict ordering;
  separately model legacy future-timestamp sanity checks as a liveness boundary.

## Impact

Adds an explicit causal evaluator and Match consumer integration for raw signed
history, authorized projections, durable review state and new reviewed commands.
Other MetaMesh consumers retain their current admission paths. No deployment,
CI change or policy/transport WASM packaging split.
