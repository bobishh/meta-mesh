# Verification

## Core and model

Checked 2026-10-06 against current production evaluator and rebuilt browser WASM.

- `cargo test --locked -p meta-mesh-core --lib`: 174 passed, 3 unrelated ignored.
- `npm test` in MetaMesh: 26 files, 288 tests passed, including three actual-WASM
  causal tests and the existing coownership regression tests.
- `npm run check`: passed.
- `scripts/build-wasm.sh`: passed. Existing generated API names retained;
  causal admission adds one static browser method alongside opt-in coownership.
- `formal/check_causal_admission.sh --graph-dir /tmp/meta-mesh-causal-verified`:
  3,147 distinct model states, conditional liveness and three clock samples;
  four named model negative controls caught.
- Fresh graph supplies 854 clean replica-state snapshots to the real Rust
  evaluator, checking admitted/quarantined/pending decisions and authorized
  Automerge projection. 10,699 action edges are exported, not action-replayed.
- Four real Rust mutations fail their intended concrete assertions: renewed
  grant rebinding, missing-dependency admission, receiver-clock dependence,
  and owner rebinding of legacy editor identity. Pristine baseline passes;
  compilation failure is not accepted as a caught mutation.
- Actual WASM tests cover late revocation of a previously accepted hash,
  immutable grant provenance, missing dependencies, receiver-clock variation,
  strict top-level input and a far-future edit followed by an authorized causal
  successor. Future timestamp does not lock that field.

The model shares raw/evidence between two independently refreshed views. It
abstracts cryptographic validation and does not simulate two independent raw
stores or transport. Signed fixture verification, actual Automerge dependencies
and projection replay are checked separately by Rust. This is bounded snapshot
conformance, not an unbounded refinement proof.

## Host integration

Checked against Match's integrated consumer, separately from the model:

- `npm test`: 95 files passed; 855 tests passed, one unrelated skipped.
- `npm run quality`: types, lint, unused-code, dependency, duplication and pattern
  checks passed. `npm run build` passed.
- `TINCANBAN_E2E_PORT=4247 npx playwright test --project=core e2e/causal-admission.spec.ts`:
  real-route browser scenario passed. An actual signed editor change is accepted,
  then a late signed device revocation retracts it. Its owner-authored descendant
  becomes pending. Field previews, disabled pending review, exact retained raw
  bytes and decisions after reload, injected storage failure and reload retry,
  and a new signed review command are checked. The original stays quarantined.
  This fixture exercises late-evidence admission, not a real network partition.
- `TINCANBAN_E2E_PORT=4245 npx playwright test --project=durable-mesh e2e/durable-mesh.spec.ts --grep 'paired editor goes offline|owner removes access'`:
  two real Iroh browser scenarios passed: edits on both sides while offline then
  convergence on reconnect; owner access removal stops writes while preserving
  previously accepted history.
- Host unit tests separately check atomic raw/view commit failure, verified-proof
  retention, unauthorized proof rejection, and review refusal during a pending
  ownership transfer. Both handshake directions require the Match-specific
  `causal-write-admission-v1` capability before importing authority.
- `TINCANBAN_E2E_PORT=4246 npx playwright test --project=core e2e/workspace-worker.spec.ts`:
  four browser scenarios passed. A 20,001-change signed history is checked by the
  reused worker, remains outside durable storage during validation, commits and
  survives reload. The menu opened in 75 ms while validation was pending on this
  machine. Worker restart failure and a forged signature leave durable document,
  proofs, UI and notifications unchanged. Exact evidence replay requires no new
  Worker; this does not claim that it skips an admission job.

Match transports serialized Automerge documents. The core's detached
`pendingChangeBytes` path is tested separately; Match has no tested orphan-byte
transport/persistence path. Other MetaMesh consumers have not been migrated.

No deployment or CI changes. Policy/transport WASM separation remains packaging
work; required policy initialization still precedes hydration.
