## 1. Contract and model

- [x] 1.1 Validate OpenSpec and define Given/When/Then acceptance for equal owners, quorum, removal, recovery, conflict, resolution and fork.
- [x] 1.2 Run bounded positive TLA+ safety/conditional-progress configurations and required negative controls.
- [x] 1.3 Document offline ambiguity, unavailable quorum, late evidence and exact model bounds.

## 2. Core protocol

- [x] 2.1 Implement opt-in v2 signed genesis/transition ledger with distinct-person quorum and parent/epoch binding; preserve v1.
- [x] 2.2 Implement merge retaining certified conflict evidence and explicit authorization status.
- [x] 2.3 Implement parent-quorum conflict resolution, competing resolution and late-evidence handling.
- [x] 2.4 Implement independent fork planning with fresh scope/genesis, without copying source authority.
- [x] 2.5 Verify real-signature happy/failure scenarios, malicious duplicates, stale owners, recovery boundaries and serialization limits.

## 3. Conformance and exposure

- [x] 3.1 Couple fresh TLC actions/state graphs to production Rust, with implementation negative controls.
- [x] 3.2 Expose v2 decisions through WASM and regenerate/type-check the browser surface.
- [x] 3.3 Run relevant v1 regressions and focused formal/conformance checks; document evidence and remaining consumer adoption.
