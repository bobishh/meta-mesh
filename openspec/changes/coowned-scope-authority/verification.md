# Verification record

## Contract and bounded model

- `openspec validate coowned-scope-authority --strict --no-interactive`: valid.
- Official-digest TLC 1.8.0: 2,144 distinct main states, 6,912 exported edges.
- Conditional fair-resolution configuration: 13 distinct states; no claim under
  missing consent, permanent partition or unavailable quorum.
- Four model negative controls caught their exact named invariants: quorum bypass,
  stale head selection, forgotten conflict and alternate-identity recovery bypass.

## Executable checks

- Core library regression run: 168 passed, 3 intentionally ignored formal tests.
- Focused coownership core suite: 11 passed with real Ed25519 signatures.
- TypeScript check passed; Vitest regression run: 25 files, 285 tests passed.
- Rebuilt WASM coownership acceptance: 4 passed, including both owner approvals,
  insufficient quorum, malformed fields on validate/merge, retained conflict,
  resolution, late evidence, independent fork and restored identity on new device.
- Existing browser declarations retained; six new static coownership methods.
- Final signed Rust/TLC replay covered every one of 6,912 edges and 2,144 states,
  with exact concrete-history equality across convergent paths.
- Three real-code mutations failed their intended assertions: quorum bypass,
  wrong parent epoch and lost sibling history. Compiler failures were rejected.
- Read-only protocol review found resource issues, then checked fixes: total
  ledger-byte bound, signature prechecks and parent-indexed graph traversal.

## Boundary

Finite model checks and executable tests are not an unbounded refinement proof.
Host persistence, request limits, document copying and transport are separate.
Match/Lighthouse do not yet consume v2 coownership or expose conflict resolution
buttons. Existing v1 remains active. No deployment, migration or CI changes.
