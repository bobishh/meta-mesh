# Co-ownership model

`CoOwnership.tla` bounds the authorization ledger to two scopes, two initial owners, three possible owners, and a fixed set of candidate records. Main scope starts at epoch 2 with Alice and Bob under strict-majority policy. This represents an already-established shared owner set. Fork scope starts absent. Certificate labels include candidate ID, kind, scope, parent, epoch, child, owners, identity, policy, signer set, and resolution references. IDs stand in for distinct canonical payload hashes; signatures themselves do not distinguish certificates.

`Issue` checks exact scope, parent, next epoch, allowed transition shape, and distinct current-owner quorum signatures. Majority means strictly more than half; unanimity means every current owner. `Observe` retains a valid non-resolution certificate. Same-parent children create retained conflict evidence; stale snapshots cannot erase it. Authorization fails closed only when unresolved conflict lies on selected head ancestry, so conflict on an abandoned branch does not block current authority. The model does not assert global consensus or that offline replicas have seen every certificate.

`Resolve` models a signed resolution record. It must use the common parent’s current quorum and reference the exact set of observed sibling children, excluding the resolution record itself. It becomes selected only when it covers every other observed child. A competing resolution or late sibling reopens conflict; a later resolution must cover the expanded set. `Fork` creates a distinct scope and genesis. When parent quorum is unavailable, resolution cannot proceed; users may fork. New governance stays blocked; content drafts/read/export are consumer obligations.

`RestoreIdentity` represents local recovery-word restoration of the same selected identity and changes no ledger authority. Alternate identity requires an ordinary quorum transition. Cryptographic phrase derivation and device key restoration remain implementation-level obligations. Model does not include phrase material.

The state graph exports `heads`, `nodes`, `children`, `selected`, `covered`, `open`, `issued`, `observed`, and `headProof`. `nodes` maps each record ID to `[epoch, owners, identity, policy, parent, scope]`. Edges carry TLC action labels with full candidate record fields, which lets conformance replay map model IDs to canonical certificate payload hashes. `headProof` is an independently updated selection witness; it supports the stale-head negative control. `recoveredIdentity` records only the local restore projection.

The main model checks the finite candidate graph. It includes branches A/B, late child C, descendant D, competing resolution R/S, covering resolution T, later resolution U, and separate fork F. Resolution IDs have distinct payloads through target ownership or policy fields. Positive TLC run found 2,144 distinct states. Fair liveness model restricts proposals to A/B/R and checks eventual conflict closure under weak fairness for resolution issue, resolution observation, and observation delivery. This assumes parent quorum remains available and fair message delivery; it makes no liveness claim under permanent partition or signer loss.

Four mutation runs require their named invariant to fail: one-signature threshold bypass, stale-head replay, conflict-evidence forgetting, and unilateral alternate-identity recovery. The focused runner stores compact logs and can retain a fresh graph with `--graph-dir PATH` or `COOWNERSHIP_GRAPH_DIR=PATH`.

Focused runner pins TLA+ tools 1.8.0 to SHA-256 `7beec0f04818732a62fa193731711a99aa4f11279499b2360a7d156c519ea78d` in its separate cache file. This matches the `tla2tools.jar` asset digest from the [official v1.8.0 GitHub release API](https://api.github.com/repos/tlaplus/tlaplus/releases/tags/v1.8.0). Existing `formal/check.sh` pin remains untouched.

## Executable conformance

Run the separate gate without changing CI:

```sh
./formal/check_coownership.sh --graph-dir /tmp/meta-mesh-coownership-graph
```

The gate exports fresh action-labeled TLC graphs, runs the ignored
`tlc_coownership` Rust replay, then runs real implementation mutations.
`MESH_TLC_COOWNERSHIP_GRAPH` is mandatory for standalone replay; missing input
fails rather than skips. Native fixtures create signed genesis and the initial
two-owner transition through real core APIs. Main model epoch 2 matches Rust
epoch 2; fork model epoch 0 maps to Rust genesis epoch 1. Offsets are fixed,
not inferred from an expected resulting head.

The replay builds state using planners, signatures and merge APIs, executes every
exported edge, and compares authorized owner sets/policy/epoch/certificate hash
or the active ambiguity and retained sibling evidence. A convergent model state
must have the same concrete signed history, pending records and local recovery
projection across incoming paths. The checked final graph covered all 6,912
edges across 2,144 states. Recovery fixtures seal/open the same root; browser
tests separately exercise restored identities on new devices.

`check_coownership_implementation.py` copies crates into a disposable workspace
and separately disables quorum, exact parent epoch, and transition-history union.
Each mutated build uses its own target directory and must fail its named concrete
assertion. Compiler errors and successful tests fail this verification. These
negative probes are focused signed scenarios, while the positive replay covers
the full finite model graph; no unbounded refinement proof is claimed.
