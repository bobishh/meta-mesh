# Causal write admission

`CausalAdmission.tla` models write reclassification at two replicas. It keeps
received change records and authority evidence separate from the rebuilt
authorized view. The fixed DAG has five records: genesis `root`, old-grant
`inside` and `outside`, epoch-2 `regrant-edit`, and epoch-2
`depends-on-outside`. Raw changes and verified authority evidence are shared
in this bound; replicas rebuild separate views.

Model epochs are relative labels: old grant epoch `1`, newer grant epoch `2`.
The Rust fixture uses old grant epoch `1`, revocation epoch `2`, and new grant
epoch `3`; replay maps the model's newer-grant label to that signed fixture.

`inside` belongs to the signed revocation frontier; `outside` does not. Its
signed time is deliberately far in the future. Once a replica receives the
revocation, it retains `outside` in raw evidence and classifies it as
quarantined, even if it was in a prior projection. A later regrant admits
new epoch-2 records only. It does not change `outside`'s signed epoch or
frontier membership. `depends-on-outside` stays pending while `outside` is
missing and after its dependency is quarantined. A revocation becomes usable
only after its frontier head `inside` is in the raw graph. Reclassification
rebuilds projection from the full available dependency graph.
An epoch-2 change without its referenced grant proof is quarantined pending
full evidence re-evaluation; once the regrant proof arrives,
`regrant-edit` can be admitted, while its dependent outside-frontier branch
remains pending.

The clock check samples past, current, and future receiver times (`-10000`,
`0`, `10000`) while holding evidence fixed. They do not participate in the
reference classification. This checks that timestamps cannot select an
authorized write. The model abstracts verified signatures and frontier
evidence as delivered evidence labels. It does not verify cryptography or
Automerge ancestry.

## Checks

Run positive safety, conditional convergence, clock variation, four negative
controls, fresh DOT/JSON graph export, and Rust conformance replay with:

```sh
./formal/check_causal_admission.sh --graph-dir /tmp/meta-mesh-causal-admission-graph
```

The runner pins the official TLA+ tools 1.8.0 release by SHA-256. Its cache is
separate from the co-ownership model. Positive safety checks raw evidence
retention, projection agreement with the reference policy, quarantine
retention, dependency closure, and missing-dependency exclusion. The liveness
specification requires weakly fair reclassification at both replicas; once
the shared evidence contains all five changes and both authority proofs, weakly
fair rebuilds at both replicas eventually produce equal projections. Raw
change delivery and authority-proof delivery are shared in this finite bound;
the model checks their relative order and asynchronous rebuilds, not independent
network arrival at each replica.

The checked positive graph has 3,147 distinct states and 10,700 generated
states at depth 10. TLC 1.8.0 exhaustively checked all listed invariants and
the conditional liveness property within this bound. The clock-only check
visited all three clock samples. Production Rust classification and projection
were compared across 854 clean model-state/replica snapshots. The graph exports
10,699 edges; Rust did not execute those edges individually. The runner then
checks four focused production mutations: regrant rebinding,
missing-dependency admission, receiver-clock authority, and owner rebinding of
legacy editor identity. Each must fail its named Rust assertion; compiler
failures do not count as caught mutations.

TLC negative controls replace one model policy rule at a time and must violate
their named invariant. They show each property detects the modeled fault; they
do not establish that production code contains or resists the corresponding
mutation. The Rust runner separately replays the exported graph through the
real admission API, and implementation mutations are reported separately:

| Mutation | Invariant | Fault exposed |
| --- | --- | --- |
| Known hash bypass | `KnownHashBypass` | Previously accepted outside-frontier hash survives revocation reclassification |
| Timestamp priority | `TimestampPriority` | Far-future signed time admits an outside-frontier old-grant change |
| Missing dependency acceptance | `MissingDependencyAcceptance` | A child is admitted before its dependency arrives |
| Forget quarantine | `ForgettingQuarantine` | Quarantined evidence is removed from retained quarantine state |

The exported JSON includes all explored states and labeled action edges. The
Rust test compares each clean exported replica state to the production
classifier; it does not claim an independent Rust execution of every edge.
The JSON's `raw`, `proofs`, `view`, and `dirty` fields identify received IDs,
shared verified authority evidence, per-replica classifications, and whether a
rebuild is needed. Each `view` value is a tuple of admitted, quarantined, and
pending hash sets, in that order. Candidate IDs map to signed Rust fixtures
with the same grant epoch, dependency hashes, and signed time metadata. The
ignored Rust test `tlc_causal_admission` evaluates each clean exported replica
state through
`causal_admission::evaluate_causal_admission`, compare admitted, quarantined,
and pending decisions, and compare the rebuilt authorized document. Model
labels and candidate metadata are fixture selectors; Rust derives dependency
and authorization decisions from signed records and the actual Automerge
document.

This is a finite model-based conformance check, not an unbounded refinement
proof. It does not claim immediate revocation knowledge during partitions,
global consent, cryptographic verification by TLC, or automatic enforcement by
Automerge structural merge. Availability and quarantined-draft UI remain host
responsibilities.
