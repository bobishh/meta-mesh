## Previous admission path

- `authorization.rs::boundaries_allow` admits an old-grant hash only inside every
  applicable signed revocation/departure frontier, unless a newer access epoch
  authorizes it. Frontiers use Automerge ancestry, not wall-clock comparisons.
- `change_admission_flow.rs::classify_changes` classifies only unknown hashes as
  incoming; previously known hashes need explicit reconsideration semantics.
- The previous Match admission path supplied known hashes from the local
  document and asked Rust for admitted hashes. Previously accepted hashes did
  not receive full reclassification on late authority evidence.
- `authority.rs::valid_time` rejects authority timestamps more than five minutes
  ahead of the receiver clock. That sanity check remains a legacy liveness
  boundary; it does not select card winners. Coownership v2 has no timestamps.

## Causal policy

Keep raw signed change evidence separate from its authorized materialized view.
Preserve changes proved inside the signed revocation frontier. After revocation
is known, an old-grant change outside that frontier is unauthorized even if an
offline author's physical clock says it was created earlier. Concurrent events
do not gain a total chronological order from a timestamp.

Quarantine such changes and their dependent projection rather than silently
discarding them. Re-evaluate previously accepted changes when authority evidence
arrives. An authorized reviewer may explicitly create a new approved change;
this does not retroactively authorize the old signature. Availability and UI
for quarantined drafts are host responsibilities. The additive core evaluator
rebuilds the complete authorized projection; consumers must explicitly adopt it.

Use actual DAG dependencies/heads plus signed grant epochs and selected authority
certificate hashes. A large wall-clock value or unauthenticated logical counter
cannot confer priority, rights or a permanent lock. Vector clocks describe
causality; they do not prove permission. Missing dependencies stay pending rather
than advancing authority or being guessed from sequence numbers.

## Model and proof boundary

The bounded model has two independently refreshed views over shared raw change
and authority evidence, five change records, two editor grant generations and
one signed revocation frontier. It explores change/authority delivery order,
late reclassification, absent dependencies and renewed access. Separate clock
samples hold evidence fixed. This is not a two-peer transport or independent
raw-store model; host tests cover durable delivery and storage wiring.

Check eventual agreement only after equal signed evidence/dependencies arrive
and host reclassification runs fairly. Do not claim global consent, immediate
revocation knowledge during partitions, or that Automerge structural merge
automatically enforces security. Replay against production admission and actual
authorized-view/persistence operations; a TLC-only model is insufficient.


## Immutable provenance

New editor transaction metadata binds the full signed grant envelope through
`authorityGrantHash` (base64url SHA-256 of canonical JSON). Person/device metadata
must match the write signer for every role. New grants cannot be attached to old
bytes to bypass revocation. Legacy transaction metadata remains recognized;
unbound legacy edits cannot cross a revocation frontier using a regrant. Owner
re-signing cannot replace a known editor identity, and identity-less non-genesis
legacy history outside signed frontiers cannot be rebound implicitly.

Missing, pending or quarantined parents produce pending descendants before
checking the child's own grant. With admitted dependencies, missing or
incompatible write authorization produces quarantine. Both are reconsidered
when signed evidence changes; neither status authorizes application.

The causal evaluator ignores receiver time for permission, retaining signed
authority timestamp syntax checks while disabling future-skew comparison only
in this explicit API. Existing legacy authority admission retains its clock
sanity checks. No transport/policy artifact split is implemented here.
