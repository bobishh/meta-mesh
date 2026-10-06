# Causal write admission

`meta_mesh_core::causal_admission::evaluate_causal_admission` and browser
`WasmStateCore.evaluateCausalAdmission` rebuild an authorized Automerge document
from raw change history, signed write proofs and signed authority frontiers.
They reclassify every available hash, including previously accepted changes.
They do not mutate or persist the raw history.

## Input and output

Input contains `records`, a `WorkspaceWriteAuthorizationSnapshot`, optional
`pendingChangeBytes`, and `nowMs`. The snapshot document is the raw history,
not its authorized projection. Pending bytes are actual encoded Automerge
changes, allowing a missing-dependency change to remain explicit. Dependencies,
hashes and transaction metadata come from those bytes rather than a host graph.

Output contains sorted per-hash `decisions`, `verifiedAuthorizations`, and
`authorizedDocument` bytes. An admitted change requires authorized dependencies.
A missing, pending or quarantined dependency makes its descendant pending.
Once dependencies are admitted, missing or incompatible write authority makes
the change quarantined. Both statuses are reconsidered when evidence changes.
Invalid signed evidence rejects evaluation; it is not an admitted change.

## Revocation and renewed access

A signed revocation preserves old-grant history inside its frontier. Old-grant
changes outside that frontier leave the authorized projection even if a replica
accepted them before learning about revocation. Raw history remains evidence.
A renewed grant permits new commands; it cannot approve an old signature merely
by being attached to the same hash.

New editor transactions include `authorityGrantHash` in their Automerge message:
base64url SHA-256 of the canonical JSON of the complete signed grant envelope.
The hash therefore binds the change to the particular signed grant. Transaction
metadata also includes author person and device IDs, checked against the write
proof for every role. Legacy V1 transaction metadata without `kind` remains
recognized. Legacy editor changes without grant binding cannot use a renewed
grant to cross a revocation boundary. Non-genesis history without usable author
identity cannot be rebound by an owner outside signed frontiers. An explicit
review creates a new command on the authorized document, with a new hash and
signature; the original quarantined change remains unchanged.

## Clock and resource bounds

Causal permission ignores `nowMs` and Automerge change timestamps. This explicit
path retains signed authority timestamp syntax validation but disables its
receiver-clock future-skew comparison. Legacy authority APIs retain their
existing clock sanity checks; this does not claim their admission is independent
of clock skew. Automerge conflict structure remains its own merge rule; timestamps
cannot confer write authority here.

Evaluation accepts at most 256 MiB of raw plus pending change bytes, 64 MiB of
serialized write-proof records, 20,000 proof records and 1,000,000 changes.
These are rejection bounds, not a latency guarantee. The evaluator performs a
complete history replay; transport policy packaging and incremental projection
are separate work.

See [bounded model and conformance](../formal/CausalAdmission.md). Applications
own durable raw/view storage, retries, review UI and capability negotiation.
This additive API does not migrate every MetaMesh consumer to the new policy.
