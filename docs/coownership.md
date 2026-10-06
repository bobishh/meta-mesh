# Co-owned scope governance (opt-in v2)

`meta_mesh_core::coownership` owns protocol decisions. The browser facade lives in
`@meta-uber/mesh-workspace` and calls the same Rust through WASM. Existing v1
single-controller records and consumers remain unchanged. This is a new protocol
API, not automatic migration or a completed Match/Lighthouse admin interface.

## Signing and membership

Create a signed genesis with one creator. A transition binds kind/version, scope,
exact parent payload hash, next epoch, sorted unique owner identities and policy.
The parent's policy decides approval: majority is `floor(N / 2) + 1`; unanimous
requires every owner. Two owners therefore both approve removal or policy changes.
Every owner has equal authority. Separate devices belonging to one person count
as one approval. Root signatures bind signer ID to person ID; device signatures
require the owner's verified certificate chain. The browser approval helper uses
the root key when available (including after identity recovery), otherwise the
certified device key. Restoring a root does not add a vote or undo removal.

Payload hashes use the existing canonical JSON rules and SHA-256/base64url.
Approval lists are detached signatures over the common payload. Incomplete
proposals can be held by the application, but are not valid replicated ledgers.
The application persists signed history and distributes complete referenced
history; this API does not provide transport or storage.

Recovery words and encrypted identity envelope restore the existing root identity.
They do not override removal, change quorum, or recover missing document data.
Device enrollment/revocation keeps its separate existing obligations.

## Conflict and escape

Merging valid sibling records retains both and reports `ambiguous`. New ordinary
governance proposals are blocked. Read/export and independently stored drafts are
application behavior; the validator does not lock content storage.

Resolve by naming every known conflicting sibling and gathering the common
parent's quorum over the agreed owner set and policy. Resolution is another signed
record; original evidence stays. Competing resolutions or an unseen late sibling
reopen conflict. A later resolution can cover that larger set. Descendants of an
abandoned branch remain evidence and do not override the selected resolved branch.
Incomplete replicas can temporarily see different authority; no global finality
or offline consensus is promised.
Epoch belongs to a parent chain, not a global clock: a resolution can select a
shallower record than an abandoned descendant. Consumers must bind authority to
the selected certificate hash and explicit status, not choose the largest epoch.

If quorum cannot be obtained, `forkCoownershipLedger` validates the source and
creates a new scope ID with the caller as its sole creator. It works with an
ambiguous source. It does not copy the source's authority or mutate its ledger.
Copying available content and explaining incomplete copies remain host duties.

## Browser API

- `createCoownershipLedger(profile, scopeId, policy?)`
- `coownerIdentity(profile)`
- `planCoownershipTransition(ledger, owners, policy)`
- `approveCoownershipPayload(profile, payload)`
- `mergeCoownershipLedgers(currentOrNull, incoming)`
- `validateCoownershipLedger(ledger)`
- `planCoownershipResolution(ledger, parentCertificateHash, owners, policy)`
- `forkCoownershipLedger(source, profile, newScopeId, policy?)`

Planning returns unsigned payloads; collect approvals before appending records.
Validation returns an explicit authorized state or ambiguous conflict evidence.
Typed helpers sort owner IDs before planning without mutating caller arrays.
Unknown v2 fields are rejected in Rust JSON and WASM input, including records and
approvals. Embedded v1 device-certificate types retain existing deserialization
behavior. Hosts must not reinterpret v2 as single-owner v1 permissions.

## Bounds and checks

Limits: 64 owners, 4,096 transitions, 4,096 resolutions, 2,048 approvals per
record, 512 UTF-8 bytes per scope ID, 256 KiB canonical bytes per payload, 16 MiB serialized bytes per ledger. Signatures
require the fixed 86-character unpadded base64url form before decoding. Parent
traversal visits each record once, including reverse-ordered history. Epoch
increments are checked for overflow. Hosts still need request-size limits before
deserialization, persistence limits, and an explicit v2 admission/access adapter.

Core tests use real Ed25519 root/device signatures. Browser tests use real
WebCrypto identities and rebuilt WASM for quorum refusal, successful approval,
conflict/resolution/late evidence, strict fields and independent fork. Formal
bounds, assumptions and executable conformance are documented in
[CoOwnership](../formal/CoOwnership.md). These checks are bounded evidence, not
an unbounded proof or a claim that existing application UIs consume v2.
