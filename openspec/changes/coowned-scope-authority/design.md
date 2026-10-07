## Context

`scope_authority.rs` currently replays one controller from immutable signed genesis, control transfers and editor succession. Its v1 validators and consumers cannot safely interpret multiple controllers. Existing `formal/check.sh` checks bounded TLA+ models and replays exported graphs against Rust; use that toolchain for a focused coownership check.

## Decisions

### Add an explicit opt-in protocol

Keep v1 types and validators unchanged. V2 governance uses a separate ledger and domain/kind/version-bound signed records. Genesis starts with one authenticated creator. Adding owners uses a quorum certificate; no implicit owner inferred from documents, transport routes, UI state or recovery words. Unsupported consumers must not downgrade a v2 ledger into v1 single-owner access.

### Identity, devices and owners remain distinct

An owner is a person ID verified against its root public key. Certified devices may sign on its behalf, but multiple devices/signatures from one person count once. Recovery words plus encrypted envelope restore that same root identity; a different root requires ordinary quorum-authorized membership change. Device enrollment/revocation retains its existing separate validation obligations.

### Parent policy governs transitions

Every membership/policy transition binds scope ID, exact parent certificate hash and next epoch. It is authorized by distinct owners in the parent's set under the parent's policy. Policies are strict majority or unanimous; majority is floor(N/2)+1. Membership cannot become empty. A proposed policy cannot approve itself. Removed owners' signatures do not count for descendants. Signature verification uses existing cryptographic helpers, not a new implementation.

### Conflict is evidence, not arrival order

Union authenticated records without dropping valid history. Multiple certified sibling transitions represent conflict. A replica with incomplete history may temporarily see one branch; no global finality or partition consensus is claimed. Once a replica knows incompatible evidence, it denies new governance authorization until resolution. Read/export and separately held local drafts remain available. Invalid/quorum-incomplete records cannot manufacture an authenticated conflict.

### Resolution references the conflict

A resolution names the common parent and exact incompatible certificates it resolves, and supplies the agreed owner set/policy. It needs the common parent's quorum, including a parent owner removed on one disputed branch. Retain all original evidence. Two incompatible resolutions conflict in turn. A valid previously unseen sibling or competing resolution reopens conflict unless included in a later authorized resolution. No automatic timestamp/hash winner, automatic rollback or administrator-token override.

### Fork preserves escape without takeover

If the parent quorum cannot be reached, any holder may fork its available content into a new scope ID and authenticated genesis under its own identity. The source ledger, rights and data remain unchanged. Content completeness and export/copy are consumer obligations; governance planning does not claim it recovered missing data. Revocation blocks future authorized use but cannot erase previously copied data.

## Validation and limits

Use bounded owners, replicas, transitions and conflicting siblings. Model signature validity abstractly; Rust tests supply real signatures and malformed records. Check quorum, distinct-person counting, stale parent/epoch rejection, conflict retention, resolution authorization, late evidence, immutable fork separation and duplicate/reordered delivery. Check conditional progress only with eventual delivery and an available approving quorum; absent consent is not a liveness bug. Negative model/implementation mutations must fail the intended invariant/assertion. Passing a finite model is not a proof of cryptography or all production consumers.
