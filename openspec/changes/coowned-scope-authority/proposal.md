## Why

Current scope authority has one controller. Shared family/team boards need equal owners without an implicit senior owner. Offline changes can concurrently remove owners or change policy; treating arrival order as authority permits stale rights or silent takeover. A conflict pause needs an explicit resolution and independent fork escape.

## What Changes

- Add an opt-in version-2 scope governance ledger with equal owner identities, parent-bound certificates and majority/unanimous owner policy.
- Require distinct current-owner signatures for membership, governance policy and alternate-identity recovery changes. Two-owner majority requires both.
- Preserve all valid concurrent certificates, expose conflicts, and authorize no new governance action while current authority is ambiguous.
- Resolve conflicts with a certificate approved under their common parent's policy; retain both branches. Late unseen evidence can reopen a conflict.
- Plan independent forks with a new scope ID/genesis; fork copies available content separately, never the source authority.
- Model safety and conditional progress in TLA+, then couple TLC traces to real signed Rust decisions.
- Expose the platform-neutral protocol through the existing browser/WASM boundary without changing stored v1 authority or silently enabling it in consumers.

## Capabilities

### New Capabilities

- `coowned-authority`: versioned signed multi-owner governance, revocation and identity-recovery boundaries.
- `authority-conflict-resolution`: retained conflict evidence, quorum resolution and independent fork planning.
- `authority-conformance`: executable TLA+ checks, negative controls and Rust conformance.

### Modified Capabilities

None. Existing v1 scope controller and editor succession protocols remain compatible.

## Impact

Canonical work occurs in the current MetaMesh checkout at `match/vendor/meta-mesh` (`bobishh/meta-mesh`), not the older sibling `mesh` checkout. Core owns validation; WASM exposes the same decisions. Match/Lighthouse UI adoption and service-owner bootstrap are follow-up consumers, not an implicit production migration. No deployment or CI change is part of this change.
