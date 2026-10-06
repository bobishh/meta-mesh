## ADDED Requirements

### Requirement: Retain conflicts and fail closed
The system SHALL retain incompatible authenticated sibling records, expose ambiguous authority, and deny new governance authorization rather than choose by arrival order, timestamp or hash. Stale snapshots SHALL NOT erase known evidence.

#### Scenario: Concurrent offline changes arrive in either order
- **GIVEN** two quorum-certified incompatible changes from one parent
- **WHEN** replicas receive both, in either order or repeatedly
- **THEN** they retain both records and report the same conflict.

### Requirement: Explicit quorum conflict resolution
The system SHALL accept resolution only with the common parent's quorum and explicit conflicting record references, preserve history, and reopen ambiguity for valid evidence not covered by resolution.

#### Scenario: Owners agree on a resolution
- **GIVEN** two conflicting changes and an available approving parent quorum
- **WHEN** that quorum certifies the same resolution and it is delivered
- **THEN** replicas can resume under the agreed owner set without deleting the original conflict evidence.

#### Scenario: Unilateral resolution or late third branch
- **GIVEN** retained conflicting changes
- **WHEN** a resolution lacks parent quorum or a valid uncovered sibling arrives later
- **THEN** the invalid resolution grants no authority or the new evidence reopens conflict respectively.

### Requirement: Independent fork escape
The system SHALL plan forks with a new scope ID and authenticated genesis without modifying or importing source authority. Content copying/completeness SHALL remain an explicit consumer responsibility.

#### Scenario: Quorum unavailable
- **GIVEN** conflicting authority and a holder of an available content copy
- **WHEN** that holder creates an independent fork
- **THEN** its new scope starts under its own authenticated creator while the original ledger and access remain unchanged.
