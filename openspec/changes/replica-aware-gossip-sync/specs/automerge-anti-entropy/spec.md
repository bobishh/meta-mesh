## ADDED Requirements

### Requirement: Documents reconcile with native incremental sync
The system SHALL use native Automerge sync messages and per-document/per-remote-device sync state. Normal live updates SHALL NOT periodically transmit complete saved documents.

#### Scenario: One edit follows initial synchronization
- **WHEN** two devices share document heads and one device commits one additional change
- **THEN** the next synchronization transfers an incremental sync message rather than the complete saved document

#### Scenario: Different instance route resumes synchronization
- **WHEN** one route fails during a sync exchange and another route of the same remote device becomes available
- **THEN** synchronization safely continues or restarts against the same logical remote replica

### Requirement: Sync-state loss preserves correctness
Persisted or in-memory Automerge sync state SHALL be an optimization only. Resetting it after corruption, route loss, or process restart SHALL still converge from durable document history.

#### Scenario: Sync state is unavailable after reload
- **WHEN** a device reloads with document changes but without previous peer sync state
- **THEN** a new sync state exchanges the missing changes and reaches equal heads

### Requirement: Anti-entropy heals gossip omissions and partitions
Authorized neighbors SHALL periodically or eventfully compare document frontiers. Synchronization SHALL continue until neither side produces another sync message, subject to backpressure and connection availability.

#### Scenario: Eager gossip misses one device
- **WHEN** a device does not receive a freshly gossiped change
- **THEN** a later anti-entropy exchange detects and transfers the missing change

#### Scenario: Concurrent partitioned writes meet
- **WHEN** two components commit independent valid changes and later reconnect
- **THEN** both devices durably contain both branches and expose equal Automerge heads

### Requirement: Application admission precedes publication
The replication layer SHALL allow the consuming application to verify proofs, membership, protected fields, and structural invariants on an isolated candidate before durable publication or acknowledgement.

#### Scenario: Validly signed forbidden mutation arrives
- **WHEN** a certified editor signs a structurally valid Automerge change that modifies an owner-only field
- **THEN** application admission rejects the candidate and no trusted heads or acknowledgement advance

