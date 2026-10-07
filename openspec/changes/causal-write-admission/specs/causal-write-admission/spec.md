## ADDED Requirements

### Requirement: Causal permission boundary
The system SHALL evaluate write authority against signed causal frontiers and grant epochs, not the author's physical timestamp. Structural CRDT merge SHALL NOT itself constitute authorization.

#### Scenario: Historical change is inside revocation frontier
- **GIVEN** an editor change is an ancestor of the owner's signed revocation heads
- **WHEN** replicas receive the revocation and complete change evidence
- **THEN** revocation preserves that historical authorized change.

#### Scenario: Offline edit races with role downgrade
- **GIVEN** an editor's old-grant change is outside the signed revocation frontier
- **WHEN** editor-to-viewer revocation becomes known
- **THEN** that change receives no authoritative application solely from its timestamp or old grant, and its signed evidence remains available for explicit handling.

#### Scenario: Edit was already accepted on another replica
- **GIVEN** one replica accepted a change before receiving revocation and another received revocation first
- **WHEN** both receive equal complete evidence and run reclassification
- **THEN** their authorized projections and retained pending evidence agree, including hashes already known locally.

#### Scenario: Unauthorized dependency is missing or quarantined
- **GIVEN** a change depends on unavailable or unauthorized changes
- **WHEN** the change reaches a replica
- **THEN** dependencies cannot be bypassed to gain authority and the unresolved projection stays explicit.

### Requirement: Clock-independent authority and content priority
The system SHALL NOT let a peer-supplied physical timestamp or untrusted logical counter confer authority, win all future card updates or create a permanent lock. Clock sanity validation SHALL be distinguished from causal ordering and its liveness limitations SHALL be documented.

#### Scenario: Malicious far-future timestamp
- **GIVEN** a peer broadcasts an otherwise comparable change with extreme future time metadata
- **WHEN** permission and content priority are evaluated
- **THEN** the timestamp cannot override signed rights or permanently suppress subsequent authorized changes.

#### Scenario: Receiver clocks disagree
- **GIVEN** replicas have identical signed evidence and different physical clocks
- **WHEN** causal permission decisions are evaluated independently of legacy timestamp sanity admission
- **THEN** ownership and write-authority decisions agree; any legacy clock rejection is reported distinctly rather than treated as permanent higher priority.
