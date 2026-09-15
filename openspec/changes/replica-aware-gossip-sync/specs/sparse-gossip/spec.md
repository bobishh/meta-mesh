## ADDED Requirements

### Requirement: Gossip connects a bounded set of device replicas
The system SHALL select neighbors by logical device replica, not by route count, and SHALL enforce configurable lower, target, and upper bounds independent of total group size. Multiple authorized documents MAY share one transport connection, but gossip eligibility SHALL be evaluated per authorization scope.

#### Scenario: Group contains one hundred devices
- **WHEN** one runtime participates in a scope containing one hundred authorized devices
- **THEN** its maintained neighbor count remains within configured bounds rather than opening one hundred persistent sessions

#### Scenario: One neighbor has several tabs
- **WHEN** a selected neighbor advertises several live routes
- **THEN** it occupies one neighbor slot and route selection occurs below gossip

### Requirement: Fresh changes use bounded eager propagation
Newly committed local or remote changes SHALL be offered promptly to a bounded fanout of authorized neighbors. Forwarding SHALL preserve original changes, signatures, proofs, and authorship.

#### Scenario: Fresh local change propagates
- **WHEN** a local durable change is published
- **THEN** the gossip engine schedules it for a bounded set of authorized neighbor devices without sending a complete document

#### Scenario: Duplicate rumor returns
- **WHEN** a previously seen content hash returns through another neighbor
- **THEN** the receiver suppresses redundant forwarding while retaining any required acknowledgement

### Requirement: Neighbor membership adapts without deleting durable peers
The gossip engine SHALL use transient health, randomized or deterministic rotation, backoff, and available signed routes to repair under-connected overlays. Pruning a neighbor SHALL close an active topology edge only and SHALL preserve the trusted device catalog.

#### Scenario: Neighbor becomes unreachable
- **WHEN** a selected neighbor has no usable route
- **THEN** the engine selects another authorized device after bounded backoff without revoking the unreachable member

#### Scenario: Partition bridge returns
- **WHEN** a device with knowledge of two formerly disconnected components reconnects
- **THEN** gossip makes the bridge eligible and anti-entropy can exchange both histories

### Requirement: Gossip enforces authorization and resource bounds
The system SHALL authenticate the remote device and authorize each scope before advertising, requesting, accepting, or forwarding document changes. It SHALL bound frames, advertised identifiers, outstanding wants, retries, and duplicate caches.

#### Scenario: Member requests an unauthorized document
- **WHEN** an authenticated device requests a document outside its authorized scope
- **THEN** the request is rejected without revealing document heads or identifiers

