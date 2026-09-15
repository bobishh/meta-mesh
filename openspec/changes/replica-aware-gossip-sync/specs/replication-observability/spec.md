## ADDED Requirements

### Requirement: Connection and delivery states use separate evidence
The system SHALL derive route connectivity, device presence, document convergence, and durable delivery from separate evidence. A live channel SHALL NOT imply that pending changes are stored remotely.

#### Scenario: Channel is live but storage rejects
- **WHEN** transport heartbeat succeeds and remote durable admission fails
- **THEN** the route may remain connected while delivery remains pending or failed

#### Scenario: Channel closes after acknowledgement
- **WHEN** a durable acknowledgement was recorded and the transport channel later closes
- **THEN** delivered state remains recorded while presence becomes offline or unknown

### Requirement: Protocol traces carry stable correlation fields
The system SHALL emit bounded structured events for route selection, dialing, authentication, gossip advertisement, sync exchange, durable commit, acknowledgement, retry, and local invalidation. Events SHALL include stable correlation identifiers without private keys, invitation secrets, message bodies, or blob contents.

#### Scenario: Delivery changes routes
- **WHEN** one batch fails on a preferred route and succeeds on an alternate route
- **THEN** traces correlate both attempts, the durable commit, and the final device acknowledgement to one batch and target device

### Requirement: Consumers receive actionable aggregate state
The shared layer SHALL expose aggregate device and document state suitable for UI without leaking individual tab labels as members. Pending and failed states SHALL carry machine-readable reasons.

#### Scenario: Device has one connected and one failed route
- **WHEN** one route is authenticated and another route recently failed
- **THEN** aggregate device presence is connected and route-level diagnostics retain the failure

