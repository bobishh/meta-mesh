## ADDED Requirements

### Requirement: Delivery targets durable replicas
The system SHALL group routes by target `deviceId` and SHALL complete one logical delivery after any route of that device returns a valid durable acknowledgement. It SHALL NOT require delivery to every browser instance of the device.

#### Scenario: Alternate tab accepts delivery
- **WHEN** the preferred route fails and another route of the same device commits the batch
- **THEN** the device delivery succeeds once and the failed route remains only a route-health failure

#### Scenario: Two raced routes receive the same batch
- **WHEN** two instance routes commit the same content-addressed batch concurrently
- **THEN** storage contains one logical copy and the sender records one device acknowledgement

### Requirement: Acknowledgement follows durable admission
A receiving instance SHALL acknowledge only after authorization, validation, and durable idempotent storage complete. The acknowledgement SHALL bind protocol version, scope, document, batch, receiver device, and accepted frontier or change hashes.

#### Scenario: Receiver closes before commit
- **WHEN** the receiving instance closes before its storage transaction commits
- **THEN** no durable acknowledgement is emitted and another route may retry the batch

#### Scenario: Receiver closes after commit before acknowledgement
- **WHEN** storage commits but the acknowledgement is lost
- **THEN** retry recognizes existing hashes, returns an equivalent acknowledgement, and does not duplicate changes

#### Scenario: Unauthorized change arrives
- **WHEN** signature, membership, document scope, size, or application admission fails
- **THEN** no durable acknowledgement is emitted and trusted state remains unchanged

### Requirement: Outbound work has no long-lived tab leader
All live instances SHALL remain independently reachable. Duplicate outbound work SHALL be reduced with short durable outbox claims scoped to a batch and target device; correctness SHALL NOT depend on a long-lived leader or shared Iroh endpoint.

#### Scenario: Claim owner closes
- **WHEN** an instance holding an outbound claim closes before acknowledgement
- **THEN** the bounded claim expires and another live instance can deliver through its own endpoint

### Requirement: Local sibling instances reconcile from durable storage
After durable admission, the receiving instance SHALL publish a non-authoritative local invalidation. Sibling instances SHALL load durable missing changes and SHALL also reconcile on focus or explicit head mismatch when notification is lost.

#### Scenario: Broadcast notification arrives
- **WHEN** one tab commits a remote batch and publishes document heads
- **THEN** another tab reads and merges durable missing changes without another network delivery

#### Scenario: Broadcast notification is lost
- **WHEN** a sibling misses the local invalidation
- **THEN** its next focus or local reconciliation detects different heads and loads the durable changes

