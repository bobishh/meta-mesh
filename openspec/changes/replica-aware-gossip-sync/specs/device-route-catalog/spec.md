## ADDED Requirements

### Requirement: Device replicas own multiple transport routes
The system SHALL represent an authorized device as one logical durable replica and SHALL retain independently signed routes for each live browser instance of that device. Protocol version 1 SHALL use `deviceId` as `replicaId`.

#### Scenario: Two tabs advertise one device
- **WHEN** two browser instances sharing one device key advertise distinct `instanceId` and Iroh endpoints
- **THEN** the catalog retains both routes under one device replica without creating another member or device

#### Scenario: One tab refreshes its route
- **WHEN** a newer signed advertisement arrives for one existing `instanceId`
- **THEN** only that instance route is replaced and sibling routes remain available

### Requirement: Route authority is cryptographically bound
Every route SHALL bind scope, person, device, instance, transport endpoint, monotonic sequence, issue time, and expiry under the certified device signature. Route acceptance SHALL verify the identity key, device certificate chain, device signature, scope authorization, and structural bounds before publication.

#### Scenario: Endpoint is changed without resigning
- **WHEN** a route endpoint differs from its signed payload
- **THEN** the route is rejected and the existing catalog remains unchanged

#### Scenario: Instance reuses an older sequence
- **WHEN** an otherwise valid advertisement has a sequence lower than the stored sequence for the same scope, device, and instance
- **THEN** it cannot replace the stored route

### Requirement: Route health is not membership
Expiry and connection failures SHALL affect route selection only. They SHALL NOT remove a person, revoke a device or grant, delete history, or remove sibling routes.

#### Scenario: One route expires
- **WHEN** one instance route expires while another route for the same device remains usable
- **THEN** delivery uses the usable route and device membership remains unchanged

#### Scenario: All routes are currently unreachable
- **WHEN** every known route for an authorized device fails
- **THEN** the device remains an authorized offline replica and retries remain eligible for future signed routes

### Requirement: Legacy routes migrate without identity changes
The catalog SHALL accept supported legacy single-route records as synthetic legacy instances and SHALL migrate them without changing person IDs, device IDs, grants, or transport endpoint ownership.

#### Scenario: Legacy contact card loads
- **WHEN** a valid version 1 contact card lacks `instanceId` and route sequence
- **THEN** it is retained as a bounded synthetic instance route derived from its signed endpoint

