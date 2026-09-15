## ADDED Requirements

### Requirement: Contact decisions target durable devices
The system SHALL address contact decisions to a certified requester device and SHALL select from its current signed route collection. It SHALL NOT treat the browser endpoint captured by the original request as the durable response address.

#### Scenario: Initiating tab reloads before acceptance
- **GIVEN** a requester persisted and delivered a contact request
- **AND** its originating browser instance closes and a new instance advertises a valid route for the same device
- **WHEN** the recipient accepts the request
- **THEN** the accepted decision reaches the requester device through a current route or later status pull
- **AND** both sides contain one accepted contact and one direct room

#### Scenario: Original endpoint remains unreachable
- **WHEN** the request's original endpoint is dead but another certified requester-device route is live
- **THEN** decision delivery tries the live route and does not loop exclusively on the dead endpoint

### Requirement: Handshake records are durable and idempotent
The system SHALL persist a verified request or decision before network delivery. The requester SHALL acknowledge only after atomic durable admission. Repeated delivery SHALL converge without duplicate contacts, rooms, grants, or first messages.

#### Scenario: Decision acknowledgement is lost
- **WHEN** the requester admits an accepted decision but its acknowledgement is lost
- **THEN** the responder retains and redelivers the decision
- **AND** the requester returns an equivalent acknowledgement without duplicate state

#### Scenario: Two responder devices accept concurrently
- **WHEN** two currently certified devices of the recipient accept the same request while partitioned
- **THEN** both decisions resolve to the same deterministic direct-room ID
- **AND** convergence produces one accepted contact and one room

#### Scenario: Accept and decline race
- **WHEN** one certified responder device accepts while another declines the same request
- **THEN** the valid acceptance is monotonic
- **AND** decline does not revoke the admitted conversation grant

### Requirement: Requesters can pull decision status
Each request SHALL establish a private bootstrap capability that permits the requester to query only that request's decision through current recipient-device routes before conversation membership exists.

#### Scenario: Push cannot reach requester
- **GIVEN** the recipient durably accepted a request
- **AND** every requester route was unavailable during push
- **WHEN** the requester later reaches any current recipient route and queries status
- **THEN** it receives, verifies, and durably admits the stored decision
- **AND** acknowledges admission

#### Scenario: Unauthorized status query
- **WHEN** a peer queries a request without the matching signed request and bootstrap capability
- **THEN** no decision, identity detail beyond public route data, room grant, or first message is returned

### Requirement: UI never blocks on peer completion
Creating, accepting, or declining a contact request SHALL finish after local durable commit. Remote delivery SHALL run as retryable background work with bounded transport attempts. UI SHALL present durable state and SHALL NOT keep a global loading indicator active while awaiting another peer.

#### Scenario: Recipient remains offline
- **WHEN** a requester creates a valid request while every recipient route is unavailable
- **THEN** the action returns with a stable pending state
- **AND** the UI remains usable and reports delayed delivery without implying decline

#### Scenario: Page reloads while pending
- **WHEN** either side reloads with an unfinished handshake
- **THEN** boot restores its durable state and resumes push or pull reconciliation
- **AND** no user repeats pairing or clears IndexedDB

### Requirement: Contact handshake is observable without leaking content
The system SHALL trace request persistence, push, decision persistence, status pull, durable admission, acknowledgement, and reconciliation using request, device, instance, route, attempt, and elapsed-time identifiers. It SHALL exclude capability secrets and first-message contents.

#### Scenario: Support diagnoses a stuck request
- **WHEN** a request remains pending after failed routes
- **THEN** traces identify the last durable stage, attempted device routes, retry schedule, and whether a decision exists locally
- **AND** transport failure is distinguishable from missing peer consent
