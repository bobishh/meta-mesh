## ADDED Requirements

### Requirement: Topic-based gossip broadcasting using iroh-gossip
The system SHALL map application scopes to 32-byte topic identifiers and use `iroh-gossip` state machines and broadcast trees (HyParView and PlumTree) to propagate messages and change notices across connected peers.

#### Scenario: Peer joins topic and broadcasts message
- **WHEN** a peer joins a workspace or conversation topic and broadcasts a change announcement
- **THEN** neighbor peers subscribed to the topic receive the broadcast message through the broadcast tree without point-to-point flooding

#### Scenario: Duplicate gossip suppression
- **WHEN** a gossip message is delivered along multiple overlay paths
- **THEN** `iroh-gossip` suppresses duplicate deliveries and delivers the message to the application layer exactly once

### Requirement: Overlay health and neighbor adaptation
The system SHALL maintain active and passive peer views per topic using `iroh-gossip` protocols, dynamically adapting to peer disconnects and reconnects without losing membership state.

#### Scenario: Active neighbor disconnects
- **WHEN** an active gossip neighbor drops connection or times out
- **THEN** `iroh-gossip` promotes a passive neighbor to active view and repairs the broadcast tree

#### Scenario: Partitioned peer reconnects
- **WHEN** a disconnected peer rejoins the network and connects to any topic member
- **THEN** the peer is integrated into the gossip tree and receives subsequent topic broadcasts
