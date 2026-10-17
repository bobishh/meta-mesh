## ADDED Requirements

### Requirement: Explicit issuer-qualified resource connection
The SDK SHALL register resources separately from granting access, and SHALL connect an existing subject identity only after issuer approval of exact requested capabilities and expiry.

#### Scenario: Connect from an external service
- **GIVEN** a registered resource and an independently initialized service identity
- **WHEN** the client invokes connectResource and the issuer approves
- **THEN** the SDK returns a verified issuer-signed grant bound to that identity, resource and audience
- **AND** registration alone SHALL NOT authorize an operation

### Requirement: Durable approval and exact retry
The SDK SHALL retain signed requests and committed grant responses through host-provided durable storage and SHALL support pending approval after provider restart.

#### Scenario: Response is lost after issuance
- **GIVEN** an approved connection whose response is lost
- **WHEN** the exact retained request is retried
- **THEN** the same grant is returned without another approval or identity

### Requirement: Subject-bound one-time initialization
The SDK SHALL redeem invitation codes only for their intended existing subject, before expiry and at most once except exact committed-response recovery.

#### Scenario: A stolen or consumed code is presented
- **GIVEN** a code for another identity or an already consumed code
- **WHEN** a new redemption is attempted
- **THEN** access is denied without revealing private owner material

### Requirement: Current operation authorization
The shared core SHALL verify grant and operation signatures, issuer, subject, resource, audience, allowed action, received-body digest, expiry, current epoch and revocations. The provider SHALL atomically reject replayed operation nonces.

#### Scenario: A grant or operation is altered or revoked
- **GIVEN** a changed action/body/resource/audience, expired grant, revoked device/grant or replayed proof
- **WHEN** the server authorizes against current durable authority
- **THEN** the operation is denied

### Requirement: Honest encryption boundary
The SDK SHALL NOT export owner private identity keys or equate capability scope with decryption scope.

#### Scenario: An application shares a workspace key
- **GIVEN** a key decrypting more than the selected resource
- **WHEN** the application connects a node
- **THEN** it must isolate delivered data or explicitly disclose and approve the actual wider read scope
