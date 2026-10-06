## ADDED Requirements

### Requirement: Equal owners with explicit quorum
The system SHALL validate opt-in v2 scope governance using equal owner identities and parent-defined majority or unanimous policy; device identities SHALL NOT multiply votes. Existing v1 ledgers SHALL retain their validation behavior.

#### Scenario: Two owners approve membership change
- **GIVEN** two current owners and majority policy
- **WHEN** both distinctly sign the same parent-bound removal or addition
- **THEN** the valid next authority reflects the approved owner set without a senior-owner role.

#### Scenario: One owner or duplicate devices attempt takeover
- **GIVEN** two current owners
- **WHEN** one person signs a membership/policy change with one or several devices
- **THEN** quorum is insufficient and the current authority remains unchanged.

#### Scenario: Policy change attempts to approve itself
- **GIVEN** a parent requiring unanimous approval
- **WHEN** a proposed majority policy receives only its proposed threshold
- **THEN** the parent policy still governs and rejects insufficient approval.

### Requirement: Signed history governs identity access
The system SHALL bind governance records to kind, version, scope, exact parent and next epoch, verify signing devices against current owner identity, and reject empty owners, stale-parent authorization or replay across scopes. Recovery material SHALL NOT itself grant authority.

#### Scenario: Removed owner sends a later change
- **GIVEN** an accepted membership record removes an owner
- **WHEN** that identity signs a descendant governance action
- **THEN** its signature contributes no current-owner approval.

#### Scenario: Same identity recovered
- **GIVEN** a person restores its existing identity root from words and encrypted envelope
- **WHEN** its valid device signs an action
- **THEN** rights depend on the current signed owner ledger, including any removal, rather than possession of recovery material alone.

#### Scenario: Unsupported consumer encounters v2
- **GIVEN** a consumer that only validates v1
- **WHEN** v2 governance is supplied
- **THEN** no v1 single-owner authority is inferred from it.
