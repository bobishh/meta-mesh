## ADDED Requirements

### Requirement: Executable authority verification
The system SHALL run bounded TLA+ safety and conditional-progress checks, require expected negative-control violations, and couple model transitions to actual Rust decisions with real signed records. Missing tools/graphs or unexpected violations SHALL fail validation.

#### Scenario: Positive model and real implementation agree
- **GIVEN** freshly checked model graphs and fixed signed identity fixtures
- **WHEN** the conformance runner replays reachable transitions against core APIs
- **THEN** authorization, owners, epoch, conflicts, resolutions and fork separation match the model projection.

#### Scenario: Known unsafe mutation
- **GIVEN** a mutation that bypasses quorum, accepts stale authority or forgets conflict evidence
- **WHEN** the verification runner evaluates it
- **THEN** the intended invariant or implementation assertion fails; a compilation/tool error is not counted as a successful negative control.
