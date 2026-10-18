## 1. Shared resource SDK
- [x] Author outside-in connection/authorization acceptance and confirm missing implementation in CI.
- [x] Implement native-core message/grant/operation verification and policy WASM facade.
- [x] Implement provider registration, approval, revocation, epoch update and replay CAS.
- [x] Implement client connection, retained exact retry and subject-bound code redemption.
- [x] Implement bounded HTTP transport/handler and restart/negative acceptance.
- [x] Document host ownership, authority persistence, read isolation and business idempotency responsibilities.
- [x] Obtain and commit matching browser WASM artifacts built by CI.
- [x] Fix CI findings and achieve green native, browser/Node, package and formal checks.

## 2. Consumer adoption
- [x] Pin the verified SDK in consumers through their CI.
- [ ] Wire Tincanban issuer-owned approval and external Automation Connect board flow using this SDK.
- [ ] Replace implicit service log permissions with explicit resource grants in a reviewed service rollout.

## Release evidence — 2026-10-18

- SDK `0af200292beb37dc16b5430ef2c52c9e6864def7` passed [Verify](https://github.com/bobishh/meta-mesh/actions/runs/39076162873), including native/mobile/Apple/formal checks and 14 resource connection scenarios using the CI-built WASM.
- Tincanban pinned this SDK and passed all 15 [consumer Verify jobs](https://github.com/bobishh/tincanban/actions/runs/39084819409) at application `725c09daa6743c610180146960153597b58eaec6`. [Frontend](https://github.com/bobishh/tincanban/actions/runs/39085558662) and [Worker](https://github.com/bobishh/tincanban/actions/runs/39085558640) deployed; production health confirmed both source and SDK revisions.
- Generic resource SDK delivery does not complete the unchecked external Automation button or explicit TinSink grant rollout above.
