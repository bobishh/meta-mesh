## 1. Shared resource SDK
- [x] Author outside-in connection/authorization acceptance and confirm missing implementation in CI.
- [x] Implement native-core message/grant/operation verification and policy WASM facade.
- [x] Implement provider registration, approval, revocation, epoch update and replay CAS.
- [x] Implement client connection, retained exact retry and subject-bound code redemption.
- [x] Implement bounded HTTP transport/handler and restart/negative acceptance.
- [x] Document host ownership, authority persistence, read isolation and business idempotency responsibilities.
- [x] Obtain and commit matching browser WASM artifacts built by CI.
- [ ] Fix CI findings and achieve green native, browser/Node, package and formal checks.

## 2. Consumer adoption
- [ ] Pin the verified SDK in consumers through their CI.
- [ ] Wire Tincanban issuer-owned approval and external Automation Connect board flow using this SDK.
- [ ] Replace implicit service log permissions with explicit resource grants in a reviewed service rollout.
