## 1. Reproduce at the product boundary

- [ ] 1.1 Add a Twang real-route Playwright scenario: A sends a contact request, A's tab closes, A reopens with a new instance route, B accepts, and both converge to one accepted contact and one direct room.
- [ ] 1.2 Add the failure state first: B accepts while all A routes are unavailable; both UIs remain usable, B shows stored/unacknowledged, A shows pending rather than an infinite spinner.
- [ ] 1.3 Add reload, lost-decision, lost-acknowledgement, duplicate-link, and two-device concurrent-accept browser scenarios.

## 2. Canonical handshake protocol

- [ ] 2.1 Add bounded signed request, decision, and admission-acknowledgement records to canonical `mesh-contact`.
- [ ] 2.2 Add bootstrap capability derivation and verification with strict request scoping and trace redaction.
- [ ] 2.3 Define deterministic direct-room and conflict rules; verify acceptance monotonicity and reject divergent grants.

## 3. Device delivery and reconciliation

- [ ] 3.1 Route decision push through meta-mesh device-scoped delivery and current certified route collections.
- [ ] 3.2 Add authenticated status pull through current recipient-device routes.
- [ ] 3.3 Persist decisions until durable admission acknowledgement; make duplicate admission and acknowledgement idempotent.
- [ ] 3.4 Reconcile unfinished handshakes on boot, route update, focus, reconnect, and bounded schedule.

## 4. Twang integration

- [ ] 4.1 Replace frozen `request.signed.payload.endpoint` decision delivery with the canonical handshake service.
- [ ] 4.2 Separate local operation completion from background peer delivery; remove global loading waits for peer state.
- [ ] 4.3 Present pending, accepted, declined, cancelled, and delivery-problem states from durable evidence.
- [ ] 4.4 Remove superseded application-local retry after outer browser scenarios pass.

## 5. Verification and release

- [ ] 5.1 Run canonical meta-mesh tests/check and strict OpenSpec validation.
- [ ] 5.2 Update Twang vendor pin; run unit, type, build, and full real-route Playwright suites.
- [ ] 5.3 Verify on two physical browsers: request, initiating-tab reload, acceptance, automatic convergence, message exchange, and no IndexedDB clearing.
- [ ] 5.4 Record traces for happy path, stale original endpoint, all-routes-offline recovery, duplicate decision, and lost acknowledgement before deploy.
