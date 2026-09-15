## Why

Twang contact acceptance still bypasses meta-mesh device delivery. A contact request captures one browser instance endpoint. The responder persists a decision, but every retry sends it to that frozen endpoint. If the initiating tab reloads or closes, the decision cannot reach the new instance even when both people are online. The initiator remains `outgoing` indefinitely.

The defect dates to Twang's initial messenger implementation (`27e058d`). Durable retry added in `0fcf8b3`, but retained the single-endpoint destination. The replica-aware integration (`d964dab`) moved room replication to meta-mesh without moving contact bootstrap, leaving a protocol hole before room membership exists.

## What Changes

- Define contact establishment as a durable, signed, idempotent protocol with explicit request, decision, admission acknowledgement, and reconciliation states.
- Address people through certified devices and signed route collections. Raw Iroh endpoints remain transient routes, never durable response destinations.
- Give each request a private bootstrap capability. It authorizes decision push and status pull before a shared conversation grant exists.
- Persist accepted or declined decisions before network delivery. Retain unacknowledged decisions and serve them through any current responder route.
- Let the requester recover by polling current responder device routes after reload, route replacement, or lost push.
- Use meta-mesh device-scoped happy-eyeballs and durable admission acknowledgement for handshake records.
- Expose stable UI states. Network work never holds a global loading state or spinner indefinitely.
- Replace Twang's application-local single-endpoint delivery and retry after outer browser scenarios pass.

## Capabilities

### New Capabilities

- `durable-contact-handshake`: Signed contact requests and decisions converge across browser restarts, route changes, duplicate delivery, and temporary partitions.

### Modified Capabilities

- `device-route-catalog`: Contact bootstrap consumes certified device route collections before conversation membership exists.
- `durable-replica-delivery`: Bootstrap records receive the same device-scoped delivery and durable acknowledgement guarantees as authorized document changes.
- `replication-observability`: Contact bootstrap exposes protocol stage, route attempts, durable admission, and reconciliation without leaking message contents or capability secrets.

## Impact

- Canonical meta-mesh: `mesh-contact`, `mesh-directory`, `mesh-replication`, `mesh-browser-store`, and trace contracts.
- Twang: contact request persistence, acceptance/decline delivery, boot reconciliation, pending UI, and vendored meta-mesh revision.
- Existing identity keys, device certificates, contact cards, person IDs, deterministic direct-room IDs, messages, and room history remain valid.
- No mailbox or always-on server is introduced. Two peers still need a period of temporal connectivity.
