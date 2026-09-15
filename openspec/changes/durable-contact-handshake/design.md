## Context

Room replication starts only after a contact decision creates a conversation grant. Contact establishment therefore needs a narrow bootstrap protocol that works before normal room authorization.

Current Twang behavior has three separate durability levels:

1. The initiator durably stores an outgoing request.
2. The responder durably stores its decision and retries it.
3. Delivery targets only `request.signed.payload.endpoint`, the initiating browser instance captured when the request was created.

Step 3 defeats steps 1 and 2 after tab reload. Retrying a durable record against the same dead route is not durable delivery. The new meta-mesh route catalog cannot help because this path does not call device-scoped delivery.

## Goals / Non-Goals

**Goals:**

- Complete one logical contact handshake across instance replacement and temporary disconnection.
- Keep request and decision verification independent from transport endpoint identity.
- Permit both push and pull reconciliation before room membership exists.
- Make duplicate request, decision, and acknowledgement delivery harmless.
- Give UI a stable pending state plus useful delivery evidence; never bind UI completion to an open request stream.
- Reuse meta-mesh route selection, durable storage, acknowledgements, backoff, and tracing.

**Non-Goals:**

- Deliver while both people remain offline forever.
- Add a centralized contact directory, public discovery, or untrusted mailbox.
- Treat transport reachability as acceptance.
- Change identity recovery, device certification, conversation authorization, or message encryption.
- Infer decline from timeout. Silence remains pending until cancellation or a signed decision.

## Protocol records

### Contact request

A signed contact request binds:

- `requestId` and protocol version;
- requester and target person IDs;
- requester device ID;
- initial signed requester route envelopes;
- display name and bounded first message;
- random bootstrap capability public identifier and verifier;
- creation time and optional user-visible expiry policy.

The capability secret is known only to the two participants. It authorizes access to this handshake record; it grants no room membership and no access to other contacts or documents.

### Contact decision

A signed `ContactDecisionV2` binds:

- the complete request digest and bootstrap capability ID;
- responder person and certified device IDs;
- `accepted` or `declined`;
- deterministic direct-room ID and conversation grant when accepted;
- responder route envelopes usable for later pull and room sync.

The responder commits the decision before attempting delivery. An accepted decision is monotonic for a request. A later decline cannot erase an acceptance; removing an accepted contact requires the normal revocation/removal protocol.

### Admission acknowledgement

The requester acknowledges only after it has verified and durably admitted the decision, directory update, room grant, and initial room state atomically. The acknowledgement binds request digest, decision digest, requester device ID, and admitted room frontier when accepted.

## Delivery and reconciliation

The responder first pushes through the requester's certified device routes using meta-mesh device-scoped happy-eyeballs. It does not target the request's original endpoint directly.

Push is an optimization. The initiator retains its outgoing request and periodically asks current responder device routes for handshake status under the bootstrap capability. This pull path repairs:

- initiating-tab reload or closure;
- route expiry or replacement;
- lost decision delivery;
- lost acknowledgement;
- responder restart after decision persistence.

The responder retains an unacknowledged decision. Duplicate pulls return the same logical decision. Duplicate admission returns an equivalent durable acknowledgement. After acknowledgement, retention follows an explicit bounded cleanup policy; cleanup never changes accepted contact state.

Same-person sibling devices learn the handshake through the existing private identity replica. Any device may transport the record. The logical request and decision remain keyed by `requestId`, not instance or endpoint.

## State model

Requester durable states:

- `pending`: request stored; peer decision absent;
- `accepted`: accepted decision and room admitted;
- `declined`: signed decline admitted;
- `cancelled`: local user cancellation; late acceptance requires explicit user handling;
- `delivery_problem`: derived presentation state after failed attempts, not a protocol decision.

Responder durable states:

- `received`: verified request stored;
- `accepted-unacknowledged` or `declined-unacknowledged`: decision stored, admission acknowledgement absent;
- `completed`: valid acknowledgement stored.

Transport attempts have deadlines. UI actions return after local durable commit. Pending remains interactive and survives reload; no promise or spinner waits for peer acceptance.

## Conflicts and idempotency

- Request digest mismatch under one `requestId` is invalid.
- Duplicate equal decisions are idempotent.
- Any valid acceptance dominates a concurrent decline because acceptance grants membership; decline cannot revoke an existing grant.
- Conflicting accepted decisions must resolve to the deterministic direct-room ID. Divergent grants or room IDs are rejected and traced.
- Reopening the same public contact link reuses the existing person/request state and does not create duplicate contacts or direct rooms.

## Security

- Every request, decision, route, and acknowledgement is signature-verified against current device certificates.
- Bootstrap capability checks occur before returning decision status.
- Status responses reveal only the referenced handshake.
- Capability values and first-message contents are excluded from traces.
- Expired routes affect dialing only. They do not revoke membership or erase protocol records.
- Revoked device certificates cannot create new decisions or acknowledgements.

## Observability

Trace events include `operationId`, `requestId`, local/remote person and device IDs, route/instance ID, attempt, stage, result, and elapsed time. Required stages:

- `contact.request.persisted`, `contact.request.push.started|failed|admitted`;
- `contact.decision.persisted`, `contact.decision.push.started|failed|admitted`;
- `contact.status.pull.started|failed|resolved`;
- `contact.ack.persisted|admitted`;
- `contact.reconcile.completed`.

UI derives state from durable records. A failed route may explain delay but cannot change `accepted` back to `pending`.
