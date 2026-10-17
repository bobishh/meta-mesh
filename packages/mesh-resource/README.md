# Resource connections

`@meta-uber/mesh-resource` connects existing independent identities to explicit resources. The shared Rust core validates certified signatures, grants, audience, capabilities, time bounds and resource epochs. The TypeScript SDK owns the challenge/approval/retry lifecycle over injected storage and transport. No board schema, jobs logic, log-reader role or private owner key enters the protocol.

A provider registers resources it controls:

```ts
const provider = new ResourceProvider({ profile: ownerDevice, store: authorityStore })
const resource = await provider.addResource({
  id: board.id, title: board.title, audience: boardApiOrigin,
  actions: ["card:read", "card:create"], readScope: "Entire selected board",
})
```

`addResource` registers authority; it grants nobody access. The host must establish current ownership before registering an application resource, and retain its authoritative state in protected durable storage. `compareAndSwap` must be atomic across provider instances. The provider signs with its certified device key; it never exports its personal root key. Supply the complete certificate chain when the device is delegated.

An Automation button calls the same client operation as any other application:

```ts
const client = new ResourceClient({ profile: automationNode, store: pendingConnections,
  transport: createHttpResourceTransport(boardConnectionEndpoint) })
const connected = await client.connectResource({ resource, actions: ["card:read", "card:create"], signal })
```

`resource` must come from the issuer's trusted resource picker/registration, not from an arbitrary grant or an untrusted popup. `pendingConnections` durably saves the exact challenge and signed request before sending. The optional in-memory default is suitable for short-lived callers; CLI/production callers supply persistent storage to resume after process restart. Repeated calls with the same intent resume retained evidence; changed options under an explicit request ID reject.

The issuer's UI displays `listPendingRequests(resource.id)`. After the user reviews the requesting identity, actions, actual read scope and expiry, it calls `approveConnection(resource.id, requestId, decision)`, or passes `null` to decline. A suspended approval survives provider restart. Alternatively provide an async `approve` callback that presents an application-owned approval UI. The client reports connected only after verifying the issued grant. The provider persists that exact response for lost-response retry.

For CLI setup, an already authorized owner creates a subject-bound single-use invitation with `createInvitation`. `redeemInvitation(code, resource)` uses the same signed connection protocol. The `mesh-resource:v1:…` code is a short-lived invitation, never an identity seed or permanent content key. Only its intended identity can redeem it. A retained exact request may recover an acknowledged grant after a lost reply; a new redemption of an already consumed code rejects.

## Authorize protected operations

```ts
const bodyDigest = await sha256Base64Url(actualRequestBodyBytes)
const proof = await client.signOperation(connected.grant, { action: "card:create", bodyDigest })
// On the resource provider, use its trusted route/action and digest of actual received bytes:
const authorization = await provider.authorize({ resourceId: routedBoardId, action: routedAction,
  bodyDigest: receivedBodyDigest, grant: receivedGrant, proof: receivedProof })
```

The provider rereads current durable authority, verifies the grant and proof, and atomically reserves the operation nonce. Replayed proofs reject. This is authorization, not transaction execution: application handlers retain their own business idempotency/transaction boundaries. They must never copy an untrusted action or body digest from the proof as their expected value. A nonce is consumed before the handler runs; retry failed business work with a fresh proof and the same application idempotency key.

`revokeGrant` and `revokeDevice` take effect on subsequent checks sharing the authoritative store. `updateResource` advances its epoch and invalidates older grants/challenges without replacing identities. A disconnected replica of authority cannot promise immediate revocation; hosts must route privileged operations through current durable authority. Expiry further bounds access. Already received plaintext cannot be revoked.

`createResourceConnectionHandler` exposes only the connection exchange over HTTP JSON, with an exact caller-origin allowlist. Registration, approval, revocation and authority updates are host administration operations and must never be exposed unauthenticated. Hosts also provide rate limits and request routing. Transport uses a configured HTTPS endpoint (loopback HTTP for development), bounded messages, no ambient browser cookies and no redirects.

This package grants capabilities. It does not silently copy CRDT documents, hand out encryption keys, or claim field-restricted reading from a whole-workspace key. Resource-specific encrypted bootstrap/data delivery must honor the declared read scope. Tincanban and external-service UI integration are separate consumers of this shared SDK.
