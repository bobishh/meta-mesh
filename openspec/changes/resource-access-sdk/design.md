## Boundary

A resource is registered by its issuer. Registration describes an issuer-qualified ID, exact audience, supported actions, read disclosure and authority epoch; it grants nobody access. The host establishes current application ownership before registering and protects all approval/update/revocation administration. Runtime resource authority comes from the provider's durable store, never from a caller-supplied grant or copied CRDT snapshot.

Native core owns strict message validation, certified device signatures under `MESH-RESOURCE/1`, capability/expiry/epoch checks and exact operation binding. TypeScript owns I/O orchestration over injected atomic CAS storage. The same package works in browser and server runtimes. `createResourceConnectionHandler` exposes only the connection exchange; the host supplies exact CORS origins, routing and rate limits.

## Connection

`ResourceClient.connectResource` captures its existing device identity and trusted selected resource, obtains an issuer-signed challenge, durably retains the exact subject-signed request before sending, and waits for explicit approval. Provider approval persists independently of its process. UI can list pending requests and call `approveConnection`; an async callback supports an existing approval surface. Only approved requested actions/expiry may enter a signed grant. Connected is returned after verifying that grant. A lost response recovers the exact committed grant without creating another identity or grant.

A client without an explicit request ID retains the pending intent key; concurrent matching calls coalesce and changed options under the same ID reject. Durable client storage is supplied for restart recovery. A provider's CAS transition reserves one approval; competitors see pending. A request awaiting owner action can be rehydrated after provider restart.

## Keys and codes

An invitation code is a bounded, short-lived, single-use capability bound to the intended existing node identity. The provider retains only its secret hash. Redemption still requires certified possession of that identity's device key and uses the ordinary connection exchange. It is not an identity seed or a permanent content key.

The SDK does not export owner private keys, copy documents, or distribute content keys. Hosts must implement truthful isolated resource delivery: a whole-workspace decryption key cannot be presented as field-only or board-only reading.

## Operations

A grant names issuer, subject, resource, audience, actions, actual read disclosure, expiry and epoch. Each operation has a certified subject signature over the grant hash, action, request-body digest, short validity interval and random nonce. The server supplies its trusted route/action and digest of the actual received body, then validates against current durable authority and atomically consumes the nonce. Business transaction execution/idempotency remains the application's responsibility; failed business work retries with a fresh proof and a retained business operation ID.

Grant/device revocation affects subsequent operations sharing that authority. Resource configuration changes advance epoch and invalidate old grants/challenges. The system cannot erase received plaintext or promise live revocation from a disconnected stale authority copy. Store capacity and message limits reject safely instead of evicting still-valid replay protection.

## Delivery

Acceptance was committed first and failed in CI because the SDK module did not exist. User requested CI-only execution; no local test suite is run. Native core and browser/Node acceptance include wrong action/body/issuer, expiry, revocation, replay, code subject binding, lost responses, provider restart and HTTP-origin rejection. CI-generated browser WASM artifacts must be committed before claiming usable package delivery. Tincanban/external Automation UI adoption is an explicit consumer integration, not an implicit effect of publishing the package.
