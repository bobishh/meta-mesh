# Browser Identity peer runtime

`createBrowserIdentityPeerRuntime({ transportSeed })` starts one browser transport node that can both listen and dial. Use the same runtime after device enrollment through `promoteToPeerRuntime()`; promotion reuses the enrollment node and its initial connection instead of creating a second endpoint for the same seed.

Start `runtime.startHost(...)` with the current profile, certificate chain, and saved peer contacts, then use `runtime.connect(...)` for an approved saved contact. The runtime verifies signed routes and challenges before delivering peers. During simultaneous dials, the lexicographically smaller device ID keeps its outbound connection; the other side keeps the authenticated incoming connection. A later authenticated connection can replace a stale active peer. The listener remains available while application callbacks handle an accepted peer. Runtime ownership allows two established connections and one temporary inbound candidate while that candidate is authenticated; the candidate is never delivered before verification and arbitration complete.

Closing a host stops its acceptor and accepted host connections while keeping the shared node available. Closing a connected peer closes that connection only. `runtime.close()` owns final shutdown of the node and every connection it still tracks. The initial enrollment connection counts toward the runtime's two-connection bound until its owning `MeshConnection.close()` is called. Enrollment approval, certificate checks, and saved-contact authorization remain unchanged.

## Existing owner reconnect

`@meta-uber/mesh-runtime/ownerReconnect` exports
`startBrowserOwnerReconnectHost` and `connectBrowserOwnerReconnect`. This flow
returns a participant-held copy to its already verified owner. It does not enroll
a device or transfer ownership.

The host supplies its current profile/authority, exact workspace and expected
owner, and a domain `readSource` callback. The callback returns existing signed
workspace/history evidence, the exact existing DurableMesh invitation envelope,
optional paired Rusty config and owner proof, and bounded history readers. The
envelope restores the shared workspace transport secret and authenticated
persistent peer route through the normal invitation path; reconnect never
creates a replacement secret. The SDK checks it against the current owner and
source grant, and rejects a source route that is only the temporary reconnect
endpoint. The runtime owns
one ephemeral transport endpoint, invitation framing, signatures, endpoint
bindings, expiry and candidate cleanup. An unrelated Identity is rejected before
`readSource` and does not consume the unexpired invitation.

The receiver supplies its current verified profile, an approval callback and a
`commit(verified, history)` callback. Only an SDK-verified challenge reaches
approval; board and storage data arrive after approval. The SDK verifies the
source's current read grant and complete causal history independently of Rusty.
Rusty config and its owner-signed storage proof may both be absent; if either is
present, both are required and the SDK verifies their exact binding before
invoking commit. One-sided or invalid storage data rejects. A missing storage
pair does not create Rusty access; it allows returning the verified workspace
copy without Rusty availability. The app validates and receives the verified
mesh envelope with its normal invitation path, then uses its existing causal
admission/history reader and durable storage,
registers the same workspace in the owner's catalog and commits idempotently by
verified offer digest. A receipt follows successful commit; commit failure must
not report success. `ensureCurrent` guards and cancellation cover asynchronous
work. Closing a session closes only the transport it owns.

[Identity and resource access](../../docs/identity-and-resource-access.md) defines
the shared ownership, offline-revocation and user-flow contract.
