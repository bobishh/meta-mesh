# Identity and resource access

This specification defines shared sign-in and resource authorization for the
Mesh family. MetaMesh owns the reusable protocol and SDK. Identity, Tincanban,
Rusty, TinSink, Reflux and Repetitor retain their own domain state and policies.
A shared protocol does not require a shared deployment or a single service.

## Ownership and sources of truth

| Concern | Authoritative owner | Consumer responsibility |
| --- | --- | --- |
| Person and certified devices | Signed Identity authority | Verify the exact device, chain and learned revocations |
| Name, photo and approved service links | Verified Identity profile state | Persist and display a projection; do not create a second authoritative profile |
| Resource ownership and permitted operations | Resource provider | Check current ownership and policy on every protected operation |
| Workflow configuration and owner | Reflux | Store the verified creator's person ID and enforce workflow ownership |
| Delegated workflow access | Resource provider's signed grant | Retain the grant, respect scope and expiry, and handle revocation |
| Service administration | Independently configured server secret | Keep service administration separate from ordinary Identity sessions |
| Wire encoding, signatures and verification | MetaMesh SDK/core | Call public operations with domain intent; do not assemble protocol JSON in UI code |

Identity establishes who acts. A valid Identity does not itself grant access to
another person's resource or confer service administration. An app-device
certificate does not imply workspace ownership. A storage receipt proves storage,
not permission to change product data.

Resource IDs, workflow IDs, opaque Rusty storage scope IDs and Identity person IDs
have different meanings. Their links must be explicit. Equality between different
IDs must never be required accidentally by a verifier or test fixture.

## Ordinary sign-in

1. The application creates a fresh, bounded request for its exact origin and
   return route. Each new attempt supersedes its earlier attempt.
2. The same browser tab opens Identity. Identity shows the requesting application
   and selected person, and obtains the required consent.
3. Identity returns signed evidence bound to the original origin, challenge,
   device and lifetime. Browser approval data travels in a fragment, never in
   query parameters, telemetry or an external referrer.
4. The application's callback captures and clears the fragment before telemetry
   or other requests. The SDK verifies the evidence against the locally retained
   request. Unsolicited, mismatched, denied or expired evidence cannot sign in.
5. The application durably adopts the approved state or exchanges the evidence
   for a server session. It loads the verified public profile and restores the
   local return route. Success means the resulting state also survives reload.

Browser applications authorize an application device through the public
`deviceAuthorization` operations. Server applications use the shared service-login
browser transport and the same core verifier. Service-login request version 2
binds `return_to` to the exact application origin and fixed
`/.well-known/mesh-service-login/callback` route; its signed proof uses
`mesh-service-login` version 1. Protocol evolution belongs in the SDK and core,
with actual client/server compatibility tests.

The callback must not silently accept incomplete profile state as a completed
profile load. Signed name and photo must describe the same approved Identity;
transported profile data must be bound to verified evidence. A presentation cache
cannot authorize a person or revive a revoked device. Large profile histories or
images must respect explicit transport bounds rather than growing redirect URLs
without a limit.

The pending request is temporary transport state. It is not a durable user-facing
process with a separate Cancel sign-in action. A subsequent Sign in starts fresh.
An existing-board invitation and Add another device remain separate actions and
must not appear as the ordinary sign-in form.

### App-owned resource bootstrap

Ordinary sign-in to an application that already has resources for the selected
person SHALL restore that application's current owner-authorized resource
catalog. The Identity device certificate proves the person and app device; it
does not create or imply resource permission. The resource owner remains the
authority for the catalog locator, access grant, resource ownership and permitted
operations.

The owner MAY register an app-scoped bootstrap in the encrypted Personal Identity
Document. Identity acts only as a credential wallet and delivery relay: it stores
and returns the opaque owner-issued record, but cannot create, widen or renew its
resource authority. The record is bound to one exact application origin and
person. Its owner-signed content contains only the catalog locator and the access
needed to retrieve that authoritative catalog. It does not copy the catalog or
resource contents into Identity.

The signed application approval distinguishes `ready`, `empty` and
`unavailable` catalog results. `ready` contains one or more verified entries;
`empty` means a successful lookup found no entry, or the signed Identity profile
has no Rusty service pins; `unavailable` means lookup failed. The approval digest
binds this status and its entries. An application may start a new catalog flow
only for `empty`; `unavailable` keeps local work intact and exposes a retryable
state.

When the application requests a bootstrap during ordinary sign-in, the returned
envelope SHALL bind the exact application origin, person ID, app device ID,
original sign-in challenge, bootstrap revision and expiry. The SDK owns envelope
sealing, opening, binding validation and proof verification. Bootstrap secrets
SHALL NOT appear in redirect URLs, browser history, telemetry or external
referrers. Root keys, recovery evidence and data for other applications SHALL NOT
be included. The resource provider still verifies its current signed owner grant
before exposing the catalog or any resource.

An application switching from its normal anonymous initial board to the selected
person's authorized catalog SHALL preserve the anonymous board and its content,
owner and local data, but leave it inactive while that catalog is active. It must
not relabel the anonymous board as the selected person's resource. If the owner
bootstrap is missing, expired, unavailable or denied, sign-in may complete for
local use; the application SHALL keep the anonymous board active, show an explicit
pending or unavailable state, and allow a fresh retry. It must not silently treat
the person as a visitor to another person's board or imply that resource discovery
succeeded.

#### Scenario: Sign-in restores the selected person's current catalog

- **GIVEN** an application has a current owner-issued catalog locator and scoped
  access record for the selected Identity, and this device has only its normal
  anonymous initial board
- **WHEN** the user approves ordinary same-tab sign-in and the application
  verifies the exact-origin, person, device, challenge, revision and expiry
  bindings
- **THEN** the application loads only resources allowed by the current owner
  authority and selects the person's authorized resource
- **AND** it preserves the anonymous board and its data unchanged but inactive
- **AND** an existing approved device receives the latest owner-signed revision
  through Identity synchronization before using it

#### Scenario: Bootstrap is absent or denied

- **GIVEN** a valid Identity approval but no current owner-issued bootstrap, or a
  bootstrap that is expired, revoked or for another app, person or device
- **WHEN** the application returns from Identity
- **THEN** it keeps local anonymous work active and intact, reports resource
  access as pending or unavailable, and offers a fresh retry
- **AND** it does not infer ownership from the person ID or use another
  application's credentials

**Implementation status:** The SDK and Rusty transport now define a bounded,
owner-authorized catalog-access exchange. Tincanban caller and Identity provider
integration remain pending. The transport carries an opaque catalog locator and
scoped access record; it does not grant board membership or expose catalog data
to Identity. Do not substitute an unbound URL secret, manual pairing/recovery as
a sign-in prerequisite, root-key conversion or a new service.

### Tincanban presentation

- Before sign-in, the header presents **Sign in**.
- After sign-in, the same control presents the person's photo, with an accessible
  profile name and a deterministic fallback when that person has no photo.
- A separate header button named Identity must not coexist with this control.
- Profile editing has one owner in Identity. An application may show the verified
  profile and open its editor with a return route; it must not present an unrelated
  editable copy as if it were the connected Identity profile.
- A saved certificate with an unavailable profile produces an explicit loading
  or failure state. It must not fall back to an onboarding menu that hides the
  existing sign-in.

## Server sessions and sign-out

The service owns a short-lived, one-time challenge and browser-bound login intent.
Successful verification creates a bounded, HttpOnly session. Protected mutations
also require the expected origin and CSRF protection. The verifier's result must
distinguish a valid person from the set of resources that person may access.

Sign-out invalidates the application session and returns to a visible sign-in
screen. Reload must not restore that session. Signing out of one application
does not erase Identity, browser boards or other applications' sessions.

A separately labelled administrator entry uses a server-managed secret. It is
not Identity recovery and must not make one configured person a universal
operator. If HTTP Basic authentication is retained for that entry, its browser
credential caching must not be presented as a logout-capable ordinary session.

## Resource access policy

Every protected read or write resolves a resource and applies its provider's
current policy to the authenticated principal. Resource ownership is stored or
cryptographically verified by that provider; it is not inferred from a display
name, a resource ID supplied by the caller, or a successful sign-in.

TinSink initially permits analytics and log access only to a resource's current
**owner**. Editor and visitor roles do not receive this permission. The decision
belongs in one named access-policy function so changing this product rule does
not require editing unrelated query handlers. Filtering applies before event
deduplication, totals, aggregation, pagination and export. An owner of one resource
must not learn another resource's events or protected metadata.

Reflux initially permits ordinary users to list, read and manage only workflows
they own. New workflows receive the creator's verified Identity person ID.
Existing unowned workflows require an explicit administrative assignment;
sign-in must never claim them automatically. Service-wide administration and
executor configuration require the separate administrator authority.

A valid Identity with no owned resources receives an authenticated empty view
with an explanation. It must not receive all service data or a misleading
cryptographic sign-in failure. New resource ownership and explicit administrative
assignment must be durable and independently enforceable by the resource owner.

Legacy per-service owner allowlists and Tincanban-mediated service-login routes
must not remain alternate ways around these checks. A static deployment field
containing one person's key is not the resource-access model.

## Connecting resources to workflows

Reflux owns a workflow; the board or learning service owns the resource the
workflow wants to use. Workflow ownership does not implicitly authorize external
resource access.

1. The owner selects a resource operation while configuring a workflow.
2. The resource provider identifies the person through Identity and verifies the
   person's current authority over that resource.
3. The provider shows the selected workflow, resource, operations and lifetime.
   Approval issues a grant for the workflow's own principal and exact scope.
4. The caller persists the verified connection and returns to the same workflow.
   Retry after an uncertain response must resume or safely replace that intent
   without creating a second independent grant silently.
5. Execution verifies the grant and current policy. Expiry or learned revocation
   stops further authorized operations and produces an actionable workflow state.

The shared resource client/provider interface owns connection challenges,
proofs, replay protection, grants and their verification. Product adapters define
the resource vocabulary and enforce operations. They must not recreate a second
signing or HTTP protocol around that interface.

For Tincanban automation, a grant can constrain board, columns, fields and expiry.
For Repetitor, its local account must be explicitly linked to Identity before
Identity-based ownership can replace the current account/token relationship.
The provider must preserve that account's actual ownership; matching names or
assuming that all users belong to one person is insufficient.

## Rusty and learned revocations

Rusty is infrastructure linked through the signed Identity service catalog.
An approved endpoint and service key are discovered once for that Identity;
applications choose which resources replicate there. A server is not repeatedly
added as a separate per-board identity relationship.

Replacing a Rusty service key requires explicit approval of that service link.
An obsolete cached approval must not override a newer verified catalog removal.
The catalog is a discovery projection, not permission to read arbitrary encrypted
resources. Resource-level storage policies remain independently verified.

Offline local work and authorized offline exchange remain available. Revocations
take effect when learned and verified; the system must describe this consistency
limit rather than claim immediate global revocation while disconnected. A learned
revocation cannot be forgotten through an older snapshot. When a durable domain
change requires propagation, persist its delivery intent atomically or make that
intent reconstructible from authoritative state.

## Failure and verification contract

Errors distinguish denial, expired intent, callback delivery, invalid evidence,
profile loading, missing resource permission and unavailable infrastructure.
Browser text must not collapse all of them into an uninformative retry loop.
Diagnostics retain bounded operation and reason codes, with no credentials,
approval fragments, private keys or resource content.

Required acceptance coverage includes:

- Same-tab approval and denial, fresh retry, origin mismatch, replay and expiry.
- Signed-in profile and photo after return and reload; visible profile-load failure.
- Session sign-out followed by reload.
- Owner access to one resource and denial of another; editor/visitor denial and
  an authenticated empty view for a person without resources.
- Explicit resource assignment and workflow creation under the verified owner.
- Delegated resource connection, retry, expiry and learned revocation.
- Export/import preserving board content under the importing Identity without
  importing old participant authority as the new owner's authority.
- Actual SDK-to-server compatibility, including omitted JSON defaults, delegated
  certificate chains and distinct resource/storage IDs.

Production publication uses committed source and immutable checked artifacts.
Changes must reach each repository's main branch, pass its applicable CI and be
verified at the served revision. A local test, a feature-branch commit or a dirty
checkout deployment is not publication evidence.
