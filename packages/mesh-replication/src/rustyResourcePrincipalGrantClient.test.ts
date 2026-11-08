import { expect, it, vi } from "vitest"
import { createRecoverableIdentity, createIdentityAuthorityView, emptyIdentityProfileState,
  signEnvelope, sha256Base64Url, canonicalizeJson, toBase64Url } from "@meta-uber/mesh-identity"
import { registerRustyResourcePrincipalGrant } from "./rustyResourcePrincipalGrantClient"

async function fixture(change?: (status: Record<string, unknown>) => void, invalidSignature = false) {
  const owner = (await createRecoverableIdentity("better", "Owner")).profile
  const subject = (await createRecoverableIdentity("better", "Member")).profile
  const service = (await createRecoverableIdentity("better", "Rusty")).profile
  const signOwner = <T extends { kind: string }>(payload: T) =>
    signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId, "MATCH/1")
  const signService = <T extends { kind: string }>(payload: T) =>
    signEnvelope(service.privateKeys.identityPrivateKey!, payload, service.identity.personId, "RUSTY/2")
  const authorityView = await createIdentityAuthorityView(owner.identity,
    { certificates: [owner.certificate], revocations: [] }, emptyIdentityProfileState(owner.identity.personId))
  const snapshot = { genesis: await signOwner({ kind: "scope-genesis", version: 1, scopeId: "workspace",
    creator: { personId: owner.identity.personId, publicKey: owner.identity.publicKey, certificates: [owner.certificate] },
    controlEpoch: 1 }) }
  const workspaceGrant = await signOwner({ kind: "workspace-grant" as const, version: 1 as const,
    workspaceId: "workspace", personId: subject.identity.personId, role: "visitor" as const, grantId: "new-grant", accessEpoch: 3 })
  const mutations: string[] = []
  let puts = 0
  const signRevocation = vi.fn(signOwner)
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input))
    if (init?.method === "GET") return Response.json({ status: await signService({
      kind: "rusty-scope-authority-status", version: 1, serviceId: service.identity.personId,
      origin: url.origin, scopeId: "opaque", workspaceId: "workspace", state: "ready",
      controllerPersonId: owner.identity.personId, controlEpoch: 1,
      requestId: url.searchParams.get("requestId"), requestHash: url.searchParams.get("requestHash"),
      issuedAt: 50_000, enforcement: { mode: "strict", epoch: 1 }, scopeAuthority: snapshot,
    }) })
    const request = JSON.parse(String(init?.body))
    if (url.pathname.endsWith("/revocation")) {
      mutations.push("revoke")
      return Response.json({ receipt: await signService({ ...request.authorization.payload,
        kind: "rusty-resource-principal-revocation-receipt", committedAt: 50_000 }) })
    }
    puts++
    if (puts > 1) { mutations.push("register"); return new Response(null, { status: 204 }) }
    const desired = request.grant.payload
    const status = { kind: "rusty-resource-principal-replacement-required", version: 1,
      serviceId: service.identity.personId, origin: url.origin, storageScopeId: "opaque", workspaceId: "workspace",
      ownerPersonId: owner.identity.personId, subjectPersonId: subject.identity.personId,
      grantId: desired.grantId, policyEpoch: desired.policyEpoch, previousGrantId: "previous-grant", previousPolicyEpoch: 2,
      requestId: new Headers(init?.headers).get("X-Rusty-Request-Id"),
      requestHash: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(request))), issuedAt: 50_000 }
    change?.(status)
    const replacement = await signService(status)
    if (invalidSignature) replacement.signature = "invalid"
    return Response.json({ replacement })
  })
  const options = { origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
    storageScopeId: "opaque", workspaceId: "workspace", expectedScopeAuthoritySnapshot: snapshot,
    identity: owner.identity, authorityView, deviceId: owner.device.deviceId, devicePublicKey: owner.device.publicKey,
    subjectIdentity: subject.identity, workspaceGrant, readToken: toBase64Url(new Uint8Array(32).fill(7)), fetcher,
    validateSnapshot: (value: unknown) => ({ workspaceId: "workspace", controllerPersonId: owner.identity.personId,
      controllerPublicKey: owner.identity.publicKey, controlEpoch: 1, snapshot: value }),
    signAuthorization: signOwner, signRevocation, now: () => 50_000 }
  return { options, mutations, signRevocation, fetcher }
}

it("Given only the new signed membership, when Rusty proves its previous installed principal, then revoke that exact older grant before registration", async () => {
  const f = await fixture()
  expect((await registerRustyResourcePrincipalGrant(f.options)).principalGrant.payload.grantId).toBe("new-grant")
  expect(f.mutations).toEqual(["revoke", "register"])
  expect(f.signRevocation.mock.calls[0]![0]).toMatchObject({ grantId: "previous-grant", policyEpoch: 2 })
})

it.each([
  ["foreign scope", { storageScopeId: "foreign" }], ["foreign workspace", { workspaceId: "foreign" }],
  ["foreign subject", { subjectPersonId: "foreign" }], ["foreign owner", { ownerPersonId: "foreign" }],
  ["foreign service", { serviceId: "foreign" }], ["foreign origin", { origin: "https://foreign.example" }],
  ["other desired grant", { grantId: "foreign" }], ["other desired epoch", { policyEpoch: 4 }],
  ["replayed challenge", { requestId: "old-challenge" }], ["other request", { requestHash: "foreign" }],
  ["same grant", { previousGrantId: "new-grant" }], ["equal epoch", { previousPolicyEpoch: 3 }],
  ["newer epoch", { previousPolicyEpoch: 4 }], ["expired status", { issuedAt: -100_000 }],
  ["future status", { issuedAt: 120_000 }],
] as const)("Given a service-signed %s replacement status, when registering, then reject before revoking or installing any principal", async (_name, fields) => {
  const f = await fixture(status => Object.assign(status, fields))
  await expect(registerRustyResourcePrincipalGrant(f.options)).rejects.toThrow(/replacement status/)
  expect(f.signRevocation).not.toHaveBeenCalled()
  expect(f.mutations).toEqual([])
})

it("Given a forged service status, when registering, then do not sign a revocation", async () => {
  const f = await fixture(undefined, true)
  await expect(registerRustyResourcePrincipalGrant(f.options)).rejects.toThrow(/signature/)
  expect(f.signRevocation).not.toHaveBeenCalled()
})

it("Given membership changes after the signed status arrives, when registering, then abort before revoking", async () => {
  let stale = false
  const f = await fixture(() => { stale = true })
  await expect(registerRustyResourcePrincipalGrant({ ...f.options,
    ensureCurrent: () => { if (stale) throw new Error("Membership changed") } })).rejects.toThrow("Membership changed")
  expect(f.signRevocation).not.toHaveBeenCalled()
  expect(f.mutations).toEqual([])
})
