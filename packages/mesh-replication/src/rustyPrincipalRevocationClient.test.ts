import { expect, it, vi } from "vitest"
import {
  canonicalizeJson,
  createIdentityAuthorityView,
  createRecoverableIdentity,
  emptyIdentityProfileState,
  publicKeyId,
  sha256Base64Url,
  signEnvelope,
} from "@meta-uber/mesh-identity"
import { revokeRustyResourcePrincipal, verifyRustyResourcePrincipalRevocationReceipt } from "./rustyPrincipalRevocationClient"

it("Given the current workspace controller, When revoking a principal, Then signs the normalized intent and verifies the service receipt", async () => {
  const owner = (await createRecoverableIdentity("better", "Workspace owner")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const serviceId = await publicKeyId(service.identity.publicKey)
  const authorityView = await createIdentityAuthorityView(
    owner.identity,
    { certificates: [owner.certificate], revocations: [] },
    emptyIdentityProfileState(owner.identity.personId),
  )
  const scopeAuthority = { genesis: { payload: { scopeId: "workspace-1", controlEpoch: 1 } }, controlTransfers: [] }
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input))
    if (init?.method === "GET") {
      const query = url.searchParams
      return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
        kind: "rusty-scope-authority-status" as const,
        version: 1 as const,
        serviceId,
        origin: url.origin,
        scopeId: "opaque-scope",
        workspaceId: "workspace-1",
        state: "ready" as const,
        controllerPersonId: owner.identity.personId,
        controlEpoch: 1,
        requestId: query.get("requestId")!,
        requestHash: query.get("requestHash")!,
        issuedAt: 50_000,
        enforcement: { mode: "strict" as const, epoch: 1 as const },
        scopeAuthority,
      }, service.identity.personId, "RUSTY/2") })
    }
    const request = JSON.parse(String(init?.body)) as {
      version: number
      authorization: { payload: Record<string, unknown> }
    }
    const payload = request.authorization.payload
    return Response.json({ receipt: await signEnvelope(service.privateKeys.identityPrivateKey!, {
      kind: "rusty-resource-principal-revocation-receipt" as const,
      version: 1 as const,
      serviceId,
      origin: url.origin,
      storageScopeId: "opaque-scope",
      workspaceId: "workspace-1",
      grantId: "editor-grant",
      subjectPersonId: "editor-person",
      policyEpoch: 4,
      requestHash: payload.requestHash as string,
      committedAt: 50_000,
    }, service.identity.personId, "RUSTY/2") })
  })

  const receipt = await revokeRustyResourcePrincipal({
    origin: "https://rusty.example",
    servicePublicKey: service.identity.publicKey,
    storageScopeId: "opaque-scope",
    workspaceId: "workspace-1",
    grantId: "editor-grant",
    subjectPersonId: "editor-person",
    policyEpoch: 4,
    identity: owner.identity,
    authorityView,
    deviceId: owner.device.deviceId,
    devicePublicKey: owner.device.publicKey,
    fetcher,
    validateSnapshot: (snapshot) => ({
      workspaceId: "workspace-1",
      controllerPersonId: owner.identity.personId,
      controllerPublicKey: owner.identity.publicKey,
      controlEpoch: 1,
      snapshot,
    }),
    signAuthorization: (payload) => signEnvelope(owner.privateKeys.devicePrivateKey!, payload, owner.device.deviceId, "MATCH/1"),
    now: () => 50_000,
  })

  const request = JSON.parse(String(fetcher.mock.calls[1]![1]?.body)) as {
    version: number
    authorization: { payload: Record<string, unknown> }
  }
  expect(new URL(String(fetcher.mock.calls[1]![0])).pathname)
    .toBe("/v2/scopes/opaque-scope/principals/editor-grant/revocation")
  expect(request.version).toBe(1)
  expect(request.authorization.payload).toMatchObject({
    kind: "rusty-resource-principal-revocation",
    serviceId,
    origin: "https://rusty.example",
    storageScopeId: "opaque-scope",
    workspaceId: "workspace-1",
    grantId: "editor-grant",
    subjectPersonId: "editor-person",
    policyEpoch: 4,
  })
  const { requestHash, ...unsigned } = request.authorization.payload
  expect(requestHash).toBe(await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(unsigned))))
  expect(receipt.payload).toMatchObject({ kind: "rusty-resource-principal-revocation-receipt", grantId: "editor-grant",
    subjectPersonId: "editor-person", policyEpoch: 4, requestHash })
  await expect(verifyRustyResourcePrincipalRevocationReceipt({
    origin: "https://rusty.example",
    servicePublicKey: service.identity.publicKey,
    storageScopeId: "opaque-scope",
    workspaceId: "workspace-1",
    grantId: "editor-grant",
    subjectPersonId: "editor-person",
    policyEpoch: 4,
    receipt,
    now: () => 50_000,
  })).resolves.toEqual(receipt)
  expect(fetcher).toHaveBeenCalledTimes(2)
})

it("Given a signed scope controlled by another person, When revoking a principal, Then do not send the mutation", async () => {
  const owner = (await createRecoverableIdentity("better", "Workspace owner")).profile
  const successor = (await createRecoverableIdentity("better", "New controller")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const serviceId = await publicKeyId(service.identity.publicKey)
  const authorityView = await createIdentityAuthorityView(
    owner.identity,
    { certificates: [owner.certificate], revocations: [] },
    emptyIdentityProfileState(owner.identity.personId),
  )
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input))
    return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
      kind: "rusty-scope-authority-status" as const,
      version: 1 as const,
      serviceId,
      origin: url.origin,
      scopeId: "opaque-scope",
      workspaceId: "workspace-1",
      state: "ready" as const,
      controllerPersonId: successor.identity.personId,
      controlEpoch: 2,
      requestId: url.searchParams.get("requestId")!,
      requestHash: url.searchParams.get("requestHash")!,
      issuedAt: 50_000,
      enforcement: { mode: "strict" as const, epoch: 1 as const },
      scopeAuthority: { controlTransfers: [] },
    }, service.identity.personId, "RUSTY/2") })
  })

  await expect(revokeRustyResourcePrincipal({
    origin: "https://rusty.example",
    servicePublicKey: service.identity.publicKey,
    storageScopeId: "opaque-scope",
    workspaceId: "workspace-1",
    grantId: "editor-grant",
    subjectPersonId: "editor-person",
    policyEpoch: 4,
    identity: owner.identity,
    authorityView,
    deviceId: owner.device.deviceId,
    devicePublicKey: owner.device.publicKey,
    fetcher,
    validateSnapshot: (snapshot) => ({ workspaceId: "workspace-1", controllerPersonId: successor.identity.personId,
      controllerPublicKey: successor.identity.publicKey, controlEpoch: 2, snapshot }),
    signAuthorization: (payload) => signEnvelope(owner.privateKeys.devicePrivateKey!, payload, owner.device.deviceId, "MATCH/1"),
    now: () => 50_000,
  })).rejects.toThrow(/current workspace controller/u)
  expect(fetcher).toHaveBeenCalledTimes(1)
})
