import { expect, it, vi } from "vitest"
import { canonicalizeJson, createIdentityAuthorityView, createRecoverableIdentity, emptyIdentityProfileState, publicKeyId,
  sha256Base64Url,
  signEnvelope } from "@meta-uber/mesh-identity"
import { ensureRustyScopeAuthoritySnapshot, publishRustyScopeAuthoritySnapshot, readRustyScopeAuthorityStatus } from "./rustyScopeAuthorityClient"

it("Given an enrolled workspace scope with missing Rusty authority, When publishing, Then bind signed update and receipt to the active controller and full snapshot", async () => {
  const owner = (await createRecoverableIdentity("better", "Owner")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const serviceId = await publicKeyId(service.identity.publicKey)
  const authorityView = await createIdentityAuthorityView(owner.identity,
    { certificates: [owner.certificate], revocations: [] }, emptyIdentityProfileState(owner.identity.personId))
  const scopeAuthority = { genesis: { payload: { scopeId: "workspace-1", controlEpoch: 1 } }, controlTransfers: [] }
  let statusUrl = ""
  let update: { version: number; scopeAuthority: unknown; authorization: { payload: Record<string, unknown> } } | undefined
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (init?.method === "GET") {
      statusUrl = url
      const parsed = new URL(url)
      const requestId = parsed.searchParams.get("requestId")!
      const requestHash = parsed.searchParams.get("requestHash")!
      return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
        kind: "rusty-scope-authority-status" as const, version: 1 as const, serviceId,
        origin: "https://rusty.example", scopeId: "scope-1", workspaceId: null, state: "missing" as const,
        controllerPersonId: null, controlEpoch: null, requestId, requestHash, issuedAt: 50_000,
        enforcement: { mode: "additive" as const, epoch: 0 as const }, scopeAuthority: null,
      }, service.identity.personId, "RUSTY/2") })
    }
    update = JSON.parse(String(init?.body)) as typeof update
    const payload = update!.authorization.payload
    const snapshotHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(update!.scopeAuthority)))
    return Response.json({ receipt: await signEnvelope(service.privateKeys.identityPrivateKey!, {
      kind: "rusty-scope-authority-receipt" as const, version: 1 as const, serviceId,
      origin: "https://rusty.example", scopeId: "scope-1", workspaceId: "workspace-1",
      controllerPersonId: owner.identity.personId, controlEpoch: 1, requestId: payload.requestId as string,
      requestHash: payload.requestHash as string, mergedSnapshotHash: snapshotHash,
      committedAt: 50_000, enforcement: { mode: "additive" as const, epoch: 0 as const },
    }, service.identity.personId, "RUSTY/2") })
  })
  const current = vi.fn()

  const result = await publishRustyScopeAuthoritySnapshot({
    origin: "https://rusty.example", servicePublicKey: service.identity.publicKey, scopeId: "scope-1",
    workspaceId: "workspace-1", identity: owner.identity, authorityView, deviceId: owner.device.deviceId,
    devicePublicKey: owner.device.publicKey, scopeAuthority, fetcher, ensureCurrent: current,
    validateSnapshot: value => ({ workspaceId: "workspace-1", controllerPersonId: owner.identity.personId,
      controllerPublicKey: owner.identity.publicKey, controlEpoch: 1, snapshot: value }),
    mergeSnapshots: (_stored, incoming) => incoming,
    signAuthorization: payload => signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId, "MATCH/1"),
    now: () => 50_000,
  })

  expect(new URL(statusUrl).pathname).toBe("/v2/scopes/scope-1/authority/status")
  const canonicalSnapshot = { ...scopeAuthority, grants: [], grantIssuers: [], revocations: [], successionTransfers: [] }
  expect(update?.scopeAuthority).toEqual(canonicalSnapshot)
  expect(update?.authorization.payload.requestHash).toBe(await sha256Base64Url(new TextEncoder().encode(
    canonicalizeJson({ version: 1, scopeAuthority: canonicalSnapshot }))))
  expect(update?.authorization.payload).toMatchObject({ kind: "rusty-scope-authority-update", serviceId,
    origin: "https://rusty.example", scopeId: "scope-1", workspaceId: "workspace-1",
    personId: owner.identity.personId, deviceId: owner.device.deviceId, controlEpoch: 1,
    issuedAt: 50_000, expiresAt: 140_000 })
  expect(update?.authorization.payload.requestId).toMatch(/^[A-Za-z0-9_-]{43}$/u)
  expect(result.receipt.payload.enforcement).toEqual({ mode: "additive", epoch: 0 })
  expect(result.scopeAuthority).toEqual({ workspaceId: "workspace-1", controllerPersonId: owner.identity.personId,
    controllerPublicKey: owner.identity.publicKey, controlEpoch: 1, snapshot: canonicalSnapshot })
  expect(current).toHaveBeenCalledTimes(4)
})

it("Given a workspace participant without controller authority, When reading scope status, Then verify and return the signed current ledger", async () => {
  const owner = (await createRecoverableIdentity("better", "Workspace owner")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const serviceId = await publicKeyId(service.identity.publicKey)
  const snapshot = { genesis: { payload: { scopeId: "workspace-2", controlEpoch: 1 } }, controlTransfers: [] }
  let requestUrl = ""
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    void init
    requestUrl = String(input)
    const url = new URL(requestUrl)
    const requestId = url.searchParams.get("requestId")!
    const requestHash = url.searchParams.get("requestHash")!
    return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
      kind: "rusty-scope-authority-status" as const, version: 1 as const, serviceId,
      origin: "https://rusty.example", scopeId: "scope-2", workspaceId: "workspace-2", state: "ready" as const,
      controllerPersonId: owner.identity.personId, controlEpoch: 1, requestId, requestHash, issuedAt: 50_000,
      enforcement: { mode: "additive" as const, epoch: 0 as const }, scopeAuthority: snapshot,
    }, service.identity.personId, "RUSTY/2") })
  })
  const validateSnapshot = (value: unknown) => ({ workspaceId: "workspace-2", controllerPersonId: owner.identity.personId,
    controllerPublicKey: owner.identity.publicKey, controlEpoch: 1, snapshot: value })

  const result = await readRustyScopeAuthorityStatus({ origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
    scopeId: "scope-2", fetcher, validateSnapshot, now: () => 50_000 })

  const request = new URL(requestUrl)
  expect(request.pathname).toBe("/v2/scopes/scope-2/authority/status")
  expect(request.searchParams.get("requestId")).toMatch(/^[A-Za-z0-9_-]{43}$/u)
  expect(request.searchParams.get("requestHash")).toMatch(/^[A-Za-z0-9_-]{43}$/u)
  expect(result.status.payload.state).toBe("ready")
  expect(result.authority).toEqual(validateSnapshot(snapshot))
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it("Given Rusty already has the exact accepted authority snapshot, When reconciling it, Then do not spend an update write", async () => {
  const owner = (await createRecoverableIdentity("better", "Workspace owner")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const serviceId = await publicKeyId(service.identity.publicKey)
  const authorityView = await createIdentityAuthorityView(owner.identity,
    { certificates: [owner.certificate], revocations: [] }, emptyIdentityProfileState(owner.identity.personId))
  const snapshot = { genesis: { payload: { scopeId: "workspace-3", controlEpoch: 1 } }, grants: [], grantIssuers: [],
    revocations: [], controlTransfers: [], successionTransfers: [] }
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    void init
    const url = new URL(String(input))
    const requestId = url.searchParams.get("requestId")!
    const requestHash = url.searchParams.get("requestHash")!
    return Response.json({ status: await signEnvelope(service.privateKeys.identityPrivateKey!, {
      kind: "rusty-scope-authority-status" as const, version: 1 as const, serviceId,
      origin: "https://rusty.example", scopeId: "scope-3", workspaceId: "workspace-3", state: "ready" as const,
      controllerPersonId: owner.identity.personId, controlEpoch: 1, requestId, requestHash, issuedAt: 50_000,
      enforcement: { mode: "additive" as const, epoch: 0 as const }, scopeAuthority: snapshot,
    }, service.identity.personId, "RUSTY/2") })
  })
  const validateSnapshot = (value: unknown) => ({ workspaceId: "workspace-3", controllerPersonId: owner.identity.personId,
    controllerPublicKey: owner.identity.publicKey, controlEpoch: 1, snapshot: value })

  const result = await ensureRustyScopeAuthoritySnapshot({ origin: "https://rusty.example",
    servicePublicKey: service.identity.publicKey, scopeId: "scope-3", workspaceId: "workspace-3",
    identity: owner.identity, authorityView, deviceId: owner.device.deviceId, devicePublicKey: owner.device.publicKey,
    scopeAuthority: snapshot, fetcher, validateSnapshot, mergeSnapshots: (_current, incoming) => incoming,
    signAuthorization: payload => signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId, "MATCH/1"),
    now: () => 50_000 })

  expect(result.receipt).toBeNull()
  expect(result.scopeAuthority.snapshot).toEqual(snapshot)
  expect(fetcher).toHaveBeenCalledTimes(1)
  expect(fetcher.mock.calls[0]?.[1]?.method).not.toBe("PUT")
})
