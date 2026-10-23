import { expect, it, vi } from "vitest"
import { canonicalizeJson, createRecoverableIdentity, sha256Base64Url, signEnvelope, toBase64Url } from "@meta-uber/mesh-identity"
import { createRustyManagementMutationClient, type RustyManagementUpdateAuthorization } from "./rustyManagementMutation"
import type { RustyManagementCapability } from "./rustyManagementCapability"
import { rustyHash } from "./rustyReplica"

const origin = "https://rusty.example"

it("Given a new Identity root, When creating its person capability, Then persist and sign a bootstrap resource.create policy before sending it", async () => {
  const profile = (await createRecoverableIdentity("better", "Owner", new Uint8Array(32).fill(5))).profile
  const serviceKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", serviceKeys.publicKey)))
  const serviceId = await rustyHash(new Uint8Array(await crypto.subtle.exportKey("raw", serviceKeys.publicKey)))
  let sent: Record<string, unknown> | undefined
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe(`${origin}/v2/management/person/${profile.identity.personId}`)
    expect(init?.method).toBe("PUT")
    sent = JSON.parse(String(init?.body)) as Record<string, unknown>
    const authorization = sent.authorization
    const authPayload = (sent.authorization as { payload: { requestId: string; expectedRevision: number; operations: string[]; revokedDeviceIds: string[]; restoredDeviceIds?: string[] } }).payload
    const payload = { kind: "rusty-person-management-capability" as const, version: 1 as const, serviceId, origin,
      personId: profile.identity.personId, resourceKind: "person" as const, resourceId: profile.identity.personId,
      revision: authPayload.expectedRevision + 1, operations: authPayload.operations, revokedDeviceIds: authPayload.revokedDeviceIds,
      restoredDeviceIds: authPayload.restoredDeviceIds ?? [], requestId: authPayload.requestId,
      authorizationHash: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(authorization))), issuedAt: Date.now() }
    return Response.json({ capability: await signEnvelope(serviceKeys.privateKey, payload, serviceId, "RUSTY/2") })
  })
  const requestJournal: unknown[] = []
  const journal = {
    read: vi.fn(async () => undefined),
    prepare: vi.fn(async (_binding: unknown, request: unknown) => { requestJournal.push(structuredClone(request)) }),
    complete: vi.fn(),
  }
  const signAuthorization = vi.fn(async (payload: RustyManagementUpdateAuthorization) =>
    signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId))
  const client = createRustyManagementMutationClient({
    binding: { origin, servicePublicKey, resourceKind: "person", resourceId: profile.identity.personId },
    identity: profile.identity, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
    certificates: [profile.certificate], fetcher, ensureCurrent: async () => {},
    getCapability: async () => undefined, getParentCapability: async () => undefined, ensureAuthorityCurrent: async () => {},
    signAuthorization, journal,
  })

  const capability = await client.update({ operations: ["management.update", "resource.create"], revokedDeviceIds: [] })
  expect(capability.payload).toMatchObject({ kind: "rusty-person-management-capability", revision: 1,
    operations: ["management.update", "resource.create"] })
  expect(sent).toMatchObject({ version: 1, identity: profile.identity, deviceId: profile.device.deviceId,
    certificates: [profile.certificate] })
  const request = requestJournal[0] as { authorization: { payload: Record<string, unknown> } }
  expect(request.authorization.payload).toMatchObject({ kind: "rusty-management-policy-update", origin,
    personId: profile.identity.personId, deviceId: profile.device.deviceId, resourceKind: "person",
    resourceId: profile.identity.personId, expectedRevision: 0, operations: ["management.update", "resource.create"] })
  expect((sent?.authorization as { payload: { requestId: string } }).payload.requestId).toBe(request.authorization.payload.requestId)
  expect((await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(request.authorization)))).length).toBe(43)
  expect(journal.prepare).toHaveBeenCalledOnce()
  expect(journal.complete).toHaveBeenCalledOnce()
  expect(fetcher).toHaveBeenCalledOnce()
})

it("Given a managed scope and its owner parent capability, When updating scope policy, Then send only the scope capability as resource authority", async () => {
  const profile = (await createRecoverableIdentity("better", "Owner", new Uint8Array(32).fill(7))).profile
  const serviceKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", serviceKeys.publicKey)))
  const serviceId = await rustyHash(new Uint8Array(await crypto.subtle.exportKey("raw", serviceKeys.publicKey)))
  const binding = { origin, servicePublicKey, resourceKind: "scope" as const, resourceId: "scope-1" }
  const capability = async (resourceKind: "scope" | "person", resourceId: string, revision: number,
    operations: string[], kind: RustyManagementCapability["kind"]) => signEnvelope(serviceKeys.privateKey, {
    kind, version: 1, serviceId, origin, personId: profile.identity.personId, resourceKind, resourceId, revision,
    operations, revokedDeviceIds: [], requestId: `request-${revision}-${resourceKind}`, authorizationHash: "A".repeat(43), issuedAt: Date.now(),
  } satisfies RustyManagementCapability, serviceId, "RUSTY/2")
  const current = await capability("scope", binding.resourceId, 1, ["management.update", "scope.policy"], "rusty-scope-management-capability")
  const parent = await capability("person", profile.identity.personId, 1, ["management.update", "resource.create"], "rusty-person-management-capability")
  let sent: Record<string, unknown> | undefined
  const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    sent = JSON.parse(String(init?.body)) as Record<string, unknown>
    const authorization = sent.authorization
    const payload = (authorization as { payload: { requestId: string; expectedRevision: number; operations: string[]; revokedDeviceIds: string[] } }).payload
    return Response.json({ capability: await signEnvelope(serviceKeys.privateKey, {
      kind: "rusty-scope-management-capability", version: 1, serviceId, origin, personId: profile.identity.personId,
      resourceKind: "scope", resourceId: binding.resourceId, revision: payload.expectedRevision + 1,
      operations: payload.operations, revokedDeviceIds: payload.revokedDeviceIds, requestId: payload.requestId,
      authorizationHash: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(authorization))), issuedAt: Date.now(),
    }, serviceId, "RUSTY/2") })
  })
  const client = createRustyManagementMutationClient({
    binding, identity: profile.identity, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
    certificates: [profile.certificate], fetcher, ensureCurrent: async () => {},
    getCapability: async () => current, getParentCapability: async () => parent, ensureAuthorityCurrent: async () => {},
    signAuthorization: async payload => signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId),
    journal: { read: async () => undefined, prepare: async () => {}, complete: async () => {} },
  })

  await expect(client.update({ operations: ["management.update", "scope.policy"], revokedDeviceIds: [] })).resolves.toMatchObject({ payload: { revision: 2 } })
  expect(sent?.managementCapability).toEqual(current)
  expect(sent).not.toHaveProperty("personManagementCapability")
  expect((sent?.authorization as { payload: Record<string, unknown> }).payload).not.toHaveProperty("personManagementRevision")
})

it("Given an unprovisioned scope without its owner's resource.create capability, When mutating policy, Then reject before sending", async () => {
  const profile = (await createRecoverableIdentity("better", "Owner", new Uint8Array(32).fill(6))).profile
  const serviceKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", serviceKeys.publicKey)))
  const fetcher = vi.fn()
  const client = createRustyManagementMutationClient({
    binding: { origin, servicePublicKey, resourceKind: "scope", resourceId: "scope-1" },
    identity: profile.identity, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
    certificates: [profile.certificate], fetcher, ensureCurrent: async () => {},
    getCapability: async () => undefined, getParentCapability: async () => undefined, ensureAuthorityCurrent: async () => {},
    signAuthorization: async (payload: RustyManagementUpdateAuthorization) => signEnvelope(profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId),
    journal: { read: async () => undefined, prepare: async () => {}, complete: async () => {} },
  })
  await expect(client.update({ operations: ["management.update", "scope.policy"], revokedDeviceIds: [] }))
    .rejects.toThrow(/person.*capability|resource.create/i)
  expect(fetcher).not.toHaveBeenCalled()
})
