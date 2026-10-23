import { expect, it, vi } from "vitest"
import { canonicalizeJson, createRecoverableIdentity, sha256Base64Url, signEnvelope, toBase64Url } from "@meta-uber/mesh-identity"
import { rustyHash } from "./rustyReplica"
import { createRustyScopeEnrollmentClient, type RustyScopeEnrollmentAuthorization } from "./rustyScopeEnrollment"

const origin = "https://rusty.example"
const scopeId = "scope-private"
const readToken = "read-token-never-put-in-url"
const writeToken = "write-token-never-put-in-url"

async function fixture(scopeManagement: unknown = 0) {
  const owner = await createRecoverableIdentity("better", "Owner", new Uint8Array(32).fill(4))
  const serviceKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", serviceKeys.publicKey)))
  const serviceId = await rustyHash(new Uint8Array(await crypto.subtle.exportKey("raw", serviceKeys.publicKey)))
  const now = Date.now()
  const requestBodies: Record<string, unknown>[] = []
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url === `${origin}/.well-known/mesh-lighthouse`) return Response.json({
      protocolVersions: [2], publicOrigin: origin, service: { publicKey: servicePublicKey, serviceId },
      capabilities: { modes: ["blind"], applicationWrites: false, classification: false,
        scopeManagement, scopeEnrollmentRetry: 1, writerPolicy: { version: 1, maximumWriterVersion: 2 } },
    })
    if (url === `${origin}/v2/enrollment/challenge`) {
      const body = JSON.parse(String(init?.body)) as { identity: { personId: string }; deviceId: string }
      const challenge = await signEnvelope(serviceKeys.privateKey, {
        kind: "rusty-enrollment-challenge", version: 1, challengeId: "challenge-1", nonce: "nonce-1", serviceId,
        publicOrigin: origin, scopeId, personId: body.identity.personId, deviceId: body.deviceId, deviceKeyId: body.deviceId,
        expectedRevision: 0, issuedAt: now, expiresAt: now + 60_000,
      }, serviceId, "RUSTY/2")
      return Response.json({ challenge })
    }
    if (url === `${origin}/v2/scopes/${scopeId}`) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      requestBodies.push(body)
      const authorization = body.authorization as { payload: Record<string, unknown> }
      const receipt = await signEnvelope(serviceKeys.privateKey, {
        kind: "rusty-scope-policy-receipt", version: 1, serviceId, scopeId,
        personId: owner.profile.identity.personId, revision: 0, revoked: false, challengeId: "challenge-1",
        authorizationHash: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(body.authorization))), minimumWriterVersion: 2,
      }, serviceId, "RUSTY/2")
      return Response.json({ receipt })
    }
    throw new Error(`Unexpected Rusty request: ${url}`)
  })
  return { owner, serviceId, servicePublicKey, fetcher, requestBodies }
}

it("Given a pinned Rusty service and current Identity device, When enrolling scope policy, Then bind the signed challenge, exact tokens, identity evidence and verified receipt", async () => {
  const f = await fixture()
  const ensureCurrent = vi.fn()
  const signAuthorization = vi.fn(async (payload: RustyScopeEnrollmentAuthorization) =>
    signEnvelope(f.owner.profile.privateKeys.devicePrivateKey, payload, f.owner.profile.device.deviceId))
  const journal = { read: vi.fn(async () => undefined), prepare: vi.fn(), replace: vi.fn(), complete: vi.fn() }
  const client = createRustyScopeEnrollmentClient({
    access: { origin, scopeId, servicePublicKey: f.servicePublicKey, readToken, writeToken },
    identity: f.owner.profile.identity, deviceId: f.owner.profile.device.deviceId, devicePublicKey: f.owner.profile.device.publicKey,
    certificates: [f.owner.profile.certificate],
    fetcher: f.fetcher, ensureCurrent, getManagementCapability: async () => undefined,
    ensureManagementCurrent: async () => {}, signAuthorization, journal,
  })

  await expect(client.enroll({ minimumWriterVersion: 2, requireExactRetry: true })).resolves.toMatchObject({ policyRevision: 0 })
  const request = f.requestBodies[0]!
  expect(request).toMatchObject({ identity: f.owner.profile.identity, deviceId: f.owner.profile.device.deviceId,
    certificates: [f.owner.profile.certificate], readToken, writeToken, revoked: false })
  expect((request.authorization as { payload: Record<string, unknown> }).payload).toMatchObject({
    kind: "rusty-scope-enrollment", serviceId: f.serviceId, publicOrigin: origin, scopeId,
    personId: f.owner.profile.identity.personId, deviceId: f.owner.profile.device.deviceId,
    readTokenHash: await sha256Base64Url(new TextEncoder().encode(readToken)),
    writeTokenHash: await sha256Base64Url(new TextEncoder().encode(writeToken)), minimumWriterVersion: 2,
  })
  expect(f.fetcher.mock.calls.map(([url]) => String(url))).toEqual([
    `${origin}/.well-known/mesh-lighthouse`, `${origin}/v2/enrollment/challenge`, `${origin}/v2/scopes/${scopeId}`,
  ])
  expect(journal.prepare).toHaveBeenCalledOnce()
  expect(journal.complete).toHaveBeenCalledOnce()
  expect(ensureCurrent.mock.calls.length).toBeGreaterThan(0)
})

it("Given a managed Rusty service with no signed capability, When no adapter attests verified unmanaged status, Then reject before enrollment", async () => {
  const f = await fixture({ version: 1 })
  const client = createRustyScopeEnrollmentClient({
    access: { origin, scopeId, servicePublicKey: f.servicePublicKey, readToken, writeToken },
    identity: f.owner.profile.identity, deviceId: f.owner.profile.device.deviceId, devicePublicKey: f.owner.profile.device.publicKey,
    certificates: [f.owner.profile.certificate], fetcher: f.fetcher, ensureCurrent: async () => {},
    getManagementCapability: async () => undefined, ensureManagementCurrent: async () => {},
    signAuthorization: async payload => signEnvelope(f.owner.profile.privateKeys.devicePrivateKey, payload, f.owner.profile.device.deviceId),
    journal: { read: async () => undefined, prepare: vi.fn(), replace: vi.fn(), complete: vi.fn() },
  })

  await expect(client.enroll()).rejects.toThrow(/management authority/i)
  expect(f.requestBodies).toEqual([])
})

it("Given a managed service whose signed status confirms no scope or parent policy, When the adapter explicitly permits legacy unmanaged use, Then enroll without inventing a management capability", async () => {
  const f = await fixture({ version: 1 })
  const client = createRustyScopeEnrollmentClient({
    access: { origin, scopeId, servicePublicKey: f.servicePublicKey, readToken, writeToken },
    identity: f.owner.profile.identity, deviceId: f.owner.profile.device.deviceId, devicePublicKey: f.owner.profile.device.publicKey,
    certificates: [f.owner.profile.certificate], fetcher: f.fetcher, ensureCurrent: async () => {},
    getManagementCapability: async () => undefined, ensureManagementCurrent: async () => {},
    signAuthorization: async payload => signEnvelope(f.owner.profile.privateKeys.devicePrivateKey, payload, f.owner.profile.device.deviceId),
    journal: { read: async () => undefined, prepare: vi.fn(), replace: vi.fn(), complete: vi.fn() },
  })

  await expect(client.enroll({ minimumWriterVersion: 2, allowLegacyUnmanagedScope: true })).resolves.toMatchObject({ policyRevision: 0 })
  expect(f.requestBodies[0]).not.toHaveProperty("managementCapability")
})

it("Given a saved enrollment request with substituted token evidence, When retrying, Then reject before requesting a fresh challenge or mutating policy", async () => {
  const f = await fixture()
  const base = {
    access: { origin, scopeId, servicePublicKey: f.servicePublicKey, readToken, writeToken },
    identity: f.owner.profile.identity, deviceId: f.owner.profile.device.deviceId,
    devicePublicKey: f.owner.profile.device.publicKey, certificates: [f.owner.profile.certificate],
    fetcher: f.fetcher, ensureCurrent: async () => {}, getManagementCapability: async () => undefined,
    ensureManagementCurrent: async () => {},
    signAuthorization: async (payload: RustyScopeEnrollmentAuthorization) =>
      signEnvelope(f.owner.profile.privateKeys.devicePrivateKey, payload, f.owner.profile.device.deviceId),
  }
  const firstJournal = { read: async () => undefined, prepare: vi.fn(), replace: vi.fn(), complete: vi.fn() }
  const first = createRustyScopeEnrollmentClient({ ...base, journal: firstJournal })
  await first.enroll({ minimumWriterVersion: 2, requireExactRetry: true })
  const original = firstJournal.prepare.mock.calls[0]![1] as string
  const parsed = JSON.parse(original) as { authorization: { payload: Record<string, unknown> } }
  parsed.authorization.payload.readTokenHash = "substituted-token-hash"
  const altered = JSON.stringify(parsed)
  f.fetcher.mockClear()
  f.requestBodies.length = 0
  const retry = createRustyScopeEnrollmentClient({ ...base,
    journal: { read: async () => ({ body: altered }), prepare: vi.fn(), replace: vi.fn(), complete: vi.fn() } })

  await expect(retry.enroll({ minimumWriterVersion: 2, requireExactRetry: true })).rejects.toThrow(/binding|signature/i)
  expect(f.fetcher.mock.calls.map(([url]) => String(url))).toEqual([`${origin}/.well-known/mesh-lighthouse`])
  expect(f.requestBodies).toEqual([])
})
