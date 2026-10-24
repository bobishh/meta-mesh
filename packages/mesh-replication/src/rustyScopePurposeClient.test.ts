import { expect, it, vi } from "vitest"
import { createIdentityAuthorityView, createRecoverableIdentity, createIdentityEnrollmentDevice,
  emptyIdentityProfileState, publicKeyId, signEnvelope } from "@meta-uber/mesh-identity"
import { classifyRustyPersonIdentityScope, RustyScopePurposeError } from "./rustyScopePurposeClient"

it("Given an active app-only device and matching unclassified scope revision, When classifying, Then send a signed one-time owner request and verify the service receipt", async () => {
  const owner = (await createRecoverableIdentity("better", "Owner")).profile
  const app = await createIdentityEnrollmentDevice("App signer")
  const certificate = await signEnvelope(owner.privateKeys.identityPrivateKey!, {
    kind: "device-certificate" as const, version: 1 as const, personId: owner.identity.personId,
    deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
    issuerCertificateHash: null, canEnrollDevices: false,
  }, owner.identity.personId)
  const view = await createIdentityAuthorityView(owner.identity,
    { certificates: [owner.certificate, certificate], revocations: [] },
    emptyIdentityProfileState(owner.identity.personId))
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  let sent: { scopePurpose: string; authorization: { payload: Record<string, unknown> } } | undefined
  const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    sent = JSON.parse(String(init?.body)) as typeof sent
    const payload = sent!.authorization.payload
    return Response.json({ receipt: await signEnvelope(service.privateKeys.identityPrivateKey!, {
      kind: "rusty-scope-purpose-receipt" as const, version: 1 as const,
      serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
      scopeId: "identity-private", scopePurpose: "person-identity" as const,
      personId: owner.identity.personId, policyRevision: 3, requestId: payload.requestId as string,
      requestHash: payload.requestHash as string, committedAt: 20_000,
      enforcement: { mode: "additive" as const, epoch: 0 as const },
    }, service.identity.personId, "RUSTY/2") })
  })
  const ensureCurrent = vi.fn()

  const receipt = await classifyRustyPersonIdentityScope({
    origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
    scopeId: "identity-private", policyRevision: 3, identity: owner.identity, authorityView: view,
    deviceId: app.device.deviceId, devicePublicKey: app.device.publicKey,
    signAuthorization: async payload => signEnvelope(app.privateKey, payload, app.device.deviceId, "MATCH/1"),
    fetcher, ensureCurrent, now: () => 20_000,
  })

  expect(fetcher).toHaveBeenCalledOnce()
  expect(String(fetcher.mock.calls[0]![0])).toBe("https://rusty.example/v2/scopes/identity-private/purpose")
  expect(sent).toMatchObject({ version: 1, scopePurpose: "person-identity" })
  expect(sent!.authorization.payload).toMatchObject({
    kind: "rusty-scope-purpose-update", serviceId: await publicKeyId(service.identity.publicKey),
    scopeId: "identity-private", scopePurpose: "person-identity", personId: owner.identity.personId,
    deviceId: app.device.deviceId, policyRevision: 3, issuedAt: 20_000, expiresAt: 110_000,
  })
  expect(sent!.authorization.payload.requestId).toMatch(/^[A-Za-z0-9_-]{43}$/u)
  expect(receipt.payload.enforcement).toEqual({ mode: "additive", epoch: 0 })
  expect(ensureCurrent).toHaveBeenCalledTimes(3)
  expect(JSON.stringify(sent)).not.toContain(owner.privateKeys.identityPrivateKey)
})

it("Given a signed classification receipt for another scope revision, When classifying, Then fail without accepting it", async () => {
  const owner = (await createRecoverableIdentity("better", "Owner")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const view = await createIdentityAuthorityView(owner.identity,
    { certificates: [owner.certificate], revocations: [] }, emptyIdentityProfileState(owner.identity.personId))
  await expect(classifyRustyPersonIdentityScope({
    origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
    scopeId: "identity-private", policyRevision: 3, identity: owner.identity, authorityView: view,
    deviceId: owner.device.deviceId, devicePublicKey: owner.device.publicKey,
    signAuthorization: async payload => signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId, "MATCH/1"),
    now: () => 20_000,
    fetcher: async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { authorization: { payload: { requestId: string; requestHash: string } } }
      return Response.json({ receipt: await signEnvelope(service.privateKeys.identityPrivateKey!, {
        kind: "rusty-scope-purpose-receipt" as const, version: 1 as const,
        serviceId: await publicKeyId(service.identity.publicKey), origin: "https://rusty.example",
        scopeId: "identity-private", scopePurpose: "person-identity" as const,
        personId: owner.identity.personId, policyRevision: 2, requestId: body.authorization.payload.requestId,
        requestHash: body.authorization.payload.requestHash, committedAt: 20_000,
        enforcement: { mode: "strict" as const, epoch: 1 as const },
      }, service.identity.personId, "RUSTY/2") })
    },
  })).rejects.toThrow(/does not match/i)
})

it.each([
  { status: 400, body: { message: "Scope unavailable" }, reason: "scope-unavailable" },
  { status: 400, body: { message: "Invalid scope classification" }, reason: "http" },
  { status: 403, body: { message: "Scope unavailable" }, reason: "http" },
] as const)("Given HTTP $status with bounded error $body.message, When classifying, Then only exact missing-scope response has a recovery reason", async ({ status, body, reason }) => {
  const owner = (await createRecoverableIdentity("better", "Owner")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const view = await createIdentityAuthorityView(owner.identity,
    { certificates: [owner.certificate], revocations: [] }, emptyIdentityProfileState(owner.identity.personId))
  const error = await classifyRustyPersonIdentityScope({
    origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
    scopeId: "identity-private", policyRevision: 3, identity: owner.identity, authorityView: view,
    deviceId: owner.device.deviceId, devicePublicKey: owner.device.publicKey,
    signAuthorization: async payload => signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId, "MATCH/1"),
    fetcher: async () => Response.json(body, { status }),
  }).catch(value => value)
  expect(error).toBeInstanceOf(RustyScopePurposeError)
  expect(error).toMatchObject({ reason, status, message: `Rusty scope classification failed with HTTP ${status}` })
})

it("Given a non-JSON scope error, When classifying, Then do not label it as a missing scope", async () => {
  const owner = (await createRecoverableIdentity("better", "Owner")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const view = await createIdentityAuthorityView(owner.identity,
    { certificates: [owner.certificate], revocations: [] }, emptyIdentityProfileState(owner.identity.personId))
  const error = await classifyRustyPersonIdentityScope({
    origin: "https://rusty.example", servicePublicKey: service.identity.publicKey,
    scopeId: "identity-private", policyRevision: 3, identity: owner.identity, authorityView: view,
    deviceId: owner.device.deviceId, devicePublicKey: owner.device.publicKey,
    signAuthorization: async payload => signEnvelope(owner.privateKeys.devicePrivateKey, payload, owner.device.deviceId, "MATCH/1"),
    fetcher: async () => new Response("not-json", { status: 400 }),
  }).catch(value => value)
  expect(error).toBeInstanceOf(RustyScopePurposeError)
  expect(error).toMatchObject({ reason: "http", status: 400, message: "Rusty scope classification failed with HTTP 400" })
})
