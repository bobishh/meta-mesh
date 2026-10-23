import { expect, it, vi } from "vitest"
import { canonicalizeJson, createIdentityAuthorityView, createIdentityRootSuccession, createRecoverableIdentity,
  publicKeyId, sha256Base64Url, signEnvelope } from "@meta-uber/mesh-identity"
import { publishRustyIdentityRootSuccession, readRustyIdentityRootSuccessionStatus } from "./rustyIdentitySuccessionClient"

const now = 80_000
const origin = "https://rusty.example"

async function setup() {
  const previous = (await createRecoverableIdentity("better", "Previous")).profile
  const successor = (await createRecoverableIdentity("better", "Successor")).profile
  const service = (await createRecoverableIdentity("better", "Rusty service")).profile
  const previousView = await createIdentityAuthorityView(previous.identity,
    { certificates: [previous.certificate], revocations: [] }, { version: 1, personId: previous.identity.personId, operations: [], legacy: [] })
  const successorView = await createIdentityAuthorityView(successor.identity,
    { certificates: [successor.certificate], revocations: [] }, { version: 1, personId: successor.identity.personId, operations: [], legacy: [] })
  const succession = await createIdentityRootSuccession(previous, successor, previousView)
  const serviceId = await publicKeyId(service.identity.publicKey)
  return { previous, successor, service, previousView, successorView, succession, serviceId }
}

it("Given a root-succession request, When Rusty returns a durable retired receipt, Then verify both roots, active actor, request binding and receipt", async () => {
  const f = await setup()
  let requestUrl = ""
  let request: any
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    requestUrl = String(input)
    request = JSON.parse(String(init?.body))
    const payload = request.actorAuthorization.payload
    return Response.json({ receipt: await signEnvelope(f.service.privateKeys.identityPrivateKey!, {
      kind: "rusty-identity-root-succession-receipt" as const, version: 1 as const,
      serviceId: f.serviceId, origin, previousPersonId: f.previous.identity.personId,
      successorPersonId: f.successor.identity.personId, transitionHash: payload.transitionHash,
      actorDeviceId: f.successor.device.deviceId, requestId: payload.requestId,
      requestHash: payload.requestHash, committedAt: now, retired: true,
      transferred: [{ kind: "scope", resourceId: "scope-1", evidenceHash: "a".repeat(43), epoch: 2 }],
      enforcement: { mode: "strict" as const, epoch: 1 as const },
    }, f.service.identity.personId, "RUSTY/2") })
  })

  const result = await publishRustyIdentityRootSuccession({
    origin, servicePublicKey: f.service.identity.publicKey, succession: f.succession,
    previousAuthorityView: f.previousView, successorIdentity: f.successor.identity,
    successorAuthorityView: f.successorView, actorDeviceId: f.successor.device.deviceId,
    actorDevicePublicKey: f.successor.device.publicKey, fetcher,
    signAuthorization: payload => signEnvelope(f.successor.privateKeys.devicePrivateKey, payload,
      f.successor.device.deviceId, "MATCH/1"), now: () => now,
  })

  expect(new URL(requestUrl).pathname).toBe("/v2/identity/succession")
  expect(request).toMatchObject({ version: 1, succession: f.succession, actorDeviceId: f.successor.device.deviceId })
  expect(request.actorAuthorization.payload).toMatchObject({
    kind: "rusty-identity-root-succession-request", serviceId: f.serviceId, origin,
    previousPersonId: f.previous.identity.personId, successorPersonId: f.successor.identity.personId,
    actorDeviceId: f.successor.device.deviceId, issuedAt: now, expiresAt: now + 90_000,
  })
  expect(result.payload.retired).toBe(true)
  expect(result.payload.requestHash).toBe(request.actorAuthorization.payload.requestHash)
})

it("Given an authenticated but pending retirement response, When publishing, Then expose pending state without reporting success", async () => {
  const f = await setup()
  const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body))
    const payload = body.actorAuthorization.payload
    return Response.json({ receipt: await signEnvelope(f.service.privateKeys.identityPrivateKey!, {
      kind: "rusty-identity-root-succession-receipt" as const, version: 1 as const,
      serviceId: f.serviceId, origin, previousPersonId: f.previous.identity.personId,
      successorPersonId: f.successor.identity.personId, transitionHash: payload.transitionHash,
      actorDeviceId: payload.actorDeviceId, requestId: payload.requestId, requestHash: payload.requestHash,
      committedAt: now, retired: false, transferred: [], enforcement: { mode: "additive" as const, epoch: 0 as const },
    }, f.service.identity.personId, "RUSTY/2") })
  })

  await expect(publishRustyIdentityRootSuccession({
    origin, servicePublicKey: f.service.identity.publicKey, succession: f.succession,
    previousAuthorityView: f.previousView, successorIdentity: f.successor.identity,
    successorAuthorityView: f.successorView, actorDeviceId: f.successor.device.deviceId,
    actorDevicePublicKey: f.successor.device.publicKey, fetcher,
    signAuthorization: payload => signEnvelope(f.successor.privateKeys.devicePrivateKey, payload,
      f.successor.device.deviceId, "MATCH/1"), now: () => now,
  })).rejects.toMatchObject({ name: "RustyIdentityRootSuccessionPendingError" })
})

it("Given a retired receipt from an additive service, When publishing, Then do not claim global revocation completion", async () => {
  const f = await setup()
  const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body))
    const payload = request.actorAuthorization.payload
    return Response.json({ receipt: await signEnvelope(f.service.privateKeys.identityPrivateKey!, {
      kind: "rusty-identity-root-succession-receipt" as const, version: 1 as const,
      serviceId: f.serviceId, origin, previousPersonId: f.previous.identity.personId,
      successorPersonId: f.successor.identity.personId, transitionHash: payload.transitionHash,
      actorDeviceId: payload.actorDeviceId, requestId: payload.requestId, requestHash: payload.requestHash,
      committedAt: now, retired: true, transferred: [], enforcement: { mode: "additive" as const, epoch: 0 as const },
    }, f.service.identity.personId, "RUSTY/2") })
  })

  await expect(publishRustyIdentityRootSuccession({
    origin, servicePublicKey: f.service.identity.publicKey, succession: f.succession,
    previousAuthorityView: f.previousView, successorIdentity: f.successor.identity,
    successorAuthorityView: f.successorView, actorDeviceId: f.successor.device.deviceId,
    actorDevicePublicKey: f.successor.device.publicKey, fetcher,
    signAuthorization: payload => signEnvelope(f.successor.privateKeys.devicePrivateKey, payload,
      f.successor.device.deviceId, "MATCH/1"), now: () => now,
  })).rejects.toMatchObject({ name: "RustyIdentityRootSuccessionPendingError" })
})

it("Given a request-bound signed status, When reading it, Then distinguish pending from durable retirement", async () => {
  const f = await setup()
  let requestUrl = ""
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    requestUrl = String(input)
    const url = new URL(requestUrl)
    const requestId = url.searchParams.get("requestId")!
    const requestHash = url.searchParams.get("requestHash")!
    const transitionHash = url.pathname.split("/").at(-1)!
    return Response.json({ status: await signEnvelope(f.service.privateKeys.identityPrivateKey!, {
      kind: "rusty-identity-root-succession-status" as const, version: 1 as const,
      serviceId: f.serviceId, origin, previousPersonId: f.previous.identity.personId,
      transitionHash, state: "pending" as const, requestId, requestHash, issuedAt: now,
      successorPersonId: f.successor.identity.personId, actorDeviceId: f.successor.device.deviceId,
      retired: false, enforcement: { mode: "additive" as const, epoch: 0 as const },
      transferred: [], receipt: null,
    }, f.service.identity.personId, "RUSTY/2") })
  })
  const transitionHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(f.succession)))

  const result = await readRustyIdentityRootSuccessionStatus({ origin, servicePublicKey: f.service.identity.publicKey,
    previousPersonId: f.previous.identity.personId, transitionHash, fetcher, now: () => now })

  expect(new URL(requestUrl).pathname).toBe(`/v2/identity/succession/${f.previous.identity.personId}/${transitionHash}`)
  expect(result.status.payload.state).toBe("pending")
  expect(result.complete).toBe(false)
})

it("Given a ready status, When its embedded receipt is valid and retired, Then report completion", async () => {
  const f = await setup()
  const transitionHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(f.succession)))
  const transferred = [{ kind: "scope", resourceId: "scope-1", evidenceHash: "e".repeat(43), epoch: 3 }]
  const receipt = await signEnvelope(f.service.privateKeys.identityPrivateKey!, {
    kind: "rusty-identity-root-succession-receipt" as const, version: 1 as const,
    serviceId: f.serviceId, origin, previousPersonId: f.previous.identity.personId,
    successorPersonId: f.successor.identity.personId, transitionHash,
    actorDeviceId: f.successor.device.deviceId, requestId: "f".repeat(43), requestHash: "g".repeat(43),
    committedAt: now, retired: true, transferred, enforcement: { mode: "strict" as const, epoch: 1 as const },
  }, f.service.identity.personId, "RUSTY/2")
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input))
    const requestId = url.searchParams.get("requestId")!
    const requestHash = url.searchParams.get("requestHash")!
    return Response.json({ status: await signEnvelope(f.service.privateKeys.identityPrivateKey!, {
      kind: "rusty-identity-root-succession-status" as const, version: 1 as const,
      serviceId: f.serviceId, origin, previousPersonId: f.previous.identity.personId, transitionHash,
      state: "ready" as const, requestId, requestHash, issuedAt: now,
      successorPersonId: f.successor.identity.personId, actorDeviceId: f.successor.device.deviceId,
      retired: true, enforcement: { mode: "strict" as const, epoch: 1 as const }, transferred, receipt,
    }, f.service.identity.personId, "RUSTY/2") })
  })

  const result = await readRustyIdentityRootSuccessionStatus({ origin, servicePublicKey: f.service.identity.publicKey,
    previousPersonId: f.previous.identity.personId, transitionHash, fetcher, now: () => now })

  expect(result.complete).toBe(true)
  expect(result.receipt).toEqual(receipt)
})
