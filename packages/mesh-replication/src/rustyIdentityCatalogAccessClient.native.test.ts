import { spawn, type ChildProcess } from "node:child_process"
import { createServer } from "node:net"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { resolve } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { expect, it, vi } from "vitest"
import {
  certificateHash,
  createDelegatedCertificate,
  createDeviceAuthorizationApproval,
  createDeviceAuthorizationRequest,
  createIdentityAuthorityView,
  createIdentityEnrollmentDevice,
  createRecoverableIdentity,
  createIdentityProfileOperation,
  createIdentityRustyServicePinOperation,
  emptyIdentityProfileState,
  openApprovedIdentityCatalogAccess,
  publicKeyId,
  readIdentityProfileState,
  signEnvelope,
  verifyIdentityAuthorityView,
  type IdentityProfileState,
  type LocalProfile,
} from "@meta-uber/mesh-identity"
import { discoverRustyService } from "./rustyDiscovery"
import { publishRustyIdentityAuthorityView } from "./rustyIdentityAuthority"
import {
  publishRustyIdentityCatalogAccess,
  requestRustyIdentityCatalogAccess,
  type IdentityCatalogAccessPublicationJournal,
  type IdentityCatalogAccessPublicationJournalEntry,
} from "./rustyIdentityCatalogAccessClient"

const rustyBinary = process.env.TINCANBAN_RUSTY_BINARY

it.skipIf(!rustyBinary)("Given an active Identity manager and same-person app device, when SDK publishes and requests opaque catalog access, then real Rusty verifies both directions", async () => {
  const identity = (await createRecoverableIdentity("better", "Catalog owner")).profile
  const appKey = (await createRecoverableIdentity("better", "Board app key")).profile
  const stateDirectory = await mkdtemp(resolve(tmpdir(), "mesh-identity-catalog-access-"))
  const port = await unusedLoopbackPort()
  const origin = `http://127.0.0.1:${port}`
  const applicationOrigin = "https://boards.example"
  const catalogId = "private-identity-catalog"
  const opaqueAccess = new TextEncoder().encode(JSON.stringify({ scopeId: "opaque-scope", readToken: "opaque-read-token" }))
  let child: ChildProcess | undefined
  try {
    child = await startRusty(stateDirectory, port)
    const service = await discoverRustyService(origin)
    const servicePin = { origin, serviceId: service.serviceId, servicePublicKey: service.servicePublicKey }
    let profileState = emptyIdentityProfileState(identity.identity.personId)
    const pinOperation = await createIdentityRustyServicePinOperation(identity, profileState, servicePin, [identity.certificate])
    profileState = await readIdentityProfileState({ ...profileState, operations: [pinOperation] }, identity.identity,
      [identity.certificate])
    const requestNow = Date.now()
    const request = await createDeviceAuthorizationRequest(appKey, {
      applicationOrigin, challenge: "a".repeat(64), expiresAt: requestNow + 90_000,
      personId: null, includeIdentityCatalogAccess: true,
    })
    const approval = await createDeviceAuthorizationApproval(identity, request, {
      applicationOrigin, challenge: request.payload.challenge, now: () => requestNow + 1_000,
      certificates: [identity.certificate], profileState, revocations: [], includeProfileState: true,
      identityCatalogAccess: [],
    })
    expect(approval.proof.payload.version).toBe(5)
    expect(request.payload.personId).toBeNull()
    expect(approval.identity.personId).toBe(identity.identity.personId)
    const publisher: LocalProfile = {
      ...appKey,
      identity: identity.identity,
      certificate: approval.certificate,
    }
    const authorityView = await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate, approval.certificate], revocations: [] }, profileState)
    const checkedView = await verifyIdentityAuthorityView(authorityView)
    const signOwner = <T extends { kind: string }>(payload: T) => signEnvelope(
      identity.privateKeys.devicePrivateKey, payload, identity.device.deviceId, "MATCH/1")
    await publishRustyIdentityAuthorityView({
      origin, servicePublicKey: service.servicePublicKey, identity: identity.identity,
      deviceId: identity.device.deviceId, devicePublicKey: identity.device.publicKey,
      view: checkedView, signAuthorization: signOwner,
    })

    const { journal, entries: journalEntries } = createMemoryJournal()
    const failures: string[] = []
    const transmitted: unknown[] = []
    let dropFirstPublicationReceipt = true
    const captureServerError: typeof fetch = async (input, init) => {
      const requestBody = typeof init?.body === "string" ? init.body : undefined
      const url = new URL(String(input))
      const response = await fetch(input, init)
      if (!response.ok) failures.push(`${response.status}: ${await response.clone().text()}`)
      if (url.pathname === "/v2/identity/catalog-access" && init?.method === "PUT" && requestBody) {
        transmitted.push(JSON.parse(requestBody) as unknown)
        if (dropFirstPublicationReceipt && response.ok) {
          dropFirstPublicationReceipt = false
          await response.arrayBuffer()
          throw new Error("simulated lost publication receipt")
        }
      }
      return response
    }
    await expect(publishRustyIdentityCatalogAccess({
      origin, servicePublicKey: service.servicePublicKey, publisher, currentAuthorityView: checkedView,
      retainedAuthorization: approval, applicationOrigin, catalogId, access: opaqueAccess, journal,
      fetcher: captureServerError,
    })).rejects.toThrow(/simulated lost publication receipt/)
    expect([...journalEntries.values()][0]?.state).toBe("pending")
    let published
    try {
      published = await publishRustyIdentityCatalogAccess({
        origin, servicePublicKey: service.servicePublicKey, publisher, currentAuthorityView: checkedView,
        retainedAuthorization: approval, applicationOrigin, catalogId, access: opaqueAccess, journal,
        fetcher: captureServerError,
      })
    } catch (error) {
      throw new Error(`${String(error)}; Rusty response: ${failures.join(" | ")}`)
    }
    expect(published).toHaveLength(1)
    expect(transmitted).toHaveLength(2)
    expect(transmitted[1]).toEqual(transmitted[0])
    expect([...journalEntries.values()][0]?.state).toBe("published")
    const retry = await publishRustyIdentityCatalogAccess({
      origin, servicePublicKey: service.servicePublicKey, publisher, currentAuthorityView: checkedView,
      retainedAuthorization: approval, applicationOrigin, catalogId, access: opaqueAccess, journal,
      fetcher: captureServerError,
    })
    expect(retry[0]).toEqual(published[0])
    expect(transmitted).toHaveLength(2)

    const grants = await requestRustyIdentityCatalogAccess({
      manager: identity, currentAuthorityView: checkedView, profileState, applicationOrigin,
    })
    expect(grants).toHaveLength(1)

    const enrollManager = async (label: string) => {
      const enrollment = await createIdentityEnrollmentDevice(label)
      const certificate = await createDelegatedCertificate(identity.privateKeys.devicePrivateKey,
        identity.device.deviceId, identity.identity.personId, enrollment.device.deviceId,
        enrollment.device.publicKey, await certificateHash(identity.certificate))
      const manager: LocalProfile = { identity: identity.identity, device: enrollment.device, certificate,
        privateKeys: { devicePrivateKey: enrollment.privateKey } }
      return { manager, certificate }
    }
    const { manager: newManager, certificate: newManagerCertificate } = await enrollManager("New manager B")
    const authorityWithNewManager = await verifyIdentityAuthorityView(await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate, approval.certificate, newManagerCertificate], revocations: [] }, profileState))
    await publishRustyIdentityAuthorityView({
      origin, servicePublicKey: service.servicePublicKey, identity: identity.identity,
      deviceId: identity.device.deviceId, devicePublicKey: identity.device.publicKey,
      view: authorityWithNewManager, signAuthorization: signOwner,
    })
    const refreshedApproval = await createDeviceAuthorizationApproval(identity, request, {
      applicationOrigin, challenge: request.payload.challenge,
      certificates: [identity.certificate, approval.certificate, newManagerCertificate], profileState,
      revocations: [], includeProfileState: true, identityCatalogAccess: [],
    })
    const retriedBodies: string[] = []
    let republishedForNewManager = false
    const publishOnPending: typeof fetch = async (input, init) => {
      const response = await fetch(input, init)
      if (new URL(String(input)).pathname === "/v2/identity/catalog-access/request" && init?.method === "POST") {
        retriedBodies.push(String(init.body))
        if (!republishedForNewManager && response.status === 503) {
          republishedForNewManager = true
          await publishRustyIdentityCatalogAccess({
            origin, servicePublicKey: service.servicePublicKey, publisher, currentAuthorityView: authorityWithNewManager,
            retainedAuthorization: refreshedApproval, applicationOrigin, catalogId, access: opaqueAccess, journal,
          })
        }
      }
      return response
    }
    const grantsForNewManager = await requestRustyIdentityCatalogAccess({ manager: newManager,
      currentAuthorityView: authorityWithNewManager, profileState, applicationOrigin, fetcher: publishOnPending })
    expect(grantsForNewManager).toHaveLength(1)
    expect(retriedBodies).toHaveLength(2)
    expect(retriedBodies[1]).toBe(retriedBodies[0])
    const newManagerApproval = await createDeviceAuthorizationApproval(newManager, request, {
      applicationOrigin, challenge: request.payload.challenge,
      certificates: [identity.certificate, approval.certificate, newManagerCertificate], profileState,
      revocations: [], includeProfileState: true, identityCatalogAccess: grantsForNewManager,
    })
    await expect(openApprovedIdentityCatalogAccess(newManagerApproval, request, publisher)).resolves.toEqual({ status: "ready", entries: [
      { serviceId: service.serviceId, catalogId, sourceRevision: 1, access: opaqueAccess },
    ] })

    const foreignOriginRequests: string[] = []
    const captureForeignOrigin: typeof fetch = async (input, init) => {
      const response = await fetch(input, init)
      if (new URL(String(input)).pathname === "/v2/identity/catalog-access/request" && init?.method === "POST") {
        foreignOriginRequests.push(String(init.body))
      }
      return response
    }
    const foreignOriginGrants = await requestRustyIdentityCatalogAccess({ manager: newManager,
      currentAuthorityView: authorityWithNewManager, profileState, applicationOrigin: "https://another-app.example",
      fetcher: captureForeignOrigin })
    expect(foreignOriginGrants).toEqual([])
    expect(foreignOriginRequests).toHaveLength(1)

    const { manager: offlineManager, certificate: offlineManagerCertificate } = await enrollManager("Offline source manager")
    const authorityWithOfflineManager = await verifyIdentityAuthorityView(await createIdentityAuthorityView(identity.identity,
      { certificates: [identity.certificate, approval.certificate, newManagerCertificate, offlineManagerCertificate], revocations: [] }, profileState))
    await publishRustyIdentityAuthorityView({
      origin, servicePublicKey: service.servicePublicKey, identity: identity.identity,
      deviceId: identity.device.deviceId, devicePublicKey: identity.device.publicKey,
      view: authorityWithOfflineManager, signAuthorization: signOwner,
    })
    const offlineBodies: string[] = []
    const offlineFetcher: typeof fetch = async (input, init) => {
      const response = await fetch(input, init)
      if (new URL(String(input)).pathname === "/v2/identity/catalog-access/request" && init?.method === "POST") {
        offlineBodies.push(String(init.body))
      }
      return response
    }
    await expect(requestRustyIdentityCatalogAccess({ manager: offlineManager,
      currentAuthorityView: authorityWithOfflineManager, profileState, applicationOrigin, fetcher: offlineFetcher,
    })).rejects.toThrow(/remained pending after bounded retries/i)
    expect(offlineBodies).toHaveLength(8)
    expect(new Set(offlineBodies).size).toBe(1)

    let genericFailureRequests = 0
    const generic503Fetcher: typeof fetch = async (input, init) => {
      if (new URL(String(input)).pathname === "/v2/identity/catalog-access/request" && init?.method === "POST") {
        genericFailureRequests += 1
        return Response.json({ code: "service_unavailable" }, { status: 503 })
      }
      return fetch(input, init)
    }
    await expect(requestRustyIdentityCatalogAccess({ manager: offlineManager,
      currentAuthorityView: authorityWithOfflineManager, profileState, applicationOrigin, fetcher: generic503Fetcher,
    })).rejects.toThrow(/failed with HTTP 503/i)
    expect(genericFailureRequests).toBe(1)

    const guardedRequests: string[] = []
    let currentChecks = 0
    const guardedFetcher: typeof fetch = async (input, init) => {
      const response = await fetch(input, init)
      if (new URL(String(input)).pathname === "/v2/identity/catalog-access/request" && init?.method === "POST") {
        guardedRequests.push(String(init.body))
      }
      return response
    }
    await expect(requestRustyIdentityCatalogAccess({ manager: offlineManager,
      currentAuthorityView: authorityWithOfflineManager, profileState, applicationOrigin, fetcher: guardedFetcher,
      ensureCurrent: () => { currentChecks += 1; if (currentChecks >= 3) throw new Error("Identity changed") },
    })).rejects.toThrow("Identity changed")
    expect(guardedRequests).toHaveLength(1)

    let clockReads = 0
    const expiryRequests: string[] = []
    const expiryFetcher: typeof fetch = async (input, init) => {
      const response = await fetch(input, init)
      if (new URL(String(input)).pathname === "/v2/identity/catalog-access/request" && init?.method === "POST") {
        expiryRequests.push(String(init.body))
      }
      return response
    }
    const clock = Date.now()
    await expect(requestRustyIdentityCatalogAccess({ manager: offlineManager,
      currentAuthorityView: authorityWithOfflineManager, profileState, applicationOrigin, fetcher: expiryFetcher,
      now: () => ++clockReads < 3 ? clock : clock + 120_001,
    })).rejects.toThrow(/expired while waiting/i)
    expect(expiryRequests).toHaveLength(1)
    const managerRequest = await createDeviceAuthorizationRequest(appKey, {
      applicationOrigin, challenge: "b".repeat(64), expiresAt: Date.now() + 90_000,
      personId: identity.identity.personId, includeIdentityCatalogAccess: true,
    })
    const managerApproval = await createDeviceAuthorizationApproval(identity, managerRequest, {
      applicationOrigin, challenge: managerRequest.payload.challenge,
      certificates: [identity.certificate, approval.certificate], profileState, revocations: [],
      includeProfileState: true, identityCatalogAccess: grants,
    })
    const opened = await openApprovedIdentityCatalogAccess(managerApproval, managerRequest, publisher)
    expect(opened).toEqual({ status: "ready", entries: [
      { serviceId: service.serviceId, catalogId, sourceRevision: 1, access: opaqueAccess },
    ] })

    const managerPublisherRequest = await createDeviceAuthorizationRequest(identity, {
      applicationOrigin, challenge: "c".repeat(64), expiresAt: Date.now() + 90_000,
      personId: null, includeIdentityCatalogAccess: true,
    })
    const managerPublisherApproval = await createDeviceAuthorizationApproval(identity, managerPublisherRequest, {
      applicationOrigin, challenge: managerPublisherRequest.payload.challenge,
      certificates: [identity.certificate, approval.certificate], profileState, revocations: [],
      includeProfileState: true, identityCatalogAccess: [],
    })
    const managerPublication = await publishRustyIdentityCatalogAccess({
      origin, servicePublicKey: service.servicePublicKey, publisher: identity, currentAuthorityView: checkedView,
      retainedAuthorization: managerPublisherApproval, applicationOrigin, catalogId: "manager-device-catalog",
      access: opaqueAccess, journal, fetcher: captureServerError,
    })
    expect(managerPublication).toHaveLength(1)
    const managerEnvelope = transmitted.at(-1) as { payload: { publisherAuthorization: {
      request: { payload: { personId: string | null } }; certificate: { payload: { canEnrollDevices: boolean } } } } }
    expect(managerEnvelope.payload.publisherAuthorization.request.payload.personId).toBeNull()
    expect(managerEnvelope.payload.publisherAuthorization.certificate.payload.canEnrollDevices).toBe(true)
    const nativeFetch = globalThis.fetch
    vi.stubGlobal("fetch", function (this: unknown, input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) {
      if (this !== globalThis) throw new TypeError("Illegal invocation: browser fetch lost its receiver")
      return nativeFetch(input, init)
    })
    try {
      const browserPublication = await publishRustyIdentityCatalogAccess({
        origin, servicePublicKey: service.servicePublicKey, publisher: identity, currentAuthorityView: checkedView,
        retainedAuthorization: managerPublisherApproval, applicationOrigin, catalogId: "browser-bound-catalog",
        access: opaqueAccess, journal,
      })
      expect(browserPublication).toHaveLength(1)
      const browserGrants = await requestRustyIdentityCatalogAccess({
        manager: identity, currentAuthorityView: checkedView, profileState, applicationOrigin,
      })
      expect(browserGrants).toHaveLength(3)
    } finally { vi.unstubAllGlobals() }
    expect(failures).toEqual([])
  } finally {
    if (child) await stopRusty(child)
    await rm(stateDirectory, { recursive: true, force: true })
  }
}, 45_000)

function createMemoryJournal(): {
  journal: IdentityCatalogAccessPublicationJournal
  entries: Map<string, IdentityCatalogAccessPublicationJournalEntry>
} {
  const entries = new Map<string, IdentityCatalogAccessPublicationJournalEntry>()
  return {
    entries,
    journal: {
      read: async key => structuredClone(entries.get(key) ?? null),
      compareAndSet: async (key, expectedVersion, next) => {
        const current = entries.get(key)
        if ((current?.version ?? null) !== expectedVersion) return false
        entries.set(key, structuredClone(next))
        return true
      },
    },
  }
}

async function startRusty(stateDirectory: string, port: number): Promise<ChildProcess> {
  const origin = `http://127.0.0.1:${port}`
  const child = spawn(resolve(rustyBinary!), [stateDirectory, `127.0.0.1:${port}`], {
    env: { ...process.env, RUSTY_PUBLIC_ORIGIN: origin,
      RUSTY_IDENTITY_AUTHORITY_ENFORCEMENT: "strict", RUSTY_LOG: "off" },
    stdio: ["ignore", "pipe", "pipe"],
  })
  let output = ""
  child.stdout?.on("data", (chunk: Buffer) => { output = `${output}${chunk}`.slice(-8_000) })
  child.stderr?.on("data", (chunk: Buffer) => { output = `${output}${chunk}`.slice(-8_000) })
  let spawnError: Error | undefined
  child.once("error", error => { spawnError = error })
  const deadline = Date.now() + 30_000
  try {
    while (Date.now() < deadline) {
      if (spawnError) throw new Error(`Unable to spawn Rusty: ${spawnError.message}`)
      if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Rusty exited during startup: ${output}`)
      try {
        if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(2_000) })).ok) return child
      } catch { /* Rusty may still be starting. */ }
      await delay(40)
    }
    throw new Error(`Rusty did not become ready: ${output}`)
  } catch (error) {
    await stopRusty(child)
    throw error
  }
}

async function stopRusty(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return
  child.kill("SIGINT")
  await Promise.race([
    new Promise<void>(resolveExit => child.once("exit", () => resolveExit())),
    delay(5_000).then(() => { throw new Error("Rusty did not stop") }),
  ])
}

async function unusedLoopbackPort(): Promise<number> {
  const listener = createServer()
  await new Promise<void>((resolveListen, reject) => {
    listener.once("error", reject)
    listener.listen(0, "127.0.0.1", () => resolveListen())
  })
  const address = listener.address()
  if (!address || typeof address === "string") throw new Error("Loopback listener did not expose a port")
  await new Promise<void>((resolveClose, reject) => listener.close(error => error ? reject(error) : resolveClose()))
  return address.port
}
