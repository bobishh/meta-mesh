import { spawn, type ChildProcess } from "node:child_process"
import { createServer } from "node:net"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { resolve } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { expect, it } from "vitest"
import {
  createDeviceAuthorizationApproval,
  createDeviceAuthorizationRequest,
  createIdentityAuthorityView,
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
      personId: identity.identity.personId, includeIdentityCatalogAccess: true,
    })
    const approval = await createDeviceAuthorizationApproval(identity, request, {
      applicationOrigin, challenge: request.payload.challenge, now: () => requestNow + 1_000,
      certificates: [identity.certificate], profileState, revocations: [], includeProfileState: true,
      identityCatalogAccess: [],
    })
    expect(approval.proof.payload.version).toBe(5)
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
  } finally {
    if (child) await stopRusty(child)
    await rm(stateDirectory, { recursive: true, force: true })
  }
})

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
