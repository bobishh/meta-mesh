import { spawn, type ChildProcess } from "node:child_process"
import { createServer } from "node:net"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { resolve } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { expect, it } from "vitest"
import { certificateHash, createIdentityAuthorityView, createIdentityEnrollmentDevice, createRecoverableIdentity,
  emptyIdentityProfileState, signEnvelope } from "@meta-uber/mesh-identity"
import { discoverRustyService } from "./rustyDiscovery"
import { publishRustyIdentityAuthorityView } from "./rustyIdentityAuthority"
import { createRustyScopeEnrollmentClient, type RustyScopeEnrollmentJournal } from "./rustyScopeEnrollment"
import { publishRustyScopeAuthoritySnapshot, type ScopeAuthorityValidation } from "./rustyScopeAuthorityClient"

const rustyBinary = process.env.TINCANBAN_RUSTY_BINARY

it.skipIf(!rustyBinary)("Given an active Identity device absent from the immutable legacy controller chain, When the SDK publishes scope authority, Then Rusty accepts the same-root update without rewriting genesis", async () => {
  const profile = (await createRecoverableIdentity("better", "Legacy scope owner")).profile
  const stateDirectory = await mkdtemp(resolve(tmpdir(), "mesh-scope-authority-legacy-"))
  const port = await unusedLoopbackPort()
  const origin = `http://127.0.0.1:${port}`
  let child: ChildProcess | undefined
  let updateResponse: { status: number; body: string } | undefined
  try {
    child = await startRusty(stateDirectory, port)
    const service = await discoverRustyService(origin)
    const oldDevice = await createIdentityEnrollmentDevice("Former workspace controller")
    const currentDevice = await createIdentityEnrollmentDevice("Current Identity device")
    const oldCertificate = await signEnvelope(profile.privateKeys.devicePrivateKey, {
      kind: "device-certificate" as const, version: 1 as const, personId: profile.identity.personId,
      deviceId: oldDevice.device.deviceId, devicePublicKey: oldDevice.device.publicKey,
      issuerCertificateHash: await certificateHash(profile.certificate), canEnrollDevices: false,
    }, profile.device.deviceId, "MATCH/1")
    const currentCertificate = await signEnvelope(profile.privateKeys.devicePrivateKey, {
      kind: "device-certificate" as const, version: 1 as const, personId: profile.identity.personId,
      deviceId: currentDevice.device.deviceId, devicePublicKey: currentDevice.device.publicKey,
      issuerCertificateHash: await certificateHash(profile.certificate), canEnrollDevices: false,
    }, profile.device.deviceId, "MATCH/1")
    const view = await createIdentityAuthorityView(profile.identity,
      { certificates: [profile.certificate, oldCertificate, currentCertificate], revocations: [] },
      emptyIdentityProfileState(profile.identity.personId))
    const signOwner = <T extends { kind: string }>(payload: T) => signEnvelope(
      profile.privateKeys.devicePrivateKey, payload, profile.device.deviceId, "MATCH/1")
    await publishRustyIdentityAuthorityView({ origin, servicePublicKey: service.servicePublicKey,
      identity: profile.identity, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
      view, signAuthorization: signOwner })

    const scopeId = `scope-${crypto.randomUUID()}`
    const workspaceId = `workspace-${crypto.randomUUID()}`
    const readToken = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")
    const writeToken = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")
    const enrollment = createRustyScopeEnrollmentClient({
      scopePurpose: "workspace", access: { origin, scopeId, servicePublicKey: service.servicePublicKey, readToken, writeToken },
      identity: profile.identity, deviceId: profile.device.deviceId, devicePublicKey: profile.device.publicKey,
      certificates: [profile.certificate], ensureCurrent: () => {}, getManagementCapability: async () => undefined,
      ensureManagementCurrent: () => {}, signAuthorization: signOwner, journal: memoryJournal(),
    })
    await enrollment.enroll({ minimumWriterVersion: 2, allowLegacyUnmanagedScope: true })

    const snapshot = {
      genesis: await signEnvelope(oldDevice.privateKey, { kind: "scope-genesis", version: 1, scopeId: workspaceId,
        creator: { personId: profile.identity.personId, publicKey: profile.identity.publicKey,
          certificates: [profile.certificate, oldCertificate] }, controlEpoch: 1 }, oldDevice.device.deviceId, "MATCH/1"),
    }
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await fetch(input, init)
      if (init?.method === "PUT") updateResponse = { status: response.status, body: await response.clone().text() }
      return response
    }
    const validateSnapshot = (value: unknown): ScopeAuthorityValidation => ({
      workspaceId, controllerPersonId: profile.identity.personId, controllerPublicKey: profile.identity.publicKey,
      controlEpoch: 1, snapshot: value,
    })
    const result = await publishRustyScopeAuthoritySnapshot({ origin, servicePublicKey: service.servicePublicKey, scopeId, workspaceId,
      identity: profile.identity, authorityView: view, deviceId: currentDevice.device.deviceId, devicePublicKey: currentDevice.device.publicKey,
      scopeAuthority: snapshot, fetcher, validateSnapshot, mergeSnapshots: (_current, incoming) => incoming,
      signAuthorization: payload => signEnvelope(currentDevice.privateKey, payload, currentDevice.device.deviceId, "MATCH/1")
    })
    expect(updateResponse?.status).toBe(200)
    expect(result.receipt.payload).toMatchObject({ kind: "rusty-scope-authority-receipt", workspaceId,
      controllerPersonId: profile.identity.personId, controlEpoch: 1 })
    expect(result.scopeAuthority.snapshot).toEqual({ ...snapshot,
      grants: [], grantIssuers: [], revocations: [], controlTransfers: [], successionTransfers: [] })
  } finally {
    if (child) await stopRusty(child)
    await rm(stateDirectory, { recursive: true, force: true })
  }
})

function memoryJournal(): RustyScopeEnrollmentJournal {
  let value: string | undefined
  return { read: async () => value ? { body: value } : undefined,
    prepare: async (_binding, body) => { value = body },
    replace: async (_binding, previous, next) => { if (value !== previous) throw new Error("journal changed"); value = next },
    complete: async (_binding, body) => { value = body } }
}

async function startRusty(directory: string, port: number) {
  const origin = `http://127.0.0.1:${port}`
  const child = spawn(resolve(rustyBinary!), [directory, `127.0.0.1:${port}`], { env: { ...process.env,
    RUSTY_PUBLIC_ORIGIN: origin, RUSTY_IDENTITY_AUTHORITY_ENFORCEMENT: "strict", RUSTY_LOG: "off" },
    stdio: ["ignore", "pipe", "pipe"] })
  let error: Error | undefined
  child.once("error", value => { error = value })
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    if (error) throw error
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("Rusty exited during startup")
    try { if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(2_000) })).ok) return child } catch { /* starting */ }
    await delay(50)
  }
  child.kill("SIGINT")
  throw new Error("Rusty startup timed out")
}

async function stopRusty(child: ChildProcess) {
  if (child.exitCode !== null || child.signalCode !== null) return
  child.kill("SIGINT")
  await Promise.race([new Promise<void>(resolveExit => child.once("exit", () => resolveExit())),
    delay(5_000).then(() => { throw new Error("Rusty shutdown timed out") })])
}

async function unusedLoopbackPort() {
  const server = createServer()
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => resolveListen())
  })
  const address = server.address()
  if (!address || typeof address === "string") throw new Error("No available loopback port")
  await new Promise<void>((resolveClose, reject) => server.close(error => error ? reject(error) : resolveClose()))
  return address.port
}
