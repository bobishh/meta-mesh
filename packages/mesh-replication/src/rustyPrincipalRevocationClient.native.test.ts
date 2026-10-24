import { spawn, type ChildProcess } from "node:child_process"
import { createServer } from "node:net"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { resolve } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { expect, it } from "vitest"
import {
  createIdentityAuthorityView,
  createRecoverableIdentity,
  emptyIdentityProfileState,
  publicKeyId,
  sha256Base64Url,
  signEnvelope,
} from "@meta-uber/mesh-identity"
import { discoverRustyService } from "./rustyDiscovery"
import { publishRustyIdentityAuthorityView } from "./rustyIdentityAuthority"
import { createRustyScopeEnrollmentClient, type RustyScopeEnrollmentJournal } from "./rustyScopeEnrollment"
import { publishRustyScopeAuthoritySnapshot, type ScopeAuthorityValidation } from "./rustyScopeAuthorityClient"
import { createRustyIdentityRequestProof } from "./rustyIdentityRequestProof"
import { revokeRustyResourcePrincipal } from "./rustyPrincipalRevocationClient"

const rustyBinary = process.env.TINCANBAN_RUSTY_BINARY

it.skipIf(!rustyBinary)("Given strict Rusty and an accepted scope controller, When the SDK revokes a principal, Then Rusty returns the same durable receipt after restart", async () => {
  const profile = (await createRecoverableIdentity("better", "Revocation contract owner")).profile
  const editor = (await createRecoverableIdentity("better", "Revocation contract editor")).profile
  const stateDirectory = await mkdtemp(resolve(tmpdir(), "mesh-principal-revocation-"))
  const port = await unusedLoopbackPort()
  const origin = `http://127.0.0.1:${port}`
  const opaqueScopeId = `scope-${crypto.randomUUID()}`
  const readToken = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")
  const writeToken = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")
  let child: ChildProcess | undefined
  try {
    child = await startRusty(profile, stateDirectory, port)
    const discovery = await discoverRustyService(origin)
    const authorityView = await createIdentityAuthorityView(
      profile.identity,
      { certificates: [profile.certificate], revocations: [] },
      emptyIdentityProfileState(profile.identity.personId),
    )
    const signOwner = <T extends { kind: string }>(payload: T) => signEnvelope(
      profile.privateKeys.devicePrivateKey,
      payload,
      profile.device.deviceId,
      "MATCH/1",
    )
    await publishRustyIdentityAuthorityView({
      origin,
      servicePublicKey: discovery.servicePublicKey,
      identity: profile.identity,
      deviceId: profile.device.deviceId,
      devicePublicKey: profile.device.publicKey,
      view: authorityView,
      signAuthorization: signOwner,
    })

    const access = { origin, scopeId: opaqueScopeId, servicePublicKey: discovery.servicePublicKey, readToken, writeToken }
    const journal = createMemoryEnrollmentJournal()
    const enrollment = createRustyScopeEnrollmentClient({
      scopePurpose: "workspace",
      access,
      identity: profile.identity,
      deviceId: profile.device.deviceId,
      devicePublicKey: profile.device.publicKey,
      certificates: [profile.certificate],
      ensureCurrent: () => {},
      getManagementCapability: async () => undefined,
      ensureManagementCurrent: () => {},
      signAuthorization: signOwner,
      journal,
    })
    await enrollment.enroll({ minimumWriterVersion: 2, allowLegacyUnmanagedScope: true })

    const scopeAuthority = {
      genesis: await signEnvelope(profile.privateKeys.devicePrivateKey, {
        kind: "scope-genesis",
        version: 1,
        scopeId: opaqueScopeId,
        creator: { personId: profile.identity.personId, publicKey: profile.identity.publicKey,
          certificates: [profile.certificate] },
        controlEpoch: 1,
      }, profile.device.deviceId, "MATCH/1"),
      grants: [], grantIssuers: [], revocations: [], controlTransfers: [], successionTransfers: [],
    }
    const validateSnapshot = (snapshot: unknown): ScopeAuthorityValidation => ({
      workspaceId: opaqueScopeId,
      controllerPersonId: profile.identity.personId,
      controllerPublicKey: profile.identity.publicKey,
      controlEpoch: 1,
      snapshot,
    })
    await publishRustyScopeAuthoritySnapshot({
      origin,
      servicePublicKey: discovery.servicePublicKey,
      scopeId: opaqueScopeId,
      workspaceId: opaqueScopeId,
      identity: profile.identity,
      authorityView,
      deviceId: profile.device.deviceId,
      devicePublicKey: profile.device.publicKey,
      scopeAuthority,
      validateSnapshot,
      mergeSnapshots: (_current, incoming) => incoming,
      signAuthorization: signOwner,
    })

    const editorAuthorityView = await createIdentityAuthorityView(
      editor.identity,
      { certificates: [editor.certificate], revocations: [] },
      emptyIdentityProfileState(editor.identity.personId),
    )
    const signEditor = <T extends { kind: string }>(payload: T) => signEnvelope(
      editor.privateKeys.devicePrivateKey,
      payload,
      editor.device.deviceId,
      "MATCH/1",
    )
    await publishRustyIdentityAuthorityView({
      origin,
      servicePublicKey: discovery.servicePublicKey,
      identity: editor.identity,
      deviceId: editor.device.deviceId,
      devicePublicKey: editor.device.publicKey,
      view: editorAuthorityView,
      signAuthorization: signEditor,
    })

    const grantId = "editor-grant-revoked"
    const workspaceGrant = await signOwner({ kind: "workspace-grant", version: 1, grantId,
      workspaceId: opaqueScopeId, personId: editor.identity.personId, role: "editor", accessEpoch: 3 })
    const principalGrant = await signOwner({
      kind: "rusty-resource-principal-grant",
      version: 1,
      serviceId: await publicKeyId(discovery.servicePublicKey),
      origin,
      workspaceId: opaqueScopeId,
      resourceKind: "scope",
      resourceId: opaqueScopeId,
      scopeId: opaqueScopeId,
      ownerPersonId: profile.identity.personId,
      subjectPersonId: editor.identity.personId,
      subjectPublicKey: editor.identity.publicKey,
      grantId,
      policyEpoch: 3,
      readTokenHash: await sha256Base64Url(new TextEncoder().encode(readToken)),
      writeTokenHash: await sha256Base64Url(new TextEncoder().encode(writeToken)),
      actions: ["read", "write"],
      workspaceGrant,
      scopeAuthority,
    })
    const registerResponse = await fetch(`${origin}/v2/scopes/${encodeURIComponent(opaqueScopeId)}/principals/${grantId}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ version: 1, grant: principalGrant }),
    })
    expect(registerResponse.status).toBe(204)
    const readProof = await createEditorReadProof(origin, discovery.servicePublicKey, opaqueScopeId, readToken,
      editor, editorAuthorityView, grantId, 3)
    const readUrl = `${origin}/v2/scopes/${encodeURIComponent(opaqueScopeId)}/objects`
    const readBeforeRevoke = await fetch(readUrl, { method: "GET", headers: readProof.headers, cache: "no-store" })
    expect(readBeforeRevoke.status).toBe(200)

    const revoke = () => revokeRustyResourcePrincipal({
      origin,
      servicePublicKey: discovery.servicePublicKey,
      storageScopeId: opaqueScopeId,
      workspaceId: opaqueScopeId,
      grantId,
      subjectPersonId: editor.identity.personId,
      policyEpoch: 3,
      identity: profile.identity,
      authorityView,
      deviceId: profile.device.deviceId,
      devicePublicKey: profile.device.publicKey,
      validateSnapshot,
      signAuthorization: signOwner,
    })
    const first = await revoke()
    expect(first.payload).toMatchObject({
      kind: "rusty-resource-principal-revocation-receipt",
      serviceId: await publicKeyId(discovery.servicePublicKey),
      origin,
      storageScopeId: opaqueScopeId,
      workspaceId: opaqueScopeId,
      grantId: "editor-grant-revoked",
      subjectPersonId: editor.identity.personId,
      policyEpoch: 3,
    })
    const readAfterRevoke = await fetch(readUrl, { method: "GET", headers: readProof.headers, cache: "no-store" })
    expect(readAfterRevoke.status).toBe(403)

    await stopRusty(child)
    child = await startRusty(profile, stateDirectory, port)
    const replay = await revoke()
    expect(replay).toEqual(first)
    const deniedAfterRestart = await fetch(readUrl, { method: "GET", headers: readProof.headers, cache: "no-store" })
    expect(deniedAfterRestart.status).toBe(403)
  } finally {
    if (child) await stopRusty(child)
    await rm(stateDirectory, { recursive: true, force: true })
  }
})

function createMemoryEnrollmentJournal(): RustyScopeEnrollmentJournal {
  const requests = new Map<string, string>()
  return {
    read: async (binding) => {
      const body = requests.get(binding.scopeId)
      return body === undefined ? undefined : { body }
    },
    prepare: async (binding, body) => { requests.set(binding.scopeId, body) },
    replace: async (binding, previousBody, nextBody) => {
      if (requests.get(binding.scopeId) !== previousBody) throw new Error("Enrollment retry journal changed")
      requests.set(binding.scopeId, nextBody)
    },
    complete: async (binding, body) => { requests.set(binding.scopeId, body) },
  }
}

async function createEditorReadProof(
  origin: string,
  servicePublicKey: string,
  scopeId: string,
  token: string,
  editor: Awaited<ReturnType<typeof createRecoverableIdentity>>["profile"],
  authorityView: Awaited<ReturnType<typeof createIdentityAuthorityView>>,
  grantId: string,
  policyEpoch: number,
) {
  const url = `${origin}/v2/scopes/${encodeURIComponent(scopeId)}/objects`
  return createRustyIdentityRequestProof({
    origin,
    servicePublicKey,
    identity: editor.identity,
    view: authorityView,
    deviceId: editor.device.deviceId,
    devicePublicKey: editor.device.publicKey,
    scopeId,
    token,
    method: "GET",
    url,
    bodyBytes: new Uint8Array(),
    action: "read",
    grantId,
    policyEpoch,
    signAuthorization: (payload) => signEnvelope(editor.privateKeys.devicePrivateKey, payload,
      editor.device.deviceId, "MATCH/1"),
  })
}

async function startRusty(profile: Awaited<ReturnType<typeof createRecoverableIdentity>>["profile"],
  stateDirectory: string, port: number): Promise<ChildProcess> {
  const origin = `http://127.0.0.1:${port}`
  const child = spawn(resolve(rustyBinary!), [stateDirectory, `127.0.0.1:${port}`], {
    env: {
      ...process.env,
      RUSTY_PUBLIC_ORIGIN: origin,
      RUSTY_IDENTITY_AUTHORITY_ENFORCEMENT: "strict",
      RUSTY_LOG: "off",
    },
    stdio: ["ignore", "pipe", "pipe"],
  })
  let output = ""
  child.stdout?.on("data", (chunk: Buffer) => { output = `${output}${chunk}`.slice(-8_000) })
  child.stderr?.on("data", (chunk: Buffer) => { output = `${output}${chunk}`.slice(-8_000) })
  let spawnError: Error | undefined
  child.once("error", (error) => { spawnError = error })
  try {
    await waitForRusty(child, origin, () => output, () => spawnError)
    return child
  } catch (error) {
    await stopRusty(child)
    throw error
  }
}

async function unusedLoopbackPort(): Promise<number> {
  const listener = createServer()
  await new Promise<void>((resolveListen, reject) => {
    listener.once("error", reject)
    listener.listen(0, "127.0.0.1", () => resolveListen())
  })
  const address = listener.address()
  if (!address || typeof address === "string") throw new Error("Loopback listener did not expose a port")
  await new Promise<void>((resolveClose, reject) => listener.close((error) => error ? reject(error) : resolveClose()))
  return address.port
}

async function waitForRusty(child: ChildProcess, origin: string, output: () => string,
  spawnError: () => Error | undefined): Promise<void> {
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    if (spawnError()) throw new Error(`Unable to spawn Rusty: ${spawnError()?.message}`)
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Rusty exited during startup: ${output()}`)
    try {
      if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(2_000) })).ok) return
    } catch { /* The listener may still be starting. */ }
    await delay(40)
  }
  throw new Error(`Rusty did not become ready: ${output()}`)
}

async function stopRusty(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return
  child.kill("SIGINT")
  await Promise.race([
    new Promise<void>((resolveExit) => child.once("exit", () => resolveExit())),
    delay(5_000).then(() => { throw new Error("Rusty did not stop") }),
  ])
}
