import { authorizeIdentityDataDevice, canonicalizeJson, publicKeyId, sha256Base64Url, verifyEnvelope,
  verifyIdentityAuthorityView, type IdentityAuthorityView, type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { rustyOrigin } from "./rustyReplica"
import type { RustyFetch } from "./rustyDiscovery"
import type { RustyIdentityEnforcement } from "./rustyIdentityAuthority"

const encoder = new TextEncoder()

export type RustyScopeAuthorityUpdateAuthorization = {
  kind: "rusty-scope-authority-update"
  version: 1
  serviceId: string
  origin: string
  scopeId: string
  workspaceId: string
  personId: string
  deviceId: string
  controlEpoch: number
  requestId: string
  issuedAt: number
  expiresAt: number
  requestHash: string
}

export type RustyScopeAuthorityStatus = SignedEnvelope<{
  kind: "rusty-scope-authority-status"
  version: 1
  serviceId: string
  origin: string
  scopeId: string
  workspaceId: string | null
  state: "missing" | "ready"
  controllerPersonId: string | null
  controlEpoch: number | null
  requestId: string
  requestHash: string
  issuedAt: number
  enforcement: RustyIdentityEnforcement
  scopeAuthority: unknown | null
}>

export type RustyScopeAuthorityReceipt = SignedEnvelope<{
  kind: "rusty-scope-authority-receipt"
  version: 1
  serviceId: string
  origin: string
  scopeId: string
  workspaceId: string
  controllerPersonId: string
  controlEpoch: number
  requestId: string
  requestHash: string
  mergedSnapshotHash: string
  committedAt: number
  enforcement: RustyIdentityEnforcement
}>

export type ScopeAuthorityValidation = {
  workspaceId: string
  controllerPersonId: string
  controllerPublicKey: string
  controlEpoch: number
  snapshot: unknown
}

export type PublishRustyScopeAuthorityOptions = {
  origin: string
  servicePublicKey: string
  scopeId: string
  workspaceId: string
  identity: PublicIdentity
  authorityView: IdentityAuthorityView
  deviceId: string
  devicePublicKey: string
  scopeAuthority: unknown
  fetcher?: RustyFetch
  ensureCurrent?: () => void | Promise<void>
  validateSnapshot: (snapshot: unknown) => ScopeAuthorityValidation
  mergeSnapshots: (current: unknown, incoming: unknown) => unknown
  observeEnforcement?: (enforcement: RustyIdentityEnforcement) => void | Promise<void>
  signAuthorization: (payload: RustyScopeAuthorityUpdateAuthorization) => Promise<SignedEnvelope<RustyScopeAuthorityUpdateAuthorization>>
  now?: () => number
}

export type ReadRustyScopeAuthorityOptions = {
  origin: string
  servicePublicKey: string
  scopeId: string
  fetcher?: RustyFetch
  validateSnapshot: (snapshot: unknown) => ScopeAuthorityValidation
  now?: () => number
}

export type ReadRustyScopeAuthorityResult = {
  status: RustyScopeAuthorityStatus
  authority: ScopeAuthorityValidation | null
}

export class RustyScopeAuthorityStaleError extends Error {
  constructor(readonly status: RustyScopeAuthorityStatus, readonly scopeAuthority: unknown) {
    super("Rusty workspace scope authority changed; merge the signed current snapshot and retry")
    this.name = "RustyScopeAuthorityStaleError"
  }
}

/** Read Rusty's signed workspace authority without requiring the caller to control it. */
export async function readRustyScopeAuthorityStatus(
  options: ReadRustyScopeAuthorityOptions,
): Promise<ReadRustyScopeAuthorityResult> {
  const now = options.now ?? Date.now
  const fetcher = options.fetcher ?? fetch
  const origin = rustyOrigin(options.origin)
  const scopeId = options.scopeId
  const serviceId = await publicKeyId(options.servicePublicKey)
  if (!idPattern.test(scopeId)) throw new Error("Invalid Rusty workspace scope authority binding")
  const requestId = randomNonce()
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson({ version: 1, scopeId, requestId })))
  const query = new URLSearchParams({ requestId, requestHash })
  const response = await fetcher(`${origin}/v2/scopes/${encodeURIComponent(scopeId)}/authority/status?${query.toString()}`, {
    method: "GET", headers: { accept: "application/json" }, cache: "no-store", redirect: "error",
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty workspace scope authority status failed with HTTP ${response.status}`)
  }
  const status = await readSignedResponse<RustyScopeAuthorityStatus>(response, "status")
  await assertStatus(status, { serviceId, servicePublicKey: options.servicePublicKey, origin, scopeId,
    requestId, requestHash, now: now() })
  if (status.payload.state === "missing") return { status, authority: null }
  if (status.payload.workspaceId === null || status.payload.scopeAuthority === null) {
    throw new Error("Rusty ready scope authority status omitted its workspace ledger")
  }
  const authority = options.validateSnapshot(status.payload.scopeAuthority)
  assertSnapshotBinding(authority, status.payload.workspaceId)
  if (authority.controllerPersonId !== status.payload.controllerPersonId || authority.controlEpoch !== status.payload.controlEpoch) {
    throw new Error("Rusty signed scope authority status does not match its snapshot")
  }
  return { status, authority }
}

/** Register a workspace's signed succession ledger before its protected scope is used. */
export async function publishRustyScopeAuthoritySnapshot(
  options: PublishRustyScopeAuthorityOptions,
): Promise<{ receipt: RustyScopeAuthorityReceipt; scopeAuthority: ScopeAuthorityValidation }> {
  const now = options.now ?? Date.now
  const fetcher = options.fetcher ?? fetch
  const origin = rustyOrigin(options.origin)
  const scopeId = options.scopeId
  const workspaceId = options.workspaceId
  const identity = structuredClone(options.identity)
  const serviceId = await publicKeyId(options.servicePublicKey)
  const view = await verifyIdentityAuthorityView(options.authorityView)
  if (!idPattern.test(scopeId) || !idPattern.test(workspaceId) || view.personId !== identity.personId ||
      view.identityPublicKey !== identity.publicKey) throw new Error("Invalid Rusty workspace scope authority binding")
  const activeKey = await authorizeIdentityDataDevice(view, options.deviceId)
  if (activeKey !== options.devicePublicKey) throw new Error("Rusty scope authority signer is not an active Identity device")
  await options.ensureCurrent?.()

  const requestId = randomNonce()
  const statusPath = `/v2/scopes/${encodeURIComponent(scopeId)}/authority/status`
  const statusQuery = new URLSearchParams({ requestId })
  const statusRequestHash = await sha256Base64Url(encoder.encode(canonicalizeJson({ version: 1, scopeId, requestId })))
  statusQuery.set("requestHash", statusRequestHash)
  const statusUrl = `${origin}${statusPath}?${statusQuery.toString()}`
  const statusResponse = await fetcher(statusUrl, { method: "GET", headers: { accept: "application/json" }, cache: "no-store",
    redirect: "error", signal: AbortSignal.timeout(10_000) })
  if (!statusResponse.ok) {
    await statusResponse.body?.cancel()
    throw new Error(`Rusty workspace scope authority status failed with HTTP ${statusResponse.status}`)
  }
  const status = await readSignedResponse<RustyScopeAuthorityStatus>(statusResponse, "status")
  await assertStatus(status, { serviceId, servicePublicKey: options.servicePublicKey, origin, scopeId, requestId,
    requestHash: statusRequestHash, now: now() })
  await options.observeEnforcement?.(status.payload.enforcement)

  let proposed = structuredClone(options.scopeAuthority)
  if (status.payload.state === "ready") {
    if (status.payload.workspaceId !== workspaceId || status.payload.scopeAuthority === null) {
      throw new Error("Rusty workspace scope authority belongs to another workspace")
    }
    const stored = options.validateSnapshot(status.payload.scopeAuthority)
    assertSnapshotBinding(stored, workspaceId)
    if (stored.controllerPersonId !== status.payload.controllerPersonId || stored.controlEpoch !== status.payload.controlEpoch) {
      throw new Error("Rusty signed scope authority status does not match its snapshot")
    }
    proposed = options.mergeSnapshots(status.payload.scopeAuthority, proposed)
  } else if (status.payload.workspaceId !== null || status.payload.scopeAuthority !== null ||
      status.payload.controllerPersonId !== null || status.payload.controlEpoch !== null) {
    throw new Error("Rusty missing scope authority status contains authority state")
  }
  const validated = options.validateSnapshot(proposed)
  assertSnapshotBinding(validated, workspaceId)
  if (status.payload.state === "ready" && validated.controlEpoch < (status.payload.controlEpoch ?? 0)) {
    throw new Error("Local workspace scope authority is behind Rusty’s accepted history")
  }
  if (validated.controllerPersonId !== identity.personId || validated.controllerPublicKey !== identity.publicKey) {
    throw new Error("Rusty scope authority controller must be the active Identity")
  }
  await options.ensureCurrent?.()

  const requestBody = { version: 1 as const, scopeAuthority: JSON.parse(JSON.stringify(proposed)) as unknown }
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson(requestBody)))
  const issuedAt = now()
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) throw new Error("Invalid Rusty scope authority request time")
  const authorizationPayload: RustyScopeAuthorityUpdateAuthorization = {
    kind: "rusty-scope-authority-update", version: 1, serviceId, origin, scopeId, workspaceId,
    personId: identity.personId, deviceId: options.deviceId, controlEpoch: validated.controlEpoch,
    requestId: randomNonce(), issuedAt, expiresAt: issuedAt + 90_000, requestHash,
  }
  const authorization = await options.signAuthorization(authorizationPayload)
  if (!authorization || authorization.signerKeyId !== options.deviceId ||
      canonicalizeJson(authorization.payload) !== canonicalizeJson(authorizationPayload) ||
      !await verifyEnvelope(authorization, activeKey, "MATCH/1")) {
    throw new Error("Invalid Rusty scope authority update signature")
  }
  await options.ensureCurrent?.()
  const response = await fetcher(`${origin}/v2/scopes/${encodeURIComponent(scopeId)}/authority`, {
    method: "PUT", headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ ...requestBody, authorization }), cache: "no-store", redirect: "error", signal: AbortSignal.timeout(10_000),
  })
  if (response.status === 409) {
    const staleBody = await readResponseJson(response)
    const stale = staleBody.authorityStatus as RustyScopeAuthorityStatus
    await assertStatus(stale, { serviceId, servicePublicKey: options.servicePublicKey, origin, scopeId,
      requestId: authorizationPayload.requestId, requestHash, now: now() })
    if (stale.payload.state !== "ready" || stale.payload.workspaceId !== workspaceId || !stale.payload.scopeAuthority) {
      throw new Error("Rusty scope authority stale response omitted current workspace authority")
    }
    throw new RustyScopeAuthorityStaleError(stale, stale.payload.scopeAuthority)
  }
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty workspace scope authority update failed with HTTP ${response.status}`)
  }
  const responseBody = await readResponseJson(response)
  const receipt = responseBody.receipt as RustyScopeAuthorityReceipt
  await options.ensureCurrent?.()
  if (receipt.signerKeyId !== serviceId || !await verifyEnvelope(receipt, options.servicePublicKey, "RUSTY/2")) {
    throw new Error("Invalid Rusty scope authority receipt signature")
  }
  const receiptPayload = receipt.payload
  if (!hasExactKeys(receiptPayload, ["kind", "version", "serviceId", "origin", "scopeId", "workspaceId", "controllerPersonId",
    "controlEpoch", "requestId", "requestHash", "mergedSnapshotHash", "committedAt", "enforcement"]) ||
      receiptPayload.kind !== "rusty-scope-authority-receipt" || receiptPayload.version !== 1 ||
      receiptPayload.serviceId !== serviceId || receiptPayload.origin !== origin || receiptPayload.scopeId !== scopeId ||
      receiptPayload.workspaceId !== workspaceId || receiptPayload.controllerPersonId !== identity.personId ||
      receiptPayload.controlEpoch !== validated.controlEpoch || receiptPayload.requestId !== authorizationPayload.requestId ||
      receiptPayload.requestHash !== requestHash ||
      receiptPayload.mergedSnapshotHash !== await sha256Base64Url(encoder.encode(canonicalizeJson(proposed))) ||
      !Number.isSafeInteger(receiptPayload.committedAt) || !validEnforcement(receiptPayload.enforcement) ||
      Math.abs(now() - receiptPayload.committedAt) > 120_000) {
    throw new Error("Rusty scope authority receipt does not match this update")
  }
  const echoed = options.validateSnapshot(responseBody.scopeAuthority)
  assertSnapshotBinding(echoed, workspaceId)
  if (canonicalizeJson(echoed.snapshot) !== canonicalizeJson(proposed) || echoed.controlEpoch !== validated.controlEpoch ||
      echoed.controllerPersonId !== validated.controllerPersonId || echoed.controllerPublicKey !== validated.controllerPublicKey) {
    throw new Error("Rusty scope authority receipt returned a different snapshot")
  }
  await options.observeEnforcement?.(receiptPayload.enforcement)
  return { receipt, scopeAuthority: echoed }
}

async function assertStatus(status: RustyScopeAuthorityStatus, expected: { serviceId: string; servicePublicKey: string; origin: string;
  scopeId: string; requestId: string; requestHash: string; now: number }) {
  if (!hasExactKeys(status, ["payload", "signerKeyId", "signature"]) || status.signerKeyId !== expected.serviceId ||
      !await verifyEnvelope(status, expected.servicePublicKey, "RUSTY/2")) throw new Error("Invalid Rusty scope authority status signature")
  const payload = status.payload
  if (!hasExactKeys(payload, ["kind", "version", "serviceId", "origin", "scopeId", "workspaceId", "state", "controllerPersonId",
    "controlEpoch", "requestId", "requestHash", "issuedAt", "enforcement", "scopeAuthority"]) ||
      payload.kind !== "rusty-scope-authority-status" || payload.version !== 1 || payload.serviceId !== expected.serviceId ||
      payload.origin !== expected.origin || payload.scopeId !== expected.scopeId || payload.requestId !== expected.requestId ||
      payload.requestHash !== expected.requestHash || !Number.isSafeInteger(payload.issuedAt) ||
      Math.abs(expected.now - payload.issuedAt) > 120_000 || !validEnforcement(payload.enforcement) ||
      (payload.state !== "missing" && payload.state !== "ready") ||
      (payload.state === "missing" && (payload.workspaceId !== null || payload.controllerPersonId !== null ||
        payload.controlEpoch !== null || payload.scopeAuthority !== null)) ||
      (payload.state === "ready" && (typeof payload.workspaceId !== "string" || typeof payload.controllerPersonId !== "string" ||
        !Number.isSafeInteger(payload.controlEpoch) || payload.controlEpoch! < 0 || payload.scopeAuthority === null))) {
    throw new Error("Rusty scope authority status does not match this request")
  }
}

function assertSnapshotBinding(value: ScopeAuthorityValidation, workspaceId: string) {
  if (!value || value.workspaceId !== workspaceId || !value.controllerPersonId || !value.controllerPublicKey ||
      !Number.isSafeInteger(value.controlEpoch) || value.controlEpoch < 0 || value.snapshot === undefined) {
    throw new Error("Invalid Rusty workspace scope authority snapshot")
  }
}

function validEnforcement(value: unknown): value is RustyIdentityEnforcement {
  if (!hasExactKeys(value, ["mode", "epoch"])) return false
  const enforcement = value as { mode?: unknown; epoch?: unknown }
  return (enforcement.mode === "additive" && enforcement.epoch === 0) ||
    (enforcement.mode === "strict" && enforcement.epoch === 1)
}

function randomNonce(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)))
}

function base64Url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "")
}

function hasExactKeys(value: unknown, keys: string[]): value is Record<string, any> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)))
}

async function readSignedResponse<T>(response: Response, property: string): Promise<T> {
  const body = await readResponseJson(response)
  const envelope = body[property]
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) throw new Error(`Rusty response omitted signed ${property}`)
  return envelope as T
}

async function readResponseJson(response: Response): Promise<Record<string, any>> {
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > 1_048_576)) {
    await response.body?.cancel()
    throw new Error("Rusty scope authority response is too large")
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength > 1_048_576) throw new Error("Rusty scope authority response is too large")
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes))
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error()
    return value
  } catch { throw new Error("Invalid Rusty scope authority response") }
}

const idPattern = /^[A-Za-z0-9_-]{1,128}$/u
