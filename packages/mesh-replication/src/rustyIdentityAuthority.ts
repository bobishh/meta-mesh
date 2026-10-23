import { authorizeIdentityDataDevice, canonicalizeJson, publicKeyId, sha256Base64Url,
  verifyEnvelope, verifyIdentityAuthorityView,
  type IdentityAuthorityHead, type IdentityAuthorityView, type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { rustyOrigin } from "./rustyReplica"
import type { RustyFetch } from "./rustyDiscovery"

const encoder = new TextEncoder()

export type RustyIdentityAuthorityUpdateAuthorization = {
  kind: "rusty-identity-authority-update"
  version: 1
  serviceId: string
  origin: string
  personId: string
  deviceId: string
  authorityHead: IdentityAuthorityHead
  viewDigest: string
  nonce: string
  issuedAt: number
  requestHash: string
}

export type RustyIdentityEnforcement = {
  mode: "additive" | "strict"
  epoch: 0 | 1
}

export type RustyIdentityAuthorityReceipt = SignedEnvelope<{
  kind: "rusty-identity-authority-receipt"
  version: 1
  serviceId: string
  origin: string
  personId: string
  authorityHead: IdentityAuthorityHead
  viewDigest: string
  requestHash: string
  committedAt: number
  enforcement: RustyIdentityEnforcement
}>

export type RustyIdentityAuthorityStatus = SignedEnvelope<{
  kind: "rusty-identity-authority-status"
  version: 1
  serviceId: string
  origin: string
  personId: string
  state: "missing" | "ready" | "retired"
  requestNonce: string
  requestHash: string
  issuedAt: number
  view: IdentityAuthorityView | null
  enforcement: RustyIdentityEnforcement
}>

export class RustyIdentityAuthorityStaleError extends Error {
  readonly status: RustyIdentityAuthorityStatus
  readonly view: IdentityAuthorityView

  constructor(status: RustyIdentityAuthorityStatus, view: IdentityAuthorityView) {
    super("Rusty Identity authority changed; merge the signed current view and retry")
    this.name = "RustyIdentityAuthorityStaleError"
    this.status = status
    this.view = view
  }
}

export type RustyIdentityAuthorityRequest = {
  version: 1
  view: IdentityAuthorityView
  authorization: SignedEnvelope<RustyIdentityAuthorityUpdateAuthorization>
}

export type PublishRustyIdentityAuthorityOptions = {
  origin: string
  servicePublicKey: string
  identity: PublicIdentity
  deviceId: string
  devicePublicKey: string
  view: IdentityAuthorityView
  fetcher?: RustyFetch
  ensureCurrent?: () => void | Promise<void>
  signAuthorization: (payload: RustyIdentityAuthorityUpdateAuthorization) => Promise<SignedEnvelope<RustyIdentityAuthorityUpdateAuthorization>>
  now?: () => number
}

export type ReadRustyIdentityAuthorityStatusOptions = {
  origin: string
  servicePublicKey: string
  identity: PublicIdentity
  fetcher?: RustyFetch
  now?: () => number
}

/** Read Rusty's signed high-water view without bearer access; transport failure never means an empty view. */
export async function readRustyIdentityAuthorityStatus(
  options: ReadRustyIdentityAuthorityStatusOptions,
): Promise<RustyIdentityAuthorityStatus> {
  const fetcher = options.fetcher ?? fetch
  const now = options.now ?? Date.now
  const origin = rustyOrigin(options.origin)
  const serviceId = await publicKeyId(options.servicePublicKey)
  const nonce = randomNonce()
  const path = `/v2/identity/authority/${encodeURIComponent(options.identity.personId)}/status?nonce=${nonce}`
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson({ method: "GET", path })))
  const response = await fetcher(`${origin}${path}`, {
    method: "GET", headers: { accept: "application/json" }, cache: "no-store", signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty Identity authority status failed with HTTP ${response.status}`)
  }
  const status = await readAuthorityStatus(response)
  const currentTime = now()
  if (!Number.isSafeInteger(currentTime) || status.signerKeyId !== serviceId ||
      !await verifyEnvelope(status, options.servicePublicKey, "RUSTY/2")) {
    throw new Error("Invalid Rusty Identity authority status signature")
  }
  const payload = status.payload
  if (payload.kind !== "rusty-identity-authority-status" || payload.version !== 1 ||
      payload.serviceId !== serviceId || payload.origin !== origin || payload.personId !== options.identity.personId ||
      payload.requestNonce !== nonce || payload.requestHash !== requestHash || !Number.isSafeInteger(payload.issuedAt) ||
      Math.abs(currentTime - payload.issuedAt) > 120_000 ||
      (payload.state !== "missing" && payload.state !== "ready" && payload.state !== "retired") ||
      ((payload.state === "missing" || payload.state === "retired") ? payload.view !== null : payload.view === null) ||
      !isRustyIdentityEnforcement(payload.enforcement)) {
    throw new Error("Rusty Identity authority status does not match this request")
  }
  if (payload.view) {
    const view = await verifyIdentityAuthorityView(payload.view)
    if (view.personId !== options.identity.personId || view.identityPublicKey !== options.identity.publicKey) {
      throw new Error("Rusty Identity authority status contains another Identity view")
    }
  }
  return status
}

/** Advance Rusty's per-person authority high-water; resolve only after verifying its durable receipt. */
export async function publishRustyIdentityAuthorityView(options: PublishRustyIdentityAuthorityOptions): Promise<RustyIdentityAuthorityReceipt> {
  const fetcher = options.fetcher ?? fetch
  const now = options.now ?? Date.now
  const origin = rustyOrigin(options.origin)
  const serviceId = await publicKeyId(options.servicePublicKey)
  const identity = structuredClone(options.identity)
  const view = await verifyIdentityAuthorityView(options.view)
  if (view.personId !== identity.personId || view.identityPublicKey !== identity.publicKey) {
    throw new Error("Rusty Identity authority view belongs to another Identity")
  }
  const activeKey = await authorizeIdentityDataDevice(view, options.deviceId)
  if (activeKey !== options.devicePublicKey) throw new Error("Rusty Identity authority signer key does not match its active device")
  await options.ensureCurrent?.()

  const bodyWithoutAuthorization = { version: 1 as const, view: JSON.parse(JSON.stringify(view)) as IdentityAuthorityView }
  const requestHash = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(bodyWithoutAuthorization)))
  const issuedAt = now()
  if (!Number.isSafeInteger(issuedAt)) throw new Error("Invalid Rusty Identity authority request time")
  const authorizationPayload: RustyIdentityAuthorityUpdateAuthorization = {
    kind: "rusty-identity-authority-update", version: 1, serviceId, origin,
    personId: identity.personId, deviceId: options.deviceId,
    authorityHead: view.revocationHead, viewDigest: view.viewDigest,
    nonce: randomNonce(), issuedAt, requestHash,
  }
  const authorization = await options.signAuthorization(authorizationPayload)
  if (!authorization || authorization.signerKeyId !== options.deviceId ||
      canonicalizeJson(authorization.payload) !== canonicalizeJson(authorizationPayload) ||
      !await verifyEnvelope(authorization, activeKey, "MATCH/1")) {
    throw new Error("Invalid Rusty Identity authority authorization signature")
  }
  await options.ensureCurrent?.()
  const request: RustyIdentityAuthorityRequest = { ...bodyWithoutAuthorization, authorization }
  const response = await fetcher(`${origin}/v2/identity/authority`, {
    method: "PUT", headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(request), cache: "no-store", signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    if (response.status === 409) {
      const status = await readStaleAuthorityResponse(response)
      const payload = status.payload
      const currentTime = now()
      if (status.signerKeyId !== serviceId || !await verifyEnvelope(status, options.servicePublicKey, "RUSTY/2") ||
          payload.kind !== "rusty-identity-authority-status" || payload.version !== 1 ||
          payload.serviceId !== serviceId || payload.origin !== origin || payload.personId !== identity.personId ||
          payload.state !== "ready" || payload.requestNonce !== authorizationPayload.nonce ||
          payload.requestHash !== requestHash || !Number.isSafeInteger(payload.issuedAt) ||
          !Number.isSafeInteger(currentTime) || Math.abs(currentTime - payload.issuedAt) > 120_000 || !payload.view ||
          !isRustyIdentityEnforcement(payload.enforcement)) {
        throw new Error("Invalid Rusty Identity stale-authority response")
      }
      const currentView = await verifyIdentityAuthorityView(payload.view)
      if (currentView.personId !== identity.personId || currentView.identityPublicKey !== identity.publicKey) {
        throw new Error("Rusty stale-authority response belongs to another Identity")
      }
      throw new RustyIdentityAuthorityStaleError(status, currentView)
    }
    await response.body?.cancel()
    throw new Error(`Rusty Identity authority update failed with HTTP ${response.status}`)
  }
  const receipt = await readReceipt(response)
  await options.ensureCurrent?.()
  if (receipt.signerKeyId !== serviceId ||
      !await verifyEnvelope(receipt, options.servicePublicKey, "RUSTY/2")) {
    throw new Error("Invalid Rusty Identity authority receipt signature")
  }
  const payload = receipt.payload
  if (payload.kind !== "rusty-identity-authority-receipt" || payload.version !== 1 ||
      payload.serviceId !== serviceId || payload.origin !== origin || payload.personId !== identity.personId ||
      canonicalizeJson(payload.authorityHead) !== canonicalizeJson(view.revocationHead) ||
      payload.viewDigest !== view.viewDigest || payload.requestHash !== requestHash ||
      !Number.isSafeInteger(payload.committedAt) || !isRustyIdentityEnforcement(payload.enforcement)) {
    throw new Error("Rusty Identity authority receipt does not match the submitted view")
  }
  return receipt
}

/** Additive mode acknowledges storage only; strict mode enforces the authority view on data routes. */
export function isRustyIdentityAuthorityStrict(value: RustyIdentityEnforcement): boolean {
  return isRustyIdentityEnforcement(value) && value.mode === "strict"
}

/** Keep the highest enforcement mode observed from a service; signed downgrades must fail closed. */
export function mergeRustyIdentityEnforcement(
  previous: RustyIdentityEnforcement | null,
  incoming: RustyIdentityEnforcement,
): RustyIdentityEnforcement {
  if (!isRustyIdentityEnforcement(incoming) || (previous !== null && !isRustyIdentityEnforcement(previous))) {
    throw new Error("Invalid Rusty Identity enforcement state")
  }
  if (previous?.mode === "strict" && incoming.mode !== "strict") {
    throw new Error("Rusty Identity enforcement was downgraded by the service")
  }
  return { ...incoming }
}

function isRustyIdentityEnforcement(value: unknown): value is RustyIdentityEnforcement {
  if (!value || typeof value !== "object") return false
  const enforcement = value as Partial<RustyIdentityEnforcement>
  return (enforcement.mode === "additive" && enforcement.epoch === 0) ||
    (enforcement.mode === "strict" && enforcement.epoch === 1)
}

function randomNonce(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)))
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "")
}

async function readReceipt(response: Response): Promise<RustyIdentityAuthorityReceipt> {
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > 1_048_576)) {
    await response.body?.cancel()
    throw new Error("Rusty Identity authority receipt is too large")
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error("Rusty Identity authority response is empty")
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > 1_048_576) {
        await reader.cancel()
        throw new Error("Rusty Identity authority receipt is too large")
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new Error("Invalid Rusty Identity authority receipt") }
  if (!isRecord(value) || !hasExactKeys(value, ["receipt"]) || !isRecord(value.receipt) ||
      !hasExactKeys(value.receipt, ["payload", "signerKeyId", "signature"]) ||
      typeof value.receipt.signerKeyId !== "string" || typeof value.receipt.signature !== "string" ||
      !isRecord(value.receipt.payload) ||
      !hasExactKeys(value.receipt.payload, ["kind", "version", "serviceId", "origin", "personId", "authorityHead",
        "viewDigest", "requestHash", "committedAt", "enforcement"])) {
    throw new Error("Invalid Rusty Identity authority receipt")
  }
  return value.receipt as unknown as RustyIdentityAuthorityReceipt
}

async function readAuthorityStatus(response: Response): Promise<RustyIdentityAuthorityStatus> {
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > 1_048_576)) {
    await response.body?.cancel()
    throw new Error("Rusty Identity authority status is too large")
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error("Rusty Identity authority status is empty")
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > 1_048_576) {
        await reader.cancel()
        throw new Error("Rusty Identity authority status is too large")
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new Error("Invalid Rusty Identity authority status") }
  if (!isRecord(value) || !hasExactKeys(value, ["status"]) || !isRecord(value.status) ||
      !hasExactKeys(value.status, ["payload", "signerKeyId", "signature"]) ||
      typeof value.status.signerKeyId !== "string" || typeof value.status.signature !== "string" ||
      !isRecord(value.status.payload)) {
    throw new Error("Invalid Rusty Identity authority status envelope")
  }
  if (!hasExactKeys(value.status.payload, ["kind", "version", "serviceId", "origin", "personId", "state", "requestNonce",
      "requestHash", "issuedAt", "view", "enforcement"])) {
    throw new Error(`Invalid Rusty Identity authority status fields: ${Object.keys(value.status.payload).join(",")}`)
  }
  return value.status as unknown as RustyIdentityAuthorityStatus
}

async function readStaleAuthorityResponse(response: Response): Promise<RustyIdentityAuthorityStatus> {
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > 1_048_576)) {
    await response.body?.cancel()
    throw new Error("Rusty Identity stale-authority response is too large")
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error("Rusty Identity stale-authority response is empty")
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > 1_048_576) {
        await reader.cancel()
        throw new Error("Rusty Identity stale-authority response is too large")
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  let value: unknown
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) } catch {
    throw new Error("Invalid Rusty Identity stale-authority response")
  }
  if (!isRecord(value) || value.code !== "identity_authority_stale" || !isRecord(value.authorityStatus) ||
      !hasExactKeys(value.authorityStatus, ["payload", "signerKeyId", "signature"]) ||
      typeof value.authorityStatus.signerKeyId !== "string" || typeof value.authorityStatus.signature !== "string" ||
      !isRecord(value.authorityStatus.payload) ||
      !hasExactKeys(value.authorityStatus.payload, ["kind", "version", "serviceId", "origin", "personId", "state",
        "requestNonce", "requestHash", "issuedAt", "view", "enforcement"])) {
    throw new Error("Invalid Rusty Identity stale-authority response")
  }
  return value.authorityStatus as unknown as RustyIdentityAuthorityStatus
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}
