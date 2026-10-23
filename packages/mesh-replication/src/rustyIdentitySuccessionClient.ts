import { authorizeIdentityDataDevice, canonicalizeJson, publicKeyId, sha256Base64Url, verifyEnvelope,
  verifyIdentityAuthorityView, verifyIdentityRootSuccession,
  type IdentityAuthorityView, type IdentityRootSuccession, type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { rustyOrigin } from "./rustyReplica"
import type { RustyFetch } from "./rustyDiscovery"
import type { RustyIdentityEnforcement } from "./rustyIdentityAuthority"

const encoder = new TextEncoder()

export type RustyIdentityRootSuccessionRequestAuthorization = {
  kind: "rusty-identity-root-succession-request"
  version: 1
  serviceId: string
  origin: string
  previousPersonId: string
  successorPersonId: string
  transitionHash: string
  actorDeviceId: string
  requestId: string
  issuedAt: number
  expiresAt: number
  requestHash: string
}

export type RustyIdentitySuccessionTransferredResource = {
  kind: string
  resourceId: string
  evidenceHash: string
  epoch: number | null
}

export type RustyIdentityRootSuccessionReceipt = SignedEnvelope<{
  kind: "rusty-identity-root-succession-receipt"
  version: 1
  serviceId: string
  origin: string
  previousPersonId: string
  successorPersonId: string
  transitionHash: string
  actorDeviceId: string
  requestId: string
  requestHash: string
  committedAt: number
  retired: boolean
  transferred: RustyIdentitySuccessionTransferredResource[]
  enforcement: RustyIdentityEnforcement
}>

export type RustyIdentityRootSuccessionStatus = SignedEnvelope<{
  kind: "rusty-identity-root-succession-status"
  version: 1
  serviceId: string
  origin: string
  previousPersonId: string
  transitionHash: string
  state: "missing" | "pending" | "ready"
  requestId: string
  requestHash: string
  issuedAt: number
  successorPersonId: string | null
  actorDeviceId: string | null
  retired: boolean
  enforcement: RustyIdentityEnforcement
  transferred: RustyIdentitySuccessionTransferredResource[]
  receipt: RustyIdentityRootSuccessionReceipt | null
}>

export type ReadRustyIdentityRootSuccessionStatusOptions = {
  origin: string
  servicePublicKey: string
  previousPersonId: string
  transitionHash: string
  fetcher?: RustyFetch
  now?: () => number
}

export type ReadRustyIdentityRootSuccessionStatusResult = {
  status: RustyIdentityRootSuccessionStatus
  complete: boolean
  receipt: RustyIdentityRootSuccessionReceipt | null
}

export type PublishRustyIdentityRootSuccessionOptions = {
  origin: string
  servicePublicKey: string
  succession: IdentityRootSuccession
  previousAuthorityView: IdentityAuthorityView
  successorIdentity: PublicIdentity
  successorAuthorityView: IdentityAuthorityView
  actorDeviceId: string
  actorDevicePublicKey: string
  fetcher?: RustyFetch
  ensureCurrent?: () => void | Promise<void>
  signAuthorization: (payload: RustyIdentityRootSuccessionRequestAuthorization) =>
    Promise<SignedEnvelope<RustyIdentityRootSuccessionRequestAuthorization>>
  now?: () => number
}

export class RustyIdentityRootSuccessionPendingError extends Error {
  constructor(readonly receipt: RustyIdentityRootSuccessionReceipt) {
    super("Rusty accepted the root succession request but global strict enforcement is not confirmed")
    this.name = "RustyIdentityRootSuccessionPendingError"
  }
}

/** Read request-bound Rusty succession status; only a verified retired receipt is complete. */
export async function readRustyIdentityRootSuccessionStatus(
  options: ReadRustyIdentityRootSuccessionStatusOptions,
): Promise<ReadRustyIdentityRootSuccessionStatusResult> {
  const now = options.now ?? Date.now
  const origin = rustyOrigin(options.origin)
  const serviceId = await publicKeyId(options.servicePublicKey)
  assertId(options.previousPersonId, "previous Identity")
  assertDigest(options.transitionHash, "transition hash")
  const requestId = randomNonce()
  const path = `/v2/identity/succession/${encodeURIComponent(options.previousPersonId)}/${options.transitionHash}`
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson({
    version: 1, previousPersonId: options.previousPersonId, transitionHash: options.transitionHash, requestId,
  })))
  const query = new URLSearchParams({ requestId, requestHash })
  const response = await (options.fetcher ?? fetch)(`${origin}${path}?${query.toString()}`, {
    method: "GET", headers: { accept: "application/json" }, cache: "no-store", redirect: "error",
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty Identity succession status failed with HTTP ${response.status}`)
  }
  const status = await readSignedEnvelope<RustyIdentityRootSuccessionStatus>(response, "status")
  const currentTime = now()
  await assertStatus(status, { serviceId, servicePublicKey: options.servicePublicKey, origin,
    previousPersonId: options.previousPersonId, transitionHash: options.transitionHash, requestId, requestHash, now: currentTime })
  const receipt = status.payload.receipt
  if (receipt) {
    await assertReceipt(receipt, { serviceId, servicePublicKey: options.servicePublicKey, origin,
      previousPersonId: options.previousPersonId, successorPersonId: status.payload.successorPersonId,
      transitionHash: options.transitionHash, actorDeviceId: status.payload.actorDeviceId,
      now: currentTime, requireRetired: status.payload.state === "ready" })
    if (receipt.payload.retired !== status.payload.retired ||
        canonicalizeJson(receipt.payload.transferred) !== canonicalizeJson(status.payload.transferred) ||
        canonicalizeJson(receipt.payload.enforcement) !== canonicalizeJson(status.payload.enforcement)) {
      throw new Error("Rusty Identity succession status conflicts with its receipt")
    }
  }
  const complete = status.payload.state === "ready" && status.payload.retired && receipt?.payload.retired === true &&
    isStrict(status.payload.enforcement) && isStrict(receipt.payload.enforcement)
  return { status, complete, receipt }
}

/** Submit the dual-root proof with an active successor actor; return only after a valid terminal receipt. */
export async function publishRustyIdentityRootSuccession(
  options: PublishRustyIdentityRootSuccessionOptions,
): Promise<RustyIdentityRootSuccessionReceipt> {
  const now = options.now ?? Date.now
  const fetcher = options.fetcher ?? fetch
  const origin = rustyOrigin(options.origin)
  const serviceId = await publicKeyId(options.servicePublicKey)
  const succession = structuredClone(options.succession)
  const previousView = await verifyIdentityAuthorityView(options.previousAuthorityView)
  const previousId = previousView.personId
  const successorIdentity = structuredClone(options.successorIdentity)
  const successorView = await verifyIdentityAuthorityView(options.successorAuthorityView)
  const verified = await verifyIdentityRootSuccession(succession, previousView)
  if (successorView.personId !== successorIdentity.personId || successorView.identityPublicKey !== successorIdentity.publicKey ||
      verified.previousPersonId !== previousId || verified.successorPersonId !== successorIdentity.personId ||
      verified.successorIdentityPublicKey !== successorIdentity.publicKey) {
    throw new Error("Rusty root succession identities do not match their verified authority views")
  }
  const activeKey = await authorizeIdentityDataDevice(successorView, options.actorDeviceId)
  if (activeKey !== options.actorDevicePublicKey) throw new Error("Rusty succession actor is not an active successor device")
  const transitionHash = await sha256Base64Url(encoder.encode(canonicalizeJson(succession)))
  const requestBody = { version: 1 as const, succession, actorDeviceId: options.actorDeviceId }
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson(requestBody)))
  const issuedAt = now()
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) throw new Error("Invalid Rusty succession request time")
  const authorizationPayload: RustyIdentityRootSuccessionRequestAuthorization = {
    kind: "rusty-identity-root-succession-request", version: 1, serviceId, origin,
    previousPersonId: verified.previousPersonId, successorPersonId: verified.successorPersonId,
    transitionHash, actorDeviceId: options.actorDeviceId, requestId: randomNonce(), issuedAt,
    expiresAt: issuedAt + 90_000, requestHash,
  }
  const authorization = await options.signAuthorization(authorizationPayload)
  if (!hasExactKeys(authorization, ["payload", "signerKeyId", "signature"]) ||
      authorization.signerKeyId !== options.actorDeviceId ||
      canonicalizeJson(authorization.payload) !== canonicalizeJson(authorizationPayload) ||
      !await verifyEnvelope(authorization, activeKey, "MATCH/1")) {
    throw new Error("Invalid Rusty root succession request signature")
  }
  await options.ensureCurrent?.()
  const response = await fetcher(`${origin}/v2/identity/succession`, {
    method: "PUT", headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ ...requestBody, actorAuthorization: authorization }), cache: "no-store", redirect: "error",
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty Identity succession update failed with HTTP ${response.status}`)
  }
  const receipt = await readSignedEnvelope<RustyIdentityRootSuccessionReceipt>(response, "receipt")
  const currentTime = now()
  await assertReceipt(receipt, { serviceId, servicePublicKey: options.servicePublicKey, origin,
    previousPersonId: verified.previousPersonId, successorPersonId: verified.successorPersonId,
    transitionHash, actorDeviceId: options.actorDeviceId, requestId: authorizationPayload.requestId,
    requestHash, now: currentTime, requireRetired: false })
  await options.ensureCurrent?.()
  if (!receipt.payload.retired || !isStrict(receipt.payload.enforcement)) {
    throw new RustyIdentityRootSuccessionPendingError(receipt)
  }
  return receipt
}

async function assertStatus(status: RustyIdentityRootSuccessionStatus, expected: {
  serviceId: string; servicePublicKey: string; origin: string; previousPersonId: string; transitionHash: string;
  requestId: string; requestHash: string; now: number
}): Promise<void> {
  if (!hasExactKeys(status, ["payload", "signerKeyId", "signature"]) || status.signerKeyId !== expected.serviceId ||
      !await verifyEnvelope(status, expected.servicePublicKey, "RUSTY/2")) throw new Error("Invalid Rusty Identity succession status signature")
  const payload = status.payload
  if (!hasExactKeys(payload, ["kind", "version", "serviceId", "origin", "previousPersonId", "transitionHash", "state",
    "requestId", "requestHash", "issuedAt", "successorPersonId", "actorDeviceId", "retired", "enforcement", "transferred", "receipt"]) ||
      payload.kind !== "rusty-identity-root-succession-status" || payload.version !== 1 ||
      payload.serviceId !== expected.serviceId || payload.origin !== expected.origin ||
      payload.previousPersonId !== expected.previousPersonId || payload.transitionHash !== expected.transitionHash ||
      payload.requestId !== expected.requestId || payload.requestHash !== expected.requestHash ||
      !validTime(payload.issuedAt, expected.now) || !validEnforcement(payload.enforcement) ||
      (payload.state !== "missing" && payload.state !== "pending" && payload.state !== "ready") ||
      typeof payload.retired !== "boolean" || !validTransferred(payload.transferred) ||
      !nullableId(payload.successorPersonId) || !nullableId(payload.actorDeviceId) ||
      (payload.state === "missing" && (payload.successorPersonId !== null || payload.actorDeviceId !== null ||
        payload.retired || payload.transferred.length !== 0 || payload.receipt !== null)) ||
      (payload.state === "pending" && payload.retired) ||
      (payload.state === "pending" && payload.receipt !== null && typeof payload.receipt !== "object") ||
      (payload.state === "ready" && (!payload.retired || payload.successorPersonId === null ||
        payload.actorDeviceId === null || payload.receipt === null))) {
    throw new Error("Rusty Identity succession status does not match this request")
  }
}

async function assertReceipt(receipt: RustyIdentityRootSuccessionReceipt, expected: {
  serviceId: string; servicePublicKey: string; origin: string; previousPersonId: string; successorPersonId: string | null;
  transitionHash: string; actorDeviceId: string | null; requestId?: string; requestHash?: string; now: number; requireRetired: boolean
}): Promise<void> {
  if (!hasExactKeys(receipt, ["payload", "signerKeyId", "signature"]) || receipt.signerKeyId !== expected.serviceId ||
      !await verifyEnvelope(receipt, expected.servicePublicKey, "RUSTY/2")) throw new Error("Invalid Rusty Identity succession receipt signature")
  const payload = receipt.payload
  if (!hasExactKeys(payload, ["kind", "version", "serviceId", "origin", "previousPersonId", "successorPersonId",
    "transitionHash", "actorDeviceId", "requestId", "requestHash", "committedAt", "retired", "transferred", "enforcement"]) ||
      payload.kind !== "rusty-identity-root-succession-receipt" || payload.version !== 1 ||
      payload.serviceId !== expected.serviceId || payload.origin !== expected.origin ||
      payload.previousPersonId !== expected.previousPersonId || payload.successorPersonId !== expected.successorPersonId ||
      payload.transitionHash !== expected.transitionHash || payload.actorDeviceId !== expected.actorDeviceId ||
      (expected.requestId !== undefined && payload.requestId !== expected.requestId) ||
      (expected.requestHash !== undefined && payload.requestHash !== expected.requestHash) ||
      !isNonce(payload.requestId) || !isDigest(payload.requestHash) || !validTime(payload.committedAt, expected.now) ||
      typeof payload.retired !== "boolean" || (expected.requireRetired && !payload.retired) ||
      !validTransferred(payload.transferred) || !validEnforcement(payload.enforcement)) {
    throw new Error("Rusty Identity succession receipt does not match this transition")
  }
}

function validTransferred(value: unknown): value is RustyIdentitySuccessionTransferredResource[] {
  return Array.isArray(value) && value.length <= 10_000 && value.every(item => hasExactKeys(item,
    ["kind", "resourceId", "evidenceHash", "epoch"]) && typeof item.kind === "string" && item.kind.length > 0 &&
    item.kind.length <= 64 && typeof item.resourceId === "string" && idPattern.test(item.resourceId) &&
    isDigest(item.evidenceHash) && (item.epoch === null || (Number.isSafeInteger(item.epoch) && item.epoch >= 0)))
}

function validEnforcement(value: unknown): value is RustyIdentityEnforcement {
  return hasExactKeys(value, ["mode", "epoch"]) &&
    ((value.mode === "additive" && value.epoch === 0) || (value.mode === "strict" && value.epoch === 1))
}

function isStrict(value: RustyIdentityEnforcement): boolean {
  return value.mode === "strict" && value.epoch === 1
}

function validTime(value: unknown, now: number): value is number {
  return Number.isSafeInteger(value) && Number.isSafeInteger(now) && Math.abs(now - (value as number)) <= 120_000
}

function nullableId(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && idPattern.test(value))
}

function assertId(value: string, label: string): void {
  if (!idPattern.test(value)) throw new Error(`Invalid ${label} binding`)
}

function assertDigest(value: string, label: string): void {
  if (!isDigest(value)) throw new Error(`Invalid ${label}`)
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && digestPattern.test(value)
}

function isNonce(value: unknown): value is string {
  return typeof value === "string" && noncePattern.test(value)
}

function randomNonce(): string {
  let binary = ""
  for (const byte of crypto.getRandomValues(new Uint8Array(32))) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "")
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, any> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key)))
}

async function readSignedEnvelope<T>(response: Response, property: string): Promise<T> {
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > 1_048_576)) {
    await response.body?.cancel()
    throw new Error("Rusty Identity succession response is too large")
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength > 1_048_576) throw new Error("Rusty Identity succession response is too large")
  try {
    const body: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))
    if (!hasExactKeys(body, [property])) throw new Error("invalid wrapper")
    return (body as Record<string, unknown>)[property] as T
  } catch { throw new Error(`Invalid Rusty Identity succession ${property} response`) }
}

const idPattern = /^[A-Za-z0-9_-]{1,128}$/u
const digestPattern = /^[A-Za-z0-9_-]{43}$/u
const noncePattern = /^[A-Za-z0-9_-]{43}$/u
