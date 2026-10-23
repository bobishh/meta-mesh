import { authorizeIdentityDataDevice, canonicalizeJson, publicKeyId, sha256Base64Url, verifyEnvelope,
  verifyIdentityAuthorityView, type IdentityAuthorityView, type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { rustyOrigin } from "./rustyReplica"
import type { RustyFetch } from "./rustyDiscovery"

const encoder = new TextEncoder()
const purpose = "person-identity" as const

export type RustyScopePurposeAuthorization = {
  kind: "rusty-scope-purpose-update"
  version: 1
  serviceId: string
  origin: string
  scopeId: string
  scopePurpose: typeof purpose
  personId: string
  deviceId: string
  policyRevision: number
  requestId: string
  issuedAt: number
  expiresAt: number
  requestHash: string
}

export type RustyScopePurposeReceipt = SignedEnvelope<{
  kind: "rusty-scope-purpose-receipt"
  version: 1
  serviceId: string
  origin: string
  scopeId: string
  scopePurpose: typeof purpose
  personId: string
  policyRevision: number
  requestId: string
  requestHash: string
  committedAt: number
  enforcement: { mode: "additive" | "strict"; epoch: 0 | 1 }
}>

export type RustyScopePurposeClientOptions = {
  origin: string
  servicePublicKey: string
  scopeId: string
  policyRevision: number
  identity: PublicIdentity
  authorityView: IdentityAuthorityView
  deviceId: string
  devicePublicKey: string
  fetcher?: RustyFetch
  ensureCurrent?: () => void | Promise<void>
  signAuthorization: (payload: RustyScopePurposeAuthorization) => Promise<SignedEnvelope<RustyScopePurposeAuthorization>>
  now?: () => number
}

/** Permanently classify only the caller-owned legacy personal identity scope. */
export async function classifyRustyPersonIdentityScope(options: RustyScopePurposeClientOptions): Promise<RustyScopePurposeReceipt> {
  const origin = rustyOrigin(options.origin)
  const scopeId = options.scopeId
  const policyRevision = options.policyRevision
  const identity = structuredClone(options.identity)
  const serviceId = await publicKeyId(options.servicePublicKey)
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(scopeId) || !Number.isSafeInteger(policyRevision) || policyRevision < 0) {
    throw new Error("Invalid Rusty personal scope classification input")
  }
  const view = await verifyIdentityAuthorityView(options.authorityView)
  if (view.personId !== identity.personId || view.identityPublicKey !== identity.publicKey) {
    throw new Error("Rusty personal scope authority belongs to another Identity")
  }
  const activeKey = await authorizeIdentityDataDevice(view, options.deviceId)
  if (activeKey !== options.devicePublicKey) throw new Error("Rusty personal scope signer is not an active Identity device")
  await options.ensureCurrent?.()

  const requestBody = { version: 1 as const, scopePurpose: purpose }
  const requestHash = await sha256Base64Url(encoder.encode(canonicalizeJson(requestBody)))
  const issuedAt = (options.now ?? Date.now)()
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) throw new Error("Invalid Rusty scope classification time")
  const authorizationPayload: RustyScopePurposeAuthorization = {
    kind: "rusty-scope-purpose-update", version: 1, serviceId, origin, scopeId, scopePurpose: purpose,
    personId: identity.personId, deviceId: options.deviceId, policyRevision,
    requestId: randomNonce(), issuedAt, expiresAt: issuedAt + 90_000, requestHash,
  }
  const authorization = await options.signAuthorization(authorizationPayload)
  if (!hasExactKeys(authorization, ["payload", "signerKeyId", "signature"]) || authorization.signerKeyId !== options.deviceId ||
      canonicalizeJson(authorization.payload) !== canonicalizeJson(authorizationPayload) ||
      !await verifyEnvelope(authorization, activeKey, "MATCH/1")) {
    throw new Error("Invalid Rusty scope classification authorization")
  }
  await options.ensureCurrent?.()
  const fetcher = options.fetcher ?? fetch
  const response = await fetcher(`${origin}/v2/scopes/${encodeURIComponent(scopeId)}/purpose`, {
    method: "PUT", headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ ...requestBody, authorization }), cache: "no-store", redirect: "error", signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty scope classification failed with HTTP ${response.status}`)
  }
  await options.ensureCurrent?.()
  const body = await readReceiptBody(response)
  const receipt = body.receipt
  if (!receipt || receipt.signerKeyId !== serviceId ||
      !await verifyEnvelope(receipt, options.servicePublicKey, "RUSTY/2")) {
    throw new Error("Invalid Rusty scope classification receipt signature")
  }
  const payload = receipt.payload
  const committedAt = (options.now ?? Date.now)()
  if (!hasExactKeys(receipt, ["payload", "signerKeyId", "signature"]) ||
      !hasExactKeys(payload, ["kind", "version", "serviceId", "origin", "scopeId", "scopePurpose", "personId",
        "policyRevision", "requestId", "requestHash", "committedAt", "enforcement"]) ||
      payload.kind !== "rusty-scope-purpose-receipt" || payload.version !== 1 ||
      payload.serviceId !== serviceId || payload.origin !== origin || payload.scopeId !== scopeId ||
      payload.scopePurpose !== purpose || payload.personId !== identity.personId || payload.policyRevision !== policyRevision ||
      payload.requestId !== authorizationPayload.requestId || payload.requestHash !== requestHash ||
      !Number.isSafeInteger(payload.committedAt) || !Number.isSafeInteger(committedAt) ||
      Math.abs(committedAt - payload.committedAt) > 120_000 ||
      !validEnforcement(payload.enforcement)) {
    throw new Error("Rusty scope classification receipt does not match this request")
  }
  return receipt
}

function validEnforcement(value: unknown): value is RustyScopePurposeReceipt["payload"]["enforcement"] {
  if (!hasExactKeys(value, ["mode", "epoch"])) return false
  const enforcement = value as { mode?: unknown; epoch?: unknown }
  return (enforcement.mode === "additive" && enforcement.epoch === 0) ||
    (enforcement.mode === "strict" && enforcement.epoch === 1)
}

function randomNonce(): string {
  let binary = ""
  for (const byte of crypto.getRandomValues(new Uint8Array(32))) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "")
}

function hasExactKeys(value: unknown, keys: string[]): value is Record<string, any> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)))
}

async function readReceiptBody(response: Response): Promise<{ receipt: RustyScopePurposeReceipt }> {
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > 65_536)) {
    await response.body?.cancel()
    throw new Error("Rusty scope classification receipt is too large")
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error("Rusty scope classification response is empty")
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > 65_536) {
        await reader.cancel()
        throw new Error("Rusty scope classification receipt is too large")
      }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))
    if (!hasExactKeys(value, ["receipt"])) throw new Error("invalid wrapper")
    return value as { receipt: RustyScopePurposeReceipt }
  } catch { throw new Error("Invalid Rusty scope classification response") }
}
