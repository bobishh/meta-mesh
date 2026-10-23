import { authorizeIdentityDevice, canonicalizeJson, publicKeyId, sha256Base64Url,
  verifyEnvelope, verifyIdentityAuthorityView, verifyIdentityDeviceAuthority,
  type IdentityAuthorityHead, type IdentityAuthorityView, type PublicIdentity, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { rustyOrigin } from "./rustyReplica"
import type { RustyFetch } from "./rustyDiscovery"

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
}>

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
  const authority = await verifyIdentityDeviceAuthority(identity,
    { certificates: view.certificates, revocations: view.revocations })
  const activeKey = await authorizeIdentityDevice(authority, options.deviceId)
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
      !Number.isSafeInteger(payload.committedAt)) {
    throw new Error("Rusty Identity authority receipt does not match the submitted view")
  }
  return receipt
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
  if (!isRecord(value) || !hasExactKeys(value, ["payload", "signerKeyId", "signature"]) ||
      typeof value.signerKeyId !== "string" || typeof value.signature !== "string" || !isRecord(value.payload) ||
      !hasExactKeys(value.payload, ["kind", "version", "serviceId", "origin", "personId", "authorityHead",
        "viewDigest", "requestHash", "committedAt"])) {
    throw new Error("Invalid Rusty Identity authority receipt")
  }
  return value as unknown as RustyIdentityAuthorityReceipt
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}
