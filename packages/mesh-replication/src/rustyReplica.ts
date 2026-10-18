import { canonicalizeJson, fromBase64Url, publicKeyId, sha256Base64Url, toBase64Url, verifyEnvelope,
  type SignedEnvelope } from "@meta-uber/mesh-identity"

/** Opaque protocol-2 object. The ciphertext and AAD formats are wire contracts. */
export type BlindObject = { version: 1; scopeId: string; keyEpoch: number; nonce: string; ciphertext: string }
export type PurposeBoundBinding = {
  purpose: "identity-state" | "attachment" | "archive"
  subjectId: string
  scopeId: string
  keyEpoch: number
}
export type RustyReplicaAccess = {
  origin: string
  scopeId: string
  servicePublicKey: string
  readToken: string
  writeToken: string
  policyRevision: number
  client?: string
  clientBuild?: string
}
export type RustyFetch = (url: string, init: RequestInit) => Promise<Response>
export class RustyResponseError extends Error {
  readonly code: unknown
  readonly status?: number

  constructor(message: string, detail: { code?: unknown; status?: number; cause?: unknown } = {}) {
    super(message, detail.cause === undefined ? undefined : { cause: detail.cause })
    this.name = "RustyResponseError"
    this.code = detail.code
    if (detail.status !== undefined) this.status = detail.status
  }
}
export type RustyStorageReceipt = SignedEnvelope<{
  kind: "blind-storage-receipt"
  version: 2
  serviceId: string
  scopeId: string
  keyEpoch: number
  objectId: string
  sequence: number
  policyRevision: number
  requestId: string
}>

const encoder = new TextEncoder()
const scopePattern = /^[a-zA-Z0-9_-]{1,128}$/
const purposeValues = new Set<PurposeBoundBinding["purpose"]>(["identity-state", "attachment", "archive"])

export function rustyOrigin(input: string): string {
  const url = new URL(input.includes("://") ? input : `https://${input}`)
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) {
    throw new Error("Rusty needs an HTTPS origin; HTTP is allowed only on loopback")
  }
  return url.origin
}

export function encodeBlindBytes(bytes: Uint8Array): string {
  let text = ""
  for (let offset = 0; offset < bytes.length; offset += 32768) text += String.fromCharCode(...bytes.subarray(offset, offset + 32768))
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function decodeBlindBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[a-zA-Z0-9_-]*$/.test(value)) throw new Error("Invalid encrypted object encoding")
  const bytes = Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), character => character.charCodeAt(0))
  if (encodeBlindBytes(bytes) !== value) throw new Error("Non-canonical encrypted object encoding")
  return bytes
}

function binding(scopeId: string, keyEpoch: number): Uint8Array<ArrayBuffer> {
  if (!scopePattern.test(scopeId) || !Number.isSafeInteger(keyEpoch) || keyEpoch < 1) throw new Error("Invalid encrypted object scope or epoch")
  return new Uint8Array(encoder.encode(`RUSTY/2/object\0${scopeId}\0${keyEpoch}`))
}

function purposeBinding(input: PurposeBoundBinding): { value: PurposeBoundBinding; additionalData: Uint8Array<ArrayBuffer> } {
  const value = structuredClone(input)
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Object.keys(value).length !== 4 || !["purpose", "subjectId", "scopeId", "keyEpoch"].every(key => Object.hasOwn(value, key)) ||
      !purposeValues.has(value.purpose) || typeof value.subjectId !== "string" || !value.subjectId.trim() || value.subjectId.length > 512 ||
      !scopePattern.test(value.scopeId) || !Number.isSafeInteger(value.keyEpoch) || value.keyEpoch < 1) {
    throw new Error("Invalid purpose-bound encrypted object binding")
  }
  const context = JSON.stringify([value.purpose, value.subjectId, value.scopeId, value.keyEpoch])
  return { value, additionalData: new Uint8Array(encoder.encode(`RUSTY/2/purpose-bound-object\0${context}`)) }
}

async function contentKey(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (key.length !== 32) throw new Error("Content key must contain 32 bytes")
  return crypto.subtle.importKey("raw", new Uint8Array(key), "AES-GCM", false, [usage])
}

export async function encryptBlindObject(scopeId: string, keyEpoch: number, key: Uint8Array, plaintext: Uint8Array): Promise<BlindObject> {
  const additionalData = binding(scopeId, keyEpoch)
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
    await contentKey(key, "encrypt"), new Uint8Array(plaintext))
  return { version: 1, scopeId, keyEpoch, nonce: encodeBlindBytes(nonce), ciphertext: encodeBlindBytes(new Uint8Array(ciphertext)) }
}

export async function decryptBlindObject(object: BlindObject, scopeId: string, keyEpoch: number, key: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  if (object.version !== 1 || object.scopeId !== scopeId || object.keyEpoch !== keyEpoch) throw new Error("Encrypted object does not match scope/epoch")
  const nonce = decodeBlindBytes(object.nonce), ciphertext = decodeBlindBytes(object.ciphertext)
  if (nonce.length !== 12 || ciphertext.length < 16) throw new Error("Invalid encrypted object")
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: binding(scopeId, keyEpoch), tagLength: 128 },
    await contentKey(key, "decrypt"), ciphertext)
  return new Uint8Array(plaintext)
}

/** Encrypt with purpose and subject bound into AAD while retaining the opaque v1 wire shape. */
export async function encryptPurposeBoundObject(bindingInput: PurposeBoundBinding, key: Uint8Array,
  plaintext: Uint8Array): Promise<BlindObject> {
  const { value, additionalData } = purposeBinding(bindingInput)
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
    await contentKey(new Uint8Array(key), "encrypt"), new Uint8Array(plaintext))
  return { version: 1, scopeId: value.scopeId, keyEpoch: value.keyEpoch,
    nonce: encodeBlindBytes(nonce), ciphertext: encodeBlindBytes(new Uint8Array(ciphertext)) }
}

/** Decrypt only when every private application scope binding matches authenticated AAD. */
export async function decryptPurposeBoundObject(object: BlindObject, bindingInput: PurposeBoundBinding,
  key: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const { value, additionalData } = purposeBinding(bindingInput)
  if (!object || object.version !== 1 || object.scopeId !== value.scopeId || object.keyEpoch !== value.keyEpoch) {
    throw new Error("Encrypted object does not match purpose-bound scope/epoch")
  }
  const nonce = decodeBlindBytes(object.nonce), ciphertext = decodeBlindBytes(object.ciphertext)
  if (nonce.length !== 12 || ciphertext.length < 16) throw new Error("Invalid encrypted object")
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
    await contentKey(new Uint8Array(key), "decrypt"), ciphertext)
  return new Uint8Array(plaintext)
}

export function canonicalRustyJson(value: unknown): string { return canonicalizeJson(value) }
export async function rustyHash(bytes: Uint8Array): Promise<string> { return sha256Base64Url(new Uint8Array(bytes)) }
export async function rustyObjectId(object: BlindObject): Promise<string> {
  return rustyHash(encoder.encode(canonicalRustyJson(object)))
}

export async function fetchRusty(url: string, init: RequestInit, fetcher: RustyFetch = fetch): Promise<Response> {
  const response = await fetcher(url, { ...init, redirect: "manual" })
  if (response.redirected || response.status >= 300 && response.status < 400) {
    await response.body?.cancel().catch(() => {})
    throw new Error("Rusty redirects are not allowed")
  }
  return response
}

/** Read a JSON body with a caller-tightened bound; over-budget reads cancel the source stream. */
export async function readRustyJson(response: Response, maximumBytes = 32 * 1024 * 1024): Promise<unknown> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) throw new Error("Invalid Rusty response limit")
  const declared = response.headers.get("Content-Length")
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
    await response.body?.cancel().catch(() => {})
    throw new RustyResponseError("Rusty response too large", { status: response.status })
  }
  const reader = response.body?.getReader()
  if (!reader) throw new RustyResponseError("Empty Rusty response", { status: response.status })
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    for (;;) {
      const chunk = await reader.read()
      if (chunk.done) break
      if (chunk.value.length > maximumBytes - length) throw new Error("Rusty response too large")
      length += chunk.value.length
      chunks.push(chunk.value)
    }
  } catch (error) {
    await reader.cancel().catch(() => {})
    if (error instanceof RustyResponseError) throw error
    throw new RustyResponseError(error instanceof Error ? error.message : "Rusty response read failed",
      { status: response.status, cause: error })
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
  let value: unknown
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) }
  catch { throw new RustyResponseError("Invalid Rusty JSON response", { status: response.status }) }
  if (!response.ok) {
    const detail = value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}
    throw new RustyResponseError(typeof detail.message === "string" ? detail.message : `Rusty returned HTTP ${response.status}`,
      { code: detail.code, status: response.status })
  }
  return value
}

export async function verifyRustyStorageReceipt(receipt: RustyStorageReceipt, access: RustyReplicaAccess,
  object: BlindObject, requestId: string): Promise<void> {
  const payload = receipt?.payload
  const serviceId = await publicKeyId(access.servicePublicKey)
  const objectId = await rustyObjectId(object)
  const expected: RustyStorageReceipt["payload"] = { kind: "blind-storage-receipt", version: 2, serviceId,
    scopeId: access.scopeId, keyEpoch: object.keyEpoch, objectId, sequence: payload?.sequence,
    policyRevision: access.policyRevision, requestId }
  if (!payload || !Number.isSafeInteger(payload.sequence) || payload.sequence < 1 ||
      !Number.isSafeInteger(payload.keyEpoch) || payload.keyEpoch < 1 || receipt.signerKeyId !== serviceId ||
      canonicalRustyJson(payload) !== canonicalRustyJson(expected) ||
      !await verifyEnvelope(receipt, access.servicePublicKey, "RUSTY/2")) {
    throw new Error("Rusty receipt does not cover this encrypted object")
  }
}

export function rustyProducerHeaders(access: RustyReplicaAccess): Record<string, string> {
  return { "X-Rusty-Client": access.client ?? "mesh-replication",
    ...(access.clientBuild && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(access.clientBuild) ? { "X-Rusty-Build": access.clientBuild } : {}) }
}

export async function uploadRustyObject(access: RustyReplicaAccess, object: BlindObject, requestId: string,
  observedSequence = 0, fetcher: RustyFetch = fetch): Promise<RustyStorageReceipt> {
  if (!Number.isSafeInteger(observedSequence) || observedSequence < 0 ||
      typeof requestId !== "string" || !/^[\x21-\x7e]{1,128}$/.test(requestId)) throw new Error("Invalid Rusty upload request")
  const id = await rustyObjectId(object)
  const response = await fetchRusty(`${rustyOrigin(access.origin)}/v2/scopes/${encodeURIComponent(access.scopeId)}/objects/${id}?writerVersion=2&observedSequence=${observedSequence}`, {
    method: "PUT", signal: AbortSignal.timeout(30000),
    headers: { ...rustyProducerHeaders(access), Authorization: `Bearer ${access.writeToken}`, "Content-Type": "application/json", "X-Rusty-Request-Id": requestId },
    body: JSON.stringify(object),
  }, fetcher)
  const receipt = await readRustyJson(response, 16 * 1024) as RustyStorageReceipt
  await verifyRustyStorageReceipt(receipt, access, object, requestId)
  return receipt
}

export async function inventoryRustyObjects(access: RustyReplicaAccess, after: number, fetcher: RustyFetch = fetch): Promise<{
  objects: Array<{ objectId: string; sequence: number }>; cursor: number; hasMore: boolean; objectCount?: number; maxSequence?: number
}> {
  if (!Number.isSafeInteger(after) || after < 0) throw new Error("Invalid Rusty inventory cursor")
  const result = await readRustyJson(await fetchRusty(`${rustyOrigin(access.origin)}/v2/scopes/${encodeURIComponent(access.scopeId)}/objects?after=${after}`, {
    signal: AbortSignal.timeout(15000), headers: { ...rustyProducerHeaders(access), Authorization: `Bearer ${access.readToken}` },
  }, fetcher), 64 * 1024) as {
    objects: Array<{ objectId: string; sequence: number }>; cursor: number; hasMore: boolean; objectCount?: number; maxSequence?: number
  }
  if (!Array.isArray(result.objects) || result.objects.length > 128 || typeof result.hasMore !== "boolean" ||
      !Number.isSafeInteger(result.cursor) || result.cursor < after ||
      result.objects.some((object, index) => !/^[A-Za-z0-9_-]{43}$/.test(object.objectId) || !Number.isSafeInteger(object.sequence) ||
        object.sequence <= (result.objects[index - 1]?.sequence ?? after)) ||
      result.cursor !== (result.objects.at(-1)?.sequence ?? after) || result.hasMore && result.objects.length === 0) {
    throw new Error("Invalid Rusty inventory")
  }
  if (result.objectCount !== undefined && (!Number.isSafeInteger(result.objectCount) || result.objectCount < 0 || result.objectCount > 10001) ||
      result.maxSequence !== undefined && (!Number.isSafeInteger(result.maxSequence) || result.maxSequence < result.cursor ||
        !result.hasMore && result.maxSequence !== result.cursor)) throw new Error("Invalid Rusty checkpoint inventory")
  return result
}

export async function downloadRustyObject(access: RustyReplicaAccess, id: string, fetcher: RustyFetch = fetch): Promise<BlindObject> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(id)) throw new Error("Invalid encrypted object ID")
  const object = await readRustyJson(await fetchRusty(`${rustyOrigin(access.origin)}/v2/scopes/${encodeURIComponent(access.scopeId)}/objects/${id}`, {
    signal: AbortSignal.timeout(30000), headers: { ...rustyProducerHeaders(access), Authorization: `Bearer ${access.readToken}` },
  }, fetcher)) as BlindObject
  if (object.scopeId !== access.scopeId || await rustyObjectId(object) !== id) throw new Error("Rusty object integrity failure")
  return object
}

export { fromBase64Url as decodeRustyBase64Url, toBase64Url as encodeRustyBase64Url }
