import { canonicalizeJson, sha256Base64Url, publicKeyId, fromBase64Url, toBase64Url, verifyEnvelope, type SignedEnvelope } from "@meta-uber/mesh-identity"
import { captureEncryptedArchiveObject, type EncryptedArchiveObject } from "./historyArchiveCrypto"
import { validateArchiveObjectId } from "./historyArchive"
import { archiveCoverageBranch, captureArchiveCoverageChild, verifyArchiveCoverageChild, type ArchiveCoverageObject,
  type ArchiveCoverageBatchReceipt, type ArchiveCoverageAggregateReceipt } from "./historyArchiveCoverage"
export type { ArchiveCoverageObject, ArchiveCoverageBatchReceipt, ArchiveCoverageAggregateReceipt, ArchiveCoverageChild } from "./historyArchiveCoverage"

export type ArchiveRemoteAccess = {
  origin: string; scopeId: string; policyRevision: number; servicePublicKey: string
  readToken: string; writeToken: string
}
export type ArchiveStorageReceipt = SignedEnvelope<{ kind: "blind-archive-storage-receipt"; version: 1;
  serviceId: string; scopeId: string; policyRevision: number; requestId: string; objectId: string; keyEpoch: number }>
export type ArchiveRemotePort = { fetch: typeof fetch; ensureCurrent: () => void | Promise<void> }

export class ArchiveRemoteError extends Error {
  readonly status: number
  readonly code: string
  constructor(status: number, body: unknown) {
    const detail = body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : {}
    const message = typeof detail.message === "string" && detail.message.length <= 512 ? detail.message : "Request failed"
    super(`Rusty archive HTTP ${status}: ${message}`)
    this.name = "ArchiveRemoteError"
    this.status = status
    const known: Record<number, string> = { 403: "access_denied", 404: "object_unavailable", 409: "conflict",
      426: "writer_upgrade_required", 507: "capacity_exceeded", 503: "storage_unavailable" }
    this.code = typeof detail.code === "string" && /^[a-z0-9_]{1,64}$/.test(detail.code) ? detail.code : known[status] ?? `http_${status}`
  }
}

const encoder = new TextEncoder()
function fail(message: string): never { throw new Error(message) }
function positive(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail("Invalid archive remote revision or epoch")
}
function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail("Invalid archive remote schema")
}
function challenge(value: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{20,64}$/.test(value)) fail("Invalid archive remote request ID")
  return value
}
function canonicalBytes(value: unknown): Uint8Array { return encoder.encode(canonicalizeJson(value)) }
function accessSnapshot(input: ArchiveRemoteAccess): ArchiveRemoteAccess {
  const access = structuredClone(input)
  if (!access || typeof access !== "object" || typeof access.origin !== "string" ||
      typeof access.scopeId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(access.scopeId)) fail("Invalid archive remote access")
  positive(access.policyRevision)
  const origin = new URL(access.origin)
  const local = ["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname)
  if (origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash ||
      origin.protocol !== "https:" && !(origin.protocol === "http:" && local)) fail("Invalid archive remote origin")
  for (const token of [access.readToken, access.writeToken]) {
    if (typeof token !== "string" || !/^[\x21-\x7e]{1,512}$/.test(token)) fail("Invalid archive remote credential")
  }
  validateArchiveObjectId(access.servicePublicKey)
  return { ...access, origin: origin.origin }
}
function entriesSnapshot(input: unknown): ArchiveCoverageObject[] {
  if (!Array.isArray(input) || input.length < 1 || input.length > 64) fail("Invalid archive coverage batch size")
  const entries = input.map(item => {
    exact(item, ["objectId", "keyEpoch"])
    validateArchiveObjectId(item.objectId); positive(item.keyEpoch)
    return { objectId: item.objectId, keyEpoch: item.keyEpoch }
  }).sort((left, right) => left.objectId < right.objectId ? -1 : left.objectId > right.objectId ? 1 : 0)
  if (entries.some((entry, i) => i > 0 && entries[i - 1]!.objectId === entry.objectId)) fail("Duplicate archive coverage object")
  return entries
}

async function readJson(response: Response, maximum: number): Promise<unknown> {
  const declared = response.headers.get("Content-Length")
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum)) {
    await response.body?.cancel().catch(() => {})
    fail("Archive remote response exceeds size limit")
  }
  const reader = response.body?.getReader()
  if (!reader && !response.ok) throw new ArchiveRemoteError(response.status, undefined)
  if (!reader) fail("Archive remote response body unavailable")
  let size = 0
  const parts: Uint8Array[] = []
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (!(value instanceof Uint8Array) || value.length > maximum - size) fail("Archive remote response exceeds size limit")
      size += value.length; parts.push(value)
    }
    const bytes = new Uint8Array(size)
    let offset = 0
    for (const part of parts) { bytes.set(part, offset); offset += part.length }
    let value: unknown
    try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) }
    catch { if (response.ok) fail("Invalid archive remote JSON") }
    if (!response.ok) throw new ArchiveRemoteError(response.status, value)
    return value
  } catch (error) {
    await reader.cancel().catch(() => {})
    throw error
  } finally { reader.releaseLock() }
}

/** Shared browser/Worker transport. Callers persist ciphertext/request IDs and provide a live session/authority guard. */
export function createArchiveRemote(accessInput: ArchiveRemoteAccess, port: ArchiveRemotePort) {
  const access = accessSnapshot(accessInput)
  if (typeof port?.fetch !== "function" || typeof port.ensureCurrent !== "function") fail("Archive remote requires a live authority guard")
  const fetcher = port.fetch, guard = port.ensureCurrent
  let serviceId: string | undefined
  const identity = async () => serviceId ??= await publicKeyId(access.servicePublicKey)
  const request = async (path: string, method: string, token: string, body?: unknown, requestId?: string, maximum = 16 * 1024) => {
    await guard()
    const response = await fetcher(`${access.origin}/v2/scopes/${access.scopeId}/${path}`, { method, redirect: "manual",
      signal: AbortSignal.timeout(30000), headers: { Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(requestId === undefined ? {} : { "X-Rusty-Request-Id": requestId }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) })
    try { await guard() } catch (error) { await response.body?.cancel().catch(() => {}); throw error }
    if (response.redirected || response.status >= 300 && response.status < 400) {
      await response.body?.cancel().catch(() => {})
      fail("Rusty archive redirects are not allowed")
    }
    const value = await readJson(response, maximum)
    await guard()
    return value
  }
  const verifiedReceipt = async <T extends { kind: string }>(input: unknown, expected: T): Promise<SignedEnvelope<T>> => {
    exact(input, ["payload", "signerKeyId", "signature"])
    if (input.signerKeyId !== await identity() || typeof input.signature !== "string" ||
        canonicalizeJson(input.payload) !== canonicalizeJson(expected)) fail("Archive receipt does not cover this exact request")
    const signature = fromBase64Url(input.signature)
    if (signature.length !== 64 || toBase64Url(signature) !== input.signature) fail("Invalid archive receipt signature encoding")
    const receipt = input as SignedEnvelope<T>
    if (!await verifyEnvelope(receipt, access.servicePublicKey, "RUSTY/2")) fail("Archive receipt signature invalid")
    await guard()
    return receipt
  }
  return {
    async upload(objectInput: EncryptedArchiveObject, requestIdInput: string): Promise<ArchiveStorageReceipt> {
      const object = captureEncryptedArchiveObject(objectInput, access.scopeId), requestId = challenge(requestIdInput)
      await guard()
      const objectId = await sha256Base64Url(canonicalBytes(object))
      const expected: ArchiveStorageReceipt["payload"] = { kind: "blind-archive-storage-receipt", version: 1,
        serviceId: await identity(), scopeId: access.scopeId, policyRevision: access.policyRevision,
        requestId, objectId, keyEpoch: object.keyEpoch }
      return verifiedReceipt(await request(`archives/${objectId}?writerVersion=2`, "PUT", access.writeToken, object, requestId), expected)
    },
    async download(id: string): Promise<EncryptedArchiveObject> {
      validateArchiveObjectId(id)
      const object = captureEncryptedArchiveObject(await request(`archives/${id}`, "GET", access.readToken,
        undefined, undefined, 360 * 1024), access.scopeId)
      if (await sha256Base64Url(canonicalBytes(object)) !== id) fail("Archive remote ciphertext hash integrity failure")
      await guard()
      return object
    },
    async coverage(objectsInput: ArchiveCoverageObject[], requestIdInput: string): Promise<ArchiveCoverageBatchReceipt> {
      const objects = entriesSnapshot(objectsInput), requestId = challenge(requestIdInput)
      await guard()
      const expected: ArchiveCoverageBatchReceipt["payload"] = { kind: "blind-archive-coverage-batch-receipt", version: 1,
        serviceId: await identity(), scopeId: access.scopeId, policyRevision: access.policyRevision, requestId, objects }
      return verifiedReceipt(await request("archive-coverage", "POST", access.readToken, { version: 1, requestId, objects }), expected)
    },
    async aggregate(archiveRootId: string, input: unknown[], requestIdInput: string): Promise<ArchiveCoverageAggregateReceipt> {
      validateArchiveObjectId(archiveRootId)
      const requestId = challenge(requestIdInput)
      if (!Array.isArray(input) || input.length < 1 || input.length > 8) fail("Invalid archive coverage aggregate size")
      const children = input.map(captureArchiveCoverageChild)
      const body = { version: 1, requestId, archiveRootId, children }
      if (encoder.encode(JSON.stringify(body)).length > 64 * 1024) fail("Archive coverage request exceeds size limit")
      await guard()
      const summaries = []
      for (const child of children) summaries.push(await verifyArchiveCoverageChild(child, access, archiveRootId))
      const summary = await archiveCoverageBranch(archiveRootId, summaries)
      const expected: ArchiveCoverageAggregateReceipt["payload"] = { kind: "blind-archive-coverage-aggregate-receipt", version: 1,
        serviceId: await identity(), scopeId: access.scopeId, policyRevision: access.policyRevision, requestId, archiveRootId, ...summary }
      return verifiedReceipt(await request("archive-coverage/aggregate", "POST", access.readToken, body), expected)
    },
  }
}
