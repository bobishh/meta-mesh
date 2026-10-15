import { blake3 } from "@noble/hashes/blake3.js"
import { bytesToHex } from "@noble/hashes/utils.js"
import { decodePairingFrame, encodePairingFrame, inspectPairingFrame } from "@meta-uber/mesh-pairing"
import type { MeshConnection, MeshStream } from "@meta-uber/mesh-transport"
import type { MeshStore } from "../../mesh-browser-store/src/index"
import type { BlobByteSource } from "./stream"
import type { BlobStreamWriteOptions } from "./streamStore"
import { BLOB_CHUNK_BYTES, MAX_BLOB_BYTES, normalizeName, normalizeMediaType, isValidBlobId,
  validateBlobDescriptor, createBlobDescriptorFromId, type BlobDescriptor } from "./descriptor"
export { BLOB_CHUNK_BYTES, MAX_BLOB_BYTES, isValidBlobId, validateBlobDescriptor, createBlobDescriptorFromId, type BlobDescriptor } from "./descriptor"
import {
  fromBase64Url,
  signEnvelope,
  toBase64Url,
  verifyDeviceCertificateChain,
  verifyEnvelope,
  type DeviceCertificate,
  type LocalProfile,
  type PublicIdentity,
  type SignedEnvelope,
} from "../../mesh-identity/src/index"

export const BLOB_SIGNATURE_DOMAIN = "MESH-BLOB/1"
export const MAX_ATTACHMENTS = 4
export const BLOB_REQUEST_FRAME = "mesh-blob-request-v1"
export const BLOB_RESPONSE_FRAME = "mesh-blob-response-v1"
export const BLOB_ERROR_FRAME = "mesh-blob-error-v1"
const MAX_TIMER_DELAY_MS = 2_147_483_647
// One base64url chunk plus bounded response metadata and the pairing header.
const MAX_BLOB_RESPONSE_FRAME_BYTES = Math.ceil(BLOB_CHUNK_BYTES / 3) * 4 + 4096

type MaybePromise<T> = T | Promise<T>

export interface BlobEngineInterface {
  createBlob(data: Uint8Array, name: string, mediaType: string, nodeEndpoint?: string | null): MaybePromise<BlobDescriptor>
  putBlob(hash: string, data: Uint8Array): MaybePromise<void>
  getBlob(hash: string): MaybePromise<Uint8Array | undefined>
  hasBlob(hash: string): MaybePromise<boolean>
  verifyBlob(hash: string, data: Uint8Array): MaybePromise<boolean>
  fetchBlob?(ticket: string): MaybePromise<Uint8Array>
}

export type BlobRequestPayload = {
  kind: "blob-request"
  version: 1
  requestId: string
  conversationId: string
  blobId: string
  requesterPersonId: string
  requesterDeviceId: string
  offset: number
  length: number
  createdAt: string
}

export type BlobRequest = SignedEnvelope<BlobRequestPayload>

export type BlobResponse = {
  kind: "blob-response"
  version: 1
  requestId: string
  blobId: string
  offset: number
  totalSize: number
  data: string
}

export type RequestBlobOptions = {
  /** Abort pending stream I/O without closing the owning mesh connection. */
  signal?: AbortSignal
  /** Revalidate caller-owned authority at each chunk boundary and after pending I/O. */
  ensureCurrent?: () => void | Promise<void>
  /** Absolute deadline in epoch milliseconds for the complete transfer. */
  deadlineAt?: number
}


export async function blobIdFor(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return `sha256:${toBase64Url(new Uint8Array(digest))}`
}

export function blake3HashFor(bytes: Uint8Array): string {
  return bytesToHex(blake3(bytes))
}

export async function createBlobDescriptor(bytes: Uint8Array, name: string, mediaType: string): Promise<BlobDescriptor> {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_BLOB_BYTES) {
    throw new Error(`File must be 1 byte–${MAX_BLOB_BYTES / 1024 / 1024} MiB`)
  }
  return createBlobDescriptorFromId(await blobIdFor(bytes), bytes.byteLength, name, mediaType)
}

export async function createIrohBlobDescriptor(
  engine: BlobEngineInterface,
  bytes: Uint8Array,
  name: string,
  mediaType: string,
  nodeEndpoint?: string | null,
): Promise<BlobDescriptor> {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_BLOB_BYTES) {
    throw new Error(`File must be 1 byte–${MAX_BLOB_BYTES / 1024 / 1024} MiB`)
  }
  const descriptor = await engine.createBlob(bytes, normalizeName(name), normalizeMediaType(mediaType), nodeEndpoint)
  return validateBlobDescriptor(descriptor)
}

export async function verifyBlobBytes(descriptor: BlobDescriptor, bytes: Uint8Array, engine?: BlobEngineInterface): Promise<Uint8Array> {
  validateBlobDescriptor(descriptor)
  if (bytes.byteLength !== descriptor.size) {
    throw new Error("Blob content does not match descriptor")
  }
  if (descriptor.blobId.startsWith("blake3:")) {
    const hash = descriptor.blobId.slice(7)
    const valid = engine ? await engine.verifyBlob(hash, bytes) : bytesToHex(blake3(bytes)) === hash.toLowerCase()
    if (!valid) throw new Error("Blob content does not match descriptor")
  } else {
    if (await blobIdFor(bytes) !== descriptor.blobId) {
      throw new Error("Blob content does not match descriptor")
    }
  }
  return bytes
}

export async function createBlobRequest(
  profile: LocalProfile,
  conversationId: string,
  blobId: string,
  offset: number,
  length = BLOB_CHUNK_BYTES,
  now = Date.now(),
): Promise<BlobRequest> {
  if (!conversationId || !isValidBlobId(blobId) ||
    !Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1 || length > BLOB_CHUNK_BYTES) {
    throw new Error("Invalid blob request")
  }
  return signEnvelope(profile.privateKeys.devicePrivateKey, {
    kind: "blob-request", version: 1, requestId: crypto.randomUUID(), conversationId, blobId,
    requesterPersonId: profile.identity.personId, requesterDeviceId: profile.device.deviceId,
    offset, length, createdAt: new Date(now).toISOString(),
  }, profile.device.deviceId, BLOB_SIGNATURE_DOMAIN)
}

export async function verifyBlobRequest(
  request: BlobRequest,
  identity: PublicIdentity,
  certificates: DeviceCertificate[],
  conversationId: string,
  now = Date.now(),
): Promise<BlobRequest> {
  const payload = request?.payload
  if (!payload || payload.kind !== "blob-request" || payload.version !== 1 ||
    payload.conversationId !== conversationId || payload.requesterPersonId !== identity.personId ||
    payload.requesterDeviceId !== request.signerKeyId || !payload.requestId ||
    !isValidBlobId(payload.blobId) ||
    !Number.isSafeInteger(payload.offset) || payload.offset < 0 ||
    !Number.isSafeInteger(payload.length) || payload.length < 1 || payload.length > BLOB_CHUNK_BYTES) {
    throw new Error("Invalid blob request")
  }
  const timestamp = Date.parse(payload.createdAt)
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > 5 * 60 * 1000) throw new Error("Expired blob request")
  const key = await verifyDeviceCertificateChain(identity, payload.requesterDeviceId, certificates)
  if (!await verifyEnvelope(request, key, BLOB_SIGNATURE_DOMAIN)) throw new Error("Invalid blob request signature")
  return request
}

export function createBlobResponse(
  request: BlobRequest,
  descriptor: BlobDescriptor,
  bytes: Uint8Array,
): BlobResponse {
  validateBlobDescriptor(descriptor)
  const { offset, length } = request.payload
  if (request.payload.blobId !== descriptor.blobId || offset >= descriptor.size || bytes.byteLength > length ||
    bytes.byteLength !== Math.min(length, descriptor.size - offset)) throw new Error("Invalid blob response range")
  return {
    kind: "blob-response", version: 1, requestId: request.payload.requestId,
    blobId: descriptor.blobId, offset, totalSize: descriptor.size, data: toBase64Url(bytes),
  }
}

export function verifyBlobResponse(response: BlobResponse, request: BlobRequest, descriptor: BlobDescriptor): Uint8Array {
  validateBlobDescriptor(descriptor)
  const bytes = fromBase64Url(response?.data ?? "")
  if (response?.kind !== "blob-response" || response.version !== 1 ||
    response.requestId !== request.payload.requestId || response.blobId !== descriptor.blobId ||
    response.offset !== request.payload.offset || response.totalSize !== descriptor.size ||
    bytes.byteLength !== Math.min(request.payload.length, descriptor.size - request.payload.offset)) {
    throw new Error("Invalid blob response")
  }
  return bytes
}

export async function requestBlob(
  connection: Pick<MeshConnection, "openStream">,
  secret: string,
  profile: LocalProfile,
  scopeId: string,
  descriptor: BlobDescriptor,
  options: RequestBlobOptions = {},
): Promise<Uint8Array> {
  const captured = {
    secret,
    profile: structuredClone(profile),
    scopeId,
    descriptor: structuredClone(descriptor),
    signal: options.signal,
    ensureCurrent: options.ensureCurrent,
    deadlineAt: options.deadlineAt,
  }
  validateBlobDescriptor(captured.descriptor)
  if (captured.deadlineAt !== undefined && (!Number.isSafeInteger(captured.deadlineAt) || captured.deadlineAt < 0)) {
    throw new Error("Invalid blob transfer deadline")
  }
  const result = new Uint8Array(captured.descriptor.size)
  for (let offset = 0; offset < captured.descriptor.size; offset += BLOB_CHUNK_BYTES) {
    await ensureBlobCurrent(captured)
    const request = await awaitBlobOperation(() =>
      createBlobRequest(captured.profile, captured.scopeId, captured.descriptor.blobId, offset), captured)
    await ensureBlobCurrent(captured)
    let stream: MeshStream | undefined
    let sendClosed = false
    try {
      stream = await awaitBlobOperation(() => connection.openStream(), captured, candidate => {
        releaseBlobStream(candidate, true)
      })
      await ensureBlobCurrent(captured)
      await awaitBlobOperation(() => stream!.send(encodePairingFrame(BLOB_REQUEST_FRAME, captured.secret, encodeJson(request))), captured)
      await ensureBlobCurrent(captured)
      await awaitBlobOperation(() => stream!.closeSend(), captured)
      sendClosed = true
      await ensureBlobCurrent(captured)
      const frame = await awaitBlobOperation(() => stream!.read(MAX_BLOB_RESPONSE_FRAME_BYTES), captured)
      await ensureBlobCurrent(captured)
      if (frame.byteLength > MAX_BLOB_RESPONSE_FRAME_BYTES) throw new Error("Blob response frame is too large")
      const type = inspectPairingFrame(frame).type
      if (type === BLOB_ERROR_FRAME) {
        const failure = decodeJson(decodePairingFrame(frame, BLOB_ERROR_FRAME, captured.secret)) as { message?: unknown }
        throw new Error(typeof failure.message === "string" ? failure.message : "Blob transfer failed")
      }
      const response = decodeJson(decodePairingFrame(frame, BLOB_RESPONSE_FRAME, captured.secret)) as BlobResponse
      result.set(verifyBlobResponse(response, request, captured.descriptor), offset)
    } finally {
      if (stream) releaseBlobStream(stream, !sendClosed)
    }
  }
  await ensureBlobCurrent(captured)
  const verified = await awaitBlobOperation(() => verifyBlobBytes(captured.descriptor, result), captured)
  await ensureBlobCurrent(captured)
  return verified
}

type CapturedBlobRequestOptions = {
  signal?: AbortSignal
  ensureCurrent?: RequestBlobOptions["ensureCurrent"]
  deadlineAt?: number
}

async function ensureBlobCurrent(options: CapturedBlobRequestOptions): Promise<void> {
  if (options.signal?.aborted) throw blobAbortError(options.signal)
  if (options.deadlineAt !== undefined && Date.now() >= options.deadlineAt) throw new Error("Blob transfer deadline exceeded")
  if (options.ensureCurrent) await awaitBlobOperation(() => options.ensureCurrent!(), options)
  if (options.signal?.aborted) throw blobAbortError(options.signal)
  if (options.deadlineAt !== undefined && Date.now() >= options.deadlineAt) throw new Error("Blob transfer deadline exceeded")
}

function awaitBlobOperation<T>(
  operation: () => Promise<T> | T,
  options: CapturedBlobRequestOptions,
  onLate?: (value: T) => void,
): Promise<T> {
  const { signal, deadlineAt } = options
  if (signal?.aborted) return Promise.reject(blobAbortError(signal))
  if (deadlineAt !== undefined && Date.now() >= deadlineAt) {
    return Promise.reject(new Error("Blob transfer deadline exceeded"))
  }
  const pending = Promise.resolve().then(() => {
    if (signal?.aborted) throw blobAbortError(signal)
    if (deadlineAt !== undefined && Date.now() >= deadlineAt) throw new Error("Blob transfer deadline exceeded")
    return operation()
  })
  if (!signal && deadlineAt === undefined) return pending
  return new Promise<T>((resolve, reject) => {
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer)
      signal?.removeEventListener("abort", onAbort)
    }
    const finish = (complete: () => void) => {
      if (settled) return
      settled = true
      cleanup()
      complete()
    }
    const onAbort = () => finish(() => reject(blobAbortError(signal!)))
    signal?.addEventListener("abort", onAbort, { once: true })
    if (signal?.aborted) onAbort()
    if (!settled && deadlineAt !== undefined) {
      const scheduleDeadlineCheck = () => {
        const remaining = deadlineAt - Date.now()
        if (remaining <= 0) finish(() => reject(new Error("Blob transfer deadline exceeded")))
        else timer = setTimeout(scheduleDeadlineCheck, Math.min(remaining, MAX_TIMER_DELAY_MS))
      }
      scheduleDeadlineCheck()
    }
    pending.then(value => {
      if (settled) { onLate?.(value); return }
      finish(() => resolve(value))
    }, error => finish(() => reject(error)))
  })
}

function blobAbortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("Blob transfer aborted")
}

function releaseBlobStream(stream: MeshStream, closeSend: boolean): void {
  try {
    if (stream.reset) { void Promise.resolve(stream.reset()).catch(() => undefined); return }
    if (closeSend) void Promise.resolve(stream.closeSend()).catch(() => undefined)
  }
  catch { /* Best-effort stream cleanup must preserve the transfer error. */ }
}

export async function respondToBlobRequest(
  stream: Pick<MeshStream, "send" | "closeSend">,
  frame: Uint8Array,
  options: {
    secret: string
    scopeId: string
    identity: PublicIdentity
    certificates: DeviceCertificate[]
    descriptor(blobId: string): Promise<BlobDescriptor | undefined>
    bytes(descriptor: BlobDescriptor): Promise<Uint8Array | undefined>
  },
): Promise<void> {
  let requestId = ""
  try {
    const request = decodeJson(decodePairingFrame(frame, BLOB_REQUEST_FRAME, options.secret)) as BlobRequest
    requestId = request?.payload?.requestId ?? ""
    await verifyBlobRequest(request, options.identity, options.certificates, options.scopeId)
    const descriptor = await options.descriptor(request.payload.blobId)
    if (!descriptor || descriptor.blobId !== request.payload.blobId) throw new Error("Blob is not referenced by this workspace")
    const bytes = await options.bytes(descriptor)
    if (!bytes) throw new Error("Blob is not available on this peer")
    await verifyBlobBytes(descriptor, bytes)
    const { offset, length } = request.payload
    if (offset >= bytes.byteLength) throw new Error("Blob request range is outside the file")
    const response = createBlobResponse(request, descriptor, bytes.slice(offset, Math.min(offset + length, bytes.byteLength)))
    await stream.send(encodePairingFrame(BLOB_RESPONSE_FRAME, options.secret, encodeJson(response)))
  } catch (error) {
    const message = (error instanceof Error ? error.message : String(error)).slice(0, 240)
    await stream.send(encodePairingFrame(BLOB_ERROR_FRAME, options.secret, encodeJson({ version: 1, requestId, message })))
  } finally {
    await stream.closeSend()
  }
}

function encodeJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value))
}

function decodeJson(bytes: Uint8Array): unknown {
  try { return JSON.parse(new TextDecoder().decode(bytes)) }
  catch { throw new Error("Invalid blob transfer frame") }
}

export class MeshBlobStore {
  constructor(
    private readonly store: MeshStore,
    private readonly storeName = "blobs",
    private readonly engine?: BlobEngineInterface,
  ) {}

  async putStream(descriptor: BlobDescriptor, source: BlobByteSource, options?: BlobStreamWriteOptions): Promise<void> {
    const captured = { ...validateBlobDescriptor(descriptor) }
    const ensureCurrent = options?.ensureCurrent
    return (await import("./streamStore")).putBlobStream(this.store, this.storeName, captured, source, { ensureCurrent })
  }

  async getStream(descriptor: BlobDescriptor): Promise<BlobByteSource | undefined> {
    const captured = { ...validateBlobDescriptor(descriptor) }
    return (await import("./streamStore")).readBlobStream(this.store, this.storeName, captured)
  }

  async put(descriptor: BlobDescriptor, bytes: Uint8Array): Promise<void> {
    await verifyBlobBytes(descriptor, bytes, this.engine)
    if (this.engine) {
      const hash = descriptor.hash ?? (descriptor.blobId.startsWith("blake3:") ? descriptor.blobId.replace("blake3:", "") : undefined)
      if (hash) {
        await this.engine.putBlob(hash, bytes)
      }
    }
    await this.store.put(this.storeName, descriptor.blobId, bytes)
  }

  async putUnsafe(blobId: string, bytes: Uint8Array): Promise<void> {
    await this.store.put(this.storeName, blobId, bytes)
  }

  async get(blobId: string): Promise<Uint8Array | undefined> {
    const streamed = await (await import("./streamStore")).collectStoredBlob(this.store, this.storeName, blobId)
    if (streamed) return streamed
    if (this.engine) {
      const hash = blobId.startsWith("blake3:") ? blobId.replace("blake3:", "") : blobId
      const fromEngine = await this.engine.getBlob(hash)
      if (fromEngine) return fromEngine
    }
    return this.store.get<Uint8Array>(this.storeName, blobId)
  }

  async getVerified(descriptor: BlobDescriptor): Promise<Uint8Array | undefined> {
    let bytes = await this.get(descriptor.blobId)
    if (!bytes && descriptor.hash && this.engine) {
      bytes = await this.engine.getBlob(descriptor.hash)
    }
    return bytes ? verifyBlobBytes(descriptor, bytes, this.engine) : undefined
  }

  async has(descriptor: BlobDescriptor): Promise<boolean> {
    if (this.engine) {
      const hash = descriptor.hash ?? (descriptor.blobId.startsWith("blake3:") ? descriptor.blobId.replace("blake3:", "") : undefined)
      if (hash && await this.engine.hasBlob(hash)) return true
    }
    return Boolean(await this.getVerified(descriptor))
  }
}
