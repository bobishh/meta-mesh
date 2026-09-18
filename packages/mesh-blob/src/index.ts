import type { MeshStore } from "../../mesh-browser-store/src/index"
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
export const MAX_BLOB_BYTES = 8 * 1024 * 1024
export const BLOB_CHUNK_BYTES = 256 * 1024
export const MAX_ATTACHMENTS = 4

export type BlobDescriptor = {
  kind: "blob"
  version: 1
  blobId: string
  name: string
  mediaType: string
  size: number
  hash?: string
  ticket?: string
}

export interface BlobEngineInterface {
  createBlob(data: Uint8Array, name: string, mediaType: string, nodeEndpoint?: string | null): BlobDescriptor
  putBlob(hash: string, data: Uint8Array): void
  getBlob(hash: string): Uint8Array | undefined
  hasBlob(hash: string): boolean
  verifyBlob(hash: string, data: Uint8Array): boolean
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

function normalizeName(value: string): string {
  const name = value.trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 180)
  if (!name) throw new Error("Blob name is required")
  return name
}

function normalizeMediaType(value: string): string {
  const mediaType = value.trim().toLowerCase()
  if (!/^[\w.+-]+\/[\w.+-]+$/.test(mediaType)) return "application/octet-stream"
  return mediaType.slice(0, 120)
}

export function isValidBlobId(blobId: string): boolean {
  return typeof blobId === "string" && (/^sha256:[A-Za-z0-9_-]{43}$/.test(blobId) || /^blake3:[0-9a-fA-F]{64}$/.test(blobId))
}

export function validateBlobDescriptor(value: BlobDescriptor): BlobDescriptor {
  if (value?.kind !== "blob" || value.version !== 1 ||
    !isValidBlobId(value?.blobId) ||
    normalizeName(value.name) !== value.name || normalizeMediaType(value.mediaType) !== value.mediaType ||
    !Number.isSafeInteger(value.size) || value.size < 1 || value.size > MAX_BLOB_BYTES) {
    throw new Error(`Invalid blob descriptor; files must be 1 byte–${MAX_BLOB_BYTES / 1024 / 1024} MiB`)
  }
  return value
}

export async function blobIdFor(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return `sha256:${toBase64Url(new Uint8Array(digest))}`
}

export async function createBlobDescriptor(bytes: Uint8Array, name: string, mediaType: string): Promise<BlobDescriptor> {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_BLOB_BYTES) {
    throw new Error(`File must be 1 byte–${MAX_BLOB_BYTES / 1024 / 1024} MiB`)
  }
  return validateBlobDescriptor({
    kind: "blob", version: 1, blobId: await blobIdFor(bytes),
    name: normalizeName(name), mediaType: normalizeMediaType(mediaType), size: bytes.byteLength,
  })
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
  const descriptor = engine.createBlob(bytes, normalizeName(name), normalizeMediaType(mediaType), nodeEndpoint)
  return validateBlobDescriptor(descriptor)
}

export async function verifyBlobBytes(descriptor: BlobDescriptor, bytes: Uint8Array, engine?: BlobEngineInterface): Promise<Uint8Array> {
  validateBlobDescriptor(descriptor)
  if (bytes.byteLength !== descriptor.size) {
    throw new Error("Blob content does not match descriptor")
  }
  if (descriptor.blobId.startsWith("blake3:")) {
    const hash = descriptor.hash ?? descriptor.blobId.replace("blake3:", "")
    if (engine) {
      if (!engine.verifyBlob(hash, bytes)) {
        throw new Error("Blob content does not match descriptor")
      }
    }
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

export class MeshBlobStore {
  constructor(
    private readonly store: MeshStore,
    private readonly storeName = "blobs",
    private readonly engine?: BlobEngineInterface,
  ) {}

  async put(descriptor: BlobDescriptor, bytes: Uint8Array): Promise<void> {
    await verifyBlobBytes(descriptor, bytes, this.engine)
    if (this.engine) {
      const hash = descriptor.hash ?? (descriptor.blobId.startsWith("blake3:") ? descriptor.blobId.replace("blake3:", "") : undefined)
      if (hash) {
        this.engine.putBlob(hash, bytes)
      }
    }
    await this.store.put(this.storeName, descriptor.blobId, bytes)
  }

  async putUnsafe(blobId: string, bytes: Uint8Array): Promise<void> {
    await this.store.put(this.storeName, blobId, bytes)
  }

  async get(blobId: string): Promise<Uint8Array | undefined> {
    if (this.engine) {
      const hash = blobId.startsWith("blake3:") ? blobId.replace("blake3:", "") : blobId
      const fromEngine = this.engine.getBlob(hash)
      if (fromEngine) return fromEngine
    }
    return this.store.get<Uint8Array>(this.storeName, blobId)
  }

  async getVerified(descriptor: BlobDescriptor): Promise<Uint8Array | undefined> {
    let bytes = await this.get(descriptor.blobId)
    if (!bytes && descriptor.hash && this.engine) {
      bytes = this.engine.getBlob(descriptor.hash)
    }
    return bytes ? verifyBlobBytes(descriptor, bytes, this.engine) : undefined
  }

  async has(descriptor: BlobDescriptor): Promise<boolean> {
    if (this.engine) {
      const hash = descriptor.hash ?? (descriptor.blobId.startsWith("blake3:") ? descriptor.blobId.replace("blake3:", "") : undefined)
      if (hash && this.engine.hasBlob(hash)) return true
    }
    return Boolean(await this.getVerified(descriptor))
  }
}
