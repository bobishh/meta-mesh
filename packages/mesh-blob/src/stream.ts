import { blake3 } from "@noble/hashes/blake3.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { bytesToHex } from "@noble/hashes/utils.js"
import {
  BLOB_CHUNK_BYTES,
  MAX_BLOB_BYTES,
  createBlobDescriptorFromId,
  validateBlobDescriptor,
  type BlobDescriptor,
} from "./descriptor"

export type BlobByteSource = AsyncIterable<Uint8Array>

/** Warm lazy local storage while online so the first offline import needs no new module fetch. */
export async function preloadBlobStreamStorage(): Promise<void> {
  await import("./streamStore")
}

type IncrementalHash = {
  update(data: Uint8Array): IncrementalHash
  digest(): Uint8Array
}

function blobHash(blobId: string): IncrementalHash {
  if (blobId.startsWith("sha256:")) return sha256.create()
  if (blobId.startsWith("blake3:")) return blake3.create()
  throw new Error("Unsupported blob hash")
}

function base64Url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

export function createBlobStreamVerifier(descriptor: BlobDescriptor): {
  update(bytes: Uint8Array): void
  finish(): void
} {
  const captured = { ...validateBlobDescriptor(descriptor) }
  const hash = blobHash(captured.blobId)
  let size = 0
  let finished = false

  return {
    update(bytes) {
      if (finished) throw new Error("Blob verifier is finished")
      if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > BLOB_CHUNK_BYTES) {
        throw new Error("Invalid blob chunk")
      }
      if (size + bytes.byteLength > captured.size || size + bytes.byteLength > MAX_BLOB_BYTES) {
        throw new Error("Blob exceeds declared size")
      }
      hash.update(bytes)
      size += bytes.byteLength
    },
    finish() {
      if (finished) throw new Error("Blob verifier is finished")
      finished = true
      if (size !== captured.size) throw new Error("Blob size mismatch")
      const digest = hash.digest()
      const actual = captured.blobId.startsWith("sha256:")
        ? `sha256:${base64Url(digest)}`
        : `blake3:${bytesToHex(digest)}`
      const expected = captured.blobId.startsWith("blake3:") ? captured.blobId.toLowerCase() : captured.blobId
      if (actual !== expected) throw new Error("Blob digest mismatch")
    },
  }
}

export async function* chunkBlobSource(source: BlobByteSource): AsyncGenerator<Uint8Array> {
  let total = 0
  let buffer = new Uint8Array(BLOB_CHUNK_BYTES)
  let used = 0

  for await (const input of source) {
    if (!(input instanceof Uint8Array) || input.byteLength < 1 || input.byteLength > BLOB_CHUNK_BYTES) {
      throw new Error("Invalid source chunk")
    }
    total += input.byteLength
    if (total > MAX_BLOB_BYTES) throw new Error("Blob source exceeds maximum size")

    let offset = 0
    while (offset < input.byteLength) {
      const count = Math.min(buffer.byteLength - used, input.byteLength - offset)
      buffer.set(input.subarray(offset, offset + count), used)
      used += count
      offset += count
      if (used === buffer.byteLength) {
        const full = buffer
        buffer = new Uint8Array(BLOB_CHUNK_BYTES)
        used = 0
        yield full
      }
    }
  }

  if (total === 0) throw new Error("Blob source is empty")
  if (used > 0) {
    yield buffer.slice(0, used)
  }
}

export async function createBlobStreamDescriptor(
  source: BlobByteSource,
  size: number,
  name: string,
  mediaType: string,
): Promise<BlobDescriptor> {
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_BLOB_BYTES) {
    throw new Error("Invalid blob size")
  }
  const hash = sha256.create()
  let total = 0
  for await (const chunk of chunkBlobSource(source)) {
    total += chunk.byteLength
    if (total > size) throw new Error("Blob source exceeds declared size")
    hash.update(chunk)
  }
  if (total !== size) throw new Error("Blob source size mismatch")
  const blobId = `sha256:${base64Url(hash.digest())}`
  return createBlobDescriptorFromId(blobId, size, name, mediaType)
}
