export const MAX_BLOB_BYTES = 8 * 1024 * 1024
export const BLOB_CHUNK_BYTES = 256 * 1024

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

export function normalizeName(value: string): string {
  const name = value.trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 180)
  if (!name) throw new Error("Blob name is required")
  return name
}

export function normalizeMediaType(value: string): string {
  const mediaType = value.trim().toLowerCase()
  if (!/^[\w.+-]+\/[\w.+-]+$/.test(mediaType)) return "application/octet-stream"
  return mediaType.slice(0, 120)
}

export function isValidBlobId(blobId: string): boolean {
  return typeof blobId === "string" && (/^sha256:[A-Za-z0-9_-]{43}$/.test(blobId) || /^blake3:[0-9a-fA-F]{64}$/.test(blobId))
}

export function validateBlobDescriptor(value: BlobDescriptor): BlobDescriptor {
  if (value?.kind !== "blob" || value.version !== 1 || !isValidBlobId(value?.blobId) ||
    (value.hash !== undefined && (!value.blobId.startsWith("blake3:") || value.hash !== value.blobId.slice(7))) ||
    normalizeName(value.name) !== value.name || normalizeMediaType(value.mediaType) !== value.mediaType ||
    !Number.isSafeInteger(value.size) || value.size < 1 || value.size > MAX_BLOB_BYTES) {
    throw new Error(`Invalid blob descriptor; files must be 1 byte–${MAX_BLOB_BYTES / 1024 / 1024} MiB`)
  }
  return value
}

export function createBlobDescriptorFromId(blobId: string, size: number, name: string, mediaType: string): BlobDescriptor {
  return validateBlobDescriptor({ kind: "blob", version: 1, blobId, size,
    name: normalizeName(name), mediaType: normalizeMediaType(mediaType) })
}
