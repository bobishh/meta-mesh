import type { MeshStore } from "../../mesh-browser-store/src/index"
import { BLOB_CHUNK_BYTES, MAX_BLOB_BYTES, validateBlobDescriptor, type BlobDescriptor } from "./descriptor"
import { chunkBlobSource, createBlobStreamVerifier, type BlobByteSource } from "./stream"

export type BlobStreamWriteOptions = { ensureCurrent?: () => void }
type Manifest = { kind: "mesh-blob-stream"; version: 1; blobId: string; size: number; transferId: string; chunks: number }
const manifestKey = (id: string) => `mesh-blob-stream-v1:${id}`
const chunkKey = (manifest: Manifest, index: number) => `mesh-blob-chunk-v1:${manifest.blobId}:${manifest.transferId}:${index}`

function readManifest(value: unknown, blobId: string): Manifest {
  if (typeof value !== "string" || value.length > 1024) throw new Error("Invalid stored blob manifest")
  let parsed: unknown
  try { parsed = JSON.parse(value) as unknown } catch { throw new Error("Invalid stored blob manifest") }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).length !== 6) throw new Error("Invalid stored blob manifest")
  const manifest = parsed as Manifest
  if (manifest.kind !== "mesh-blob-stream" || manifest.version !== 1 || manifest.blobId !== blobId ||
    !Number.isSafeInteger(manifest.size) || manifest.size < 1 || manifest.size > MAX_BLOB_BYTES ||
    manifest.chunks !== Math.ceil(manifest.size / BLOB_CHUNK_BYTES) ||
    typeof manifest.transferId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(manifest.transferId)) throw new Error("Invalid stored blob manifest")
  return { ...manifest }
}

/** Publish a new immutable chunk set only after the complete source digest passes. Old byte records remain untouched. */
export async function putBlobStream(store: MeshStore, name: string, descriptorInput: BlobDescriptor,
  source: BlobByteSource, options: BlobStreamWriteOptions = {}): Promise<void> {
  const descriptor = { ...validateBlobDescriptor(descriptorInput) }
  const ensureCurrent = options.ensureCurrent ?? (() => {})
  const verifier = createBlobStreamVerifier(descriptor)
  const key = manifestKey(descriptor.blobId)
  ensureCurrent()
  const previous = await store.get<string>(name, key)
  if (previous !== undefined) readManifest(previous, descriptor.blobId)
  const manifest: Manifest = { kind: "mesh-blob-stream", version: 1, blobId: descriptor.blobId, size: descriptor.size,
    transferId: crypto.randomUUID(), chunks: 0 }
  const staged: string[] = []
  try {
    for await (const part of chunkBlobSource(source)) {
      ensureCurrent()
      verifier.update(part)
      const partKey = chunkKey(manifest, manifest.chunks)
      staged.push(partKey)
      await store.put(name, partKey, part)
      ensureCurrent()
      manifest.chunks++
    }
    verifier.finish()
    ensureCurrent()
    if (!await store.compareAndSwap([{ store: name, key, expected: previous }],
      [{ type: "put", store: name, key, value: JSON.stringify(manifest) }], ensureCurrent)) throw new Error("Blob stream publication conflict")
    ensureCurrent()
  } catch (cause) {
    await discardUnpublished(store, name, key, manifest, staged)
    throw cause
  }
}

async function discardUnpublished(store: MeshStore, name: string, key: string, manifest: Manifest, staged: string[]) {
  try {
    // A transaction may have committed before its result was lost. Never remove published bytes.
    if (await store.get(name, key) === JSON.stringify(manifest)) return
    for (const part of staged) await store.delete(name, part)
  } catch { /* Preserve the original failure and retain uncertain bytes for recovery. */ }
}

/** Consumers must finish iteration before publishing bytes: the final digest authenticates the complete file. */
export async function readBlobStream(store: MeshStore, name: string, descriptorInput: BlobDescriptor): Promise<BlobByteSource | undefined> {
  const descriptor = { ...validateBlobDescriptor(descriptorInput) }
  const raw = await store.get(name, manifestKey(descriptor.blobId))
  if (raw === undefined) {
    const legacy = await store.get<Uint8Array>(name, descriptor.blobId)
    if (legacy === undefined) return undefined
    if (!(legacy instanceof Uint8Array) || legacy.byteLength !== descriptor.size) throw new Error("Stored blob size mismatch")
    return verifyParts(descriptor, (async function* () {
      // Existing byte records require one legacy read; never rewrite or delete them on read.
      for (let offset = 0; offset < legacy.length; offset += BLOB_CHUNK_BYTES) yield legacy.slice(offset, offset + BLOB_CHUNK_BYTES)
    })())
  }
  const manifest = readManifest(raw, descriptor.blobId)
  if (manifest.size !== descriptor.size) throw new Error("Stored blob size mismatch")
  return verifyParts(descriptor, (async function* () {
    for (let index = 0; index < manifest.chunks; index++) {
      const part = await store.get<Uint8Array>(name, chunkKey(manifest, index))
      if (!(part instanceof Uint8Array)) throw new Error("Stored blob chunk unavailable")
      if (part.length !== Math.min(BLOB_CHUNK_BYTES, manifest.size - index * BLOB_CHUNK_BYTES)) throw new Error("Stored blob chunk size mismatch")
      yield part
    }
  })())
}

async function* verifyParts(descriptor: BlobDescriptor, source: BlobByteSource): BlobByteSource {
  const verifier = createBlobStreamVerifier(descriptor)
  for await (const part of source) { verifier.update(part); yield part }
  verifier.finish()
}

/** Compatibility callers explicitly request one complete allocation; streaming callers use readBlobStream. */
export async function collectStoredBlob(store: MeshStore, name: string, blobId: string): Promise<Uint8Array | undefined> {
  const raw = await store.get(name, manifestKey(blobId))
  if (raw === undefined) return undefined
  const manifest = readManifest(raw, blobId)
  const descriptor: BlobDescriptor = { kind: "blob", version: 1, blobId, size: manifest.size, name: "blob", mediaType: "application/octet-stream" }
  const source = await readBlobStream(store, name, descriptor)
  const output = new Uint8Array(manifest.size)
  let offset = 0
  for await (const part of source!) { output.set(part, offset); offset += part.length }
  return output
}
