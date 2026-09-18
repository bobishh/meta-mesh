import { beforeEach, describe, expect, it, vi } from "vitest"
import { MemoryMeshStore } from "../../mesh-browser-store/src/index"
import { BrowserIdentityStore } from "../../mesh-identity/src/index"
import {
  MAX_BLOB_BYTES,
  MeshBlobStore,
  createBlobDescriptor,
  createBlobRequest,
  createBlobResponse,
  createIrohBlobDescriptor,
  verifyBlobRequest,
  verifyBlobResponse,
  type BlobEngineInterface,
} from "./index"

describe("mesh blob transfer", () => {
  let alice: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>

  beforeEach(async () => {
    alice = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Alice")
  })

  it("Given a room member and stored bytes, when ranges are requested, then signed access and content hash verify", async () => {
    const bytes = new TextEncoder().encode("hello across mesh")
    const descriptor = await createBlobDescriptor(bytes, "hello.txt", "text/plain")
    const store = new MeshBlobStore(new MemoryMeshStore())
    await store.put(descriptor, bytes)
    const request = await createBlobRequest(alice, "room-1", descriptor.blobId, 0, 8)

    await expect(verifyBlobRequest(request, alice.identity, [alice.certificate], "room-1")).resolves.toEqual(request)
    const response = createBlobResponse(request, descriptor, (await store.get(descriptor.blobId))!.slice(0, 8))
    expect(verifyBlobResponse(response, request, descriptor)).toEqual(new TextEncoder().encode("hello ac"))
    await expect(store.getVerified(descriptor)).resolves.toEqual(bytes)
  })

  it("Given oversized or corrupted bytes, when described or loaded, then transfer is rejected", async () => {
    await expect(createBlobDescriptor(new Uint8Array(MAX_BLOB_BYTES + 1), "huge.bin", "application/octet-stream"))
      .rejects.toThrow("8 MiB")
    const bytes = new TextEncoder().encode("right")
    const descriptor = await createBlobDescriptor(bytes, "file.txt", "text/plain")
    const store = new MeshBlobStore(new MemoryMeshStore())
    await store.put(descriptor, bytes)
    await store.putUnsafe(descriptor.blobId, new TextEncoder().encode("wrong"))

    await expect(store.getVerified(descriptor)).rejects.toThrow("Blob content does not match descriptor")
  })

  it("Given iroh-blobs engine and file bytes, when described and stored, then Automerge descriptor retains Blake3 metadata and ticket", async () => {
    const mockBlobEngine: BlobEngineInterface = {
      createBlob: vi.fn((data: Uint8Array, name: string, mediaType: string, nodeEndpoint?: string | null) => {
        const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        return {
          kind: "blob" as const,
          version: 1 as const,
          blobId: `blake3:${hash}`,
          hash,
          ticket: `blob:${hash}@${nodeEndpoint || "local"}`,
          name,
          mediaType,
          size: data.byteLength,
        }
      }),
      putBlob: vi.fn(),
      getBlob: vi.fn((hash: string) => hash.includes("0123") ? new TextEncoder().encode("iroh blob payload") : undefined),
      hasBlob: vi.fn((hash: string) => hash.includes("0123")),
      verifyBlob: vi.fn((hash: string, data: Uint8Array) => hash.includes("0123") && data.byteLength === 17),
    }

    const bytes = new TextEncoder().encode("iroh blob payload")
    const descriptor = await createIrohBlobDescriptor(mockBlobEngine, bytes, "image.png", "image/png", "endpoint-1")

    expect(descriptor.blobId).toMatch(/^blake3:[0-9a-f]{64}$/)
    expect(descriptor.hash).toBe("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    expect(descriptor.ticket).toContain("endpoint-1")
    expect(descriptor.size).toBe(bytes.byteLength)

    const store = new MeshBlobStore(new MemoryMeshStore(), "blobs", mockBlobEngine)
    await store.put(descriptor, bytes)
    expect(mockBlobEngine.putBlob).toHaveBeenCalledWith(descriptor.hash, bytes)

    const loaded = await store.getVerified(descriptor)
    expect(loaded).toEqual(bytes)
    expect(await store.has(descriptor)).toBe(true)
  })
})
