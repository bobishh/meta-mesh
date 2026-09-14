import { beforeEach, describe, expect, it } from "vitest"
import { MemoryMeshStore } from "../../mesh-browser-store/src/index"
import { BrowserIdentityStore } from "../../mesh-identity/src/index"
import {
  MAX_BLOB_BYTES,
  MeshBlobStore,
  createBlobDescriptor,
  createBlobRequest,
  createBlobResponse,
  verifyBlobRequest,
  verifyBlobResponse,
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
})
