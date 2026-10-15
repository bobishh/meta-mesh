import { expect, it, vi } from "vitest"
import { BrowserMeshStore, MemoryMeshStore } from "../../mesh-browser-store/src/index"
import { IDBFactory } from "fake-indexeddb"
import { BLOB_CHUNK_BYTES, MeshBlobStore, createBlobDescriptor } from "./index"

async function fixture() {
  const bytes = new Uint8Array(BLOB_CHUNK_BYTES + 17).fill(71)
  const descriptor = await createBlobDescriptor(bytes, "stream.txt", "text/plain")
  const storage = new MemoryMeshStore()
  return { bytes, descriptor, storage, blobs: new MeshBlobStore(storage) }
}

async function* source(bytes: Uint8Array) {
  for (let offset = 0; offset < bytes.length; offset += 65001) yield bytes.slice(offset, offset + 65001)
}

it("Given a bounded source, when streamed into local storage, then publish only verified chunk records and preserve full-byte readers across restart", async () => {
  const f = await fixture()
  await f.blobs.putStream(f.descriptor, source(f.bytes))
  expect(await f.storage.get("blobs", f.descriptor.blobId)).toBeUndefined()
  const records = await f.storage.list<unknown>("blobs")
  const parts = records.filter(record => record.value instanceof Uint8Array)
  expect(parts.map(part => (part.value as Uint8Array).length)).toEqual([BLOB_CHUNK_BYTES, 17])
  const restarted = new MeshBlobStore(f.storage)
  const stream = await restarted.getStream(f.descriptor)
  const sizes: number[] = []
  for await (const part of stream!) sizes.push(part.length)
  expect(sizes).toEqual([BLOB_CHUNK_BYTES, 17])
  expect(await restarted.getVerified(f.descriptor)).toEqual(f.bytes)
})

it("Given a source fails before completion, when storage is reopened, then its staged chunks never appear as a complete file", async () => {
  const f = await fixture()
  async function* interrupted() { yield f.bytes.slice(0, BLOB_CHUNK_BYTES); throw new Error("Source closed") }
  await expect(f.blobs.putStream(f.descriptor, interrupted())).rejects.toThrow("Source closed")
  expect(await new MeshBlobStore(f.storage).getStream(f.descriptor)).toBeUndefined()
  expect(await f.blobs.getVerified(f.descriptor)).toBeUndefined()
  expect(await f.storage.list("blobs")).toEqual([])
})

it("Given an existing byte record, when a streamed replacement is invalid, then retain the original and support bounded legacy reads", async () => {
  const f = await fixture()
  await f.blobs.put(f.descriptor, f.bytes)
  const wrong = new Uint8Array(f.bytes.length).fill(22)
  await expect(f.blobs.putStream(f.descriptor, source(wrong))).rejects.toThrow(/match|digest|hash/i)
  expect(await f.blobs.getVerified(f.descriptor)).toEqual(f.bytes)
  const stream = await f.blobs.getStream(f.descriptor)
  const parts: Uint8Array[] = []
  for await (const part of stream!) parts.push(part)
  expect(parts.map(part => part.length)).toEqual([BLOB_CHUNK_BYTES, 17])
})

it("Given saved chunks are missing or altered, when fully consumed, then reject integrity instead of returning verified file bytes", async () => {
  const f = await fixture()
  await f.blobs.putStream(f.descriptor, source(f.bytes))
  const part = (await f.storage.list<unknown>("blobs")).find(record => record.value instanceof Uint8Array)!
  await f.storage.put("blobs", part.key, new Uint8Array(BLOB_CHUNK_BYTES).fill(9))
  await expect(f.blobs.getVerified(f.descriptor)).rejects.toThrow(/match|digest|hash/i)
  await f.storage.delete("blobs", part.key)
  await expect(f.blobs.getVerified(f.descriptor)).rejects.toThrow(/missing|unavailable|chunk/i)
})

it("Given the caller loses access before publication, when stream storage completes, then leave no visible file pointer", async () => {
  const f = await fixture()
  let allowed = true
  async function* revoked() { yield* source(f.bytes); allowed = false }
  const ensureCurrent = () => { if (!allowed) throw new Error("Access revoked") }
  await expect(f.blobs.putStream(f.descriptor, revoked(), { ensureCurrent })).rejects.toThrow("Access revoked")
  expect(await f.blobs.getStream(f.descriptor)).toBeUndefined()
})

it("Given independent concurrent stream writers, when both publish from the same basis, then one CAS wins and its complete bytes survive", async () => {
  const f = await fixture()
  const outcomes = await Promise.allSettled([f.blobs.putStream(f.descriptor, source(f.bytes)),
    new MeshBlobStore(f.storage).putStream(f.descriptor, source(f.bytes))])
  expect(outcomes.filter(result => result.status === "fulfilled")).toHaveLength(1)
  expect(outcomes.filter(result => result.status === "rejected")).toHaveLength(1)
  expect(await f.blobs.getVerified(f.descriptor)).toEqual(f.bytes)
})

it("Given an old-format byte record, when a new reader streams it, then retain its exact bytes and never rewrite the source", async () => {
  const f = await fixture()
  await f.blobs.put(f.descriptor, f.bytes)
  const put = vi.spyOn(f.storage, "put")
  for await (const _part of (await f.blobs.getStream(f.descriptor))!) { /* Fully consume verification. */ }
  expect(put).not.toHaveBeenCalled()
  expect(await f.storage.get("blobs", f.descriptor.blobId)).toEqual(f.bytes)
})

it("Given an old byte record is corrupt, when a verified streamed repair commits, then all readers use the repair while preserving the old record", async () => {
  const f = await fixture()
  const corrupt = new Uint8Array(f.bytes.length).fill(3)
  await f.blobs.putUnsafe(f.descriptor.blobId, corrupt)
  await f.blobs.putStream(f.descriptor, source(f.bytes))
  const reopened = new MeshBlobStore(f.storage)
  expect(await reopened.getVerified(f.descriptor)).toEqual(f.bytes)
  expect(await reopened.get(f.descriptor.blobId)).toEqual(f.bytes)
  expect(await f.storage.get("blobs", f.descriptor.blobId)).toEqual(corrupt)
})

it("Given caller metadata changes while the implementation loads, when publication finishes, then retain the original verified descriptor and guard", async () => {
  const f = await fixture()
  const requested = { ...f.descriptor }
  const originalGuard = vi.fn()
  const options = { ensureCurrent: originalGuard }
  const pending = f.blobs.putStream(requested, source(f.bytes), options)
  requested.blobId = `sha256:${"A".repeat(43)}`
  options.ensureCurrent = vi.fn()
  await pending
  expect(originalGuard).toHaveBeenCalled()
  expect(options.ensureCurrent).not.toHaveBeenCalled()
  expect(await f.blobs.getVerified(f.descriptor)).toEqual(f.bytes)
})

it("Given an existing stream manifest, when reimporting the same verified file, then publish from its exact serialized basis", async () => {
  const f = await fixture()
  await f.blobs.putStream(f.descriptor, source(f.bytes))
  await f.blobs.putStream(f.descriptor, source(f.bytes))
  expect(await new MeshBlobStore(f.storage).getVerified(f.descriptor)).toEqual(f.bytes)
})

it("Given real IndexedDB transactions, when independent handles publish the same stream, then exactly one wins and a fresh handle reads its verified bytes", async () => {
  vi.stubGlobal("indexedDB", new IDBFactory())
  try {
    const f = await fixture()
    const database = `stream-store-${crypto.randomUUID()}`
    const first = new MeshBlobStore(new BrowserMeshStore(database, ["blobs"]))
    const second = new MeshBlobStore(new BrowserMeshStore(database, ["blobs"]))
    const outcomes = await Promise.allSettled([first.putStream(f.descriptor, source(f.bytes)), second.putStream(f.descriptor, source(f.bytes))])
    expect(outcomes.filter(result => result.status === "fulfilled")).toHaveLength(1)
    expect(outcomes.filter(result => result.status === "rejected")).toHaveLength(1)
    expect(await new MeshBlobStore(new BrowserMeshStore(database, ["blobs"])).getVerified(f.descriptor)).toEqual(f.bytes)
  } finally { vi.unstubAllGlobals() }
})

it("Given publication commits but its response is lost, when cleanup runs, then preserve all published chunks for restart recovery", async () => {
  const f = await fixture()
  const commit = f.storage.compareAndSwap.bind(f.storage)
  vi.spyOn(f.storage, "compareAndSwap").mockImplementation(async (...args) => {
    expect(await commit(...args)).toBe(true)
    throw new Error("Publication response lost")
  })
  await expect(f.blobs.putStream(f.descriptor, source(f.bytes))).rejects.toThrow("Publication response lost")
  expect(await new MeshBlobStore(f.storage).getVerified(f.descriptor)).toEqual(f.bytes)
})
