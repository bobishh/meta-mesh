import { expect, it, vi } from "vitest"
import { IDBFactory } from "fake-indexeddb"
import { BrowserMeshStore } from "../../mesh-browser-store/src/index"
import { sha256Base64Url } from "@meta-uber/mesh-identity"
import { buildArchiveIndex, readArchiveIndex } from "./historyArchive"
import { createArchiveObjectStore, type ArchiveObjectPersistence } from "./historyArchiveStore"

async function fixture() {
  vi.stubGlobal("indexedDB", new IDBFactory())
  const name = crypto.randomUUID()
  const storage = new BrowserMeshStore(name, ["history"])
  const port = (db: BrowserMeshStore): ArchiveObjectPersistence => ({
    read: key => db.get<string>("history", key),
    compareAndSwap: (key, expected, next, guard) => db.compareAndSwap([{ store: "history", key, expected }],
      [{ type: "put", store: "history", key, value: next }], guard),
  })
  return { storage, port, open: () => new BrowserMeshStore(name, ["history"]),
    bytes: new TextEncoder().encode("retain original signed evidence") }
}

it("Given immutable archive bytes, when a fresh IndexedDB handle reopens them, then authenticate exact bytes without rewriting", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  await createArchiveObjectStore("person/workspace", f.port(f.storage), () => {}).write(id, f.bytes)
  const reopened = f.open()
  const port = f.port(reopened)
  port.compareAndSwap = vi.fn(port.compareAndSwap)
  const store = createArchiveObjectStore("person/workspace", port, () => {})
  expect(await store.read(id, 1024)).toEqual(f.bytes)
  expect(port.compareAndSwap).not.toHaveBeenCalled()
})

it("Given two independent writers of identical evidence, when both commit, then converge on one immutable object", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const left = createArchiveObjectStore("partition", f.port(f.storage), () => {})
  const right = createArchiveObjectStore("partition", f.port(f.open()), () => {})
  await Promise.all([left.write(id, f.bytes), right.write(id, f.bytes)])
  expect(await left.read(id, 1024)).toEqual(f.bytes)
  expect(await f.storage.list("history")).toHaveLength(1)
})

it("Given an immutable object already exists, when a caller supplies different bytes or stored corruption, then preserve the original record and reject", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const store = createArchiveObjectStore("partition", f.port(f.storage), () => {})
  await store.write(id, f.bytes)
  const original = (await f.storage.list<string>("history"))[0]!
  await expect(store.write(id, new Uint8Array([1, 2, 3]))).rejects.toThrow(/hash|immutable|integrity/i)
  expect(await f.storage.get("history", original.key)).toBe(original.value)
  const corrupted = original.value.replace("retain", "broken") + " "
  await f.storage.put("history", original.key, corrupted)
  await expect(store.read(id, 1024)).rejects.toThrow(/canonical|schema|integrity|encoding/i)
  await expect(store.write(id, f.bytes)).rejects.toThrow(/canonical|schema|integrity|encoding/i)
  expect(await f.storage.get("history", original.key)).toBe(corrupted)
})

it("Given a transaction commits but its reply is lost, when reopened and retried, then retain the exact object without another write", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const port = f.port(f.storage)
  const commit = port.compareAndSwap
  port.compareAndSwap = async (...args) => { await commit(...args); throw new Error("Commit reply lost") }
  await expect(createArchiveObjectStore("partition", port, () => {}).write(id, f.bytes)).rejects.toThrow("Commit reply lost")
  const retry = f.port(f.open())
  retry.compareAndSwap = vi.fn(retry.compareAndSwap)
  const reopened = createArchiveObjectStore("partition", retry, () => {})
  await reopened.write(id, f.bytes)
  expect(retry.compareAndSwap).not.toHaveBeenCalled()
  expect(await reopened.read(id, 1024)).toEqual(f.bytes)
  expect(await f.storage.list("history")).toHaveLength(1)
})

it("Given authority changes inside the IndexedDB transaction, when its publication guard runs, then commit no object", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const port = f.port(f.storage)
  const commit = port.compareAndSwap
  let allowed = true
  port.compareAndSwap = (key, expected, next, guard) => commit(key, expected, next, () => { allowed = false; guard() })
  const store = createArchiveObjectStore("partition", port, () => { if (!allowed) throw new Error("Access changed") })
  await expect(store.write(id, f.bytes)).rejects.toThrow("Access changed")
  expect(await f.storage.list("history")).toEqual([])
})

it("Given caller bytes change after writing starts, when hashing and commit finish, then retain the captured original bytes", async () => {
  const f = await fixture()
  const original = f.bytes.slice()
  const id = await sha256Base64Url(original)
  const store = createArchiveObjectStore("partition", f.port(f.storage), () => {})
  const writing = store.write(id, f.bytes)
  f.bytes.fill(0)
  await writing
  expect(await store.read(id, 1024)).toEqual(original)
})

it("Given different private partitions, when a record ID matches, then neither reads the other's archive object", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const left = createArchiveObjectStore("person-a/workspace", f.port(f.storage), () => {})
  const right = createArchiveObjectStore("person-b/workspace", f.port(f.storage), () => {})
  await left.write(id, f.bytes)
  expect(await right.read(id, 1024)).toBeUndefined()
})

it("Given a strict requested byte limit, when a stored object exceeds it, then reject before returning bytes", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const store = createArchiveObjectStore("partition", f.port(f.storage), () => {})
  await store.write(id, f.bytes)
  await expect(store.read(id, 1)).rejects.toThrow(/bound|limit|size/i)
  expect(await store.read(id, f.bytes.length)).toEqual(f.bytes)
})

it.each(["\ud800", "\udc00"])("Given an unpaired Unicode partition %s, when reading an object, then reject before hashing or storage", async partition => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  expect(new TextEncoder().encode("\ud800")).toEqual(new TextEncoder().encode("\udc00"))
  const port = f.port(f.storage)
  port.read = vi.fn(port.read)
  port.compareAndSwap = vi.fn(port.compareAndSwap)
  const digest = vi.spyOn(crypto.subtle, "digest")

  let outcome: { error?: unknown; bytes?: Uint8Array }
  try {
    try {
      const store = createArchiveObjectStore(partition, port, () => {})
      outcome = { bytes: await store.read(id, f.bytes.length) }
    } catch (error) {
      outcome = { error }
    }
    expect(outcome!.error).toBeInstanceOf(Error)
    expect(digest).not.toHaveBeenCalled()
    expect(port.read).not.toHaveBeenCalled()
    expect(port.compareAndSwap).not.toHaveBeenCalled()
  } finally {
    digest.mockRestore()
  }
})

it("Given namespace hashing fails once, when the same repository reads again, then recompute and recover", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const writer = createArchiveObjectStore("recoverable-partition", f.port(f.storage), () => {})
  await writer.write(id, f.bytes)
  const port = f.port(f.open())
  port.read = vi.fn(port.read)
  const reader = createArchiveObjectStore("recoverable-partition", port, () => {})
  const digest = vi.spyOn(crypto.subtle, "digest").mockRejectedValueOnce(new Error("temporary namespace SHA failure"))

  try {
    await expect(reader.read(id, f.bytes.length)).rejects.toThrow("temporary namespace SHA failure")
    await expect(reader.read(id, f.bytes.length)).resolves.toEqual(f.bytes)
    const digestInputs = digest.mock.calls.map(([, input]) => input)
    const namespaceInputs = digestInputs.filter(input => input instanceof Uint8Array &&
      new TextDecoder().decode(input).startsWith("MESH-HISTORY/1/store-partition\0"))
    const contentInputs = digestInputs.filter(input => input instanceof Uint8Array &&
      new TextDecoder().decode(input) === new TextDecoder().decode(f.bytes))
    expect(namespaceInputs).toHaveLength(2)
    expect(contentInputs).toHaveLength(1)
    expect(port.read).toHaveBeenCalledOnce()
  } finally {
    digest.mockRestore()
  }
})

it("Given a persisted multi-level history index, when only one entry is reopened, then retain bounded tree access on a fresh IndexedDB handle", async () => {
  const f = await fixture()
  const id = await sha256Base64Url(f.bytes)
  const context = { workspaceId: "workspace", historyEpoch: 1, indexId: "changes" }
  const first = createArchiveObjectStore("partition", f.port(f.storage), () => {})
  await first.write(id, f.bytes)
  const root = await buildArchiveIndex(context, Array.from({ length: 1000 }, (_, i) => ({ key: i.toString().padStart(6, "0"), objectId: id })), first)
  const reopened = createArchiveObjectStore("partition", f.port(f.open()), () => {})
  expect(await readArchiveIndex(context, root, reopened, { after: "000511", limit: 1 })).toEqual({ entries: [{ key: "000512", objectId: id }], nextAfter: "000512" })
  expect(await reopened.read(id, f.bytes.length)).toEqual(f.bytes)
})
