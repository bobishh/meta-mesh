import { IDBFactory, IDBKeyRange, IDBCursor as FDBCursor, IDBObjectStore as FDBObjectStore } from "fake-indexeddb"
import { afterEach, describe, expect, it, vi } from "vitest"
import { BrowserMeshStore, MemoryMeshStore, type MeshStore } from "./index"

const scan = <T>(store: MeshStore, name: string, prefix: string, after: string | undefined, limit: number) =>
  store.scan<T>(name, prefix, after, limit)

afterEach(() => vi.unstubAllGlobals())

describe("bounded key-prefix scan", () => {
  it("Given memory records in varied insertion order, when scanning pages, then keys are sorted and after is exclusive", async () => {
    const store = new MemoryMeshStore()
    for (const key of ["a3", "b1", "a1", "a2", "a4"]) await store.put("records", key, key)

    await expect(scan(store, "records", "a", undefined, 2)).resolves.toEqual({
      entries: [{ key: "a1", value: "a1" }, { key: "a2", value: "a2" }], nextAfter: "a2",
    })
    await expect(scan(store, "records", "a", "a2", 2)).resolves.toEqual({
      entries: [{ key: "a3", value: "a3" }, { key: "a4", value: "a4" }], nextAfter: null,
    })
    await expect(scan(store, "records", "z", undefined, 1)).resolves.toEqual({ entries: [], nextAfter: null })
  })

  it("Given IndexedDB records shared by independent handles, when scanning, then bounded pages preserve exact prefix including U+FFFF suffixes", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory())
    vi.stubGlobal("IDBKeyRange", IDBKeyRange)
    const first = new BrowserMeshStore("prefix-scan-test", ["records"])
    const second = new BrowserMeshStore("prefix-scan-test", ["records"])
    for (const key of ["a\ufffftail", "a3", "a1", "b1", "a2"]) await first.put("records", key, { key })

    await expect(scan(second, "records", "a", undefined, 1)).resolves.toEqual({
      entries: [{ key: "a1", value: { key: "a1" } }], nextAfter: "a1",
    })
    await expect(scan(second, "records", "a", "a1", 2)).resolves.toEqual({
      entries: [{ key: "a2", value: { key: "a2" } }, { key: "a3", value: { key: "a3" } }], nextAfter: "a3",
    })
    await expect(scan(second, "records", "a", "a3", 2)).resolves.toEqual({
      entries: [{ key: "a\ufffftail", value: { key: "a\ufffftail" } }], nextAfter: null,
    })
  })

  it("Given invalid scan bounds, when called on either store, then reject invalid prefix, limit, and continuation key", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory())
    vi.stubGlobal("IDBKeyRange", IDBKeyRange)
    const stores = [new MemoryMeshStore(), new BrowserMeshStore("prefix-scan-invalid", ["records"])]
    for (const store of stores) {
      for (const prefix of ["", "x".repeat(2049)]) {
        await expect(scan(store, "records", prefix, undefined, 1)).rejects.toThrow()
      }
      for (const limit of [0, 1.5, 129, Number.NaN]) {
        await expect(scan(store, "records", "a", undefined, limit)).rejects.toThrow()
      }
      await expect(scan(store, "records", "a", "b", 1)).rejects.toThrow()
    }
  })

  it("Given an all-U+FFFF prefix and other IndexedDB key types, when scanned, then only string keys with that prefix are returned", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory())
    vi.stubGlobal("IDBKeyRange", IDBKeyRange)
    const name = "prefix-scan-all-ffff"
    const store = new BrowserMeshStore(name, ["records"])
    await store.put("records", "\uffff", "exact")
    await store.put("records", "\uffff\ufffftail", "suffix")
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(name)
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction("records", "readwrite")
      transaction.objectStore("records").put("array key", ["\uffff", "array"])
      transaction.oncomplete = () => resolve()
      transaction.onerror = () => reject(transaction.error)
      transaction.onabort = () => reject(transaction.error)
    })
    database.close()

    await expect(scan(store, "records", "\uffff", undefined, 8)).resolves.toEqual({
      entries: [{ key: "\uffff", value: "exact" }, { key: "\uffff\ufffftail", value: "suffix" }], nextAfter: null,
    })
  })

  it("Given many matching IndexedDB records, when scanning a page, then continue only through limit plus one and avoid getAll", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory())
    vi.stubGlobal("IDBKeyRange", IDBKeyRange)
    const store = new BrowserMeshStore("prefix-scan-bounded", ["records"])
    for (let index = 0; index < 40; index += 1) await store.put("records", `match-${String(index).padStart(2, "0")}`, index)
    const continueCursor = vi.spyOn(FDBCursor.prototype, "continue")
    const getAll = vi.spyOn(FDBObjectStore.prototype, "getAll")

    await expect(scan(store, "records", "match-", undefined, 2)).resolves.toMatchObject({
      entries: [{ key: "match-00", value: 0 }, { key: "match-01", value: 1 }], nextAfter: "match-01",
    })
    expect(continueCursor).toHaveBeenCalledTimes(2)
    expect(getAll).not.toHaveBeenCalled()
  })
})
