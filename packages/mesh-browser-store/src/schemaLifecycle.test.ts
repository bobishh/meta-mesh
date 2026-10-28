import { forceCloseDatabase, IDBFactory } from "fake-indexeddb"
import { afterEach, expect, it, vi } from "vitest"
import { BrowserMeshStore } from "./index"

afterEach(() => vi.unstubAllGlobals())

it("Given an existing tab retains local state, when another client adds an object store, then the original tab reopens its handle and preserves all records", async () => {
  vi.stubGlobal("indexedDB", new IDBFactory())
  const name = `schema-upgrade-${crypto.randomUUID()}`
  const original = new BrowserMeshStore(name, ["records"])
  await original.put("records", "retained", "original")
  const upgraded = new BrowserMeshStore(name, ["records", "history"])
  await upgraded.put("history", "generation", "first")
  await expect(original.get("records", "retained")).resolves.toBe("original")
  await original.updateRecords("records", ["retained"], ([value]) => ({ writes: [{ key: "retained", value: `${value}-updated` }], result: true }))
  await expect(upgraded.get("records", "retained")).resolves.toBe("original-updated")
  await expect(upgraded.get("history", "generation")).resolves.toBe("first")
})

it("Given the browser unexpectedly closes an IndexedDB connection, when the same store is read again, then reopen without losing committed state", async () => {
  const factory = new IDBFactory()
  vi.stubGlobal("indexedDB", factory)
  const opened = vi.spyOn(factory, "open")
  const store = new BrowserMeshStore(`forced-close-${crypto.randomUUID()}`, ["records"])
  await store.put("records", "retained", "private state")
  const connection = opened.mock.results.at(-1)!.value.result
  const closed = new Promise<void>(resolve => connection.addEventListener("close", () => resolve(), { once: true }))
  forceCloseDatabase(connection)
  await closed
  await expect(store.get("records", "retained")).resolves.toBe("private state")
})

it("Given two clients concurrently require different new stores, when they race the same schema version, then both reopen complete schemas and preserve every committed record", async () => {
  vi.stubGlobal("indexedDB", new IDBFactory())
  const name = `schema-race-${crypto.randomUUID()}`
  const retained = new BrowserMeshStore(name, ["records"])
  await retained.put("records", "retained", "original")
  const alpha = new BrowserMeshStore(name, ["records", "alpha"])
  const beta = new BrowserMeshStore(name, ["records", "beta"])
  await Promise.all([alpha.put("alpha", "value", "first"), beta.put("beta", "value", "second")])
  await expect(alpha.get("alpha", "value")).resolves.toBe("first")
  await expect(beta.get("beta", "value")).resolves.toBe("second")
  await expect(retained.get("records", "retained")).resolves.toBe("original")
})

it("Given another tab keeps an old schema open, when an upgrade is blocked, then report that refusal without waiting for the tab and allow retry after it closes", async () => {
  const factory = new IDBFactory()
  vi.stubGlobal("indexedDB", factory)
  const name = `schema-blocked-${crypto.randomUUID()}`
  const retained = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(name, 1)
    request.onupgradeneeded = () => request.result.createObjectStore("records")
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
  const write = retained.transaction("records", "readwrite")
  const committed = new Promise<void>((resolve, reject) => {
    write.oncomplete = () => resolve()
    write.onabort = () => reject(write.error)
  })
  write.objectStore("records").put("original", "retained")
  await committed
  const open = factory.open.bind(factory)
  let blocked = false
  const observedOpen = vi.spyOn(factory, "open").mockImplementation((databaseName, version) => {
    const request = version === undefined ? open(databaseName) : open(databaseName, version)
    request.addEventListener("blocked", () => { blocked = true })
    return request
  })
  const store = new BrowserMeshStore(name, ["records", "history"])
  let failure: unknown
  const pending = store.put("history", "generation", "first").catch(error => { failure = error })
  try {
    await vi.waitFor(() => expect(blocked).toBe(true))
    await vi.waitFor(() => expect(failure).toBeInstanceOf(Error), { timeout: 500 })
    expect((failure as Error).message).toMatch(/blocked by another tab/u)
    await expect(store.get("records", "retained")).rejects.toThrow(/blocked by another tab/u)
  } finally {
    retained.close()
    await pending
  }
  await vi.waitFor(async () => { await store.put("history", "generation", "retried") })
  expect(await store.get("records", "retained")).toBe("original")
  expect(await store.get("history", "generation")).toBe("retried")
  observedOpen.mockRestore()
})
