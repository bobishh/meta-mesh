import { afterEach, expect, it, vi } from "vitest"
import { IDBDatabase, IDBFactory, IDBObjectStore } from "fake-indexeddb"
import { PeerStore, STORE_AUTHORITY, STORE_NODE, type WorkspaceMeshCredential } from "./index"

afterEach(() => vi.restoreAllMocks())

const credential = (workspaceId: string): WorkspaceMeshCredential => ({ version: 1, workspaceId,
  ownerPersonId: "owner", ownerPublicKey: "owner-key", ownerCertificates: [], transportSecret: "secret",
  epoch: 1, updatedAt: "2026-10-28T00:00:00.000Z" })

it("Given a concurrent credential and authority replacement, when reading selected board authorization, then one readonly transaction returns coherent pairs", async () => {
  const store = new PeerStore(`authorization-snapshot-${crypto.randomUUID()}`, new IDBFactory())
  await store.putWorkspaceCredential(credential("board-a"))
  await store.putWorkspaceCredential(credential("board-b"))
  let competingWrite: Promise<void> | undefined
  const requests: IDBTransaction[] = []
  const original = IDBObjectStore.prototype.get
  vi.spyOn(IDBObjectStore.prototype, "get").mockImplementation(function (this: IDBObjectStore, key) {
    const request = original.call(this, key)
    requests.push(this.transaction)
    if (this.name === STORE_NODE && key === "workspace:board-a" && !competingWrite) {
      request.addEventListener("success", () => {
        competingWrite = store.putWorkspaceCredential({ ...credential("board-a"), epoch: 2 })
      }, { once: true })
    }
    return request
  })
  const snapshot = await store.readWorkspaceAuthorization(["board-a", "board-b"])
  expect(snapshot.map(item => [item.workspaceId, item.credential?.epoch, item.authority?.epoch]))
    .toEqual([["board-a", 1, 1], ["board-b", 1, 1]])
  expect(new Set(requests.slice(0, 4)).size).toBe(1)
  expect(requests[0]?.mode).toBe("readonly")
  await competingWrite
  expect((await store.readWorkspaceAuthorization(["board-a"]))[0]?.authority?.epoch).toBe(2)
})

it("Given a credential predating the authority store, when its snapshot is read, then derive authority without migration writes and retain caller selection order", async () => {
  const factory = new IDBFactory(), name = `authorization-legacy-${crypto.randomUUID()}`, store = new PeerStore(name, factory)
  await store.putWorkspaceCredential(credential("board-a"))
  const opened = factory.open(name)
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    opened.onsuccess = () => resolve(opened.result)
    opened.onerror = () => reject(opened.error)
  })
  const tx = db.transaction(STORE_AUTHORITY, "readwrite")
  tx.objectStore(STORE_AUTHORITY).delete("board-a")
  await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error) })
  const put = vi.spyOn(IDBObjectStore.prototype, "put"), remove = vi.spyOn(IDBObjectStore.prototype, "delete")
  const transactions = vi.spyOn(IDBDatabase.prototype, "transaction")
  const result = await store.readWorkspaceAuthorization(["missing", "board-a"])
  expect(result[0]).toEqual({ workspaceId: "missing", credential: null, authority: null })
  expect(result[1]?.authority).toMatchObject({ workspaceId: "board-a", epoch: 1 })
  expect(result[1]?.authority).not.toHaveProperty("transportSecret")
  expect(put).not.toHaveBeenCalled(); expect(remove).not.toHaveBeenCalled()
  expect(transactions.mock.calls).toEqual([[[STORE_NODE, STORE_AUTHORITY], "readonly"]])
  result[1]!.credential!.transportSecret = "caller mutation"
  expect((await store.readWorkspaceAuthorization(["board-a"]))[0]?.credential?.transportSecret).toBe("secret")
  db.close()
})

it.each([[], ["board-a", "board-a"], [""], ["x".repeat(257)], Array.from({ length: 513 }, (_, index) => `board-${index}`)].map(ids => ({ ids })))(
  "Given invalid selected board IDs $ids, when capturing authorization, then reject before opening IndexedDB", async ({ ids }) => {
    const factory = new IDBFactory(), open = vi.spyOn(factory, "open")
    await expect(new PeerStore("invalid-selected-authorization", factory).readWorkspaceAuthorization(ids))
      .rejects.toThrow(/workspace.*selection/i)
    expect(open).not.toHaveBeenCalled()
  })
