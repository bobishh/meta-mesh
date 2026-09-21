import * as Automerge from "@automerge/automerge"
import { describe, expect, it, vi } from "vitest"
import { BrowserReplicaInvalidation, DurableReplicaStore, MemoryMeshStore, type StoredDocumentSnapshot } from "./index"

describe("mesh store", () => {
  it("Given a stored CRDT blob, when read and changed, then storage retains an isolated copy", async () => {
    const store = new MemoryMeshStore()
    const original = { bytes: new Uint8Array([1, 2, 3]) }
    await store.put("rooms", "one", original)
    const loaded = await store.get<typeof original>("rooms", "one")
    loaded!.bytes[0] = 9

    expect((await store.get<typeof original>("rooms", "one"))!.bytes[0]).toBe(1)
  })

  it("Given several records, when one is deleted, then list returns the remainder", async () => {
    const store = new MemoryMeshStore()
    await store.put("contacts", "a", { name: "Alice" })
    await store.put("contacts", "b", { name: "Bob" })
    await store.delete("contacts", "a")

    expect(await store.list("contacts")).toEqual([{ key: "b", value: { name: "Bob" } }])
  })

  it("Given sibling tabs commit concurrent Automerge branches, when admitted, then both immutable changes reopen safely", async () => {
    const memory = new MemoryMeshStore()
    const store = new DurableReplicaStore(memory)
    const base = Automerge.from({ messages: [] as string[] })
    const left = Automerge.change(Automerge.clone(base), doc => { doc.messages.push("left") })
    const right = Automerge.change(Automerge.clone(base), doc => { doc.messages.push("right") })
    const leftChange = Automerge.getChanges(base, left)[0]
    const rightChange = Automerge.getChanges(base, right)[0]

    await Promise.all([
      store.admitChanges({ documentId: "room-1", changes: [{ hash: "left", bytes: leftChange, proof: { deviceId: "left" } }], verify: async () => true }),
      store.admitChanges({ documentId: "room-1", changes: [{ hash: "right", bytes: rightChange, proof: { deviceId: "right" } }], verify: async () => true }),
    ])

    const saved = await store.changes("room-1")
    const [reopened] = Automerge.applyChanges(base, saved.map(change => change.bytes))
    expect([...reopened.messages].sort()).toEqual(["left", "right"])

    const snapshot: StoredDocumentSnapshot = {
      version: 1, documentId: "room-1", heads: Automerge.getHeads(reopened), bytes: Automerge.save(reopened),
      createdAt: "2026-09-15T12:00:00.000Z",
    }
    await store.putSnapshot(snapshot)
    expect(Automerge.getHeads(Automerge.load((await store.snapshot("room-1"))!.bytes)).sort()).toEqual(snapshot.heads.sort())
  })

  it("Given admission fails before atomic commit, when inspected, then no partial change is durable", async () => {
    const memory = new MemoryMeshStore()
    const store = new DurableReplicaStore(memory)
    memory.batch = vi.fn(async () => { throw new Error("quota exceeded") })

    await expect(store.admitChanges({
      documentId: "room-1",
      changes: [{ hash: "one", bytes: new Uint8Array([1]), proof: {} }, { hash: "two", bytes: new Uint8Array([2]), proof: {} }],
      verify: async () => true,
    })).rejects.toThrow("quota exceeded")
    expect(await store.changes("room-1")).toEqual([])
  })

  it("Given a durable change already exists, when acknowledgement was lost and the batch retries, then admission is idempotent", async () => {
    const store = new DurableReplicaStore(new MemoryMeshStore())
    const input = { documentId: "room-1", changes: [{ hash: "one", bytes: new Uint8Array([1]), proof: {} }], verify: async () => true }

    await expect(store.admitChanges(input)).resolves.toEqual({ acceptedHashes: ["one"], duplicateHashes: [] })
    await expect(store.admitChanges(input)).resolves.toEqual({ acceptedHashes: [], duplicateHashes: ["one"] })
  })

  it("Given an outbox owner closes, when its short claim expires, then another instance takes the same batch", async () => {
    const store = new DurableReplicaStore(new MemoryMeshStore())
    const base = { documentId: "room-1", targetDeviceId: "device-2", batchId: "batch-1", ttlMs: 100 }

    await expect(store.claimOutbox({ ...base, ownerInstanceId: "tab-a", now: 0 })).resolves.toMatchObject({ ownerInstanceId: "tab-a" })
    await expect(store.claimOutbox({ ...base, ownerInstanceId: "tab-b", now: 50 })).resolves.toBeUndefined()
    await expect(store.claimOutbox({ ...base, ownerInstanceId: "tab-b", now: 101 })).resolves.toMatchObject({ ownerInstanceId: "tab-b" })
  })

  it("Given local invalidation arrives or is missed, when heads differ or focus reconciles, then sibling reloads durable state", async () => {
    const reconciled: string[] = []
    const channel = new TestChannel()
    const invalidation = new BrowserReplicaInvalidation(
      channel,
      async () => ["old-head"],
      async documentId => { reconciled.push(documentId) },
    )

    channel.emit({ version: 1, documentId: "room-live", heads: ["new-head"] })
    await vi.waitFor(() => expect(reconciled).toEqual(["room-live"]))
    await invalidation.reconcileOnFocus(["room-missed"], async () => ["durable-head"])
    expect(reconciled).toEqual(["room-live", "room-missed"])
    invalidation.close()
  })

  it("Given invalidation work is in flight, when the consumer closes, then late work cannot reconcile", async () => {
    let releaseHeads!: (heads: string[]) => void
    const heads = new Promise<string[]>(resolve => { releaseHeads = resolve })
    const reconcile = vi.fn(async () => undefined)
    const channel = new TestChannel()
    const invalidation = new BrowserReplicaInvalidation(channel, async () => heads, reconcile)

    channel.emit({ version: 1, documentId: "room-closing", heads: ["new-head"] })
    invalidation.close()
    releaseHeads(["old-head"])
    await Promise.resolve()
    await Promise.resolve()

    expect(reconcile).not.toHaveBeenCalled()
  })

  it("Given broadcast reconciliation fails, when delivered outside a caller promise, then the error reaches its boundary", async () => {
    const report = vi.fn()
    const channel = new TestChannel()
    const invalidation = new BrowserReplicaInvalidation(
      channel,
      async () => { throw new Error("heads unavailable") },
      async () => undefined,
      report,
    )

    channel.emit({ version: 1, documentId: "room-failed", heads: ["new-head"] })
    await vi.waitFor(() => expect(report).toHaveBeenCalledWith(expect.objectContaining({ message: "heads unavailable" })))
    invalidation.close()
  })
})

class TestChannel {
  private listener?: (event: MessageEvent) => void
  postMessage(_value: unknown): void {}
  addEventListener(_type: "message", listener: (event: MessageEvent) => void): void { this.listener = listener }
  removeEventListener(_type: "message", listener: (event: MessageEvent) => void): void {
    if (this.listener === listener) this.listener = undefined
  }
  close(): void {}
  emit(value: unknown): void { this.listener?.({ data: value } as MessageEvent) }
}
