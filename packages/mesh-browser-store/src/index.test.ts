import { describe, expect, it } from "vitest"
import { MemoryMeshStore } from "./index"

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
})
