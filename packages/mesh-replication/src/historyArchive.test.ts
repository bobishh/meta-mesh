import { describe, expect, it, vi } from "vitest"
import { readFile } from "node:fs/promises"
import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"
import {
  buildArchiveIndex, readArchiveIndex, MAX_ARCHIVE_CHILDREN, MAX_ARCHIVE_DEPTH, MAX_ARCHIVE_PAGE_BYTES,
  type ArchiveIndexEntry, type ArchiveObjectStore, type ArchiveTreeContext,
} from "./historyArchive"

const encoder = new TextEncoder()
const context: ArchiveTreeContext = { workspaceId: "workspace", historyEpoch: 1, indexId: "changes" }

async function fixture() {
  const objects = new Map<string, Uint8Array>()
  const store: ArchiveObjectStore = {
    read: vi.fn(async id => objects.get(id)?.slice()),
    write: vi.fn(async (id, bytes) => {
      if (objects.has(id) && !objects.get(id)!.every((byte, i) => bytes[i] === byte)) throw new Error("Immutable object conflict")
      objects.set(id, bytes.slice())
    }),
  }
  return { objects, store, value: await sha256Base64Url(encoder.encode("retained evidence")) }
}

function* entries(count: number, objectId: string): Iterable<ArchiveIndexEntry> {
  for (let i = 0; i < count; i++) yield { key: `change:${i.toString(16).padStart(12, "0")}`, objectId }
}

describe("authenticated history archive index", () => {
  it("Given the shared native/browser wire fixture, when rebuilt and opened, then preserve exact canonical page bytes and UTF-16 key order", async () => {
    const sample = JSON.parse(await readFile(new URL("../fixtures/history-archive-v1.json", import.meta.url), "utf8"))
    const f = await fixture()
    const root = await buildArchiveIndex(sample.context, sample.entries, f.store)
    expect(root).toEqual(sample.root)
    expect(f.objects.size).toBe(sample.objects.length)
    for (const object of sample.objects) expect(f.objects.get(object.objectId)).toEqual(new Uint8Array(Buffer.from(object.bytes, "base64url")))
    const page = await readArchiveIndex(sample.context, root, f.store, { limit: 256 })
    expect(page).toEqual({ entries: sample.entries, nextAfter: null })
  })
  it.each([1_000, 10_000, 100_000])(
    "Given %i archived records, when one historical page opens, then read only bounded authenticated paths",
    async count => {
      const f = await fixture()
      const root = await buildArchiveIndex(context, entries(count, f.value), f.store)
      expect(root.count).toBe(count)
      expect(root.height).toBeLessThan(MAX_ARCHIVE_DEPTH)
      expect(encoder.encode(JSON.stringify(root)).length).toBeLessThan(2048)
      for (const bytes of f.objects.values()) {
        expect(bytes.length).toBeLessThanOrEqual(MAX_ARCHIVE_PAGE_BYTES)
        const page = JSON.parse(new TextDecoder().decode(bytes))
        expect((page.entries ?? page.children).length).toBeLessThanOrEqual(MAX_ARCHIVE_CHILDREN)
      }
      vi.mocked(f.store.read).mockClear()
      const result = await readArchiveIndex(context, root, f.store, { after: "change:0000000001f3", limit: 20 })
      expect(result.entries.map(entry => entry.key)).toEqual([...entries(521, f.value)].slice(500, 520).map(entry => entry.key))
      expect(result.nextAfter).toBe(result.entries.at(-1)?.key)
      expect(vi.mocked(f.store.read).mock.calls.length).toBeLessThanOrEqual(2 * (root.height + 1) + 1)
    }, 30_000,
  )

  it("Given a prefix crossing leaf boundaries, when paging to completion, then return each original entry once without reading unrelated leaves", async () => {
    const f = await fixture()
    const all = [...entries(2_000, f.value)]
    const root = await buildArchiveIndex(context, all, f.store)
    const received: ArchiveIndexEntry[] = []
    let after: string | undefined
    do {
      const page = await readArchiveIndex(context, root, f.store, { prefix: "change:0000000003", after, limit: 7 })
      received.push(...page.entries)
      after = page.nextAfter ?? undefined
    } while (after)
    expect(received).toEqual(all.filter(entry => entry.key.startsWith("change:0000000003")))
    expect(received).toHaveLength(256)
    expect(new Set(received.map(entry => entry.key)).size).toBe(256)
  })

  it("Given maximum-length Unicode keys, when pages pack, then both leaves and branch metadata obey the byte budget", async () => {
    const f = await fixture()
    const all = Array.from({ length: 5_000 }, (_, i) => ({ key: `${i.toString().padStart(6, "0")}:${"я".repeat(250)}`, objectId: f.value }))
    const root = await buildArchiveIndex(context, all, f.store)
    for (const bytes of f.objects.values()) expect(bytes.length).toBeLessThanOrEqual(MAX_ARCHIVE_PAGE_BYTES)
    const last = await readArchiveIndex(context, root, f.store, { after: all.at(-2)!.key, limit: 1 })
    expect(last).toEqual({ entries: [all.at(-1)!], nextAfter: null })
  }, 30_000)

  it("Given an empty archive, when inspected, then authenticate its empty root rather than inventing missing history", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, [], f.store)
    expect(root).toMatchObject({ height: 0, count: 0, first: null, last: null })
    expect(await readArchiveIndex(context, root, f.store)).toEqual({ entries: [], nextAfter: null })
    f.objects.delete(root.objectId)
    await expect(readArchiveIndex(context, root, f.store)).rejects.toThrow(/missing|unavailable/i)
  })

  it("Given source order or keys are invalid, when constructing an archive, then reject without returning a root", async () => {
    const f = await fixture()
    for (const keys of [["b", "a"], ["a", "a"], ["x".repeat(513)], ["bad\ud800"]]) {
      await expect(buildArchiveIndex(context, keys.map(key => ({ key, objectId: f.value })), f.store)).rejects.toThrow(/key|order/i)
    }
  })

  it("Given scope or a root descriptor is substituted, when reading, then reject before accepting an absence or entry", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(100, f.value), f.store)
    await expect(readArchiveIndex({ ...context, workspaceId: "other" }, root, f.store)).rejects.toThrow(/context|scope/i)
    await expect(readArchiveIndex({ ...context, historyEpoch: 2 }, root, f.store)).rejects.toThrow(/context|scope/i)
    await expect(readArchiveIndex({ ...context, indexId: "other" }, root, f.store)).rejects.toThrow(/context|scope/i)
    await expect(readArchiveIndex(context, { ...root, first: "z", last: "zz" }, f.store, { prefix: "a" })).rejects.toThrow(/root|range|metadata/i)
    await expect(readArchiveIndex(context, { ...root, count: root.count + 1 }, f.store)).rejects.toThrow(/root|count|metadata/i)
  })

  it("Given stored page bytes change, when opened, then reject corruption before JSON or entries are trusted", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(100, f.value), f.store)
    f.objects.set(root.objectId, encoder.encode("not JSON"))
    await expect(readArchiveIndex(context, root, f.store)).rejects.toThrow(/hash|integrity/i)
  })

  it("Given a committed child has a false range or unknown schema, when its path is visited, then reject instead of accepting its entries", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(100, f.value), f.store)
    const page = JSON.parse(new TextDecoder().decode(f.objects.get(root.objectId)!))
    page.children[0].count += 1
    const bytes = encoder.encode(canonicalizeJson(page))
    const id = await sha256Base64Url(bytes)
    f.objects.set(id, bytes)
    await expect(readArchiveIndex(context, { ...root, objectId: id, count: root.count + 1 }, f.store)).rejects.toThrow(/metadata|count|root/i)
    page.version = 2
    const unsupported = encoder.encode(canonicalizeJson(page))
    const unsupportedId = await sha256Base64Url(unsupported)
    f.objects.set(unsupportedId, unsupported)
    await expect(readArchiveIndex(context, { ...root, objectId: unsupportedId }, f.store)).rejects.toThrow(/schema|version/i)
  })

  it("Given a query bound or tree depth is invalid, when reading, then reject before storage access", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(1, f.value), f.store)
    vi.mocked(f.store.read).mockClear()
    for (const limit of [0, -1, 0.5, Infinity, 257]) await expect(readArchiveIndex(context, root, f.store, { limit })).rejects.toThrow(/limit|query/i)
    await expect(readArchiveIndex(context, { ...root, height: MAX_ARCHIVE_DEPTH }, f.store)).rejects.toThrow(/height|depth/i)
    expect(f.store.read).not.toHaveBeenCalled()
  })

  it("Given caller context changes during a write, when the tree finishes, then retain the captured workspace and epoch", async () => {
    const f = await fixture()
    const mutable = { ...context }
    const write = f.store.write
    f.store.write = async (id, bytes) => { mutable.workspaceId = "other"; mutable.historyEpoch = 2; await write(id, bytes) }
    const root = await buildArchiveIndex(mutable, entries(100, f.value), f.store)
    expect((await readArchiveIndex(context, root, f.store)).entries).toHaveLength(64)
    await expect(readArchiveIndex(mutable, root, f.store)).rejects.toThrow(/context|scope/i)
  })
})
