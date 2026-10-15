import { describe, expect, it, vi } from "vitest"
import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"
import {
  buildArchiveIndex, readArchiveIndex, readArchiveBytes, writeArchiveBytes,
  MAX_ARCHIVE_CHILDREN, MAX_ARCHIVE_PART_BYTES,
  type ArchiveIndexEntry, type ArchiveIndexQuery, type ArchiveIndexRoot, type ArchiveObjectStore, type ArchiveTreeContext,
} from "./historyArchive"

const encoder = new TextEncoder()
const context: ArchiveTreeContext = { workspaceId: "workspace", historyEpoch: 4, indexId: "proof-history" }

async function fixture() {
  const objects = new Map<string, Uint8Array>()
  const store: ArchiveObjectStore = {
    read: vi.fn(async objectId => objects.get(objectId)?.slice()),
    write: vi.fn(async (objectId, bytes) => { objects.set(objectId, bytes.slice()) }),
  }
  const objectId = await sha256Base64Url(encoder.encode("archived object"))
  return { objects, store, objectId }
}

function* entries(count: number, objectId: string, prefix = "change:"): Iterable<ArchiveIndexEntry> {
  for (let i = 0; i < count; i++) yield { key: `${prefix}${i.toString().padStart(8, "0")}`, objectId }
}

async function commitPage(f: Awaited<ReturnType<typeof fixture>>, page: Record<string, any>, encoding?: string) {
  const bytes = encoder.encode(encoding ?? canonicalizeJson(page))
  const objectId = await sha256Base64Url(bytes)
  f.objects.set(objectId, bytes)
  const children = page.children as ArchiveIndexRoot[] | undefined
  const pageEntries = page.entries as ArchiveIndexEntry[] | undefined
  const count = children ? children.reduce((total, child) => total + child.count, 0) : pageEntries!.length
  return {
    objectId,
    height: page.height,
    count,
    first: children ? children[0]!.first : pageEntries![0]?.key ?? null,
    last: children ? children.at(-1)!.last : pageEntries!.at(-1)?.key ?? null,
  } satisfies ArchiveIndexRoot
}

describe("adversarial archived history index", () => {
  it.each([
    ["overlapping child ranges", (page: Record<string, any>) => { page.children[1].first = page.children[0].last }],
    ["duplicate child IDs", (page: Record<string, any>) => { page.children[1].objectId = page.children[0].objectId }],
    ["unknown page fields", (page: Record<string, any>) => { page.unrecognized = true }],
  ] as const)("Given a committed page with %s, when its content hash is valid, then reject the page schema", async (_case, mutate) => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(1_000, f.objectId), f.store)
    const page = JSON.parse(new TextDecoder().decode(f.objects.get(root.objectId)!)) as Record<string, any>
    expect(page.children.length).toBeGreaterThanOrEqual(2)
    mutate(page)
    const hostileRoot = await commitPage(f, page)

    await expect(readArchiveIndex(context, hostileRoot, f.store)).rejects.toThrow(/overlap|child|schema/i)
  })

  it("Given committed non-canonical page bytes with a matching digest, when loaded, then reject encoding", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(8, f.objectId), f.store)
    const page = JSON.parse(new TextDecoder().decode(f.objects.get(root.objectId)!)) as Record<string, any>
    const nonCanonicalRoot = await commitPage(f, page, JSON.stringify(page, null, 2))

    await expect(readArchiveIndex(context, nonCanonicalRoot, f.store)).rejects.toThrow(/canonical/i)
  })

  it("Given committed children whose summed count is unsafe, when the page digest is valid, then reject count arithmetic", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(1_000, f.objectId), f.store)
    const page = JSON.parse(new TextDecoder().decode(f.objects.get(root.objectId)!)) as Record<string, any>
    page.children[0].count = Number.MAX_SAFE_INTEGER
    page.children[1].count = Number.MAX_SAFE_INTEGER
    const hostileRoot: ArchiveIndexRoot = {
      objectId: await sha256Base64Url(encoder.encode(canonicalizeJson(page))),
      height: page.height,
      count: 1,
      first: page.children[0].first,
      last: page.children.at(-1).last,
    }
    f.objects.set(hostileRoot.objectId, encoder.encode(canonicalizeJson(page)))

    await expect(readArchiveIndex(context, hostileRoot, f.store)).rejects.toThrow(/safe integer|count/i)
  })

  it("Given a malformed canonical 43-character digest, when reading a root, then reject before storage access", async () => {
    const f = await fixture()
    const root = await buildArchiveIndex(context, entries(1, f.objectId), f.store)
    vi.mocked(f.store.read).mockClear()
    const malformedRoot = { ...root, objectId: `${"A".repeat(42)}B` }

    await expect(readArchiveIndex(context, malformedRoot, f.store)).rejects.toThrow(/hash|object/i)
    expect(f.store.read).not.toHaveBeenCalled()
  })

  it("Given root and query objects mutate during a pending page read, when reading completes, then use their captured originals", async () => {
    const f = await fixture()
    const originalRoot = await buildArchiveIndex(context, entries(4, f.objectId), f.store)
    const mutableRoot = { ...originalRoot }
    const query: ArchiveIndexQuery = { limit: 1 }
    let entered!: () => void
    let release!: () => void
    const readEntered = new Promise<void>(resolve => { entered = resolve })
    const pendingRead = new Promise<void>(resolve => { release = resolve })
    const rawRead = f.store.read
    f.store.read = vi.fn(async (objectId, maximumBytes) => {
      entered()
      await pendingRead
      const bytes = await rawRead(objectId, maximumBytes)
      return bytes?.slice()
    })

    const resultPromise = readArchiveIndex(context, mutableRoot, f.store, query)
    await readEntered
    mutableRoot.objectId = `${"A".repeat(42)}B`
    query.limit = 4
    query.after = "change:00000002"
    release()

    const result = await resultPromise
    expect(result.entries.map(entry => entry.key)).toEqual(["change:00000000"])
    expect(result.nextAfter).toBe("change:00000000")
  })

  it("Given an archive source fails after persisting a page, when construction aborts, then return no root and keep prior root readable", async () => {
    const f = await fixture()
    const retained = await buildArchiveIndex(context, entries(3, f.objectId), f.store)
    vi.mocked(f.store.write).mockClear()
    async function* interrupted() {
      yield* entries(MAX_ARCHIVE_CHILDREN, f.objectId, "candidate:")
      throw new Error("history source interrupted")
    }

    await expect(buildArchiveIndex(context, interrupted(), f.store)).rejects.toThrow("history source interrupted")
    expect(f.store.write).toHaveBeenCalled()
    expect((await readArchiveIndex(context, retained, f.store)).entries).toEqual([...entries(3, f.objectId)])
  })

  it("Given a later immutable-part write fails, when byte archiving aborts, then return no reference and keep old evidence readable", async () => {
    const f = await fixture()
    const priorBytes = encoder.encode("retained original evidence")
    const retained = await writeArchiveBytes(context, [priorBytes], f.store)
    const write = f.store.write
    let writes = 0
    f.store.write = vi.fn(async (objectId, bytes) => {
      if (++writes === 2) throw new Error("archive quota failure")
      await write(objectId, bytes)
    })
    const sourceBytes = new Uint8Array(MAX_ARCHIVE_PART_BYTES + 1).fill(19)

    async function* source() {
      yield sourceBytes.subarray(0, MAX_ARCHIVE_PART_BYTES)
      yield sourceBytes.subarray(MAX_ARCHIVE_PART_BYTES)
    }

    await expect(writeArchiveBytes(context, source(), f.store)).rejects.toThrow("archive quota failure")
    const readOnlyStore: ArchiveObjectStore = { read: f.store.read, write: vi.fn() }
    const parts: Uint8Array[] = []
    for await (const part of await readArchiveBytes(context, retained, readOnlyStore)) parts.push(part)
    expect(parts).toEqual([priorBytes])
    expect(readOnlyStore.write).not.toHaveBeenCalled()
  })
})
