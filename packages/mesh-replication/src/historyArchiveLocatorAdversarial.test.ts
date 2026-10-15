import { expect, it, vi } from "vitest"
import { canonicalizeJson, sha256Base64Url, toBase64Url } from "@meta-uber/mesh-identity"
import { openArchiveObject, sealArchiveObject, type ArchiveEncryptionBinding, type EncryptedArchiveObject } from "./historyArchiveCrypto"
import { archiveLocatorKey, buildArchiveLocators, lookupArchiveLocator, type ArchiveLocatorEntry } from "./historyArchiveLocators"
import { writeFile } from "node:fs/promises"

const encoder = new TextEncoder(), decoder = new TextDecoder()
const canonical = (value: unknown) => encoder.encode(canonicalizeJson(value))
async function fixture(count: number) {
  const scope = { scopeId: "opaque-locator-fixture", keyEpoch: 3, key: new Uint8Array(32).fill(80) }
  const context = { workspaceId: "private-locator-fixture", historyEpoch: 7, indexId: "archive-locators" }
  const entries: ArchiveLocatorEntry[] = [], bindings: ArchiveEncryptionBinding[] = []
  for (let i = 0; i < count; i++) {
    const binding: ArchiveEncryptionBinding = { ...context, indexId: "data", objectKind: "part", partIndex: i, partCount: count, objectId: await sha256Base64Url(encoder.encode(`data-${i}`)) }
    entries.push({ key: await archiveLocatorKey(binding), ciphertextId: await sha256Base64Url(encoder.encode(`cipher-${i}`)) }); bindings.push(binding)
  }
  entries.sort((a, b) => a.key < b.key ? -1 : 1)
  const pages = new Map<string, { objectId: string; ciphertextId: string; binding: ArchiveEncryptionBinding; object: EncryptedArchiveObject }>()
  const write = async (binding: ArchiveEncryptionBinding, bytes: Uint8Array) => {
    const sealed = await sealArchiveObject(scope, binding, bytes)
    pages.set(sealed.ciphertextId, { ...sealed, objectId: binding.objectId, binding: structuredClone(binding) }); return sealed
  }
  const root = await buildArchiveLocators(scope, context, entries, { write, ensureCurrent: () => {} })
  const download = vi.fn(async (id: string) => { const page = pages.get(id); if (!page) throw new Error("Missing locator page"); return page.object })
  return { scope, context, entries, bindings, root, pages, write, download }
}
async function reseal(f: Awaited<ReturnType<typeof fixture>>, mutate: (value: Record<string, unknown>) => void) {
  const old = f.pages.get(f.root.root.ciphertextId)!
  const value = JSON.parse(decoder.decode(await openArchiveObject(f.scope, old.binding, old.ciphertextId, old.object)))
  mutate(value)
  const bytes = canonical(value), objectId = await sha256Base64Url(bytes)
  const sealed = await f.write({ ...old.binding, objectId }, bytes)
  return { ...f.root, root: { ...f.root.root, objectId, ciphertextId: sealed.ciphertextId } }
}

it("Given validly encrypted malformed locator pages, when read, then reject unsupported schemas, duplicate keys and reordered entries after successful crypto", async () => {
  const f = await fixture(3)
  const mutations = [
    (value: Record<string, unknown>) => { value.version = 2 },
    (value: Record<string, unknown>) => { value.extra = true },
    (value: Record<string, unknown>) => { (value.entries as unknown[]).reverse() },
    (value: Record<string, unknown>) => { const entries = value.entries as unknown[]; entries[1] = structuredClone(entries[0]) },
    (value: Record<string, unknown>) => { ((value.entries as unknown[])[0] as Record<string, unknown>).extra = true },
  ]
  for (const mutate of mutations) {
    const root = await reseal(f, mutate)
    await expect(lookupArchiveLocator(f.scope, root, f.bindings[0], { download: f.download, ensureCurrent: () => {} })).rejects.toThrow()
  }
  expect(await lookupArchiveLocator(f.scope, f.root, f.bindings[0], { download: f.download, ensureCurrent: () => {} })).toBeDefined()
})

it("Given a forged child cardinality or duplicate opaque child pointer, when the authenticated parent is read, then reject before fetching any child", async () => {
  const f = await fixture(65)
  const firstKey = f.entries[0].key
  const keys = await Promise.all(f.bindings.map(archiveLocatorKey)), requested = f.bindings[keys.indexOf(firstKey)]
  const badCount = await reseal(f, value => { const children = value.children as Array<{ count: number }>; children[1].count = 2 })
  badCount.root.count = 66
  f.download.mockClear()
  await expect(lookupArchiveLocator(f.scope, badCount, requested, { download: f.download, ensureCurrent: () => {} })).rejects.toThrow()
  expect(f.download).toHaveBeenCalledTimes(1)
  const repeated = await reseal(f, value => {
    const children = value.children as Array<{ ciphertextId: string }>; children[1].ciphertextId = children[0].ciphertextId
  })
  f.download.mockClear()
  await expect(lookupArchiveLocator(f.scope, repeated, requested, { download: f.download, ensureCurrent: () => {} })).rejects.toThrow()
  expect(f.download).toHaveBeenCalledTimes(1)
})

it("Given an empty encrypted directory, when a binding is queried, then authenticate its empty root and return missing", async () => {
  const f = await fixture(0)
  const binding: ArchiveEncryptionBinding = { ...f.context, indexId: "data", objectKind: "page", objectId: await sha256Base64Url(encoder.encode("missing")), partIndex: 0, partCount: 1 }
  expect(await lookupArchiveLocator(f.scope, f.root, binding, { download: f.download, ensureCurrent: () => {} })).toBeUndefined()
  expect(f.root.root).toMatchObject({ count: 0, height: 0, first: null, last: null })
  expect(f.download).toHaveBeenCalledTimes(1)
})

it("Given mutations to caller keys, root and request during lookup, when pending crypto completes, then use the captured values", async () => {
  const f = await fixture(2), binding = structuredClone(f.bindings[0]), key = await archiveLocatorKey(binding)
  const expected = f.entries.find(entry => entry.key === key)
  const operation = lookupArchiveLocator(f.scope, f.root, binding, { download: f.download, ensureCurrent: () => {} })
  f.scope.key.fill(0); f.root.context.workspaceId = "changed"; f.root.root.count = 0; binding.partCount = 0
  expect(await operation).toBe(expected?.ciphertextId)
})

it("Given rejected async or valued access guards, when building or looking up a directory, then stop before storage", async () => {
  const f = await fixture(2)
  const rejected = async () => { throw new Error("Access changed") }
  f.download.mockClear()
  await expect(lookupArchiveLocator(f.scope, f.root, f.bindings[0], { download: f.download, ensureCurrent: rejected })).rejects.toThrow("Access changed")
  expect(f.download).not.toHaveBeenCalled()
  const write = vi.fn(f.write)
  await expect(buildArchiveLocators(f.scope, f.context, f.entries, { write, ensureCurrent: () => true as unknown as void })).rejects.toThrow(/guard/i)
  expect(write).not.toHaveBeenCalled()
})

it("Given the shared SDK/native locator vector, when opened, then derive the exact pointer from the encrypted branch and leaf", async () => {
  let nonce = 0
  const random = vi.spyOn(crypto, "getRandomValues").mockImplementation(array => {
    if (!(array instanceof Uint8Array) || array.length !== 12) throw new Error("Fixture only expects archive nonces")
    array.fill(0); new DataView(array.buffer, array.byteOffset, array.byteLength).setUint32(8, ++nonce); return array
  })
  let f: Awaited<ReturnType<typeof fixture>>
  try { f = await fixture(65) } finally { random.mockRestore() }
  const binding = f.bindings[17], key = await archiveLocatorKey(binding)
  const expected = f.entries.find(entry => entry.key === key)!.ciphertextId
  expect(await lookupArchiveLocator(f.scope, f.root, binding, { download: f.download, ensureCurrent: () => {} })).toBe(expected)
  expect(f.download).toHaveBeenCalledTimes(2)
  if (process.env.MESH_LOCATOR_FIXTURE_OUTPUT) await writeFile(process.env.MESH_LOCATOR_FIXTURE_OUTPUT, JSON.stringify({
    scope: { scopeId: f.scope.scopeId, keyEpoch: f.scope.keyEpoch }, key: toBase64Url(f.scope.key), root: f.root,
    binding, bindingKey: key, expectedCiphertextId: expected, objects: [...f.pages.values()], entries: f.entries,
  }, null, 2) + "\n")
})
