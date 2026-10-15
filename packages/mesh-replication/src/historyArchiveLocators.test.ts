import { expect, it, vi } from "vitest"
import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"
import { sealArchiveObject, type ArchiveEncryptionBinding, type EncryptedArchiveObject } from "./historyArchiveCrypto"
import { archiveLocatorKey, buildArchiveLocators, createLocatedArchiveStore, iterateArchiveLocatorEntries, lookupArchiveLocator, type ArchiveLocatorEntry } from "./historyArchiveLocators"

const encoder = new TextEncoder()
async function fixture(count = 131) {
  const scope = { scopeId: "opaque-locator-scope", keyEpoch: 3, key: new Uint8Array(32).fill(81) }
  const context = { workspaceId: "private-history-workspace", historyEpoch: 7, indexId: "archive-locators" }
  const data = new Map<string, EncryptedArchiveObject>(), entries: ArchiveLocatorEntry[] = [], bindings: ArchiveEncryptionBinding[] = []
  for (let i = 0; i < count; i++) {
    const bytes = encoder.encode(`ORIGINAL-PRIVATE-BYTES-${i}`)
    const binding: ArchiveEncryptionBinding = { ...context, indexId: "originals", objectId: await sha256Base64Url(bytes), objectKind: "part", partIndex: i, partCount: count }
    const sealed = await sealArchiveObject(scope, binding, bytes)
    const key = await sha256Base64Url(encoder.encode(canonicalizeJson(binding)))
    entries.push({ key, ciphertextId: sealed.ciphertextId }); bindings.push(binding); data.set(sealed.ciphertextId, sealed.object)
  }
  entries.sort((left, right) => left.key < right.key ? -1 : 1)
  const pages = new Map<string, EncryptedArchiveObject>()
  const write = vi.fn(async (binding: ArchiveEncryptionBinding, bytes: Uint8Array) => {
    expect(bytes.length).toBeLessThanOrEqual(64 * 1024)
    const sealed = await sealArchiveObject(scope, binding, bytes)
    pages.set(sealed.ciphertextId, sealed.object); return sealed
  })
  const root = await buildArchiveLocators(scope, context, entries, { write, ensureCurrent: () => {} })
  const download = vi.fn(async (id: string) => {
    const value = pages.get(id) ?? data.get(id)
    if (!value) throw new Error("Archive object missing")
    return structuredClone(value)
  })
  return { scope, context, root, entries, bindings, pages, data, write, download }
}

it("Given an encrypted locator directory, when a fresh receiver has only its root and reading key, then recover original bytes without source or a flat locator map", async () => {
  const f = await fixture()
  const store = createLocatedArchiveStore(f.scope, f.root, { download: f.download, ensureCurrent: () => {} })
  const binding = f.bindings[73]
  expect(await archiveLocatorKey(binding)).toBe(await sha256Base64Url(encoder.encode(canonicalizeJson(binding))))
  const { objectId, ...readBinding } = binding
  expect(await store.read(objectId, 256 * 1024, readBinding)).toEqual(encoder.encode("ORIGINAL-PRIVATE-BYTES-73"))
  expect(f.download).toHaveBeenCalledTimes(f.root.root.height + 2)
  expect(f.pages.size).toBe(4)
  expect(f.root.root.count).toBe(131)
  for (const object of f.pages.values()) {
    expect(JSON.stringify(object)).not.toContain(f.context.workspaceId)
    expect(JSON.stringify(object)).not.toContain("ORIGINAL-PRIVATE")
  }
  await expect(store.write(objectId, new Uint8Array())).rejects.toThrow()
})

it("Given a valid directory and a missing key, when looked up, then return missing after authenticating the directory without fetching a data object", async () => {
  const f = await fixture(3)
  const binding = { ...f.bindings[0], objectId: await sha256Base64Url(encoder.encode("missing")) }
  expect(await lookupArchiveLocator(f.scope, f.root, binding, { download: f.download, ensureCurrent: () => {} })).toBeUndefined()
  expect(f.download).toHaveBeenCalledTimes(1)
})

it("Given tampered root metadata, missing pages, wrong key or changed epoch, when cold lookup runs, then reject without writes or unauthenticated fallback", async () => {
  const f = await fixture(67), reader = { download: f.download, ensureCurrent: () => {} }
  for (const change of [{ count: f.root.root.count - 1 }, { first: f.root.root.last }, { height: 0 }]) {
    await expect(lookupArchiveLocator(f.scope, { ...f.root, root: { ...f.root.root, ...change } }, f.bindings[1], reader)).rejects.toThrow()
  }
  await expect(lookupArchiveLocator({ ...f.scope, key: new Uint8Array(32).fill(82) }, f.root, f.bindings[1], reader)).rejects.toThrow()
  await expect(lookupArchiveLocator(f.scope, f.root, { ...f.bindings[1], historyEpoch: 8 }, reader)).rejects.toThrow()
  const root = f.pages.get(f.root.root.ciphertextId)!
  f.pages.delete(f.root.root.ciphertextId)
  await expect(lookupArchiveLocator(f.scope, f.root, f.bindings[1], reader)).rejects.toThrow("missing")
  f.pages.set(f.root.root.ciphertextId, root)
  expect(f.write).toHaveBeenCalledTimes(3)
})

it("Given access revocation while a page is downloading, when lookup completes, then refuse to publish its locator or plaintext", async () => {
  const f = await fixture(2)
  let current = true
  const store = createLocatedArchiveStore(f.scope, f.root, { ensureCurrent: () => { if (!current) throw new Error("Access revoked") },
    download: async id => { const object = await f.download(id); current = false; return object } })
  const { objectId, ...binding } = f.bindings[0]
  await expect(store.read(objectId, 256 * 1024, binding)).rejects.toThrow("Access revoked")
  expect(f.download).toHaveBeenCalledTimes(1)
})

it("Given out-of-order or duplicate locator entries, when building, then fail without publishing a replacement root", async () => {
  const f = await fixture(2)
  for (const entries of [[f.entries[1], f.entries[0]], [f.entries[0], f.entries[0]]]) {
    await expect(buildArchiveLocators(f.scope, f.context, entries, { write: f.write, ensureCurrent: () => {} })).rejects.toThrow()
  }
})

it("Given a page-store failure during directory preparation, when retried, then preserve the original encrypted data and never modify a source object", async () => {
  const f = await fixture(67), original = structuredClone([...f.data])
  const write = vi.fn(f.write)
  write.mockRejectedValueOnce(new Error("Archive quota"))
  await expect(buildArchiveLocators(f.scope, f.context, f.entries, { write, ensureCurrent: () => {} })).rejects.toThrow("Archive quota")
  const root = await buildArchiveLocators(f.scope, f.context, f.entries, { write, ensureCurrent: () => {} })
  expect(root.root.count).toBe(67)
  expect([...f.data]).toEqual(original)
})

it("Given a complete encrypted directory, when preparing a full recovery export, then enumerate every data object in order and retain every authenticated directory page", async () => {
  const f = await fixture(131), pages = new Map<string, EncryptedArchiveObject>(), entries: ArchiveLocatorEntry[] = []
  for await (const entry of iterateArchiveLocatorEntries(f.scope, f.root, { download: f.download, ensureCurrent: () => {} },
    (id, object) => { pages.set(id, object) })) entries.push(entry)
  expect(entries).toEqual(f.entries)
  expect(pages).toEqual(f.pages)
  expect(f.download).toHaveBeenCalledTimes(f.pages.size)
  expect(entries.every(entry => f.data.has(entry.ciphertextId))).toBe(true)
})

it("Given an incomplete directory, when export enumerates it, then reject instead of reporting complete coverage", async () => {
  const f = await fixture(67)
  const missing = [...f.pages.keys()].find(id => id !== f.root.root.ciphertextId)!
  f.pages.delete(missing)
  await expect((async () => {
    for await (const _entry of iterateArchiveLocatorEntries(f.scope, f.root, { download: f.download, ensureCurrent: () => {} })) { /* Consume the full directory. */ }
  })()).rejects.toThrow(/missing/i)
})

it("Given access changes while enumerating an archive, when a page returns, then release no locator from that page", async () => {
  const f = await fixture(2), entries: ArchiveLocatorEntry[] = []
  let current = true
  await expect((async () => {
    for await (const entry of iterateArchiveLocatorEntries(f.scope, f.root, {
      download: async id => { const object = await f.download(id); current = false; return object },
      ensureCurrent: () => { if (!current) throw new Error("Access revoked") },
    })) entries.push(entry)
  })()).rejects.toThrow("Access revoked")
  expect(entries).toEqual([])
})
