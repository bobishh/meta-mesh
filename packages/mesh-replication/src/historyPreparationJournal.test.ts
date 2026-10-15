import { expect, it, vi } from "vitest"
import { IDBFactory, IDBKeyRange } from "fake-indexeddb"
import { BrowserMeshStore } from "../../mesh-browser-store/src/index"
import { canonicalizeJson, publicKeyId, sha256Base64Url, signEnvelope, toBase64Url } from "@meta-uber/mesh-identity"
import { createHistoryPreparationJournal, type HistoryPreparationIdentity, type HistoryPreparationPersistence,
  type HistoryPreparationRemote } from "./historyPreparationJournal"
import { archiveCoverageBranch, verifyArchiveCoverageChild, type ArchiveCoverageBatchReceipt,
  type ArchiveCoverageAggregateReceipt, type ArchiveCoverageChild, type ArchiveCoverageObject } from "./historyArchiveCoverage"
import { openArchiveObject } from "./historyArchiveCrypto"
import type { ArchiveStorageReceipt } from "./historyArchiveRemote"
import { prepareArchiveLocators } from "./historyArchiveLocatorPreparation"
import { createLocatedArchiveStore } from "./historyArchiveLocators"
import type { EncryptedArchiveObject } from "./historyArchiveCrypto"

async function fixture() {
  vi.stubGlobal("indexedDB", new IDBFactory()); vi.stubGlobal("IDBKeyRange", IDBKeyRange)
  const name = crypto.randomUUID(), db = new BrowserMeshStore(name, ["history"])
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  const serviceId = await publicKeyId(servicePublicKey)
  const scope = { scopeId: "opaque-scope", keyEpoch: 1, key: crypto.getRandomValues(new Uint8Array(32)) }
  const identity: HistoryPreparationIdentity = { transitionId: crypto.randomUUID(), personId: serviceId, workspaceId: "workspace",
    historyEpoch: 2, sourceRevision: "A".repeat(43), authorityRevision: "A".repeat(43), privateBinding: "A".repeat(43), previousBaselineId: null,
    storage: { origin: "https://rusty.example", scopeId: scope.scopeId, policyRevision: 3, servicePublicKey,
      keyEpoch: 1, keyDigest: await sha256Base64Url(scope.key) } }
  const port = (store = db): HistoryPreparationPersistence => ({
    read: key => store.get<string>("history", key),
    scan: (prefix, after, limit) => store.scan<string>("history", prefix, after, limit),
    compareAndSwap: (conditions, writes, guard) => store.compareAndSwap(conditions.map(item => ({ ...item, store: "history" })),
      writes.map(item => ({ type: "put", store: "history", ...item })), guard),
  })
  const source = new TextEncoder().encode('  { "original": "signed pending proof", "extra": "retained unchanged" }\n')
  const bytes = new TextEncoder().encode("original archive part")
  const binding = { workspaceId: identity.workspaceId, historyEpoch: identity.historyEpoch, indexId: "evidence",
    objectId: await sha256Base64Url(bytes), objectKind: "part" as const, partIndex: 0, partCount: 2 }
  const rootBytes = new TextEncoder().encode('{"archive":"catalogue"}')
  const root = { ...binding, objectId: await sha256Base64Url(rootBytes), objectKind: "page" as const, partIndex: 0, partCount: 1 }
  const sign = <T extends { kind: string }>(payload: T) => signEnvelope(keys.privateKey, payload, serviceId, "RUSTY/2")
  const common = { version: 1 as const, serviceId, scopeId: scope.scopeId, policyRevision: 3 }
  const remote: HistoryPreparationRemote = {
    upload: vi.fn(async (object, requestId): Promise<ArchiveStorageReceipt> => sign({ ...common, kind: "blind-archive-storage-receipt",
      requestId, objectId: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(object))), keyEpoch: object.keyEpoch })),
    coverage: vi.fn(async (objects: ArchiveCoverageObject[], requestId): Promise<ArchiveCoverageBatchReceipt> => sign({
      ...common, kind: "blind-archive-coverage-batch-receipt", requestId, objects })),
    aggregate: vi.fn(async (archiveRootId: string, children: ArchiveCoverageChild[], requestId): Promise<ArchiveCoverageAggregateReceipt> => {
      const summaries = []
      for (const child of children) summaries.push(await verifyArchiveCoverageChild(child, identity.storage, archiveRootId))
      return sign({ ...common, kind: "blind-archive-coverage-aggregate-receipt", requestId, archiveRootId,
        ...await archiveCoverageBranch(archiveRootId, summaries) })
    }),
  }
  return { identity, scope, db, port, source, bytes, binding, root, rootBytes, remote, sign,
    reopen: () => new BrowserMeshStore(name, ["history"]),
    journal: (p = port(), guard = () => {}) => createHistoryPreparationJournal(identity, p, guard) }
}
async function collect(source: AsyncIterable<Uint8Array>) {
  const parts: Uint8Array[] = []
  for await (const part of source) parts.push(part)
  const result = new Uint8Array(parts.reduce((count, part) => count + part.length, 0))
  let offset = 0; for (const part of parts) { result.set(part, offset); offset += part.length }
  return result
}
async function prepare(f: Awaited<ReturnType<typeof fixture>>) {
  const journal = f.journal()
  await journal.capture([f.source])
  await journal.stage(f.scope, f.binding, f.bytes)
  await journal.stage(f.scope, { ...f.binding, partIndex: 1 }, f.bytes)
  await journal.stage(f.scope, f.root, f.rootBytes)
  return journal
}

it("Given covered data and a separate locator preparation, when directory upload loses a reply, then resume exact ciphertext and cold-read without the sender journal", async () => {
  const f = await fixture(), data = await prepare(f)
  for (let i = 0; i < 70; i++) await data.stage(f.scope, { ...f.binding, indexId: `many-originals-${i}` }, f.bytes)
  const stored = new Map<string, EncryptedArchiveObject>()
  let lose = false
  const remote = { ...f.remote, upload: vi.fn(async (object: EncryptedArchiveObject, requestId: string) => {
    const receipt = await f.remote.upload(object, requestId)
    stored.set(receipt.payload.objectId, structuredClone(object))
    if (lose) { lose = false; throw new Error("Directory reply lost") }
    return receipt
  }) }
  await data.archive(f.root); await data.cover(remote)
  const dataBefore = await data.read()
  const identity = { ...f.identity, transitionId: f.identity.transitionId + "-locators" }
  const directory = () => createHistoryPreparationJournal(identity, f.port(f.reopen()), () => {})
  lose = true
  await expect(prepareArchiveLocators({ data, directory: directory(), scope: f.scope, remote, ensureCurrent: () => {} })).rejects.toThrow("Directory reply lost")
  const pending = await directory().read()
  expect(pending?.phase).toBe("archived")
  expect(await data.read()).toEqual(dataBefore)
  expect(await collect(await data.readSource())).toEqual(f.source)
  const noEncryption = vi.spyOn(crypto.subtle, "encrypt").mockRejectedValue(new Error("Directory retry resealed"))
  let result: Awaited<ReturnType<typeof prepareArchiveLocators>>
  try { result = await prepareArchiveLocators({ data, directory: directory(), scope: f.scope, remote, ensureCurrent: () => {} }); expect(noEncryption).not.toHaveBeenCalled() }
  finally { noEncryption.mockRestore() }
  expect(result.directory.phase).toBe("covered")
  expect(result.root.root.count).toBe(73)
  expect(result.root.root.height).toBe(1)
  expect(result.directory.objectCount).toBe(3)
  expect(result.root.root.ciphertextId).toBe(pending!.root!.ciphertextId)
  const uploadCount = remote.upload.mock.calls.length
  const repeated = await prepareArchiveLocators({ data, directory: directory(), scope: f.scope, remote, ensureCurrent: () => {} })
  expect(repeated).toEqual(result)
  expect(remote.upload).toHaveBeenCalledTimes(uploadCount)
  const noSender = vi.spyOn(data, "locators").mockImplementation(() => { throw new Error("Sender journal unavailable") })
  const cold = createLocatedArchiveStore(f.scope, result.root, { ensureCurrent: () => {}, download: async id => {
    const object = stored.get(id); if (!object) throw new Error("Remote bytes missing"); return object
  } })
  const { objectId, ...binding } = f.binding
  expect(await cold.read(objectId, 256 * 1024, binding)).toEqual(f.bytes)
  expect(noSender).not.toHaveBeenCalled()
})

it("Given a live or differently bound directory preparation, when requested, then reject before persisting locator source or changing data", async () => {
  const f = await fixture(), data = await prepare(f)
  const make = (change = {}) => createHistoryPreparationJournal({ ...f.identity, transitionId: f.identity.transitionId + "-locators", ...change }, f.port(), () => {})
  const directory = make()
  await expect(prepareArchiveLocators({ data, directory, scope: f.scope, remote: f.remote, ensureCurrent: () => {} })).rejects.toThrow(/covered/i)
  expect(await directory.read()).toBeUndefined()
  await data.archive(f.root); await data.cover(f.remote)
  for (const directory of [make({ workspaceId: "another-workspace" }), make({ privateBinding: "B".repeat(42) + "A" }), data]) {
    const before = await f.db.list<string>("history")
    await expect(prepareArchiveLocators({ data, directory, scope: f.scope, remote: f.remote, ensureCurrent: () => {} })).rejects.toThrow(/binding|separate/i)
    expect(await f.db.list<string>("history")).toEqual(before)
  }
})

it("Given a frozen preparation, when its portable locator source is streamed, then enumerate exact binding hashes in bounded order without rewriting ciphertext", async () => {
  const f = await fixture(), journal = await prepare(f)
  const collect = async (source: ReturnType<typeof journal.locators>) => { const result = []; for await (const value of source) result.push(value); return result }
  await expect(collect(journal.locators())).rejects.toThrow(/frozen/i)
  await journal.archive(f.root)
  const before = await f.db.list<string>("history")
  const prepared = []; for await (const value of journal.objects()) prepared.push(value)
  const expected = await Promise.all(prepared.map(async value => ({ key: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(value.binding))), ciphertextId: value.sealed.ciphertextId })))
  expected.sort((left, right) => left.key < right.key ? -1 : 1)
  expect(await collect(f.journal(f.port(f.reopen())).locators())).toEqual(expected)
  expect(await f.db.list<string>("history")).toEqual(before)
})

it("Given a damaged binding index, when producing portable locators, then reject its substituted reference and retain the original source and encrypted objects", async () => {
  const f = await fixture(), journal = await prepare(f)
  await journal.archive(f.root)
  const rows = await f.db.scan<string>("history", "meta-mesh.history-preparation.v1.", undefined, 128)
  const bindings = rows.entries.filter(row => row.key.includes(".binding."))
  expect(bindings).toHaveLength(3)
  await f.db.put("history", bindings[0].key, bindings[1].value)
  const before = await f.db.list<string>("history")
  const consume = async () => { for await (const _entry of journal.locators()) { /* Drain integrity checks. */ } }
  await expect(consume()).rejects.toThrow()
  expect(await f.db.list<string>("history")).toEqual(before)
  expect(await collect(await journal.readSource())).toEqual(f.source)
})

it("Given exact captured source bytes, when a fresh IndexedDB handle reopens the preparation, then retain source and a bounded immutable header", async () => {
  const f = await fixture(), journal = f.journal()
  const state = await journal.capture([f.source])
  expect(state).toMatchObject({ phase: "captured", identity: f.identity, objectCount: 0 })
  expect(JSON.stringify(state).length).toBeLessThan(16 * 1024)
  const reopened = f.journal(f.port(f.reopen()))
  expect(await reopened.read()).toEqual(state)
  expect(await collect(await reopened.readSource())).toEqual(f.source)
  expect(await reopened.capture([f.source])).toEqual(state)
  await expect(reopened.capture([new Uint8Array([4])])).rejects.toThrow()
  expect(await reopened.read()).toEqual(state)
})

it("Given equal plaintext at two positions, when staged and retried after restart, then retain distinct bindings and exact committed ciphertext/request IDs", async () => {
  const f = await fixture(), journal = f.journal()
  await journal.capture([f.source])
  const one = await journal.stage(f.scope, f.binding, f.bytes)
  const two = await journal.stage(f.scope, { ...f.binding, partIndex: 1 }, f.bytes)
  expect(one.sealed.ciphertextId).not.toBe(two.sealed.ciphertextId)
  const reopened = f.journal(f.port(f.reopen()))
  expect(await reopened.stage(f.scope, f.binding, f.bytes)).toEqual(one)
  expect(await openArchiveObject(f.scope, one.binding, one.sealed.ciphertextId, one.sealed.object)).toEqual(f.bytes)
  expect((await reopened.read())?.objectCount).toBe(2)
  const records = []; for await (const record of reopened.objects()) records.push(record)
  expect(records.map(item => item.sealed.ciphertextId)).toEqual([one.sealed.ciphertextId, two.sealed.ciphertextId].sort())
})

it("Given a caller mutates a returned state, when the journal resumes, then its captured identity and encryption authority stay unchanged", async () => {
  const f = await fixture(), journal = f.journal()
  const captured = await journal.capture([f.source])
  captured.identity.workspaceId = "substituted"
  captured.identity.storage.keyDigest = "A".repeat(43)
  expect((await journal.read())?.identity).toEqual(f.identity)
  expect((await journal.stage(f.scope, f.binding, f.bytes)).binding.workspaceId).toBe(f.identity.workspaceId)
})

it("Given a lost staging commit reply, when the exact binding is retried, then resolve the committed object without resealing or duplicate records", async () => {
  const f = await fixture(), journal = f.journal()
  await journal.capture([f.source])
  const port = f.port(), commit = port.compareAndSwap
  port.compareAndSwap = async (...args) => { const applied = await commit(...args); if (applied) throw new Error("Commit reply lost"); return applied }
  await expect(f.journal(port).stage(f.scope, f.binding, f.bytes)).rejects.toThrow(/reply lost/)
  const before = await f.db.list<string>("history")
  const reopened = f.journal(f.port(f.reopen()))
  const retried = await reopened.stage(f.scope, f.binding, f.bytes)
  expect(retried.index).toBe(0)
  expect((await reopened.read())?.objectCount).toBe(1)
  expect(await f.db.list<string>("history")).toEqual(before)
})

it("Given two independent preparation writers, when they race on equal or different bindings, then publish one exact object per binding without replacing source", async () => {
  const f = await fixture(), left = f.journal(), right = f.journal(f.port(f.reopen()))
  await left.capture([f.source])
  const [one, same] = await Promise.all([left.stage(f.scope, f.binding, f.bytes), right.stage(f.scope, f.binding, f.bytes)])
  expect(one).toEqual(same)
  await Promise.all([left.stage(f.scope, { ...f.binding, partIndex: 1 }, f.bytes), right.stage(f.scope, f.root, f.rootBytes)])
  expect((await right.read())?.objectCount).toBe(3)
  expect(await collect(await right.readSource())).toEqual(f.source)
})

it("Given quota failure or an identity change inside the transaction, when staging, then retain the prior source/header without a partial object", async () => {
  const f = await fixture(), journal = f.journal()
  const before = await journal.capture([f.source]), saved = await f.db.list<string>("history")
  const quota = f.port(); quota.compareAndSwap = async () => { throw new Error("QuotaExceededError") }
  await expect(f.journal(quota).stage(f.scope, f.binding, f.bytes)).rejects.toThrow(/Quota/)
  const stale = f.port(), commit = stale.compareAndSwap
  let current = true
  stale.compareAndSwap = (conditions, writes, guard) => commit(conditions, writes, () => { current = false; guard() })
  await expect(f.journal(stale, () => { if (!current) throw new Error("Identity changed") }).stage(f.scope, f.binding, f.bytes)).rejects.toThrow(/Identity changed/)
  expect(await journal.read()).toEqual(before)
  expect(await f.db.list<string>("history")).toEqual(saved)
})

it("Given wrong scope, key, epoch or binding, when staging, then reject before publishing reusable ciphertext", async () => {
  const f = await fixture(), journal = f.journal()
  await journal.capture([f.source])
  const before = await f.db.list<string>("history")
  for (const scope of [{ ...f.scope, scopeId: "other" }, { ...f.scope, keyEpoch: 2 }, { ...f.scope, key: new Uint8Array(32) }]) {
    await expect(journal.stage(scope, f.binding, f.bytes)).rejects.toThrow()
  }
  for (const binding of [{ ...f.binding, workspaceId: "other" }, { ...f.binding, historyEpoch: 3 }, { ...f.binding, objectId: "A".repeat(43) }]) {
    await expect(journal.stage(f.scope, binding, f.bytes)).rejects.toThrow()
  }
  expect(await f.db.list<string>("history")).toEqual(before)
})

it("Given an asynchronous publication guard, when capture starts, then reject the invalid guard before any storage write", async () => {
  const f = await fixture(), port = f.port(), commit = vi.fn(port.compareAndSwap)
  port.compareAndSwap = commit
  await expect(f.journal(port, async () => {}).capture([f.source])).rejects.toThrow(/synchronous/)
  expect(commit).not.toHaveBeenCalled()
  expect(await f.db.list("history")).toEqual([])
})

it("Given a prepared archive, when frozen and confirmed, then verify complete coverage from journal-owned objects and retain exact original source", async () => {
  const f = await fixture(), journal = await prepare(f)
  const archived = await journal.archive(f.root)
  expect(archived).toMatchObject({ phase: "archived", objectCount: 3, expectedCoverage: { objectCount: 3, rootCovered: true } })
  await expect(journal.stage(f.scope, { ...f.binding, indexId: "late" }, f.bytes)).rejects.toThrow()
  const covered = await journal.cover(f.remote)
  expect(covered.phase).toBe("covered")
  expect(covered.coverage?.payload.objectCount).toBe(3)
  expect(await f.journal(f.port(f.reopen())).read()).toEqual(covered)
  expect(await collect(await journal.readSource())).toEqual(f.source)
})

it("Given a lost upload response, when a fresh journal resumes, then send the exact persisted ciphertext and request again", async () => {
  const f = await fixture(), journal = await prepare(f)
  await journal.archive(f.root)
  const upload = vi.fn(f.remote.upload)
  let lost = true
  const remote = { ...f.remote, upload: vi.fn(async (...args: Parameters<typeof upload>) => {
    const result = await upload(...args)
    if (lost) { lost = false; throw new Error("Upload reply lost") }
    return result
  }) }
  await expect(journal.cover(remote)).rejects.toThrow(/reply lost/)
  expect((await journal.read())?.phase).toBe("archived")
  expect((await f.journal(f.port(f.reopen())).cover(remote)).phase).toBe("covered")
  expect(upload.mock.calls[1]).toEqual(upload.mock.calls[0])
})

it("Given a signed but substituted coverage reply, when confirming, then keep archive pending instead of declaring complete", async () => {
  const f = await fixture(), journal = await prepare(f)
  await journal.archive(f.root)
  const aggregate = f.remote.aggregate
  const remote = { ...f.remote, aggregate: async (...args: Parameters<typeof aggregate>) => {
    const result = await aggregate(...args)
    result.payload.objectCount = 1
    return result
  } }
  await expect(journal.cover(remote)).rejects.toThrow()
  expect((await journal.read())?.phase).toBe("archived")
  expect((await journal.cover(f.remote)).phase).toBe("covered")
})

it("Given missing or corrupted durable records, when reopening or freezing, then preserve retained bytes and refuse coverage", async () => {
  const f = await fixture(), journal = await prepare(f)
  const stored = await f.db.list<string>("history")
  const object = stored.find(item => item.value.includes('"kind":"workspace-history-prepared-object"'))!
  const bad = object.value + " "
  await f.db.put("history", object.key, bad)
  await expect(f.journal(f.port(f.reopen())).archive(f.root)).rejects.toThrow()
  expect(await f.db.get("history", object.key)).toBe(bad)
  expect((await journal.read())?.phase).toBe("captured")
})

it("Given more than one page of prepared objects, when reopened, then enumerate bounded sorted pages and keep the header independent of object count", async () => {
  const f = await fixture(), port = f.port(), scan = vi.fn(port.scan)
  port.scan = scan
  const journal = f.journal(port)
  await journal.capture([f.source])
  for (let i = 0; i < 70; i++) await journal.stage(f.scope, { ...f.binding, partIndex: i, partCount: 70 }, f.bytes)
  await journal.stage(f.scope, f.root, f.rootBytes)
  const archived = await journal.archive(f.root)
  expect(JSON.stringify(archived).length).toBeLessThan(16 * 1024)
  scan.mockClear()
  const ids = []; for await (const item of journal.objects()) ids.push(item.sealed.ciphertextId)
  expect(ids).toHaveLength(71)
  expect(ids).toEqual([...ids].sort())
  expect(scan).toHaveBeenCalledTimes(2)
  expect(scan.mock.calls.every(([, , limit]) => limit === 64)).toBe(true)
  scan.mockClear()
  const locators = []; for await (const item of journal.locators()) locators.push(item)
  expect(locators).toHaveLength(71)
  expect(locators.map(item => item.key)).toEqual(locators.map(item => item.key).sort())
  expect(new Set(locators.map(item => item.ciphertextId))).toEqual(new Set(ids))
  expect(scan).toHaveBeenCalledTimes(2)
  expect(scan.mock.calls.every(([, , limit]) => limit === 64)).toBe(true)
})

it("Given the final coverage transaction commits but its reply is lost, when retried from another handle, then read verified completion without another upload", async () => {
  const f = await fixture(), journal = await prepare(f)
  await journal.archive(f.root)
  const port = f.port(), commit = port.compareAndSwap
  port.compareAndSwap = async (...args) => {
    const applied = await commit(...args)
    if (applied && args[1].some(write => write.value.includes('"phase":"covered"'))) throw new Error("Coverage commit reply lost")
    return applied
  }
  const upload = vi.fn(f.remote.upload), remote = { ...f.remote, upload }
  await expect(f.journal(port).cover(remote)).rejects.toThrow(/reply lost/)
  expect(upload).toHaveBeenCalledTimes(3)
  const reopened = f.journal(f.port(f.reopen()))
  expect((await reopened.cover(remote)).phase).toBe("covered")
  expect(upload).toHaveBeenCalledTimes(3)
})

it("Given a valid service signature for another storage policy, when uploading prepared bytes, then keep the frozen archive pending", async () => {
  const f = await fixture(), journal = await prepare(f)
  await journal.archive(f.root)
  const remote = { ...f.remote, upload: async (...args: Parameters<typeof f.remote.upload>) => {
    const receipt = await f.remote.upload(...args)
    return f.sign({ ...receipt.payload, policyRevision: 4 })
  } }
  await expect(journal.cover(remote)).rejects.toThrow()
  expect((await journal.read())?.phase).toBe("archived")
})

it("Given a missing staged object or unsupported header version, when reopened, then refuse progress and preserve retained source and incompatible bytes", async () => {
  const f = await fixture(), journal = await prepare(f)
  const saved = await f.db.list<string>("history")
  const object = saved.find(item => item.value.includes('"kind":"workspace-history-prepared-object"') && item.value.includes('"objectKind":"part"'))!
  await f.db.delete("history", object.key)
  await expect(journal.archive(f.root)).rejects.toThrow()
  expect(await collect(await journal.readSource())).toEqual(f.source)
  const header = saved.find(item => item.key.endsWith(".head"))!
  const newer = canonicalizeJson({ ...JSON.parse(header.value), version: 2 })
  await f.db.put("history", header.key, newer)
  await expect(f.journal(f.port(f.reopen())).read()).rejects.toThrow()
  expect(await f.db.get("history", header.key)).toBe(newer)
})
