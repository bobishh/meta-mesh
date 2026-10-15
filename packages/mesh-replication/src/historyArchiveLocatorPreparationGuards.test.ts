import { expect, it, vi } from "vitest"
import { MemoryMeshStore } from "../../mesh-browser-store/src/index"
import { archiveCoverageBranch, verifyArchiveCoverageChild, type ArchiveCoverageChild, type ArchiveCoverageObject } from "./historyArchiveCoverage"
import { createHistoryPreparationJournal, type HistoryPreparationIdentity, type HistoryPreparationPersistence,
  type HistoryPreparationRemote } from "./historyPreparationJournal"
import { prepareArchiveLocators } from "./historyArchiveLocatorPreparation"
import { canonicalizeJson, publicKeyId, sha256Base64Url, signEnvelope, toBase64Url } from "@meta-uber/mesh-identity"
import type { ArchiveStorageReceipt } from "./historyArchiveRemote"
import type { ArchiveEncryptionScope } from "./historyArchiveCrypto"

const digest = (value: string) => sha256Base64Url(new TextEncoder().encode(value))

async function fixture() {
  const store = new MemoryMeshStore()
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)))
  const serviceId = await publicKeyId(servicePublicKey)
  const scope: ArchiveEncryptionScope = { scopeId: "locator-guard-scope", keyEpoch: 4, key: crypto.getRandomValues(new Uint8Array(32)) }
  const identity: HistoryPreparationIdentity = { transitionId: crypto.randomUUID(), personId: serviceId, workspaceId: "guard-workspace",
    historyEpoch: 9, sourceRevision: await digest("source"), authorityRevision: await digest("authority"),
    privateBinding: await digest("private-binding"), previousBaselineId: null,
    storage: { origin: "https://rusty.example", scopeId: scope.scopeId, policyRevision: 6, servicePublicKey,
      keyEpoch: scope.keyEpoch, keyDigest: await sha256Base64Url(scope.key) } }
  const persistence = (target = store): HistoryPreparationPersistence => ({
    read: key => target.get<string>("history", key),
    scan: (prefix, after, limit) => target.scan<string>("history", prefix, after, limit),
    compareAndSwap: (conditions, writes, guard) => target.compareAndSwap(
      conditions.map(item => ({ ...item, store: "history" })),
      writes.map(item => ({ type: "put" as const, store: "history", ...item })), guard),
  })
  const source = new TextEncoder().encode('{"signed":"captured original"}')
  const dataBytes = new TextEncoder().encode("covered archive bytes")
  const dataBinding = { workspaceId: identity.workspaceId, historyEpoch: identity.historyEpoch, indexId: "evidence",
    objectId: await sha256Base64Url(dataBytes), objectKind: "part" as const, partIndex: 0, partCount: 1 }
  const dataRootBytes = new TextEncoder().encode('{"kind":"catalogue"}')
  const dataRoot = { ...dataBinding, objectId: await sha256Base64Url(dataRootBytes), objectKind: "page" as const, partIndex: 0, partCount: 1 }
  const authority = { servicePublicKey, scopeId: scope.scopeId, policyRevision: identity.storage.policyRevision }
  const sign = <T extends { kind: string }>(payload: T) => signEnvelope(keys.privateKey, payload, serviceId, "RUSTY/2")
  const common = { version: 1 as const, serviceId, scopeId: scope.scopeId, policyRevision: identity.storage.policyRevision }
  const remote: HistoryPreparationRemote = {
    upload: vi.fn(async (object, requestId): Promise<ArchiveStorageReceipt> => sign({ ...common, kind: "blind-archive-storage-receipt",
      requestId, objectId: await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(object))), keyEpoch: object.keyEpoch })),
    coverage: vi.fn(async (objects: ArchiveCoverageObject[], requestId: string) => sign({ ...common,
      kind: "blind-archive-coverage-batch-receipt" as const, requestId, objects })),
    aggregate: vi.fn(async (archiveRootId: string, children: ArchiveCoverageChild[], requestId: string) => {
      const summaries = []
      for (const child of children) summaries.push(await verifyArchiveCoverageChild(child, authority, archiveRootId))
      return sign({ ...common, kind: "blind-archive-coverage-aggregate-receipt" as const, requestId, archiveRootId,
        ...await archiveCoverageBranch(archiveRootId, summaries) })
    }),
  }
  const journal = (journalIdentity: HistoryPreparationIdentity = identity, target = store) =>
    createHistoryPreparationJournal(journalIdentity, persistence(target), () => {})
  const data = journal()
  await data.capture([source])
  await data.stage(scope, dataBinding, dataBytes)
  await data.stage(scope, dataRoot, dataRootBytes)
  await data.archive(dataRoot)
  await data.cover(remote)
  vi.mocked(remote.upload).mockClear()
  vi.mocked(remote.coverage).mockClear()
  vi.mocked(remote.aggregate).mockClear()
  return { store, scope, identity, source, data, dataRoot, remote, persistence, journal }
}

function separateIdentity(identity: HistoryPreparationIdentity): HistoryPreparationIdentity {
  return { ...identity, transitionId: `${identity.transitionId}-locator-directory` }
}

it("Given wrong scope, key, epoch, or directory identity, when preparing locators, then fail before directory capture", async () => {
  const f = await fixture()
  const mismatches: Array<{ scope?: ArchiveEncryptionScope; identity?: HistoryPreparationIdentity }> = [
    { scope: { ...f.scope, scopeId: "other-scope" } },
    { scope: { ...f.scope, keyEpoch: f.scope.keyEpoch + 1 } },
    { scope: { ...f.scope, key: new Uint8Array(32) } },
    { identity: { ...separateIdentity(f.identity), workspaceId: "other-workspace" } },
    { identity: { ...separateIdentity(f.identity), historyEpoch: f.identity.historyEpoch + 1 } },
    { identity: { ...separateIdentity(f.identity), storage: { ...f.identity.storage, keyDigest: await digest("wrong-key") } } },
  ]
  for (const mismatch of mismatches) {
    const directory = f.journal(mismatch.identity ?? separateIdentity(f.identity))
    const before = await f.store.list<string>("history")
    await expect(prepareArchiveLocators({ data: f.data, directory, scope: mismatch.scope ?? f.scope,
      remote: f.remote, ensureCurrent: () => {} })).rejects.toThrow()
    expect(await directory.read()).toBeUndefined()
    expect(await f.store.list<string>("history")).toEqual(before)
  }
  expect(f.remote.upload).not.toHaveBeenCalled()
})

it("Given an async guard that rejects or returns a value, when preparing, then publish nothing", async () => {
  const f = await fixture()
  for (const guard of [
    async () => { throw new Error("identity revoked") },
    async (): Promise<void> => "unexpected" as never,
  ]) {
    const directory = f.journal(separateIdentity(f.identity))
    const before = await f.store.list<string>("history")
    await expect(prepareArchiveLocators({ data: f.data, directory, scope: f.scope, remote: f.remote, ensureCurrent: guard }))
      .rejects.toThrow()
    expect(await directory.read()).toBeUndefined()
    expect(await f.store.list<string>("history")).toEqual(before)
  }
  expect(f.remote.upload).not.toHaveBeenCalled()
})

it("Given caller replaces inputs during the first guard await, when preparing, then keep captured scope, journals, and callbacks", async () => {
  const f = await fixture()
  const decoyStore = new MemoryMeshStore()
  const decoyRemote: HistoryPreparationRemote = {
    upload: vi.fn(async () => { throw new Error("retargeted upload") }),
    coverage: vi.fn(async () => { throw new Error("retargeted coverage") }),
    aggregate: vi.fn(async () => { throw new Error("retargeted aggregate") }),
  }
  const input: Parameters<typeof prepareArchiveLocators>[0] = {
    data: f.data,
    directory: f.journal(separateIdentity(f.identity)),
    scope: { ...f.scope, key: new Uint8Array(f.scope.key) },
    remote: f.remote,
    ensureCurrent: () => {},
  }
  const originalDirectory = input.directory
  const originalRemote = input.remote
  input.ensureCurrent = async () => {
    input.scope.scopeId = "substituted-scope"
    input.scope.key.fill(0)
    input.scope.keyEpoch += 1
    input.data = f.journal({ ...f.identity, workspaceId: "substituted-data" })
    input.directory = f.journal({ ...separateIdentity(f.identity), workspaceId: "substituted-directory" }, decoyStore)
    input.remote = decoyRemote
  }

  const result = await prepareArchiveLocators(input)
  expect(result.directory.phase).toBe("covered")
  expect(await originalDirectory.read()).toEqual(result.directory)
  expect(await input.directory.read()).toBeUndefined()
  expect(await decoyStore.list("history")).toEqual([])
  expect(originalRemote.upload).toHaveBeenCalled()
  expect(decoyRemote.upload).not.toHaveBeenCalled()
})
