import type { ArchiveBytesReference } from "./historyArchive"
import type { ArchiveEncryptionBinding, ArchiveEncryptionScope, SealedArchiveObject } from "./historyArchiveCrypto"
import type { ArchiveCoverageAggregateReceipt, ArchiveCoverageSummary } from "./historyArchiveCoverage"
import type { ArchiveCoveragePort } from "./historyArchiveCoverageSet"
import type { ArchiveStorageReceipt } from "./historyArchiveRemote"
import type { ArchiveLocatorEntry } from "./historyArchiveLocators"
import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"
import { readArchiveBytes, writeArchiveBytes, validateArchiveObjectId } from "./historyArchive"
import { createArchiveObjectStore } from "./historyArchiveStore"
import { captureArchiveEncryptionScope, openArchiveObject, sealArchiveObject } from "./historyArchiveCrypto"
import { confirmArchiveCoverageSet, deriveArchiveCoverageSet } from "./historyArchiveCoverageSet"
import { capturePreparationIdentity, capturePreparationBinding, parsePreparationState, parsePreparedReference,
  digestRecord, verifyPreparedObject, verifyPreparedCoverage, verifyPreparedStorageReceipt, MAX_PREPARED_OBJECTS, fail } from "./historyPreparationData"

/** Caller-captured bindings, not proof of admission or Owner authority; Native policy must establish those separately. */
export type HistoryPreparationIdentity = {
  transitionId: string; personId: string; workspaceId: string; historyEpoch: number
  sourceRevision: string; authorityRevision: string; privateBinding: string; previousBaselineId: string | null
  storage: { origin: string; scopeId: string; policyRevision: number; servicePublicKey: string; keyEpoch: number; keyDigest: string }
}
export type HistoryPreparationState = {
  kind: "workspace-history-preparation"; version: 1; identity: HistoryPreparationIdentity
  phase: "captured" | "archived" | "covered"; source: ArchiveBytesReference
  objectCount: number; objectDigest: string | null
  root: { binding: ArchiveEncryptionBinding; ciphertextId: string } | null
  expectedCoverage: ArchiveCoverageSummary | null; coverage: ArchiveCoverageAggregateReceipt | null
}
export type HistoryPreparedObject = {
  kind: "workspace-history-prepared-object"; version: 1; index: number; previousDigest: string | null
  binding: ArchiveEncryptionBinding; requestId: string; sealed: SealedArchiveObject
}
export type HistoryPreparationPersistence = {
  read(key: string): Promise<string | undefined>
  scan(prefix: string, after: string | undefined, limit: number): Promise<{ entries: Array<{ key: string; value: string }>; nextAfter: string | null }>
  compareAndSwap(conditions: Array<{ key: string; expected: string | undefined }>, writes: Array<{ key: string; value: string }>, guard: () => void): Promise<boolean>
}
export type HistoryPreparationRemote = Omit<ArchiveCoveragePort, "ensureCurrent"> & {
  upload: (object: SealedArchiveObject["object"], requestId: string) => Promise<ArchiveStorageReceipt>
}
export type HistoryPreparationJournal = {
  readonly identity: HistoryPreparationIdentity
  capture(source: Iterable<Uint8Array> | AsyncIterable<Uint8Array>): Promise<HistoryPreparationState>
  read(): Promise<HistoryPreparationState | undefined>
  readSource(): Promise<AsyncIterable<Uint8Array>>
  stage(scope: ArchiveEncryptionScope, binding: ArchiveEncryptionBinding, bytes: Uint8Array): Promise<HistoryPreparedObject>
  objects(): AsyncIterable<HistoryPreparedObject>
  locators(): AsyncIterable<ArchiveLocatorEntry>
  archive(root: ArchiveEncryptionBinding): Promise<HistoryPreparationState>
  cover(remote: HistoryPreparationRemote): Promise<HistoryPreparationState>
}

/** Durable preparation only. No baseline activation authority and no deletion API. */
export function createHistoryPreparationJournal(identityInput: HistoryPreparationIdentity, persistence: HistoryPreparationPersistence,
  guardInput: () => void): HistoryPreparationJournal {
  const identity = capturePreparationIdentity(identityInput)
  if (typeof guardInput !== "function" || typeof persistence?.read !== "function" ||
      typeof persistence.scan !== "function" || typeof persistence.compareAndSwap !== "function") fail()
  const ensureCurrent = () => {
    const result: unknown = guardInput()
    if (result !== undefined) {
      if (result && (typeof result === "object" || typeof result === "function") && "then" in result) {
        void Promise.resolve(result).catch(() => {})
      }
      fail("History preparation guard must be synchronous and return no value")
    }
  }
  const partition = canonicalizeJson({ personId: identity.personId, workspaceId: identity.workspaceId, transitionId: identity.transitionId })
  let namespace: string | undefined
  const prefix = async () => {
    const hash = namespace ?? await digestRecord("MESH-HISTORY/1/preparation\0" + partition)
    namespace = hash; ensureCurrent()
    return `meta-mesh.history-preparation.v1.${hash}.`
  }
  const sourceContext = { workspaceId: identity.workspaceId, historyEpoch: identity.historyEpoch, indexId: "preparation-source" }
  const sourceStore = createArchiveObjectStore("preparation-source:" + partition, {
    read: key => persistence.read(key),
    compareAndSwap: (key, expected, next, guard) => persistence.compareAndSwap([{ key, expected }], [{ key, value: next }], guard),
  }, ensureCurrent)
  const head = async (required = true) => {
    ensureCurrent()
    const key = (await prefix()) + "head", raw = await persistence.read(key)
    ensureCurrent()
    if (raw === undefined) { if (required) fail("History preparation has not captured its source"); return undefined }
    const state = parsePreparationState(raw, identity)
    await verifyPreparedCoverage(state); ensureCurrent()
    return { key, raw, state }
  }
  const bindingKey = async (binding: ArchiveEncryptionBinding) => (await prefix()) + "binding." + await digestRecord(canonicalizeJson(binding))
  const orderKey = async (index: number) => (await prefix()) + "order." + index.toString(16).padStart(16, "0")
  const objectKey = async (id: string) => (await prefix()) + "object." + id
  const readObject = async (id: string, count: number) => {
    validateArchiveObjectId(id)
    const raw = await persistence.read(await objectKey(id)); ensureCurrent()
    if (raw === undefined) fail("Prepared archive object unavailable")
    const record = await verifyPreparedObject(raw, identity)
    if (record.sealed.ciphertextId !== id || record.index >= count) fail("Prepared archive object identity mismatch")
    const ordinal = await persistence.read(await orderKey(record.index)); ensureCurrent()
    if (ordinal === undefined) fail("Prepared archive order reference missing")
    const reference = parsePreparedReference(ordinal)
    if (reference.ciphertextId !== id || reference.digest !== await digestRecord(raw)) fail("Prepared archive reference integrity failure")
    ensureCurrent()
    return { record, digest: reference.digest }
  }
  const existing = async (binding: ArchiveEncryptionBinding, count: number) => {
    const id = await persistence.read(await bindingKey(binding)); ensureCurrent()
    if (id === undefined) return undefined
    const item = (await readObject(id, count)).record
    if (canonicalizeJson(item.binding) !== canonicalizeJson(binding)) fail("Prepared archive binding conflict")
    return item
  }
  const save = async (previous: NonNullable<Awaited<ReturnType<typeof head>>>, state: HistoryPreparationState) => {
    const raw = canonicalizeJson(state)
    parsePreparationState(raw, identity)
    ensureCurrent()
    if (await persistence.compareAndSwap([{ key: previous.key, expected: previous.raw }], [{ key: previous.key, value: raw }], ensureCurrent)) {
      ensureCurrent(); return state
    }
    const winner = await head()
    if (winner?.raw === raw) return winner.state
    fail("History preparation changed during commit")
  }
  async function* objects(): AsyncGenerator<HistoryPreparedObject> {
    const captured = (await head())!, objectPrefix = (await prefix()) + "object."
    let after: string | undefined, count = 0
    do {
      ensureCurrent()
      const page = await persistence.scan(objectPrefix, after, 64); ensureCurrent()
      if (!Array.isArray(page.entries) || page.entries.length > 64 || page.nextAfter !== null &&
          (typeof page.nextAfter !== "string" || page.nextAfter !== page.entries.at(-1)?.key)) fail("Invalid preparation storage page")
      for (const row of page.entries) {
        if (typeof row.key !== "string" || !row.key.startsWith(objectPrefix) || after !== undefined && row.key <= after) fail("Invalid preparation storage order")
        const id = row.key.slice(objectPrefix.length)
        const item = await readObject(id, captured.state.objectCount)
        // Cursor values must match the immutable record verified through its ordinal reference.
        if (canonicalizeJson(item.record) !== row.value) fail("Prepared archive object changed during scan")
        after = row.key
        if (++count > captured.state.objectCount) fail("Prepared archive set has extra objects")
        yield item.record
      }
      if (page.nextAfter === null) break
      if (!page.entries.length) fail("Preparation storage page made no progress")
    } while (true)
    if (count !== captured.state.objectCount || await persistence.read(captured.key) !== captured.raw) fail("Prepared archive set changed or incomplete")
    ensureCurrent()
  }
  async function* locators(): AsyncGenerator<ArchiveLocatorEntry> {
    const captured = (await head())!, bindingPrefix = (await prefix()) + "binding."
    if (captured.state.phase === "captured") fail("Archive data must be frozen before portable locator enumeration")
    let after: string | undefined, count = 0
    do {
      ensureCurrent()
      const page = await persistence.scan(bindingPrefix, after, 64); ensureCurrent()
      if (!Array.isArray(page.entries) || page.entries.length > 64 || page.nextAfter !== null &&
          (typeof page.nextAfter !== "string" || page.nextAfter !== page.entries.at(-1)?.key)) fail("Invalid preparation locator page")
      for (const row of page.entries) {
        if (typeof row.key !== "string" || !row.key.startsWith(bindingPrefix) || after !== undefined && row.key <= after) fail("Invalid preparation locator order")
        const key = row.key.slice(bindingPrefix.length)
        validateArchiveObjectId(key)
        const { record } = await readObject(row.value, captured.state.objectCount)
        if (key !== await digestRecord(canonicalizeJson(record.binding))) fail("Prepared archive locator binding mismatch")
        ensureCurrent(); after = row.key
        if (++count > captured.state.objectCount) fail("Prepared archive locator set has extra objects")
        yield { key, ciphertextId: record.sealed.ciphertextId }
      }
      if (page.nextAfter === null) break
      if (!page.entries.length) fail("Preparation locator page made no progress")
    } while (true)
    if (count !== captured.state.objectCount || await persistence.read(captured.key) !== captured.raw) fail("Prepared archive locator set changed or incomplete")
    ensureCurrent()
  }
  const readSource = async () => {
    const state = (await head())!.state
    return readArchiveBytes(sourceContext, state.source, sourceStore)
  }
  return {
    get identity() { return structuredClone(identity) },
    locators,
    async read() { return (await head(false))?.state },
    readSource,
    async capture(source) {
      ensureCurrent()
      const reference = await writeArchiveBytes(sourceContext, source, sourceStore)
      const previous = await head(false)
      if (previous) {
        if (canonicalizeJson(previous.state.source) !== canonicalizeJson(reference)) fail("History preparation source is immutable")
        return previous.state
      }
      const state: HistoryPreparationState = { kind: "workspace-history-preparation", version: 1, identity: structuredClone(identity), phase: "captured", source: reference,
        objectCount: 0, objectDigest: null, root: null, expectedCoverage: null, coverage: null }
      const key = (await prefix()) + "head", raw = canonicalizeJson(state)
      parsePreparationState(raw, identity); ensureCurrent()
      if (await persistence.compareAndSwap([{ key, expected: undefined }], [{ key, value: raw }], ensureCurrent)) {
        ensureCurrent(); return state
      }
      const winner = (await head())!
      if (canonicalizeJson(winner.state.source) !== canonicalizeJson(reference)) fail("History preparation source is immutable")
      return winner.state
    },
    async stage(scopeInput, bindingInput, bytesInput) {
      const scope = captureArchiveEncryptionScope(scopeInput), binding = capturePreparationBinding(bindingInput, identity)
      if (!(bytesInput instanceof Uint8Array) || bytesInput.length > 256 * 1024 || binding.objectKind !== "part" && bytesInput.length > 64 * 1024) fail("Prepared archive part exceeds size limit")
      const bytes = bytesInput.slice()
      ensureCurrent()
      if (scope.scopeId !== identity.storage.scopeId || scope.keyEpoch !== identity.storage.keyEpoch ||
          await sha256Base64Url(scope.key) !== identity.storage.keyDigest || await sha256Base64Url(bytes) !== binding.objectId) fail("History preparation encryption context changed")
      const bKey = await bindingKey(binding)
      let sealed: SealedArchiveObject | undefined, requestId: string | undefined
      for (let attempt = 0; attempt < 8; attempt++) {
        const previous = (await head())!, state = previous.state
        const saved = await existing(binding, state.objectCount)
        if (saved) {
          await openArchiveObject(scope, binding, saved.sealed.ciphertextId, saved.sealed.object)
          ensureCurrent(); return saved
        }
        if (state.phase !== "captured") fail("Prepared archive is frozen")
        if (state.objectCount >= MAX_PREPARED_OBJECTS) fail("Prepared archive capacity exceeded")
        sealed ??= await sealArchiveObject(scope, binding, bytes)
        requestId ??= crypto.randomUUID()
        const record: HistoryPreparedObject = { kind: "workspace-history-prepared-object", version: 1, index: state.objectCount,
          previousDigest: state.objectDigest, binding, requestId, sealed }
        const raw = canonicalizeJson(record), digest = await digestRecord(raw), oKey = await objectKey(sealed.ciphertextId)
        const ordinal = await orderKey(record.index)
        const next: HistoryPreparationState = { ...state, objectCount: state.objectCount + 1, objectDigest: digest }
        const writes = [{ key: previous.key, value: canonicalizeJson(next) }, { key: bKey, value: sealed.ciphertextId },
          { key: oKey, value: raw }, { key: ordinal, value: canonicalizeJson({ ciphertextId: sealed.ciphertextId, digest }) }]
        ensureCurrent()
        if (await persistence.compareAndSwap([{ key: previous.key, expected: previous.raw }, { key: bKey, expected: undefined },
          { key: oKey, expected: undefined }, { key: ordinal, expected: undefined }], writes, ensureCurrent)) {
          ensureCurrent(); return record
        }
      }
      fail("History preparation contention; retry from persisted state")
    },
    objects,
    async archive(rootInput) {
      const binding = capturePreparationBinding(rootInput, identity)
      if (binding.objectKind !== "page") fail("Archive catalogue root must be an index page")
      const previous = (await head())!, state = previous.state
      const root = await existing(binding, state.objectCount)
      if (!root) fail("Prepared archive root unavailable")
      if (state.phase !== "captured") {
        if (canonicalizeJson(state.root) !== canonicalizeJson({ binding, ciphertextId: root.sealed.ciphertextId })) fail("Prepared archive root changed")
        return state
      }
      // Check the retained source and complete append chain before freezing the expected set.
      for await (const _part of await readSource()) { ensureCurrent() }
      let digest: string | null = null
      for (let index = 0; index < state.objectCount; index++) {
        const raw = await persistence.read(await orderKey(index)); ensureCurrent()
        if (raw === undefined) fail("Prepared archive order is incomplete")
        const reference = parsePreparedReference(raw), item = await readObject(reference.ciphertextId, state.objectCount)
        if (item.record.index !== index || item.record.previousDigest !== digest) fail("Prepared archive append chain changed")
        digest = item.digest
      }
      if (digest !== state.objectDigest) fail("Prepared archive append root changed")
      async function* expected() { for await (const item of objects()) yield { objectId: item.sealed.ciphertextId, keyEpoch: item.sealed.object.keyEpoch } }
      const expectedCoverage = await deriveArchiveCoverageSet(root.sealed.ciphertextId, expected())
      return save(previous, { ...state, phase: "archived", root: { binding, ciphertextId: root.sealed.ciphertextId }, expectedCoverage })
    },
    async cover(remote) {
      if (typeof remote?.upload !== "function" || typeof remote.coverage !== "function" || typeof remote.aggregate !== "function") fail()
      const previous = (await head())!, state = previous.state
      if (state.phase === "covered") return state
      if (state.phase !== "archived") fail("History preparation is not frozen")
      const upload = remote.upload, coverage = remote.coverage, aggregate = remote.aggregate
      for await (const record of objects()) {
        ensureCurrent()
        await verifyPreparedStorageReceipt(await upload(record.sealed.object, record.requestId), identity, record)
        ensureCurrent()
      }
      async function* expected() { for await (const item of objects()) yield { objectId: item.sealed.ciphertextId, keyEpoch: item.sealed.object.keyEpoch } }
      const receipt = await confirmArchiveCoverageSet(identity.storage, state.root!.ciphertextId, identity.transitionId, expected(),
        { coverage, aggregate, ensureCurrent })
      const next: HistoryPreparationState = { ...state, phase: "covered", coverage: receipt }
      await verifyPreparedCoverage(next); ensureCurrent()
      return save(previous, next)
    },
  }
}
