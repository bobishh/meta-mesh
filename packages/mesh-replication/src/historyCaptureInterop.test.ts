import * as Automerge from "@automerge/automerge"
import { expect, it, vi } from "vitest"
import { IDBFactory, IDBKeyRange } from "fake-indexeddb"
import { BrowserMeshStore } from "../../mesh-browser-store/src/index"
import { canonicalizeJson, fromBase64Url, sha256Base64Url, verifyDeviceCertificateChain, verifyEnvelope } from "@meta-uber/mesh-identity"
import { meshRustRuntime } from "./runtime"
import { readArchiveBytes, readArchiveIndex, type ArchiveBytesReference, type ArchiveObjectStore, type ArchiveTreeContext } from "./historyArchive"
import { createHistoryPreparationJournal, type HistoryPreparationPersistence, type HistoryPreparedObject } from "./historyPreparationJournal"
import { openArchiveObject, type ArchiveEncryptionBinding } from "./historyArchiveCrypto"
import fixture from "../fixtures/history-capture-v1.json"

const decoder = new TextDecoder("utf-8", { fatal: true })
const encoder = new TextEncoder()
const context = fixture.catalogue.context
type CapturedChange = {
  hash: string; bytes: ArchiveBytesReference; dependencies: ArchiveBytesReference; dependencyCount: number
  authorizations: typeof fixture.catalogue.root; observation: { type: string; role?: string; reason?: string }
  admissionRevision: string; authorityRevision: string
}
async function collect(parts: AsyncIterable<Uint8Array>) {
  const values: Uint8Array[] = []
  for await (const part of parts) values.push(part)
  const bytes = new Uint8Array(values.reduce((size, part) => size + part.length, 0))
  let offset = 0; for (const part of values) { bytes.set(part, offset); offset += part.length }
  return bytes
}
const child = (indexId: string): ArchiveTreeContext => ({ ...context, indexId })
async function reference(store: ArchiveObjectStore, key: string) {
  const row = (await readArchiveIndex(context, fixture.catalogue.root, store, { prefix: key })).entries.find(entry => entry.key === key)!
  const bytes = await store.read(row.objectId, 64 * 1024, { ...context, objectKind: "record", partIndex: 0, partCount: 1 })
  expect(await sha256Base64Url(bytes!)).toBe(row.objectId)
  return JSON.parse(decoder.decode(bytes))
}
async function original(store: ArchiveObjectStore, key: string, indexId: string) {
  return collect(await readArchiveBytes(child(indexId), await reference(store, key) as ArchiveBytesReference, store))
}
function fixtureStore() {
  const read = vi.fn<ArchiveObjectStore["read"]>(async (id, maximum, binding) => {
    const found = fixture.objects.find(item => item.objectId === id && canonicalizeJson(item.binding) === canonicalizeJson(binding))
    if (!found) throw new Error("Native catalogue binding not found")
    const bytes = fromBase64Url(found.bytes)
    if (bytes.length > maximum) throw new Error("Native catalogue read too large")
    return bytes
  })
  return { read, write: async () => { throw new Error("Historical read attempted a write") } }
}

it("Given a Native-derived archive catalogue, when SDK reads one pending original, then lazily verify its actual hash/dependencies and original signature without loading the source document", async () => {
  const store = fixtureStore(), hash = fixture.expected.pendingHash
  const record = await reference(store, `change/${hash}`) as CapturedChange
  const bytes = await collect(await readArchiveBytes(child(`change/${hash}/bytes`), record.bytes, store))
  expect(bytes).toEqual(fromBase64Url(fixture.originals.pending[0]))
  const decoded = Automerge.decodeChange(bytes)
  expect(decoded.hash).toBe(hash)
  expect(record.observation.type).toBe("pending")
  expect(record.admissionRevision).toBe(fixture.catalogue.admissionRevision)
  const deps = JSON.parse(decoder.decode(await collect(await readArchiveBytes(child(`change/${hash}/dependencies`), record.dependencies, store))))
  expect(deps).toEqual(decoded.deps)
  expect(record.dependencyCount).toBe(deps.length)
  const refs = await readArchiveIndex(child(`change/${hash}/authorizations`), record.authorizations, store)
  expect(refs.entries.map(entry => entry.key)).toEqual(["0000000000000001"])
  const proofBytes = await original(store, "proof/0000000000000001", "source-proof/0000000000000001")
  expect(proofBytes).toEqual(fromBase64Url(fixture.originals.authorizations[1]))
  const proof = JSON.parse(decoder.decode(proofBytes))
  expect(Object.hasOwn(proof, "grant")).toBe(false)
  expect(proof.signed.payload.hashes).toEqual([hash])
  const key = await verifyDeviceCertificateChain({ personId: fixture.expected.personId, publicKey: fixture.expected.publicKey, displayName: "" }, proof.signed.signerKeyId, proof.certificates)
  expect(await verifyEnvelope(proof.signed, key)).toBe(true)
  const readContexts = store.read.mock.calls.map(call => call[2]?.indexId)
  expect(readContexts).not.toContain("source-document")
  expect(readContexts).not.toContain("source-control")
  expect(readContexts).not.toContain("source-proof/0000000000000000")
})

it("Given the complete Native catalogue, when original source is reconstructed and actual WASM admission reruns, then preserve admitted/pending/quarantined classifications without laundering unsigned history", async () => {
  const store = fixtureStore()
  const document = await original(store, "document", "source-document")
  const control = await original(store, "control", "source-control")
  expect(document).toEqual(fromBase64Url(fixture.originals.document))
  expect(control).toEqual(fromBase64Url(fixture.originals.control))
  const proofs = [], pending = []
  for (let i = 0; i < fixture.originals.authorizations.length; i++) {
    const ordinal = i.toString(16).padStart(16, "0")
    const bytes = await original(store, `proof/${ordinal}`, `source-proof/${ordinal}`)
    expect(bytes).toEqual(fromBase64Url(fixture.originals.authorizations[i]))
    proofs.push(JSON.parse(decoder.decode(bytes)))
  }
  for (let i = 0; i < fixture.originals.pending.length; i++) {
    const ordinal = i.toString(16).padStart(16, "0")
    const bytes = await original(store, `pending/${ordinal}`, `source-pending/${ordinal}`)
    expect(bytes).toEqual(fromBase64Url(fixture.originals.pending[i]))
    pending.push(Array.from(bytes))
  }
  const plan = meshRustRuntime().state.evaluateCausalAdmission({ snapshot: { ...JSON.parse(decoder.decode(control)), document: Array.from(document) }, records: proofs, pendingChangeBytes: pending, nowMs: 0 }) as {
    decisions: Array<{ hash: string; status: CapturedChange["observation"] }>; authorizedDocument: number[]
  }
  expect(plan.decisions).toHaveLength(fixture.catalogue.changeCount)
  for (const decision of plan.decisions) {
    const captured = await reference(store, `change/${decision.hash}`) as CapturedChange
    expect(captured.observation).toEqual(decision.status)
  }
  const admitted = Automerge.load<{ title: string }>(new Uint8Array(plan.authorizedDocument))
  try { expect(String(admitted.title)).toBe("Native admitted original") } finally { Automerge.free(admitted) }
})

it("Given Native-captured objects staged through the shared journal, when storage reopens, then reuse exact ciphertext and recover the original pending bytes through authenticated bindings", async () => {
  vi.stubGlobal("indexedDB", new IDBFactory()); vi.stubGlobal("IDBKeyRange", IDBKeyRange)
  const name = crypto.randomUUID(), scope = { scopeId: "native-capture-scope", keyEpoch: 1, key: crypto.getRandomValues(new Uint8Array(32)) }
  const identity = { transitionId: crypto.randomUUID(), personId: fixture.expected.personId, workspaceId: context.workspaceId, historyEpoch: context.historyEpoch,
    sourceRevision: fixture.catalogue.captureRevision, authorityRevision: fixture.catalogue.authorityRevision,
    privateBinding: await sha256Base64Url(encoder.encode(canonicalizeJson({ scopeId: scope.scopeId, key: Array.from(scope.key), personId: fixture.expected.personId }))), previousBaselineId: null,
    storage: { origin: "https://rusty.example", scopeId: scope.scopeId, policyRevision: 1, servicePublicKey: fixture.expected.publicKey, keyEpoch: 1, keyDigest: await sha256Base64Url(scope.key) } }
  const repository = (): HistoryPreparationPersistence => {
    const db = new BrowserMeshStore(name, ["history"])
    return { read: key => db.get<string>("history", key), scan: (prefix, after, limit) => db.scan<string>("history", prefix, after, limit),
      compareAndSwap: (conditions, writes, guard) => db.compareAndSwap(conditions.map(item => ({ store: "history", ...item })), writes.map(item => ({ type: "put", store: "history", ...item })), guard) }
  }
  try {
    const journal = createHistoryPreparationJournal(identity, repository(), () => {})
    const source = encoder.encode(canonicalizeJson(fixture.originals))
    await journal.capture([source])
    for (const item of fixture.objects) await journal.stage(scope, { ...item.binding, objectId: item.objectId } as ArchiveEncryptionBinding, fromBase64Url(item.bytes))
    const rootBinding = { ...context, objectId: fixture.catalogue.root.objectId, objectKind: "page" as const, partIndex: 0, partCount: 1 }
    const frozen = await journal.archive(rootBinding)
    const reopened = createHistoryPreparationJournal(identity, repository(), () => {})
    expect(await reopened.read()).toEqual(frozen)
    expect(await collect(await reopened.readSource())).toEqual(source)
    const prepared: HistoryPreparedObject[] = []
    for await (const item of reopened.objects()) prepared.push(item)
    const noEncryption = vi.spyOn(crypto.subtle, "encrypt").mockRejectedValue(new Error("Resume resealed Native originals"))
    try {
      for (const item of fixture.objects) await reopened.stage(scope, { ...item.binding, objectId: item.objectId } as ArchiveEncryptionBinding, fromBase64Url(item.bytes))
      expect(noEncryption).not.toHaveBeenCalled()
    } finally { noEncryption.mockRestore() }
    const cold: ArchiveObjectStore = { write: async () => { throw new Error("Cold reader attempted a write") }, read: async (id, maximum, binding) => {
      const item = prepared.find(item => item.binding.objectId === id && canonicalizeJson(item.binding) === canonicalizeJson({ ...binding, objectId: id }))
      if (!item) return undefined
      const bytes = await openArchiveObject(scope, item.binding, item.sealed.ciphertextId, item.sealed.object)
      if (bytes.length > maximum) throw new Error("Cold read exceeds bound")
      return bytes
    } }
    expect(await original(cold, "pending/0000000000000000", "source-pending/0000000000000000")).toEqual(fromBase64Url(fixture.originals.pending[0]))
  } finally { vi.unstubAllGlobals() }
})
