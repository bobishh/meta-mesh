import { expect, it, vi } from "vitest"
import { publicKeyId, signEnvelope, toBase64Url } from "@meta-uber/mesh-identity"
import { archiveCoverageBranch, verifyArchiveCoverageChild, type ArchiveCoverageObject, type ArchiveCoverageAuthority,
  type ArchiveCoverageBatchReceipt, type ArchiveCoverageChild, type ArchiveCoverageAggregateReceipt } from "./historyArchiveCoverage"
import { deriveArchiveCoverageSet, confirmArchiveCoverageSet, verifyCompleteArchiveCoverage } from "./historyArchiveCoverageSet"

const id = (n: number) => n.toString(16).padStart(8, "0") + "A".repeat(35)
function* entries(count: number): Generator<ArchiveCoverageObject> {
  for (let i = 0; i < count; i++) yield { objectId: id(i), keyEpoch: 1 }
}
async function fixture() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair
  const servicePublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)))
  const authority: ArchiveCoverageAuthority = { servicePublicKey, scopeId: "opaque-scope", policyRevision: 3 }
  const serviceId = await publicKeyId(servicePublicKey), ensureCurrent = vi.fn(() => {})
  const sign = <T extends { kind: string }>(payload: T) => signEnvelope(pair.privateKey, payload, serviceId, "RUSTY/2")
  const coverage = vi.fn(async (objects: ArchiveCoverageObject[], requestId: string): Promise<ArchiveCoverageBatchReceipt> => sign({
    kind: "blind-archive-coverage-batch-receipt", version: 1, serviceId, scopeId: authority.scopeId,
    policyRevision: authority.policyRevision, requestId, objects }))
  const aggregate = vi.fn(async (root: string, children: ArchiveCoverageChild[], requestId: string): Promise<ArchiveCoverageAggregateReceipt> => {
    const summaries = []
    for (const child of children) summaries.push(await verifyArchiveCoverageChild(child, authority, root))
    return sign({ kind: "blind-archive-coverage-aggregate-receipt", version: 1, serviceId, scopeId: authority.scopeId,
      policyRevision: authority.policyRevision, requestId, archiveRootId: root, ...await archiveCoverageBranch(root, summaries) })
  })
  return { authority, coverage, aggregate, ensureCurrent }
}

it.each([1, 64, 65, 512, 513, 4101])("Given %i sorted encrypted objects, when streamed into bounded batches, then produce a complete canonical signed tree", async count => {
  const f = await fixture(), root = id(count - 1)
  const receipt = await confirmArchiveCoverageSet(f.authority, root, "transition-00001", entries(count), f)
  const expected = await deriveArchiveCoverageSet(root, entries(count))
  expect(await verifyCompleteArchiveCoverage(receipt, f.authority, root, entries(count))).toEqual(expected)
  expect(receipt.payload).toMatchObject({ objectCount: count, rootCovered: true, setDigest: expected.setDigest })
  expect(f.coverage.mock.calls.every(([objects]) => objects.length > 0 && objects.length <= 64)).toBe(true)
  expect(f.aggregate.mock.calls.every(([, children]) => children.length > 0 && children.length <= 8)).toBe(true)
})

it("Given an interrupted confirmation, when exact transition and objects are retried, then reuse request IDs and receipt bytes", async () => {
  const f = await fixture(), root = id(64)
  const aggregate = f.aggregate.getMockImplementation()!
  let lost: ArchiveCoverageAggregateReceipt | undefined
  f.aggregate.mockImplementationOnce(async (...args) => {
    lost = await aggregate(...args)
    throw new Error("Aggregate reply lost")
  })
  await expect(confirmArchiveCoverageSet(f.authority, root, "transition-00001", entries(65), f)).rejects.toThrow(/reply lost/)
  expect(lost).toBeDefined()
  const priorCalls = f.coverage.mock.calls.map(([, request]) => request)
  f.coverage.mockClear(); f.aggregate.mockClear()
  const retry = await confirmArchiveCoverageSet(f.authority, root, "transition-00001", entries(65), f)
  expect(retry).toEqual(lost)
  expect(f.coverage.mock.calls.map(([, request]) => request)).toEqual(priorCalls)
  const next = await confirmArchiveCoverageSet(f.authority, root, "transition-00002", entries(65), f)
  expect(next.payload.requestId).not.toBe(lost!.payload.requestId)
})

it("Given a signed subset containing the catalogue root, when compared with the expected complete set, then refuse completeness", async () => {
  const f = await fixture(), root = id(0)
  const subset = await confirmArchiveCoverageSet(f.authority, root, "transition-00001", entries(64), f)
  expect(subset.payload.rootCovered).toBe(true)
  await expect(verifyCompleteArchiveCoverage(subset, f.authority, root, entries(65))).rejects.toThrow()
  const modifiedEpoch = Array.from(entries(64)); modifiedEpoch[1]!.keyEpoch = 2
  await expect(verifyCompleteArchiveCoverage(subset, f.authority, root, modifiedEpoch)).rejects.toThrow()
  await expect(verifyCompleteArchiveCoverage(subset, { ...f.authority, policyRevision: 4 }, root, entries(64))).rejects.toThrow()
})

it("Given a large lazy source, when deriving coverage, then retain bounded tree levels and agree on every source object", async () => {
  const count = 100_000
  let consumed = 0
  async function* source() { for (const value of entries(count)) { consumed++; yield value } }
  const summary = await deriveArchiveCoverageSet(id(count - 1), source())
  expect(consumed).toBe(count)
  expect(summary).toMatchObject({ objectCount: count, height: 4, rootCovered: true })
})

it("Given empty, unordered, duplicate or root-missing evidence, when confirming, then never return complete coverage", async () => {
  const f = await fixture()
  for (const source of [[], Array.from(entries(65)).reverse(), [...entries(64), ...entries(1)], Array.from(entries(3))]) {
    await expect(confirmArchiveCoverageSet(f.authority, id(99), "transition-00001", source, f)).rejects.toThrow()
  }
})

it("Given a changed device or forged signed output, when a batch completes, then stop before aggregation", async () => {
  const f = await fixture(), root = id(0)
  f.ensureCurrent.mockImplementation(() => { throw new Error("Device replaced") })
  await expect(confirmArchiveCoverageSet(f.authority, root, "transition-00001", entries(1), f)).rejects.toThrow(/Device replaced/)
  expect(f.coverage).not.toHaveBeenCalled()
  const forged = await fixture()
  const real = forged.coverage.getMockImplementation()!
  forged.coverage.mockImplementation(async (...args) => ({ ...await real(...args), signature: toBase64Url(new Uint8Array(64)) }))
  await expect(confirmArchiveCoverageSet(forged.authority, root, "transition-00001", entries(1), forged)).rejects.toThrow()
  expect(forged.aggregate).not.toHaveBeenCalled()
})
