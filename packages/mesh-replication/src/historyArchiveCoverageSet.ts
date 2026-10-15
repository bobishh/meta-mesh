import { archiveCoverageBranch, archiveCoverageLeaf, captureArchiveCoverageAuthority, captureArchiveCoverageChild,
  captureArchiveCoverageObjects, verifyArchiveCoverageChild, type ArchiveCoverageObject, type ArchiveCoverageAuthority,
  type ArchiveCoverageSummary, type ArchiveCoverageChild, type ArchiveCoverageBatchReceipt,
  type ArchiveCoverageAggregateReceipt } from "./historyArchiveCoverage"
import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"
import { validateArchiveObjectId } from "./historyArchive"

export type ArchiveCoverageSource = Iterable<ArchiveCoverageObject> | AsyncIterable<ArchiveCoverageObject>
export type ArchiveCoveragePort = {
  coverage: (objects: ArchiveCoverageObject[], requestId: string) => Promise<ArchiveCoverageBatchReceipt>
  aggregate: (root: string, children: ArchiveCoverageChild[], requestId: string) => Promise<ArchiveCoverageAggregateReceipt>
  ensureCurrent: () => void | Promise<void>
}
type Node<T> = { summary: ArchiveCoverageSummary; evidence: T }
type Factory<T> = {
  leaf: (objects: ArchiveCoverageObject[], summary: ArchiveCoverageSummary) => Promise<T>
  branch: (children: Node<T>[], summary: ArchiveCoverageSummary) => Promise<T>
}
function fail(): never { throw new Error("Incomplete or invalid archive coverage set") }
function same(left: ArchiveCoverageSummary, right: ArchiveCoverageSummary): boolean {
  return canonicalizeJson(left) === canonicalizeJson(right)
}

/** Canonical grouping: full leaves of 64 and branches of 8; promote the final short tail with unary branches. */
async function reduceSet<T>(root: string, source: ArchiveCoverageSource, factory: Factory<T>): Promise<Node<T>> {
  validateArchiveObjectId(root)
  const levels: Node<T>[][] = []
  const combine = async (children: Node<T>[]): Promise<Node<T>> => {
    const summary = await archiveCoverageBranch(root, children.map(child => child.summary))
    return { summary, evidence: await factory.branch(children, summary) }
  }
  const push = async (initial: Node<T>): Promise<void> => {
    let node = initial
    for (;;) {
      const height = node.summary.height
      const bucket = levels[height] ??= []
      bucket.push(node)
      if (bucket.length < 8) return
      levels[height] = []
      node = await combine(bucket)
    }
  }
  let objects: ArchiveCoverageObject[] = [], previous: string | undefined
  const flush = async () => {
    const batch = objects; objects = []
    const summary = await archiveCoverageLeaf(batch, root)
    await push({ summary, evidence: await factory.leaf(batch, summary) })
  }
  for await (const input of source) {
    const entry = captureArchiveCoverageObjects([input])[0]!
    if (previous !== undefined && entry.objectId <= previous) fail()
    previous = entry.objectId
    objects.push(entry)
    if (objects.length === 64) await flush()
  }
  if (objects.length) await flush()
  if (previous === undefined) fail()
  for (let height = 0; height < 32; height++) {
    const bucket = levels[height]
    if (!bucket?.length) continue
    if (height > 0 && bucket.length === 1 && !levels.slice(height + 1).some(level => level.length)) return bucket[0]!
    levels[height] = []
    await push(await combine(bucket))
  }
  fail()
}

/** Derive the expected exact set using bounded state; does not attest any remote storage. */
export async function deriveArchiveCoverageSet(root: string, source: ArchiveCoverageSource): Promise<ArchiveCoverageSummary> {
  return (await reduceSet(root, source, { leaf: async () => undefined, branch: async () => undefined })).summary
}

/** Confirm a captured, strictly ordered encrypted set. Keep source/journal immutable across retries. */
export async function confirmArchiveCoverageSet(authorityInput: ArchiveCoverageAuthority, root: string, transitionId: string,
  source: ArchiveCoverageSource, port: ArchiveCoveragePort): Promise<ArchiveCoverageAggregateReceipt> {
  const authority = captureArchiveCoverageAuthority(authorityInput)
  validateArchiveObjectId(root)
  if (typeof transitionId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(transitionId) ||
      typeof port?.coverage !== "function" || typeof port.aggregate !== "function" || typeof port.ensureCurrent !== "function") fail()
  const coverage = port.coverage, aggregate = port.aggregate, guard = port.ensureCurrent
  await guard()
  const challenge = (summary: ArchiveCoverageSummary) => sha256Base64Url(new TextEncoder().encode(
    "MESH-HISTORY/1/coverage-request\0" + canonicalizeJson({ authority, archiveRootId: root, transitionId, summary })))
  const verified = async (input: unknown, summary: ArchiveCoverageSummary, requestId: string) => {
    const receipt = captureArchiveCoverageChild(input)
    if (receipt.payload.requestId !== requestId || !same(await verifyArchiveCoverageChild(receipt, authority, root), summary)) fail()
    await guard()
    return receipt
  }
  const result = await reduceSet<ArchiveCoverageChild>(root, source, {
    leaf: async (objects, summary) => {
      const requestId = await challenge(summary)
      await guard()
      const receipt = await verified(await coverage(objects, requestId), summary, requestId)
      if (receipt.payload.kind !== "blind-archive-coverage-batch-receipt") fail()
      return receipt
    },
    branch: async (children, summary) => {
      const requestId = await challenge(summary)
      await guard()
      const receipt = await verified(await aggregate(root, children.map(child => child.evidence), requestId), summary, requestId)
      if (receipt.payload.kind !== "blind-archive-coverage-aggregate-receipt") fail()
      return receipt
    },
  })
  if (!result.summary.rootCovered || result.evidence.payload.kind !== "blind-archive-coverage-aggregate-receipt") fail()
  await guard()
  return result.evidence as ArchiveCoverageAggregateReceipt
}

/** Compare a signed final aggregate against the complete expected set, never merely its rootCovered flag. */
export async function verifyCompleteArchiveCoverage(input: unknown, authority: ArchiveCoverageAuthority, root: string,
  source: ArchiveCoverageSource): Promise<ArchiveCoverageSummary> {
  const receipt = captureArchiveCoverageChild(input)
  if (receipt.payload.kind !== "blind-archive-coverage-aggregate-receipt") fail()
  const actual = await verifyArchiveCoverageChild(receipt, authority, root)
  const expected = await deriveArchiveCoverageSet(root, source)
  if (!expected.rootCovered || !same(actual, expected)) fail()
  return actual
}
