import { canonicalizeJson, sha256Base64Url, publicKeyId, fromBase64Url, toBase64Url, verifyEnvelope,
  type SignedEnvelope } from "@meta-uber/mesh-identity"
import { validateArchiveObjectId } from "./historyArchive"

export type ArchiveCoverageObject = { objectId: string; keyEpoch: number }
export type ArchiveCoverageAuthority = { servicePublicKey: string; scopeId: string; policyRevision: number }
export type ArchiveCoverageSummary = { height: number; objectCount: number; firstObjectId: string;
  lastObjectId: string; setDigest: string; rootCovered: boolean }
type ReceiptHeader = { version: 1; serviceId: string; scopeId: string; policyRevision: number; requestId: string }
export type ArchiveCoverageBatchReceipt = SignedEnvelope<ReceiptHeader & {
  kind: "blind-archive-coverage-batch-receipt"; objects: ArchiveCoverageObject[] }>
export type ArchiveCoverageAggregateReceipt = SignedEnvelope<ReceiptHeader & ArchiveCoverageSummary & {
  kind: "blind-archive-coverage-aggregate-receipt"; archiveRootId: string }>
export type ArchiveCoverageChild = ArchiveCoverageBatchReceipt | ArchiveCoverageAggregateReceipt

export function captureArchiveCoverageAuthority(input: ArchiveCoverageAuthority): ArchiveCoverageAuthority {
  const authority = { servicePublicKey: input.servicePublicKey, scopeId: input.scopeId, policyRevision: input.policyRevision }
  validateArchiveObjectId(authority.servicePublicKey); scope(authority.scopeId); positive(authority.policyRevision)
  return authority
}

const summaryKeys = ["height", "objectCount", "firstObjectId", "lastObjectId", "setDigest", "rootCovered"]
const headerKeys = ["kind", "version", "serviceId", "scopeId", "policyRevision", "requestId"]
const encoder = new TextEncoder()
function fail(): never { throw new Error("Invalid archive coverage evidence") }
function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail()
}
function positive(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail()
}
function scope(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) fail()
}
function requestId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{20,64}$/.test(value)) fail()
}
export function captureArchiveCoverageObjects(input: unknown): ArchiveCoverageObject[] {
  if (!Array.isArray(input) || input.length < 1 || input.length > 64) fail()
  const objects = input.map(entry => {
    exact(entry, ["objectId", "keyEpoch"])
    validateArchiveObjectId(entry.objectId); positive(entry.keyEpoch)
    return { objectId: entry.objectId, keyEpoch: entry.keyEpoch }
  })
  if (objects.some((entry, i) => i > 0 && objects[i - 1]!.objectId >= entry.objectId)) fail()
  return objects
}
function summarySnapshot(input: unknown): ArchiveCoverageSummary {
  exact(input, summaryKeys)
  if (!Number.isInteger(input.height) || (input.height as number) < 0 || (input.height as number) >= 32) fail()
  positive(input.objectCount)
  validateArchiveObjectId(input.firstObjectId); validateArchiveObjectId(input.lastObjectId); validateArchiveObjectId(input.setDigest)
  if (typeof input.rootCovered !== "boolean" || input.firstObjectId > input.lastObjectId ||
      (input.objectCount === 1) !== (input.firstObjectId === input.lastObjectId) ||
      input.height === 0 && input.objectCount > 64) fail()
  return { height: input.height as number, objectCount: input.objectCount, firstObjectId: input.firstObjectId,
    lastObjectId: input.lastObjectId, setDigest: input.setDigest, rootCovered: input.rootCovered }
}
export { summarySnapshot as captureArchiveCoverageSummary }
function validateRootRange(summary: ArchiveCoverageSummary, root: string): void {
  if (summary.rootCovered && (root < summary.firstObjectId || root > summary.lastObjectId) ||
      !summary.rootCovered && (root === summary.firstObjectId || root === summary.lastObjectId)) fail()
}
async function digest(value: unknown): Promise<string> {
  return sha256Base64Url(encoder.encode("MESH-HISTORY/1/coverage-set\0" + canonicalizeJson(value)))
}

/** Capture bounded wire evidence before any await; does not establish its signature or authority. */
export function captureArchiveCoverageChild(input: unknown): ArchiveCoverageChild {
  exact(input, ["payload", "signerKeyId", "signature"])
  validateArchiveObjectId(input.signerKeyId)
  if (typeof input.signature !== "string" || input.signature.length !== 86) fail()
  const signature = fromBase64Url(input.signature)
  if (signature.length !== 64 || toBase64Url(signature) !== input.signature) fail()
  const payload = input.payload
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) fail()
  const fields = payload as Record<string, unknown>
  if (fields.kind === "blind-archive-coverage-batch-receipt") exact(fields, [...headerKeys, "objects"])
  else if (fields.kind === "blind-archive-coverage-aggregate-receipt") exact(fields, [...headerKeys, "archiveRootId", ...summaryKeys])
  else fail()
  if (fields.version !== 1) fail()
  validateArchiveObjectId(fields.serviceId); scope(fields.scopeId); positive(fields.policyRevision); requestId(fields.requestId)
  const header = { version: 1 as const, serviceId: fields.serviceId, scopeId: fields.scopeId,
    policyRevision: fields.policyRevision, requestId: fields.requestId }
  let result: ArchiveCoverageChild
  if (fields.kind === "blind-archive-coverage-batch-receipt") {
    result = { payload: { ...header, kind: fields.kind, objects: captureArchiveCoverageObjects(fields.objects) },
      signerKeyId: input.signerKeyId, signature: input.signature }
  } else {
    validateArchiveObjectId(fields.archiveRootId)
    const summary = summarySnapshot(Object.fromEntries(summaryKeys.map(key => [key, fields[key]])))
    if (summary.height === 0) fail()
    validateRootRange(summary, fields.archiveRootId)
    result = { payload: { ...header, kind: fields.kind as "blind-archive-coverage-aggregate-receipt", archiveRootId: fields.archiveRootId, ...summary },
      signerKeyId: input.signerKeyId, signature: input.signature }
  }
  if (encoder.encode(canonicalizeJson(result)).length > 8192) fail()
  return result
}

export async function archiveCoverageLeaf(input: ArchiveCoverageObject[], root: string): Promise<ArchiveCoverageSummary> {
  validateArchiveObjectId(root)
  const objects = captureArchiveCoverageObjects(input)
  return { height: 0, objectCount: objects.length, firstObjectId: objects[0]!.objectId, lastObjectId: objects.at(-1)!.objectId,
    rootCovered: objects.some(object => object.objectId === root),
    setDigest: await digest({ kind: "archive-coverage-set-leaf", version: 1, objects }) }
}
/** Compose already verified summaries. This function alone is not a storage proof. */
export async function archiveCoverageBranch(root: string, input: ArchiveCoverageSummary[]): Promise<ArchiveCoverageSummary> {
  validateArchiveObjectId(root)
  if (!Array.isArray(input) || input.length < 1 || input.length > 8) fail()
  const children = input.map(summarySnapshot), first = children[0]!, last = children.at(-1)!
  let objectCount = 0
  children.forEach((child, i) => {
    validateRootRange(child, root)
    if (child.height !== first.height || i > 0 && children[i - 1]!.lastObjectId >= child.firstObjectId) fail()
    objectCount += child.objectCount
    positive(objectCount)
  })
  if (first.height + 1 >= 32) fail()
  return { height: first.height + 1, objectCount, firstObjectId: first.firstObjectId, lastObjectId: last.lastObjectId,
    rootCovered: children.some(child => child.rootCovered),
    setDigest: await digest({ kind: "archive-coverage-set-branch", version: 1, archiveRootId: root, children }) }
}
export async function verifyArchiveCoverageChild(input: unknown, authorityInput: ArchiveCoverageAuthority,
  root: string): Promise<ArchiveCoverageSummary> {
  const receipt = captureArchiveCoverageChild(input)
  validateArchiveObjectId(root)
  const authority = captureArchiveCoverageAuthority(authorityInput)
  const serviceId = await publicKeyId(authority.servicePublicKey), payload = receipt.payload
  if (receipt.signerKeyId !== serviceId || payload.serviceId !== serviceId || payload.scopeId !== authority.scopeId ||
      payload.policyRevision !== authority.policyRevision || !await verifyEnvelope<ArchiveCoverageChild["payload"]>(receipt, authority.servicePublicKey, "RUSTY/2")) fail()
  if (payload.kind === "blind-archive-coverage-batch-receipt") return archiveCoverageLeaf(payload.objects, root)
  if (payload.archiveRootId !== root) fail()
  return summarySnapshot(Object.fromEntries(summaryKeys.map(key => [key, payload[key as keyof typeof payload]])))
}
