import { canonicalizeJson, sha256Base64Url, publicKeyId, fromBase64Url, toBase64Url, verifyEnvelope } from "@meta-uber/mesh-identity"
import { captureArchiveBytesReference, validateArchiveObjectId } from "./historyArchive"
import { captureArchiveEncryptionBinding, captureEncryptedArchiveObject } from "./historyArchiveCrypto"
import { captureArchiveCoverageAuthority, captureArchiveCoverageChild, captureArchiveCoverageSummary,
  verifyArchiveCoverageChild } from "./historyArchiveCoverage"
import type { HistoryPreparationIdentity, HistoryPreparationState, HistoryPreparedObject } from "./historyPreparationJournal"
import type { ArchiveEncryptionBinding } from "./historyArchiveCrypto"
import type { ArchiveStorageReceipt } from "./historyArchiveRemote"

export const MAX_PREPARED_OBJECTS = 1_048_576
export const encoder = new TextEncoder()
export function fail(message = "Invalid history preparation journal"): never { throw new Error(message) }
export function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail()
}
function positive(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail()
}
function text(value: unknown, maximum: number): asserts value is string {
  if (typeof value !== "string" || !value.length || value.length > maximum || encoder.encode(value).length > maximum ||
      [...value].some(char => { const code = char.codePointAt(0)!; return code >= 0xd800 && code <= 0xdfff })) fail()
}
export function capturePreparationIdentity(input: HistoryPreparationIdentity): HistoryPreparationIdentity {
  exact(input, ["transitionId", "personId", "workspaceId", "historyEpoch", "sourceRevision", "authorityRevision", "privateBinding", "previousBaselineId", "storage"])
  text(input.transitionId, 64)
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(input.transitionId)) fail()
  validateArchiveObjectId(input.personId); text(input.workspaceId, 256); positive(input.historyEpoch)
  for (const digest of [input.sourceRevision, input.authorityRevision, input.privateBinding]) validateArchiveObjectId(digest)
  if (input.previousBaselineId !== null) validateArchiveObjectId(input.previousBaselineId)
  exact(input.storage, ["origin", "scopeId", "policyRevision", "servicePublicKey", "keyEpoch", "keyDigest"])
  const authority = captureArchiveCoverageAuthority(input.storage)
  positive(input.storage.keyEpoch); validateArchiveObjectId(input.storage.keyDigest); text(input.storage.origin, 2048)
  const url = new URL(input.storage.origin)
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
      url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) fail()
  return { transitionId: input.transitionId, personId: input.personId, workspaceId: input.workspaceId, historyEpoch: input.historyEpoch,
    sourceRevision: input.sourceRevision, authorityRevision: input.authorityRevision, privateBinding: input.privateBinding,
    previousBaselineId: input.previousBaselineId, storage: { ...authority, origin: url.origin, keyEpoch: input.storage.keyEpoch, keyDigest: input.storage.keyDigest } }
}
export function capturePreparationBinding(input: ArchiveEncryptionBinding, identity: HistoryPreparationIdentity): ArchiveEncryptionBinding {
  const binding = captureArchiveEncryptionBinding(input)
  if (binding.workspaceId !== identity.workspaceId || binding.historyEpoch !== identity.historyEpoch) fail("History preparation binding changed")
  return binding
}
function parse(raw: string, maximum: number): Record<string, unknown> {
  if (typeof raw !== "string" || raw.length > maximum || encoder.encode(raw).length > maximum) fail("History preparation record exceeds size limit")
  const value: unknown = JSON.parse(raw)
  if (canonicalizeJson(value) !== raw) fail("Non-canonical history preparation record")
  if (!value || typeof value !== "object" || Array.isArray(value)) fail()
  return value as Record<string, unknown>
}
export function parsePreparationState(raw: string, identity: HistoryPreparationIdentity): HistoryPreparationState {
  const value = parse(raw, 16 * 1024)
  exact(value, ["kind", "version", "identity", "phase", "source", "objectCount", "objectDigest", "root", "expectedCoverage", "coverage"])
  if (value.kind !== "workspace-history-preparation" || value.version !== 1 ||
      canonicalizeJson(capturePreparationIdentity(value.identity as HistoryPreparationIdentity)) !== canonicalizeJson(identity) ||
      !Number.isSafeInteger(value.objectCount) || (value.objectCount as number) < 0 || (value.objectCount as number) > MAX_PREPARED_OBJECTS) fail()
  const source = captureArchiveBytesReference(value.source as HistoryPreparationState["source"])
  if (value.objectCount === 0 ? value.objectDigest !== null : value.objectDigest === null) fail()
  if (value.objectDigest !== null) validateArchiveObjectId(value.objectDigest)
  const base = { kind: "workspace-history-preparation" as const, version: 1 as const, identity: structuredClone(identity), source,
    objectCount: value.objectCount as number, objectDigest: value.objectDigest as string | null }
  if (value.phase === "captured") {
    if (value.root !== null || value.expectedCoverage !== null || value.coverage !== null) fail()
    return { ...base, phase: "captured", root: null, expectedCoverage: null, coverage: null }
  }
  if (value.phase !== "archived" && value.phase !== "covered" || value.objectCount === 0) fail()
  exact(value.root, ["binding", "ciphertextId"])
  const binding = capturePreparationBinding(value.root.binding as ArchiveEncryptionBinding, identity)
  if (binding.objectKind !== "page") fail()
  validateArchiveObjectId(value.root.ciphertextId)
  const expectedCoverage = captureArchiveCoverageSummary(value.expectedCoverage)
  if (expectedCoverage.objectCount !== value.objectCount || !expectedCoverage.rootCovered || expectedCoverage.height === 0) fail()
  const coverage = value.coverage === null ? null : captureArchiveCoverageChild(value.coverage)
  if (value.phase === "covered" ? coverage?.payload.kind !== "blind-archive-coverage-aggregate-receipt" : coverage !== null) fail()
  return { ...base, phase: value.phase, root: { binding, ciphertextId: value.root.ciphertextId }, expectedCoverage,
    coverage: coverage as HistoryPreparationState["coverage"] }
}
export function parsePreparedObject(raw: string, identity: HistoryPreparationIdentity): HistoryPreparedObject {
  const value = parse(raw, 360 * 1024)
  exact(value, ["kind", "version", "index", "previousDigest", "binding", "requestId", "sealed"])
  if (value.kind !== "workspace-history-prepared-object" || value.version !== 1 || !Number.isSafeInteger(value.index) ||
      (value.index as number) < 0 || (value.index as number) >= MAX_PREPARED_OBJECTS ||
      (value.index === 0 ? value.previousDigest !== null : value.previousDigest === null) ||
      typeof value.requestId !== "string" || !/^[A-Za-z0-9_-]{20,64}$/.test(value.requestId)) fail()
  if (value.previousDigest !== null) validateArchiveObjectId(value.previousDigest)
  const binding = capturePreparationBinding(value.binding as ArchiveEncryptionBinding, identity)
  exact(value.sealed, ["ciphertextId", "object"])
  validateArchiveObjectId(value.sealed.ciphertextId)
  const object = captureEncryptedArchiveObject(value.sealed.object, identity.storage.scopeId)
  if (object.keyEpoch !== identity.storage.keyEpoch) fail()
  return { kind: "workspace-history-prepared-object", version: 1, index: value.index as number,
    previousDigest: value.previousDigest as string | null, binding, requestId: value.requestId,
    sealed: { ciphertextId: value.sealed.ciphertextId, object } }
}
export const digestRecord = (raw: string) => sha256Base64Url(encoder.encode(raw))
export function parsePreparedReference(raw: string): { ciphertextId: string; digest: string } {
  const value = parse(raw, 256)
  exact(value, ["ciphertextId", "digest"])
  validateArchiveObjectId(value.ciphertextId); validateArchiveObjectId(value.digest)
  return { ciphertextId: value.ciphertextId, digest: value.digest }
}
export async function verifyPreparedObject(raw: string, identity: HistoryPreparationIdentity): Promise<HistoryPreparedObject> {
  const object = parsePreparedObject(raw, identity)
  if (await digestRecord(canonicalizeJson(object.sealed.object)) !== object.sealed.ciphertextId) fail("Prepared ciphertext integrity failure")
  return object
}
export async function verifyPreparedCoverage(state: HistoryPreparationState): Promise<void> {
  if (state.phase !== "covered") return
  const summary = await verifyArchiveCoverageChild(state.coverage, state.identity.storage, state.root!.ciphertextId)
  if (canonicalizeJson(summary) !== canonicalizeJson(state.expectedCoverage)) fail("Prepared archive coverage mismatch")
}
export async function verifyPreparedStorageReceipt(input: unknown, identity: HistoryPreparationIdentity, object: HistoryPreparedObject): Promise<void> {
  exact(input, ["payload", "signerKeyId", "signature"])
  exact(input.payload, ["kind", "version", "serviceId", "scopeId", "policyRevision", "requestId", "objectId", "keyEpoch"])
  if (input.payload.kind !== "blind-archive-storage-receipt" || input.payload.version !== 1 ||
      typeof input.payload.scopeId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(input.payload.scopeId) ||
      typeof input.payload.requestId !== "string" || !/^[A-Za-z0-9_-]{20,64}$/.test(input.payload.requestId)) fail()
  validateArchiveObjectId(input.payload.serviceId); validateArchiveObjectId(input.payload.objectId)
  positive(input.payload.policyRevision); positive(input.payload.keyEpoch)
  if (typeof input.signature !== "string" || input.signature.length !== 86) fail()
  const signature = input.signature, payload = { ...input.payload }, signerKeyId = input.signerKeyId
  const decoded = fromBase64Url(signature)
  if (decoded.length !== 64 || toBase64Url(decoded) !== signature) fail()
  const serviceId = await publicKeyId(identity.storage.servicePublicKey)
  const expected: ArchiveStorageReceipt["payload"] = { kind: "blind-archive-storage-receipt", version: 1, serviceId,
    scopeId: identity.storage.scopeId, policyRevision: identity.storage.policyRevision, requestId: object.requestId,
    objectId: object.sealed.ciphertextId, keyEpoch: identity.storage.keyEpoch }
  if (signerKeyId !== serviceId || canonicalizeJson(payload) !== canonicalizeJson(expected) ||
      !await verifyEnvelope({ payload: expected, signerKeyId: serviceId, signature }, identity.storage.servicePublicKey, "RUSTY/2")) fail("Invalid prepared archive storage receipt")
}
