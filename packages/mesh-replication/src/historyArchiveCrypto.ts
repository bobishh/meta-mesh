import { canonicalizeJson, sha256Base64Url, fromBase64Url, toBase64Url } from "@meta-uber/mesh-identity"
import { MAX_ARCHIVE_PAGE_BYTES, MAX_ARCHIVE_PART_BYTES, validateArchiveObjectId, type ArchiveObjectReadBinding } from "./historyArchive"

export type ArchiveEncryptionScope = { scopeId: string; keyEpoch: number; key: Uint8Array }
export type ArchiveEncryptionBinding = ArchiveObjectReadBinding & { objectId: string }
export type EncryptedArchiveObject = {
  version: 1; scopeId: string; keyEpoch: number; nonce: string; ciphertext: string
}
export type SealedArchiveObject = { ciphertextId: string; object: EncryptedArchiveObject }

const encoder = new TextEncoder()
function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) throw new Error("Invalid encrypted archive schema")
}
function positive(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new Error("Invalid archive encryption epoch or count")
}
function text(value: unknown, maximum: number): asserts value is string {
  if (typeof value !== "string" || !value.length || value.length > maximum || encoder.encode(value).length > maximum ||
      [...value].some(char => { const code = char.codePointAt(0)!; return code >= 0xd800 && code <= 0xdfff })) {
    throw new Error("Invalid archive encryption context")
  }
}
function scopeSnapshot(input: ArchiveEncryptionScope): ArchiveEncryptionScope {
  const scope = structuredClone(input)
  exact(scope, ["scopeId", "keyEpoch", "key"])
  if (typeof scope.scopeId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(scope.scopeId) ||
      !(scope.key instanceof Uint8Array) || scope.key.length !== 32) throw new Error("Invalid archive encryption scope or key")
  positive(scope.keyEpoch)
  return scope as ArchiveEncryptionScope
}
function bindingSnapshot(input: ArchiveEncryptionBinding): ArchiveEncryptionBinding {
  const binding = structuredClone(input)
  exact(binding, ["workspaceId", "historyEpoch", "indexId", "objectId", "objectKind", "partIndex", "partCount"])
  text(binding.workspaceId, 256); text(binding.indexId, 128); positive(binding.historyEpoch); positive(binding.partCount)
  validateArchiveObjectId(binding.objectId)
  if (!["page", "record", "part"].includes(binding.objectKind as string) ||
      !Number.isSafeInteger(binding.partIndex) || (binding.partIndex as number) < 0 ||
      (binding.partIndex as number) >= binding.partCount ||
      binding.objectKind !== "part" && (binding.partIndex !== 0 || binding.partCount !== 1)) {
    throw new Error("Invalid archive encryption part binding")
  }
  return binding as ArchiveEncryptionBinding
}
export { scopeSnapshot as captureArchiveEncryptionScope, bindingSnapshot as captureArchiveEncryptionBinding }
function maximum(binding: ArchiveEncryptionBinding): number {
  return binding.objectKind === "part" ? MAX_ARCHIVE_PART_BYTES : MAX_ARCHIVE_PAGE_BYTES
}
function canonical(value: unknown): Uint8Array { return encoder.encode(canonicalizeJson(value)) }
function aad(scope: ArchiveEncryptionScope, binding: ArchiveEncryptionBinding): Uint8Array {
  return encoder.encode("MESH-HISTORY/1/archive-object\0" + canonicalizeJson({ purpose: "archive",
    scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, ...binding }))
}
function decoded(value: unknown, minimum: number, maximum: number): Uint8Array {
  if (typeof value !== "string" || value.length > Math.ceil(maximum / 3) * 4 || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("Invalid archive ciphertext encoding or size limit")
  }
  const bytes = fromBase64Url(value)
  if (bytes.length < minimum || bytes.length > maximum || toBase64Url(bytes) !== value) {
    throw new Error("Non-canonical archive ciphertext encoding or size limit")
  }
  return bytes
}

/** Validate the opaque transport envelope without requiring a private reading key. */
export function captureEncryptedArchiveObject(input: unknown, scopeId: string): EncryptedArchiveObject {
  const object = structuredClone(input)
  exact(object, ["version", "scopeId", "keyEpoch", "nonce", "ciphertext"])
  if (object.version !== 1 || object.scopeId !== scopeId || !/^[A-Za-z0-9_-]{1,128}$/.test(scopeId)) {
    throw new Error("Encrypted archive object scope or version mismatch")
  }
  positive(object.keyEpoch)
  decoded(object.nonce, 12, 12)
  decoded(object.ciphertext, 16, MAX_ARCHIVE_PART_BYTES + 16)
  return object as EncryptedArchiveObject
}
async function keyFor(scope: ArchiveEncryptionScope, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", new Uint8Array(scope.key).buffer, "AES-GCM", false, [usage])
}

/** Persist the returned ciphertext and request identity before upload; uncertain retries must reuse them. */
export async function sealArchiveObject(scopeInput: ArchiveEncryptionScope, bindingInput: ArchiveEncryptionBinding,
  bytesInput: Uint8Array): Promise<SealedArchiveObject> {
  const scope = scopeSnapshot(scopeInput), binding = bindingSnapshot(bindingInput)
  if (!(bytesInput instanceof Uint8Array) || bytesInput.length > maximum(binding)) throw new Error("Archive plaintext exceeds size limit")
  const bytes = new Uint8Array(bytesInput)
  if (await sha256Base64Url(bytes) !== binding.objectId) throw new Error("Archive plaintext hash integrity failure")
  const key = await keyFor(scope, "encrypt")
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce,
    additionalData: new Uint8Array(aad(scope, binding)).buffer, tagLength: 128 }, key, bytes)
  const object: EncryptedArchiveObject = { version: 1, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
    nonce: toBase64Url(nonce), ciphertext: toBase64Url(new Uint8Array(ciphertext)) }
  return { object, ciphertextId: await sha256Base64Url(canonical(object)) }
}
export async function openArchiveObject(scopeInput: ArchiveEncryptionScope, bindingInput: ArchiveEncryptionBinding,
  ciphertextId: string, objectInput: EncryptedArchiveObject): Promise<Uint8Array> {
  const scope = scopeSnapshot(scopeInput), binding = bindingSnapshot(bindingInput), object = captureEncryptedArchiveObject(objectInput, scope.scopeId)
  validateArchiveObjectId(ciphertextId)
  exact(object, ["version", "scopeId", "keyEpoch", "nonce", "ciphertext"])
  if (object.version !== 1 || object.scopeId !== scope.scopeId || object.keyEpoch !== scope.keyEpoch) {
    throw new Error("Encrypted archive object scope or version mismatch")
  }
  const nonce = decoded(object.nonce, 12, 12), ciphertext = decoded(object.ciphertext, 16, maximum(binding) + 16)
  if (await sha256Base64Url(canonical(object)) !== ciphertextId) throw new Error("Archive ciphertext hash integrity failure")
  const key = await keyFor(scope, "decrypt")
  let plaintext: ArrayBuffer
  try {
    plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(nonce).buffer,
      additionalData: new Uint8Array(aad(scope, binding)).buffer, tagLength: 128 }, key, new Uint8Array(ciphertext).buffer)
  } catch { throw new Error("Archive ciphertext authentication failed") }
  const bytes = new Uint8Array(plaintext)
  if (await sha256Base64Url(bytes) !== binding.objectId) throw new Error("Archive plaintext hash integrity failure")
  return bytes
}
