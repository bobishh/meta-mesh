import { expect, it, vi, afterEach } from "vitest"
import { sha256Base64Url, fromBase64Url, toBase64Url, canonicalizeJson } from "@meta-uber/mesh-identity"
import { sealArchiveObject, openArchiveObject, type ArchiveEncryptionScope, type ArchiveEncryptionBinding } from "./historyArchiveCrypto"
import { MAX_ARCHIVE_PAGE_BYTES, MAX_ARCHIVE_PART_BYTES } from "./historyArchive"
import vector from "../fixtures/history-archive-crypto-v1.json"

afterEach(() => vi.restoreAllMocks())

it("Given the shared native/browser AES-GCM fixture, when opened, then reproduce the exact noncanonical original proof bytes", async () => {
  const scope = { ...vector.scope, key: fromBase64Url(vector.key) }
  expect(await openArchiveObject(scope, vector.binding as ArchiveEncryptionBinding, vector.ciphertextId,
    { ...vector.object, version: 1 })).toEqual(fromBase64Url(vector.plaintext))
})
async function fixture(kind: ArchiveEncryptionBinding["objectKind"] = "part", size = 123) {
  const bytes = new Uint8Array(size).map((_, i) => i % 251)
  const scope: ArchiveEncryptionScope = { scopeId: "opaque-scope", keyEpoch: 3, key: new Uint8Array(32).fill(71) }
  const binding: ArchiveEncryptionBinding = { workspaceId: "private-workspace", historyEpoch: 7,
    indexId: "original-changes", objectId: await sha256Base64Url(bytes), objectKind: kind, partIndex: 0, partCount: 1 }
  return { scope, binding, bytes }
}

it.each(["page", "record", "part"] as const)("Given an exact archive %s, when encrypted and reopened, then recover its authenticated bytes without routing metadata in ciphertext objects", async kind => {
  const f = await fixture(kind)
  const sealed = await sealArchiveObject(f.scope, f.binding, f.bytes)
  expect(Object.keys(sealed.object).sort()).toEqual(["ciphertext", "keyEpoch", "nonce", "scopeId", "version"])
  expect(JSON.stringify(sealed.object)).not.toContain(f.binding.workspaceId)
  expect(JSON.stringify(sealed.object)).not.toContain(f.binding.objectId)
  expect(sealed.ciphertextId).toBe(await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(sealed.object))))
  expect(await openArchiveObject(f.scope, f.binding, sealed.ciphertextId, sealed.object)).toEqual(f.bytes)
})

it("Given one sealed part, when workspace, history, index, kind, position or scope changes, then reject every substitution", async () => {
  const f = await fixture()
  const sealed = await sealArchiveObject(f.scope, f.binding, f.bytes)
  const changes: Partial<ArchiveEncryptionBinding>[] = [{ workspaceId: "other" }, { historyEpoch: 8 },
    { indexId: "other" }, { objectKind: "record" }, { partIndex: 1, partCount: 2 }, { partCount: 2 },
    { objectId: await sha256Base64Url(new Uint8Array([1])) }]
  for (const change of changes) await expect(openArchiveObject(f.scope, { ...f.binding, ...change },
    sealed.ciphertextId, sealed.object)).rejects.toThrow()
  for (const change of [{ scopeId: "other" }, { keyEpoch: 4 }, { key: new Uint8Array(32).fill(72) }]) {
    await expect(openArchiveObject({ ...f.scope, ...change }, f.binding, sealed.ciphertextId, sealed.object)).rejects.toThrow()
  }
})

it("Given modified ciphertext or a different opaque ID, when opened, then reject integrity before decryption", async () => {
  const f = await fixture()
  const sealed = await sealArchiveObject(f.scope, f.binding, f.bytes)
  const decrypt = vi.spyOn(crypto.subtle, "decrypt")
  await expect(openArchiveObject(f.scope, f.binding, "A".repeat(43), sealed.object)).rejects.toThrow(/integrity|hash|identity/i)
  const bytes = fromBase64Url(sealed.object.ciphertext); bytes[0] ^= 1
  await expect(openArchiveObject(f.scope, f.binding, sealed.ciphertextId,
    { ...sealed.object, ciphertext: toBase64Url(bytes) })).rejects.toThrow(/integrity|hash|identity/i)
  expect(decrypt).not.toHaveBeenCalled()
})

it("Given bytes not matching their plaintext object ID, when sealed, then reject before encryption", async () => {
  const f = await fixture()
  const encrypt = vi.spyOn(crypto.subtle, "encrypt")
  await expect(sealArchiveObject(f.scope, f.binding, new Uint8Array([9]))).rejects.toThrow(/hash|integrity/i)
  expect(encrypt).not.toHaveBeenCalled()
})

it("Given an authenticated producer envelope claiming another plaintext hash, when opened, then reject the false content identity after authentication", async () => {
  const f = await fixture()
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key = await crypto.subtle.importKey("raw", new Uint8Array(f.scope.key).buffer, "AES-GCM", false, ["encrypt"])
  const aad = new TextEncoder().encode("MESH-HISTORY/1/archive-object\0" + canonicalizeJson({ purpose: "archive",
    scopeId: f.scope.scopeId, keyEpoch: f.scope.keyEpoch, ...f.binding }))
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, new Uint8Array([9]))
  const object = { version: 1 as const, scopeId: f.scope.scopeId, keyEpoch: f.scope.keyEpoch,
    nonce: toBase64Url(nonce), ciphertext: toBase64Url(new Uint8Array(ciphertext)) }
  const id = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(object)))
  await expect(openArchiveObject(f.scope, f.binding, id, object)).rejects.toThrow(/plaintext hash integrity/i)
})

it("Given maximum-size parts and pages, when prepared, then accept boundaries and reject oversize before crypto", async () => {
  for (const [kind, maximum] of [["part", MAX_ARCHIVE_PART_BYTES], ["page", MAX_ARCHIVE_PAGE_BYTES], ["record", MAX_ARCHIVE_PAGE_BYTES]] as const) {
    const f = await fixture(kind, maximum)
    const sealed = await sealArchiveObject(f.scope, f.binding, f.bytes)
    expect((await openArchiveObject(f.scope, f.binding, sealed.ciphertextId, sealed.object)).length).toBe(maximum)
    const encrypt = vi.spyOn(crypto.subtle, "encrypt")
    await expect(sealArchiveObject(f.scope, f.binding, new Uint8Array(maximum + 1))).rejects.toThrow(/limit|size|large/i)
    expect(encrypt).not.toHaveBeenCalled(); encrypt.mockRestore()
  }
})

it("Given malformed schemas, unsafe epochs, surrogate context or invalid part positions, when sealed, then fail before crypto", async () => {
  const f = await fixture()
  const encrypt = vi.spyOn(crypto.subtle, "encrypt")
  for (const change of [{ historyEpoch: 0 }, { historyEpoch: 2 ** 53 }, { workspaceId: "\ud800" },
    { indexId: "" }, { objectKind: "attachment" }, { partIndex: -1 }, { partIndex: 1 },
    { partCount: 0 }, { partCount: 2 ** 53 }, { objectId: "-".repeat(43) }, { unknown: true }]) {
    await expect(sealArchiveObject(f.scope, { ...f.binding, ...change } as ArchiveEncryptionBinding, f.bytes)).rejects.toThrow()
  }
  for (const change of [{ scopeId: "../path" }, { keyEpoch: 0 }, { key: new Uint8Array(31) }, { extra: true }]) {
    await expect(sealArchiveObject({ ...f.scope, ...change }, f.binding, f.bytes)).rejects.toThrow()
  }
  expect(encrypt).not.toHaveBeenCalled()
})

it("Given malformed encrypted envelopes, when read, then reject noncanonical base64 and unknown fields before crypto", async () => {
  const f = await fixture()
  const sealed = await sealArchiveObject(f.scope, f.binding, f.bytes)
  const decrypt = vi.spyOn(crypto.subtle, "decrypt")
  for (const change of [{ version: 2 }, { nonce: sealed.object.nonce + "=" }, { nonce: "A" },
    { ciphertext: sealed.object.ciphertext + "=" }, { ciphertext: "" }, { unknown: true }]) {
    const object = { ...sealed.object, ...change }
    const id = await sha256Base64Url(new TextEncoder().encode(canonicalizeJson(object)))
    await expect(openArchiveObject(f.scope, f.binding, id, object as typeof sealed.object)).rejects.toThrow()
  }
  expect(decrypt).not.toHaveBeenCalled()
})

it("Given caller mutations during async crypto, when sealing and opening, then use captured keys, context, envelopes and exact bytes", async () => {
  const f = await fixture()
  const expected = f.bytes.slice(), binding = structuredClone(f.binding), scope = structuredClone(f.scope)
  const sealing = sealArchiveObject(f.scope, f.binding, f.bytes)
  f.scope.key.fill(0); f.scope.scopeId = "changed"; f.binding.workspaceId = "changed"; f.bytes.fill(0)
  const sealed = await sealing
  const opening = openArchiveObject(scope, binding, sealed.ciphertextId, sealed.object)
  scope.key.fill(0); binding.workspaceId = "changed"; sealed.object.ciphertext = "changed"
  expect(await opening).toEqual(expected)
})

it("Given the same plaintext object, when independently sealed, then use fresh nonces and opaque IDs", async () => {
  const f = await fixture()
  const one = await sealArchiveObject(f.scope, f.binding, f.bytes), two = await sealArchiveObject(f.scope, f.binding, f.bytes)
  expect(one.object.nonce).not.toBe(two.object.nonce)
  expect(one.ciphertextId).not.toBe(two.ciphertextId)
})
