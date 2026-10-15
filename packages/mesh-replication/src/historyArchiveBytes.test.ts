import { Buffer } from "node:buffer"
import { expect, it, vi } from "vitest"
import { BrowserIdentityStore, sha256Base64Url, signEnvelope, verifyDeviceCertificateChain, verifyEnvelope } from "@meta-uber/mesh-identity"
import { readArchiveBytes, writeArchiveBytes, MAX_ARCHIVE_PART_BYTES, MAX_ARCHIVE_PAGE_BYTES,
  type ArchiveObjectStore, type ArchiveTreeContext } from "./historyArchive"

const context: ArchiveTreeContext = { workspaceId: "workspace", historyEpoch: 1, indexId: "original-proof" }
async function fixture() {
  const objects = new Map<string, Uint8Array>()
  const store: ArchiveObjectStore = {
    read: vi.fn(async id => objects.get(id)?.slice()),
    write: vi.fn(async (id, bytes) => {
      const current = objects.get(id)
      if (current && Buffer.compare(current, bytes) !== 0) throw new Error("Immutable object conflict")
      objects.set(id, bytes.slice())
    }),
  }
  return { objects, store }
}
function* source(bytes: Uint8Array) {
  for (let offset = 0; offset < bytes.length; offset += 65_001) yield bytes.subarray(offset, offset + 65_001)
}
async function collect(source: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = []
  for await (const part of source) parts.push(part)
  const result = new Uint8Array(parts.reduce((sum, bytes) => sum + bytes.length, 0))
  let offset = 0
  for (const part of parts) { result.set(part, offset); offset += part.length }
  return result
}

it("Given exact original proof bytes and classification observations, when archived and reopened, then preserve every byte without normalizing signatures or metadata", async () => {
  const f = await fixture()
  const proof = new TextEncoder().encode(JSON.stringify({ signed: { signature: "Original / signature", payload: { z: 1, a: "я😀" } },
    observations: [{ status: "pending", reason: "Dependency absent" }, { status: "quarantined", reason: "Invalid authority" }],
    opaqueExtension: "preserve this too", retained: "x".repeat(MAX_ARCHIVE_PART_BYTES + 33) }, null, 3))
  const reference = await writeArchiveBytes(context, source(proof), f.store)
  expect(reference.partCount).toBe(2)
  expect(reference.byteLength).toBe(proof.length)
  const readOnly: ArchiveObjectStore = { read: f.store.read, write: vi.fn(async () => { throw new Error("Read wrote data") }) }
  expect(Buffer.compare(await collect(await readArchiveBytes(context, reference, readOnly)), proof)).toBe(0)
  expect(readOnly.write).not.toHaveBeenCalled()
  for (const bytes of f.objects.values()) expect(bytes.length).toBeLessThanOrEqual(MAX_ARCHIVE_PART_BYTES)
})

it("Given identical bytes at multiple part positions, when reopening through encrypted storage, then carry exact context and position to each read instead of conflating equal hashes", async () => {
  const f = await fixture()
  const original = new Uint8Array(MAX_ARCHIVE_PART_BYTES * 3).fill(11)
  const reference = await writeArchiveBytes(context, source(original), f.store)
  const calls: Array<{ id: string; binding: unknown }> = []
  const reader: ArchiveObjectStore = { write: f.store.write, read: async (id, maximum, binding?: unknown) => {
    calls.push({ id, binding }); return f.store.read(id, maximum)
  } }
  expect(Buffer.compare(await collect(await readArchiveBytes(context, reference, reader)), original)).toBe(0)
  const parts = calls.filter(call => call.id !== reference.root.objectId)
  expect(parts).toHaveLength(3)
  expect(new Set(parts.map(call => call.id)).size).toBe(1)
  expect(parts.map(call => call.binding)).toEqual([0,1,2].map(partIndex => ({ ...context, objectKind: "part", partIndex, partCount: 3 })))
  expect(calls[0]!.binding).toEqual({ ...context, objectKind: "page", partIndex: 0, partCount: 1 })
})

it("Given an actual device-signed original envelope, when restored from archive parts, then its original certificate and signature still verify without a replacement signer", async () => {
  const f = await fixture()
  const author = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Original author")
  const signed = await signEnvelope(author.privateKeys.devicePrivateKey, { kind: "workspace-changes", version: 1,
    workspaceId: context.workspaceId, personId: author.identity.personId, deviceId: author.device.deviceId,
    hashes: ["0".repeat(64)] }, author.device.deviceId)
  const original = new TextEncoder().encode(JSON.stringify({ identity: author.identity, certificates: [author.certificate], signed,
    observation: { status: "pending", reason: "Dependency absent" } }, null, 2))
  const saved = await writeArchiveBytes(context, source(original), f.store)
  const bytes = await collect(await readArchiveBytes(context, saved, f.store))
  expect(Buffer.compare(bytes, original)).toBe(0)
  const retained = JSON.parse(new TextDecoder().decode(bytes))
  const key = await verifyDeviceCertificateChain(retained.identity, retained.signed.signerKeyId, retained.certificates)
  expect(await verifyEnvelope(retained.signed, key)).toBe(true)
  expect(retained.observation.status).toBe("pending")
  expect(retained.signed).toEqual(signed)
})

it("Given irregular source boundaries, when archived twice, then canonical parts and tree roots remain identical", async () => {
  const f = await fixture()
  const bytes = new Uint8Array(MAX_ARCHIVE_PART_BYTES * 3 + 7).fill(37)
  const left = await writeArchiveBytes(context, source(bytes), f.store)
  const count = f.objects.size
  async function* alternate() {
    for (let offset = 0; offset < bytes.length; offset += MAX_ARCHIVE_PART_BYTES) yield bytes.slice(offset, offset + MAX_ARCHIVE_PART_BYTES)
  }
  const right = await writeArchiveBytes(context, alternate(), f.store)
  expect(right).toEqual(left)
  expect(f.objects.size).toBe(count)
  const sizes: number[] = []
  for await (const part of await readArchiveBytes(context, right, f.store)) sizes.push(part.length)
  expect(sizes).toEqual([MAX_ARCHIVE_PART_BYTES, MAX_ARCHIVE_PART_BYTES, MAX_ARCHIVE_PART_BYTES, 7])
})

it("Given a binary source fails or storage rejects a write, when preparation aborts, then retained prior evidence stays readable", async () => {
  const f = await fixture()
  const original = new TextEncoder().encode("already retained signature bytes")
  const saved = await writeArchiveBytes(context, source(original), f.store)
  async function* interrupted() { yield new Uint8Array(MAX_ARCHIVE_PART_BYTES).fill(19); throw new Error("Source unavailable") }
  await expect(writeArchiveBytes(context, interrupted(), f.store)).rejects.toThrow("Source unavailable")
  const badStore: ArchiveObjectStore = { read: f.store.read, write: async () => { throw new Error("Quota exhausted") } }
  await expect(writeArchiveBytes(context, source(original), badStore)).rejects.toThrow("Quota exhausted")
  expect(Buffer.compare(await collect(await readArchiveBytes(context, saved, f.store)), original)).toBe(0)
})

it.each(["missing", "corrupt"] as const)("Given a %s evidence part, when fully consumed, then reject without labeling a truncated proof verified", async kind => {
  const f = await fixture()
  const bytes = new Uint8Array(MAX_ARCHIVE_PART_BYTES + 9).fill(51)
  const saved = await writeArchiveBytes(context, source(bytes), f.store)
  const id = await sha256Base64Url(bytes.slice(MAX_ARCHIVE_PART_BYTES))
  if (kind === "missing") f.objects.delete(id)
  else f.objects.set(id, new Uint8Array(9).fill(7))
  await expect(collect(await readArchiveBytes(context, saved, f.store))).rejects.toThrow(/hash|integrity|missing|unavailable/i)
})

it("Given reference size, count or scope is substituted, when inspected, then reject without treating its parts as original evidence", async () => {
  const f = await fixture()
  const bytes = new Uint8Array(MAX_ARCHIVE_PART_BYTES + 9).fill(51)
  const saved = await writeArchiveBytes(context, source(bytes), f.store)
  await expect(collect(await readArchiveBytes({ ...context, indexId: "another-proof" }, saved, f.store))).rejects.toThrow(/context|scope/i)
  await expect(collect(await readArchiveBytes(context, { ...saved, byteLength: saved.byteLength - 1 }, f.store))).rejects.toThrow(/length|size/i)
  await expect(readArchiveBytes(context, { ...saved, partCount: saved.partCount + 1 }, f.store)).rejects.toThrow(/count|reference/i)
  await expect(readArchiveBytes(context, { ...saved, version: 2 as 1 }, f.store)).rejects.toThrow(/version|schema/i)
})

it("Given empty binary evidence, when retained, then authenticate an empty parts tree without fabricating a part", async () => {
  const f = await fixture()
  const saved = await writeArchiveBytes(context, [], f.store)
  expect(saved).toMatchObject({ byteLength: 0, partCount: 0, root: { count: 0 } })
  expect(Buffer.compare(await collect(await readArchiveBytes(context, saved, f.store)), new Uint8Array())).toBe(0)
  expect(f.objects.get(saved.root.objectId)!.length).toBeLessThan(MAX_ARCHIVE_PAGE_BYTES)
})

it("Given caller reference changes after opening, when reading, then use its captured original binding", async () => {
  const f = await fixture()
  const bytes = new Uint8Array(MAX_ARCHIVE_PART_BYTES + 9).fill(51)
  const saved = await writeArchiveBytes(context, source(bytes), f.store)
  const mutableContext = { ...context }
  const reader = await readArchiveBytes(mutableContext, saved, f.store)
  mutableContext.historyEpoch = 2
  saved.byteLength = 1
  saved.partCount = 1
  saved.root.first = "other"
  expect(Buffer.compare(await collect(reader), bytes)).toBe(0)
})

it("Given a source yields an oversized chunk, when writing, then reject before persisting that unbounded input", async () => {
  const f = await fixture()
  await expect(writeArchiveBytes(context, [new Uint8Array(MAX_ARCHIVE_PART_BYTES + 1)], f.store)).rejects.toThrow(/chunk|part|bound/i)
  expect(f.store.write).not.toHaveBeenCalled()
})
