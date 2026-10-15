import { canonicalizeJson, fromBase64Url, sha256Base64Url, toBase64Url } from "@meta-uber/mesh-identity"
import { MAX_ARCHIVE_PART_BYTES, validateArchiveObjectId, type ArchiveObjectStore } from "./historyArchive"

export type ArchiveObjectPersistence = {
  read(key: string): Promise<string | undefined>
  compareAndSwap(key: string, expected: string | undefined, next: string, guard: () => void): Promise<boolean>
}

const encoder = new TextEncoder()

async function parseObject(raw: string, objectId: string, maximumBytes: number): Promise<Uint8Array> {
  if (typeof raw !== "string" || raw.length > Math.ceil(maximumBytes / 3) * 4 + 512) throw new Error("Stored archive object exceeds size bound")
  let value: unknown
  try { value = JSON.parse(raw) } catch { throw new Error("Invalid stored archive object encoding") }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid stored archive object schema")
  const record = value as Record<string, unknown>
  const fields = ["kind", "version", "objectId", "data"]
  if (Object.keys(record).length !== fields.length || fields.some(key => !Object.hasOwn(record, key)) ||
      record.kind !== "workspace-history-object" || record.version !== 1 || record.objectId !== objectId ||
      typeof record.data !== "string" || !/^[A-Za-z0-9_-]*$/.test(record.data)) throw new Error("Invalid stored archive object schema")
  if (canonicalizeJson(record) !== raw) throw new Error("Non-canonical stored archive object encoding")
  let bytes: Uint8Array
  try { bytes = fromBase64Url(record.data) } catch { throw new Error("Invalid stored archive object encoding") }
  if (bytes.length > maximumBytes) throw new Error("Stored archive object exceeds size limit")
  if (toBase64Url(bytes) !== record.data) throw new Error("Non-canonical stored archive object encoding")
  if (await sha256Base64Url(bytes) !== objectId) throw new Error("Stored archive object hash integrity failure")
  return bytes
}

/** Immutable private local objects. Partition and guard come from the host; this repository grants no workspace authority. */
export function createArchiveObjectStore(partition: string, persistence: ArchiveObjectPersistence,
  ensureCurrent: () => void): ArchiveObjectStore {
  if (typeof partition !== "string" || !partition.length || encoder.encode(partition).length > 2048 ||
      [...partition].some(char => { const code = char.codePointAt(0)!; return code >= 0xd800 && code <= 0xdfff }) ||
      typeof ensureCurrent !== "function") throw new Error("Invalid archive object partition or guard")
  const capturedPartition = partition
  let namespace: string | undefined
  const keyFor = async (id: string) => {
    const hash = namespace ?? await sha256Base64Url(encoder.encode(`MESH-HISTORY/1/store-partition\0${capturedPartition}`))
    namespace = hash
    ensureCurrent()
    return `meta-mesh.history-archive.object.v1.${hash}.${id}`
  }
  const confirm = async (raw: string, id: string, expected: string) => {
    await parseObject(raw, id, MAX_ARCHIVE_PART_BYTES)
    ensureCurrent()
    if (raw !== expected) throw new Error("Immutable archive object conflict")
  }
  return {
    async read(objectId, maximumBytes) {
      validateArchiveObjectId(objectId)
      if (!Number.isInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > MAX_ARCHIVE_PART_BYTES) throw new Error("Invalid archive object read limit")
      ensureCurrent()
      const key = await keyFor(objectId)
      const raw = await persistence.read(key)
      ensureCurrent()
      if (raw === undefined) return undefined
      const bytes = await parseObject(raw, objectId, maximumBytes)
      ensureCurrent()
      return bytes
    },
    async write(objectId, input) {
      validateArchiveObjectId(objectId)
      if (!(input instanceof Uint8Array) || input.length > MAX_ARCHIVE_PART_BYTES) throw new Error("Archive object exceeds part size bound")
      const bytes = input.slice()
      ensureCurrent()
      if (await sha256Base64Url(bytes) !== objectId) throw new Error("Archive object hash integrity failure")
      ensureCurrent()
      const key = await keyFor(objectId)
      const expected = canonicalizeJson({ kind: "workspace-history-object", version: 1, objectId, data: toBase64Url(bytes) })
      const existing = await persistence.read(key)
      ensureCurrent()
      if (existing !== undefined) return confirm(existing, objectId, expected)
      const stored = await persistence.compareAndSwap(key, undefined, expected, ensureCurrent)
      ensureCurrent()
      if (stored) return
      const winner = await persistence.read(key)
      ensureCurrent()
      if (winner === undefined) throw new Error("Archive object changed during immutable publication")
      await confirm(winner, objectId, expected)
    },
  }
}
