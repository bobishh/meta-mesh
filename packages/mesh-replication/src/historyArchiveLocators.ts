import type { ArchiveTreeContext, ArchiveObjectStore } from "./historyArchive"
import type { ArchiveEncryptionBinding, ArchiveEncryptionScope, EncryptedArchiveObject, SealedArchiveObject } from "./historyArchiveCrypto"
import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"
import { captureArchiveEncryptionBinding, captureArchiveEncryptionScope, openArchiveObject } from "./historyArchiveCrypto"
import { MAX_LOCATOR_ENTRIES, canonical, context as captureContext, root as captureRoot, entry as captureEntry, header,
  pagePointer, parsePage, fail, type LocatorPage } from "./historyArchiveLocatorData"

export type ArchiveLocatorEntry = { key: string; ciphertextId: string }
export type ArchiveLocatorPointer = { objectId: string; ciphertextId: string; height: number; count: number; first: string | null; last: string | null }
export type ArchiveLocatorRoot = { kind: "workspace-history-locator-root"; version: 1; context: ArchiveTreeContext; root: ArchiveLocatorPointer }
export type ArchiveLocatorWriter = { write(binding: ArchiveEncryptionBinding, bytes: Uint8Array): Promise<SealedArchiveObject>; ensureCurrent(): void | Promise<void> }
export type ArchiveLocatorReader = { download(ciphertextId: string): Promise<EncryptedArchiveObject>; ensureCurrent(): void | Promise<void> }

/** Validate detached untrusted routing before any remote read. */
export function captureArchiveLocatorRoot(input: unknown): ArchiveLocatorRoot {
  return captureRoot(input as ArchiveLocatorRoot)
}

/** Same SHA-256 binding key as the durable preparation index. Pages and data still use independent authenticated contexts. */
export async function archiveLocatorKey(binding: ArchiveEncryptionBinding): Promise<string> {
  return sha256Base64Url(canonical(captureArchiveEncryptionBinding(binding)))
}
function guard(input: () => void | Promise<void>) {
  if (typeof input !== "function") fail()
  return async () => { if (await input() !== undefined) fail("Archive locator guard must return no value") }
}
function binding(context: ArchiveTreeContext, objectId: string): ArchiveEncryptionBinding {
  return { ...context, objectId, objectKind: "page", partIndex: 0, partCount: 1 }
}

/** Source must be the frozen data journal's sorted binding index. Directory pages are staged separately and never index themselves. */
export async function buildArchiveLocators(scopeInput: ArchiveEncryptionScope, contextInput: ArchiveTreeContext,
  source: Iterable<ArchiveLocatorEntry> | AsyncIterable<ArchiveLocatorEntry>, writerInput: ArchiveLocatorWriter): Promise<ArchiveLocatorRoot> {
  const scope = captureArchiveEncryptionScope(scopeInput), context = captureContext(contextInput)
  const write = writerInput?.write, ensureCurrent = guard(writerInput?.ensureCurrent)
  if (typeof write !== "function") fail()
  await ensureCurrent()
  const levels: ArchiveLocatorPointer[][] = []
  let entries: ArchiveLocatorEntry[] = [], previous: string | undefined, count = 0
  const persist = async (page: LocatorPage) => {
    const bytes = canonical(page)
    if (bytes.length > 64 * 1024) fail("Archive locator page exceeds size limit")
    const objectId = await sha256Base64Url(bytes), expected = binding(context, objectId)
    await ensureCurrent()
    const sealed = await write(structuredClone(expected), bytes.slice()), ciphertextId = sealed.ciphertextId
    await ensureCurrent()
    await openArchiveObject(scope, expected, ciphertextId, sealed.object)
    await ensureCurrent()
    return pagePointer(page, objectId, ciphertextId)
  }
  const push = async (level: number, value: ArchiveLocatorPointer): Promise<void> => {
    if (level >= 32) fail("Archive locator depth exceeded")
    const bucket = levels[level] ??= []
    bucket.push(value)
    if (bucket.length === 64) { levels[level] = []; await push(level + 1, await persist({ ...header(context, level + 1), children: bucket })) }
  }
  const flush = async () => {
    const saved = entries; entries = []
    await push(0, await persist({ ...header(context, 0), entries: saved }))
  }
  for await (const input of source) {
    const entry = captureEntry(input)
    if (++count > MAX_LOCATOR_ENTRIES || previous !== undefined && entry.key <= previous) fail("Archive locator entries must have bounded unique order")
    previous = entry.key; entries.push(entry)
    if (entries.length === 64) await flush()
  }
  if (entries.length || !count) await flush()
  for (;;) {
    const level = levels.findIndex(bucket => bucket.length > 0), bucket = levels[level]!
    if (bucket.length === 1 && levels.slice(level + 1).every(bucket => !bucket.length)) {
      await ensureCurrent()
      return { kind: "workspace-history-locator-root", version: 1, context: structuredClone(context), root: bucket[0]! }
    }
    levels[level] = []
    await push(level + 1, await persist({ ...header(context, level + 1), children: bucket }))
  }
}

function reader(scopeInput: ArchiveEncryptionScope, rootInput: ArchiveLocatorRoot, input: ArchiveLocatorReader) {
  const scope = captureArchiveEncryptionScope(scopeInput), root = captureRoot(rootInput)
  const download = input?.download, ensureCurrent = guard(input?.ensureCurrent)
  if (typeof download !== "function") fail()
  const lookup = async (requested: ArchiveEncryptionBinding): Promise<string | undefined> => {
    if (requested.workspaceId !== root.context.workspaceId || requested.historyEpoch !== root.context.historyEpoch) fail("Archive locator workspace/epoch mismatch")
    const key = await archiveLocatorKey(requested), visited = new Set<string>()
    let next = root.root
    for (let depth = 0; depth < 32; depth++) {
      if (visited.has(next.ciphertextId)) fail("Archive locator cycle")
      visited.add(next.ciphertextId); await ensureCurrent()
      const encrypted = await download(next.ciphertextId); await ensureCurrent()
      const bytes = await openArchiveObject(scope, binding(root.context, next.objectId), next.ciphertextId, encrypted)
      await ensureCurrent()
      const page = parsePage(bytes, root.context, next)
      if ("entries" in page) return page.entries.find(entry => entry.key === key)?.ciphertextId
      const child = page.children.find(child => child.first! <= key && child.last! >= key)
      if (!child) return undefined
      next = child
    }
    fail("Archive locator depth exceeded")
  }
  return { scope, lookup, download, ensureCurrent }
}

export async function lookupArchiveLocator(scope: ArchiveEncryptionScope, root: ArchiveLocatorRoot,
  bindingInput: ArchiveEncryptionBinding, port: ArchiveLocatorReader): Promise<string | undefined> {
  const binding = captureArchiveEncryptionBinding(bindingInput)
  return reader(scope, root, port).lookup(binding)
}

/** Explicit full export walks the directory; ordinary reads retain logarithmic lookup. No data object is decrypted here. */
export async function* iterateArchiveLocatorEntries(scopeInput: ArchiveEncryptionScope, rootInput: ArchiveLocatorRoot,
  port: ArchiveLocatorReader, retainDirectory?: (ciphertextId: string, object: EncryptedArchiveObject) => void | Promise<void>): AsyncIterable<ArchiveLocatorEntry> {
  const scope = captureArchiveEncryptionScope(scopeInput), root = captureRoot(rootInput)
  const download = port?.download, ensureCurrent = guard(port?.ensureCurrent)
  if (typeof download !== "function" || retainDirectory !== undefined && typeof retainDirectory !== "function") fail()
  const stack = [root.root], visited = new Set<string>()
  let count = 0, previous: string | undefined
  while (stack.length) {
    const next = stack.pop()!
    if (visited.has(next.ciphertextId) || visited.size >= MAX_LOCATOR_ENTRIES * 2) fail("Archive locator cycle or page limit exceeded")
    visited.add(next.ciphertextId)
    await ensureCurrent()
    const object = structuredClone(await download.call(port, next.ciphertextId))
    await ensureCurrent()
    const bytes = await openArchiveObject(scope, binding(root.context, next.objectId), next.ciphertextId, object)
    const page = parsePage(bytes, root.context, next)
    await ensureCurrent()
    if (retainDirectory) {
      if (await retainDirectory(next.ciphertextId, structuredClone(object)) !== undefined) fail("Archive retention callback must return no value")
      await ensureCurrent()
    }
    if ("entries" in page) {
      for (const entry of page.entries) {
        if (++count > root.root.count || count > MAX_LOCATOR_ENTRIES || previous !== undefined && entry.key <= previous) fail("Archive directory coverage or ordering changed")
        previous = entry.key
        await ensureCurrent()
        yield structuredClone(entry)
      }
    } else {
      for (let index = page.children.length - 1; index >= 0; index--) stack.push(page.children[index]!)
    }
  }
  await ensureCurrent()
  if (count !== root.root.count) fail("Archive directory has incomplete coverage")
}

/** Read-only cold adapter. A signed baseline must authorize both roots separately; this adapter establishes content integrity only. */
export function createLocatedArchiveStore(scope: ArchiveEncryptionScope, root: ArchiveLocatorRoot, port: ArchiveLocatorReader): ArchiveObjectStore {
  const captured = reader(scope, root, port)
  return {
    async read(objectId, maximumBytes, readBinding) {
      if (!readBinding || !Number.isSafeInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > 256 * 1024) fail("Invalid located archive read")
      const binding = captureArchiveEncryptionBinding({ ...readBinding, objectId })
      const id = await captured.lookup(binding)
      if (id === undefined) return undefined
      await captured.ensureCurrent()
      const encrypted = await captured.download(id); await captured.ensureCurrent()
      const bytes = await openArchiveObject(captured.scope, binding, id, encrypted)
      if (bytes.length > maximumBytes) fail("Located archive object exceeds read limit")
      await captured.ensureCurrent(); return bytes
    },
    async write() { fail("Located archive store is read-only") },
  }
}
