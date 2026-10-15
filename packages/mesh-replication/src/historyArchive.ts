import { canonicalizeJson, sha256Base64Url } from "@meta-uber/mesh-identity"

export const MAX_ARCHIVE_PAGE_BYTES = 64 * 1024
export const MAX_ARCHIVE_CHILDREN = 64
export const MAX_ARCHIVE_DEPTH = 32
export const MAX_ARCHIVE_KEY_BYTES = 512
export const MAX_ARCHIVE_PART_BYTES = 256 * 1024

export type ArchiveTreeContext = { workspaceId: string; historyEpoch: number; indexId: string }
export type ArchiveObjectReadBinding = ArchiveTreeContext & {
  objectKind: "page" | "record" | "part"; partIndex: number; partCount: number
}
export type ArchiveIndexEntry = { key: string; objectId: string }
export type ArchiveIndexRoot = {
  objectId: string
  height: number
  count: number
  first: string | null
  last: string | null
}
export type ArchiveObjectStore = {
  read(objectId: string, maximumBytes: number, binding?: ArchiveObjectReadBinding): Promise<Uint8Array | undefined>
  write(objectId: string, bytes: Uint8Array): Promise<void>
}
export type ArchiveIndexQuery = { after?: string; prefix?: string; limit?: number }
export type ArchiveIndexResult = { entries: ArchiveIndexEntry[]; nextAfter: string | null }
export type ArchiveBytesReference = {
  kind: "workspace-history-bytes"
  version: 1
  root: ArchiveIndexRoot
  byteLength: number
  partCount: number
}

type PageHeader = { kind: "workspace-history-index-page"; version: 1; context: ArchiveTreeContext; height: number }
type LeafPage = PageHeader & { entries: ArchiveIndexEntry[] }
type BranchPage = PageHeader & { children: ArchiveIndexRoot[] }
type IndexPage = LeafPage | BranchPage
const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true })
const digestPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/

function fail(message: string): never { throw new Error(message) }
function canonicalBytes(value: unknown): Uint8Array { return encoder.encode(canonicalizeJson(value)) }
function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail("Invalid archive schema")
}
function text(value: unknown, maximum: number, empty = false): asserts value is string {
  if (typeof value !== "string" || (!empty && !value.length) || value.length > maximum ||
      encoder.encode(value).length > maximum || [...value].some(char => {
        const code = char.codePointAt(0)!
        return code >= 0xd800 && code <= 0xdfff
      })) fail("Invalid archive key or context string")
}
export function validateArchiveObjectId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !digestPattern.test(value)) fail("Invalid archive object hash")
}
function captureContext(input: ArchiveTreeContext): ArchiveTreeContext {
  const value = structuredClone(input)
  exact(value, ["workspaceId", "historyEpoch", "indexId"])
  text(value.workspaceId, 256)
  text(value.indexId, 128)
  if (!Number.isSafeInteger(value.historyEpoch) || (value.historyEpoch as number) < 1) fail("Invalid archive context epoch")
  return value as ArchiveTreeContext
}
export { captureContext as captureArchiveTreeContext }
function captureEntry(input: ArchiveIndexEntry): ArchiveIndexEntry {
  const entry = structuredClone(input)
  exact(entry, ["key", "objectId"])
  text(entry.key, MAX_ARCHIVE_KEY_BYTES)
  validateArchiveObjectId(entry.objectId)
  return entry as ArchiveIndexEntry
}
function captureRoot(input: unknown): ArchiveIndexRoot {
  const root = structuredClone(input)
  exact(root, ["objectId", "height", "count", "first", "last"])
  validateArchiveObjectId(root.objectId)
  if (!Number.isInteger(root.height) || (root.height as number) < 0 || (root.height as number) >= MAX_ARCHIVE_DEPTH) fail("Invalid archive tree height")
  if (!Number.isSafeInteger(root.count) || (root.count as number) < 0) fail("Invalid archive root count")
  if (root.count === 0) {
    if (root.height !== 0 || root.first !== null || root.last !== null) fail("Invalid empty archive root metadata")
  } else {
    text(root.first, MAX_ARCHIVE_KEY_BYTES)
    text(root.last, MAX_ARCHIVE_KEY_BYTES)
    if (root.first > root.last) fail("Invalid archive root range")
  }
  return root as ArchiveIndexRoot
}

function pageRoot(page: IndexPage, objectId: string): ArchiveIndexRoot {
  if ("entries" in page) return { objectId, height: 0, count: page.entries.length,
    first: page.entries[0]?.key ?? null, last: page.entries.at(-1)?.key ?? null }
  const count = page.children.reduce((total, child) => total + child.count, 0)
  if (!Number.isSafeInteger(count)) fail("Archive count exceeds safe integer bound")
  return { objectId, height: page.height, count, first: page.children[0]!.first, last: page.children.at(-1)!.last }
}
function header(context: ArchiveTreeContext, height: number): PageHeader {
  return { kind: "workspace-history-index-page", version: 1, context, height }
}

/** Build immutable bounded pages from a strictly ordered source, retaining only one bucket per level. No active pointer or admission changes. */

export async function buildArchiveIndex(
  contextInput: ArchiveTreeContext,
  source: Iterable<ArchiveIndexEntry> | AsyncIterable<ArchiveIndexEntry>,
  store: ArchiveObjectStore,
): Promise<ArchiveIndexRoot> {
  const context = captureContext(contextInput)
  type Bucket<T> = { items: T[]; bytes: number }
  const levels: Array<Bucket<ArchiveIndexRoot> | undefined> = []
  const leafBase = canonicalBytes({ ...header(context, 0), entries: [] }).length
  let leaf: Bucket<ArchiveIndexEntry> = { items: [], bytes: leafBase }
  let previous: string | undefined
  const persist = async (page: IndexPage) => {
    if (page.height >= MAX_ARCHIVE_DEPTH) fail("Archive tree depth limit exceeded")
    const bytes = canonicalBytes(page)
    if (bytes.length > MAX_ARCHIVE_PAGE_BYTES) fail("Archive page exceeds byte limit")
    const objectId = await sha256Base64Url(bytes)
    await store.write(objectId, bytes)
    return pageRoot(page, objectId)
  }
  const fits = <T>(bucket: Bucket<T>, item: T) => bucket.items.length < MAX_ARCHIVE_CHILDREN &&
    bucket.bytes + canonicalBytes(item).length + (bucket.items.length ? 1 : 0) <= MAX_ARCHIVE_PAGE_BYTES
  const append = <T>(bucket: Bucket<T>, item: T) => {
    bucket.bytes += canonicalBytes(item).length + (bucket.items.length ? 1 : 0)
    bucket.items.push(item)
  }
  const flushLevel = async (level: number): Promise<void> => {
    const bucket = levels[level]!
    levels[level] = undefined
    await push(level + 1, await persist({ ...header(context, level + 1), children: bucket.items }))
  }
  const push = async (level: number, root: ArchiveIndexRoot): Promise<void> => {
    if (level >= MAX_ARCHIVE_DEPTH) fail("Archive tree depth limit exceeded")
    let bucket = levels[level] ??= { items: [], bytes: canonicalBytes({ ...header(context, level + 1), children: [] }).length }
    if (bucket.items.length && !fits(bucket, root)) {
      await flushLevel(level)
      bucket = levels[level] ??= { items: [], bytes: canonicalBytes({ ...header(context, level + 1), children: [] }).length }
    }
    append(bucket, root)
    if (bucket.items.length === MAX_ARCHIVE_CHILDREN) await flushLevel(level)
  }
  const flushLeaf = async () => {
    const saved = leaf
    leaf = { items: [], bytes: leafBase }
    await push(0, await persist({ ...header(context, 0), entries: saved.items }))
  }
  for await (const candidate of source) {
    const entry = captureEntry(candidate)
    if (previous !== undefined && entry.key <= previous) fail("Archive keys must have strict unique order")
    previous = entry.key
    if (!fits(leaf, entry)) await flushLeaf()
    append(leaf, entry)
    if (leaf.items.length === MAX_ARCHIVE_CHILDREN) await flushLeaf()
  }
  if (leaf.items.length || levels.every(bucket => !bucket?.items.length)) await flushLeaf()
  for (;;) {
    const level = levels.findIndex(bucket => !!bucket?.items.length)
    const bucket = levels[level]!
    if (bucket.items.length === 1 && levels.slice(level + 1).every(value => !value?.items.length)) return bucket.items[0]!
    await flushLevel(level)
  }
}

function captureQuery(input: ArchiveIndexQuery): Required<Pick<ArchiveIndexQuery, "limit">> & ArchiveIndexQuery {
  const query = structuredClone(input)
  if (!query || typeof query !== "object" || Array.isArray(query) ||
      Object.keys(query).some(key => !["after", "prefix", "limit"].includes(key))) fail("Invalid archive query")
  if (query.after !== undefined) text(query.after, MAX_ARCHIVE_KEY_BYTES, true)
  if (query.prefix !== undefined) text(query.prefix, MAX_ARCHIVE_KEY_BYTES, true)
  const limit = query.limit ?? 64
  if (!Number.isInteger(limit) || limit < 1 || limit > 256) fail("Invalid archive query limit")
  return { ...query, limit }
}

function parsePage(value: unknown, context: ArchiveTreeContext): IndexPage {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("Invalid archive page schema")
  const raw = value as Record<string, unknown>
  if (raw.kind !== "workspace-history-index-page" || raw.version !== 1) fail("Unsupported archive page schema/version")
  exact(raw, ["kind", "version", "context", "height", raw.height === 0 ? "entries" : "children"])
  const actualContext = captureContext(raw.context as ArchiveTreeContext)
  if (canonicalizeJson(actualContext) !== canonicalizeJson(context)) fail("Archive page context does not match scope")
  if (!Number.isInteger(raw.height) || (raw.height as number) < 0 || (raw.height as number) >= MAX_ARCHIVE_DEPTH) fail("Invalid archive page height")
  if (raw.height === 0) {
    if (!Array.isArray(raw.entries) || raw.entries.length > MAX_ARCHIVE_CHILDREN) fail("Invalid archive leaf size")
    const entries = raw.entries.map(captureEntry)
    if (entries.some((entry, i) => i > 0 && entry.key <= entries[i - 1]!.key)) fail("Invalid archive key order")
    return { ...header(context, 0), entries }
  }
  if (!Array.isArray(raw.children) || !raw.children.length || raw.children.length > MAX_ARCHIVE_CHILDREN) fail("Invalid archive branch size")
  const children = raw.children.map(captureRoot)
  const seen = new Set<string>()
  for (const [i, child] of children.entries()) {
    if (child.height !== (raw.height as number) - 1 || child.count < 1 || seen.has(child.objectId)) fail("Invalid archive child metadata")
    if (i > 0 && child.first! <= children[i - 1]!.last!) fail("Invalid overlapping archive child ranges")
    seen.add(child.objectId)
  }
  return { ...header(context, raw.height as number), children }
}

async function loadPage(context: ArchiveTreeContext, root: ArchiveIndexRoot, store: ArchiveObjectStore): Promise<IndexPage> {
  const saved = await store.read(root.objectId, MAX_ARCHIVE_PAGE_BYTES, { ...context, objectKind: "page", partIndex: 0, partCount: 1 })
  if (!saved) fail("Archive page unavailable or missing")
  if (!(saved instanceof Uint8Array) || saved.length > MAX_ARCHIVE_PAGE_BYTES) fail("Archive page exceeds byte limit")
  const bytes = saved.slice()
  if (await sha256Base64Url(bytes) !== root.objectId) fail("Archive page hash integrity failure")
  let value: unknown
  try { value = JSON.parse(decoder.decode(bytes)) } catch { fail("Invalid archive page JSON") }
  const page = parsePage(value, context)
  const canonical = canonicalBytes(page)
  if (canonical.length !== bytes.length || !canonical.every((byte, i) => bytes[i] === byte)) fail("Non-canonical archive page encoding")
  if (canonicalizeJson(pageRoot(page, root.objectId)) !== canonicalizeJson(root)) fail("Archive root metadata does not match its page")
  return page
}

/** One authenticated page for bounded streaming/export walks that must continue past missing sibling pages. */
export async function readArchiveIndexPage(contextInput: ArchiveTreeContext, rootInput: ArchiveIndexRoot,
  store: ArchiveObjectStore): Promise<IndexPage> {
  return loadPage(captureContext(contextInput), captureRoot(rootInput), store)
}

/** Authenticate the root even for empty/outside-range queries. Returned index entries do not establish historical author permission. */
export async function readArchiveIndex(
  contextInput: ArchiveTreeContext, rootInput: ArchiveIndexRoot, store: ArchiveObjectStore,
  queryInput: ArchiveIndexQuery = {},
): Promise<ArchiveIndexResult> {
  const context = captureContext(contextInput)
  const root = captureRoot(rootInput)
  const query = captureQuery(queryInput)
  const entries: ArchiveIndexEntry[] = []
  const seen = new Set<string>()
  const intersects = (child: ArchiveIndexRoot) => child.count > 0 &&
    (query.after === undefined || child.last! > query.after) &&
    (query.prefix === undefined || child.last! >= query.prefix && (child.first! <= query.prefix || child.first!.startsWith(query.prefix)))
  const visit = async (ref: ArchiveIndexRoot): Promise<void> => {
    if (seen.has(ref.objectId) || seen.size >= MAX_ARCHIVE_DEPTH * (query.limit + 1) + 1) fail("Archive traversal cycle or page budget exceeded")
    seen.add(ref.objectId)
    const page = await loadPage(context, ref, store)
    if ("entries" in page) {
      for (const entry of page.entries) {
        if ((query.after === undefined || entry.key > query.after) &&
            (query.prefix === undefined || entry.key.startsWith(query.prefix))) entries.push(entry)
        if (entries.length > query.limit) break
      }
    } else {
      for (const child of page.children) {
        if (intersects(child)) await visit(child)
        if (entries.length > query.limit) break
      }
    }
  }
  await visit(root)
  const more = entries.length > query.limit
  return { entries: entries.slice(0, query.limit), nextAfter: more ? entries[query.limit - 1]!.key : null }
}
function partKey(index: number): string { return index.toString(16).padStart(16, "0") }

/** Retain exact bytes as canonical bounded parts. Input chunks are bounded; failed preparation never publishes an active history pointer. */
export async function writeArchiveBytes(contextInput: ArchiveTreeContext,
  source: Iterable<Uint8Array> | AsyncIterable<Uint8Array>, store: ArchiveObjectStore): Promise<ArchiveBytesReference> {
  const context = captureContext(contextInput)
  let byteLength = 0
  let partCount = 0
  async function* parts(): AsyncIterable<ArchiveIndexEntry> {
    let buffer = new Uint8Array(MAX_ARCHIVE_PART_BYTES)
    let used = 0
    const save = async (bytes: Uint8Array): Promise<ArchiveIndexEntry> => {
      const objectId = await sha256Base64Url(bytes)
      await store.write(objectId, bytes)
      return { key: partKey(partCount++), objectId }
    }
    for await (const input of source) {
      if (!(input instanceof Uint8Array) || input.length > MAX_ARCHIVE_PART_BYTES) fail("Archive source chunk exceeds part bound")
      const bytes = input.slice()
      byteLength += bytes.length
      if (!Number.isSafeInteger(byteLength)) fail("Archive byte length exceeds safe integer bound")
      for (let offset = 0; offset < bytes.length;) {
        const length = Math.min(bytes.length - offset, buffer.length - used)
        buffer.set(bytes.subarray(offset, offset + length), used)
        used += length
        offset += length
        if (used === buffer.length) {
          yield await save(buffer)
          buffer = new Uint8Array(MAX_ARCHIVE_PART_BYTES)
          used = 0
        }
      }
    }
    if (used) yield await save(buffer.slice(0, used))
  }
  const root = await buildArchiveIndex(context, parts(), store)
  return { kind: "workspace-history-bytes", version: 1, root, byteLength, partCount }
}

function captureBytesReference(input: ArchiveBytesReference): ArchiveBytesReference {
  const ref = structuredClone(input)
  exact(ref, ["kind", "version", "root", "byteLength", "partCount"])
  if (ref.kind !== "workspace-history-bytes" || ref.version !== 1) fail("Unsupported archive byte reference schema/version")
  if (!Number.isSafeInteger(ref.byteLength) || (ref.byteLength as number) < 0 ||
      !Number.isSafeInteger(ref.partCount) || ref.partCount !== Math.ceil((ref.byteLength as number) / MAX_ARCHIVE_PART_BYTES)) fail("Invalid archive byte reference length/count")
  const root = captureRoot(ref.root)
  if (root.count !== ref.partCount || ref.partCount > 0 &&
      (root.first !== partKey(0) || root.last !== partKey((ref.partCount as number) - 1))) fail("Archive parts root count/range does not match reference")
  return { kind: "workspace-history-bytes", version: 1, root, byteLength: ref.byteLength as number, partCount: ref.partCount as number }
}
export { captureBytesReference as captureArchiveBytesReference }

/** Each yielded part is authenticated. Complete evidence verification requires draining the iterator, including the final length/count checks. */
export async function readArchiveBytes(contextInput: ArchiveTreeContext, referenceInput: ArchiveBytesReference,
  store: ArchiveObjectStore): Promise<AsyncIterable<Uint8Array>> {
  const context = captureContext(contextInput)
  const reference = captureBytesReference(referenceInput)
  return (async function* () {
    let after: string | undefined
    let index = 0
    let length = 0
    do {
      const page = await readArchiveIndex(context, reference.root, store, { after })
      for (const entry of page.entries) {
        if (entry.key !== partKey(index) || index >= reference.partCount) fail("Archive part order/count does not match reference")
        const saved = await store.read(entry.objectId, MAX_ARCHIVE_PART_BYTES,
          { ...context, objectKind: "part", partIndex: index, partCount: reference.partCount })
        if (!saved) fail("Archive evidence part unavailable or missing")
        const expectedLength = Math.min(MAX_ARCHIVE_PART_BYTES, reference.byteLength - length)
        if (!(saved instanceof Uint8Array) || saved.length !== expectedLength) fail("Archive evidence part length does not match reference")
        const bytes = saved.slice()
        if (await sha256Base64Url(bytes) !== entry.objectId) fail("Archive evidence part hash integrity failure")
        index++
        length += bytes.length
        yield bytes
      }
      after = page.nextAfter ?? undefined
    } while (after !== undefined)
    if (index !== reference.partCount || length !== reference.byteLength) fail("Archive evidence length/count is incomplete")
  })()
}
