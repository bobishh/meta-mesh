import { canonicalizeJson } from "@meta-uber/mesh-identity"
import { captureArchiveTreeContext, validateArchiveObjectId } from "./historyArchive"
import type { ArchiveTreeContext } from "./historyArchive"
import type { ArchiveLocatorEntry, ArchiveLocatorPointer, ArchiveLocatorRoot } from "./historyArchiveLocators"

export const MAX_LOCATOR_ENTRIES = 1_048_576
export const encoder = new TextEncoder()
export const decoder = new TextDecoder("utf-8", { fatal: true })
export function fail(message = "Invalid archive locator directory"): never { throw new Error(message) }
export function canonical(value: unknown): Uint8Array { return encoder.encode(canonicalizeJson(value)) }
function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail()
}
export function context(input: ArchiveTreeContext): ArchiveTreeContext {
  const value = captureArchiveTreeContext(input)
  if (value.indexId !== "archive-locators") fail("Unsupported archive locator context")
  return value
}
export function pointer(input: unknown): ArchiveLocatorPointer {
  const value = structuredClone(input)
  exact(value, ["objectId", "ciphertextId", "height", "count", "first", "last"])
  validateArchiveObjectId(value.objectId); validateArchiveObjectId(value.ciphertextId)
  if (!Number.isInteger(value.height) || (value.height as number) < 0 || (value.height as number) >= 32 ||
      !Number.isSafeInteger(value.count) || (value.count as number) < 0 || (value.count as number) > MAX_LOCATOR_ENTRIES) fail()
  if (value.count === 0) {
    if (value.height !== 0 || value.first !== null || value.last !== null) fail()
  } else {
    validateArchiveObjectId(value.first); validateArchiveObjectId(value.last)
    if (value.first > value.last || (value.count === 1) !== (value.first === value.last) || value.height === 0 && (value.count as number) > 64) fail()
  }
  return value as ArchiveLocatorPointer
}
export function root(input: ArchiveLocatorRoot): ArchiveLocatorRoot {
  const value = structuredClone(input)
  exact(value, ["kind", "version", "context", "root"])
  if (value.kind !== "workspace-history-locator-root" || value.version !== 1) fail("Unsupported archive locator format")
  return { kind: "workspace-history-locator-root", version: 1, context: context(value.context as ArchiveTreeContext), root: pointer(value.root) }
}
export function entry(input: unknown): ArchiveLocatorEntry {
  const value = structuredClone(input)
  exact(value, ["key", "ciphertextId"])
  validateArchiveObjectId(value.key); validateArchiveObjectId(value.ciphertextId)
  return value as ArchiveLocatorEntry
}
type Header = { kind: "workspace-history-locator-page"; version: 1; context: ArchiveTreeContext; height: number }
export type LocatorPage = Header & ({ entries: ArchiveLocatorEntry[] } | { children: ArchiveLocatorPointer[] })
export function header(context: ArchiveTreeContext, height: number): Header { return { kind: "workspace-history-locator-page", version: 1, context, height } }
export function pagePointer(page: LocatorPage, objectId: string, ciphertextId: string): ArchiveLocatorPointer {
  if ("entries" in page) return pointer({ objectId, ciphertextId, height: 0, count: page.entries.length, first: page.entries[0]?.key ?? null, last: page.entries.at(-1)?.key ?? null })
  return pointer({ objectId, ciphertextId, height: page.height, count: page.children.reduce((sum, child) => sum + child.count, 0),
    first: page.children[0]?.first ?? null, last: page.children.at(-1)?.last ?? null })
}
export function parsePage(bytes: Uint8Array, expected: ArchiveTreeContext, expectedPointer: ArchiveLocatorPointer): LocatorPage {
  if (bytes.length > 64 * 1024) fail("Archive locator page exceeds size limit")
  const text = decoder.decode(bytes), value: unknown = JSON.parse(text)
  if (canonicalizeJson(value) !== text) fail("Noncanonical archive locator page")
  if (!value || typeof value !== "object" || Array.isArray(value)) fail()
  const raw = value as Record<string, unknown>
  exact(raw, ["kind", "version", "context", "height", raw.height === 0 ? "entries" : "children"])
  if (raw.kind !== "workspace-history-locator-page" || raw.version !== 1) fail("Unsupported archive locator page")
  const actual = context(raw.context as ArchiveTreeContext)
  if (canonicalizeJson(actual) !== canonicalizeJson(expected) || raw.height !== expectedPointer.height) fail("Archive locator page context mismatch")
  let page: LocatorPage
  if (raw.height === 0) {
    if (!Array.isArray(raw.entries) || raw.entries.length > 64) fail()
    const entries = raw.entries.map(entry)
    if (entries.some((value, i) => i > 0 && entries[i - 1]!.key >= value.key)) fail("Invalid archive locator order")
    page = { ...header(actual, 0), entries }
  } else {
    if (!Array.isArray(raw.children) || !raw.children.length || raw.children.length > 64) fail()
    const children = raw.children.map(pointer), plain = new Set<string>(), encrypted = new Set<string>()
    for (const [i, child] of children.entries()) {
      if (!child.count || child.height !== expectedPointer.height - 1 || plain.has(child.objectId) || encrypted.has(child.ciphertextId) ||
          i > 0 && children[i - 1]!.last! >= child.first!) fail("Invalid archive locator child ranges")
      plain.add(child.objectId); encrypted.add(child.ciphertextId)
    }
    page = { ...header(actual, expectedPointer.height), children }
  }
  if (canonicalizeJson(pagePointer(page, expectedPointer.objectId, expectedPointer.ciphertextId)) !== canonicalizeJson(expectedPointer)) fail("Archive locator pointer metadata mismatch")
  return page
}
