import { type ResourceConnectionTransport, type ResourceConnectionMessage, type ResourceConnectionResponse } from "./protocol"
import type { ResourceProvider } from "./provider"

const MAX_MESSAGE_BYTES = 131_072
async function readJson(body: ReadableStream<Uint8Array> | null): Promise<unknown> {
  if (!body) throw new Error("Resource connection response is empty")
  const reader = body.getReader(), chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) {
      const next = await reader.read()
      if (next.done) break
      size += next.value.byteLength
      if (size > MAX_MESSAGE_BYTES) { await reader.cancel(); throw new Error("Resource connection message exceeds size limit") }
      chunks.push(next.value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown
}
/** Transport never discovers destinations from an untrusted grant or sends browser cookies. */
export function createHttpResourceTransport(endpoint: string, fetcher: typeof fetch = fetch): ResourceConnectionTransport {
  const url = new URL(endpoint)
  if (url.username || url.password || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) {
    throw new Error("Resource endpoint must use HTTPS or loopback HTTP")
  }
  return async (message, signal) => {
    const body = JSON.stringify(message)
    if (new TextEncoder().encode(body).byteLength > MAX_MESSAGE_BYTES) throw new Error("Resource connection message exceeds size limit")
    const response = await fetcher(url.href, { method: "POST", redirect: "error", credentials: "omit", signal,
      headers: { "Content-Type": "application/json", Accept: "application/json" }, body })
    if (!response.ok) throw Object.assign(new Error(`Resource connection returned HTTP ${response.status}`), { status: response.status })
    return await readJson(response.body) as ResourceConnectionResponse
  }
}
/** Host supplies an exact origin allowlist and rate limiting; approval and CAS storage remain on the provider. */
export function createResourceConnectionHandler(provider: ResourceProvider, allowedOrigins: readonly string[] = []) {
  const origins = new Set(allowedOrigins)
  return async (request: Request): Promise<Response> => {
    const origin = request.headers.get("Origin"), headers: Record<string, string> = { "Cache-Control": "no-store" }
    if (origin) {
      if (!origins.has(origin)) return Response.json({ error: "Origin denied" }, { status: 403, headers })
      headers["Access-Control-Allow-Origin"] = origin; headers.Vary = "Origin"
    }
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: {
      ...headers, "Access-Control-Allow-Methods": "POST", "Access-Control-Allow-Headers": "Content-Type, Accept",
    } })
    if (request.method !== "POST") return Response.json({ error: "POST required" }, { status: 405, headers })
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("Content-Type") ?? "")) {
      return Response.json({ error: "JSON required" }, { status: 415, headers })
    }
    try {
      const message = await readJson(request.body)
      const result = await provider.handleConnection(message as ResourceConnectionMessage)
      return Response.json(result, { headers })
    } catch {
      return Response.json({ error: "Resource connection rejected" }, { status: 400, headers })
    }
  }
}
