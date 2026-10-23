import { sha256Base64Url } from "@meta-uber/mesh-identity"
import { decodeBlindBytes, rustyOrigin } from "./rustyReplica"

export type RustyServiceCapabilities = {
  modes: string[]
  applicationWrites: boolean
  classification: boolean
  [name: string]: unknown
}

export type RustyServicePin = {
  origin: string
  servicePublicKey: string
  serviceId: string
  capabilities: RustyServiceCapabilities
}

export type RustyFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
export type RustyServiceDiscovery = RustyServicePin

/** Discover and pin a protocol-2 Rusty blind service from its well-known descriptor. */
export async function discoverRustyService(input: string, fetcher: RustyFetch = fetch): Promise<RustyServiceDiscovery> {
  const origin = rustyOrigin(input)
  const response = await fetcher(`${origin}/.well-known/mesh-lighthouse`, { signal: AbortSignal.timeout(10_000) })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Rusty discovery failed with HTTP ${response.status}`)
  }
  const contentLength = response.headers.get("content-length")
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > 16_384)) {
    await response.body?.cancel()
    throw new Error("Rusty service descriptor is too large")
  }
  const text = await readBoundedText(response, 16_384)
  let descriptor: unknown
  try { descriptor = JSON.parse(text) } catch { throw new Error("Invalid Rusty service descriptor") }
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("Invalid Rusty service descriptor")
  const value = descriptor as Record<string, unknown>
  const service = value.service
  const capabilities = value.capabilities
  if (!Array.isArray(value.protocolVersions) || !value.protocolVersions.includes(2) || value.publicOrigin !== origin ||
    !capabilities || typeof capabilities !== "object" || Array.isArray(capabilities)) {
    throw new Error("This service does not support Rusty protocol 2")
  }
  const advertised = capabilities as Record<string, unknown>
  if (!Array.isArray(advertised.modes) || !advertised.modes.includes("blind") || advertised.applicationWrites !== false ||
    advertised.classification !== false || !service || typeof service !== "object" || Array.isArray(service)) {
    throw new Error("This service does not support blind Rusty replication")
  }
  const identity = service as Record<string, unknown>
  if (typeof identity.publicKey !== "string" || typeof identity.serviceId !== "string") throw new Error("Invalid Rusty service identity")
  let serviceId: string
  try {
    const keyBytes = decodeBlindBytes(identity.publicKey)
    if (keyBytes.byteLength !== 32) throw new Error("Invalid key length")
    serviceId = await sha256Base64Url(keyBytes)
  } catch { throw new Error("Invalid Rusty service identity") }
  if (serviceId !== identity.serviceId) throw new Error("Rusty service identity pin mismatch")
  return { origin, servicePublicKey: identity.publicKey, serviceId, capabilities: structuredClone(advertised) as RustyServiceCapabilities }
}

async function readBoundedText(response: Response, maximumBytes: number): Promise<string> {
  if (!response.body) return ""
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maximumBytes) {
        await reader.cancel()
        throw new Error("Rusty service descriptor is too large")
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes) }
  catch { throw new Error("Invalid Rusty service descriptor") }
}
