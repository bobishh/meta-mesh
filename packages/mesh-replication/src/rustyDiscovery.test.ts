import { describe, expect, it } from "vitest"
import { sha256Base64Url } from "@meta-uber/mesh-identity"
import { encodeBlindBytes } from "./rustyReplica"
import { discoverRustyService } from "./rustyDiscovery"

async function descriptor() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))
  const publicKey = encodeBlindBytes(raw)
  const serviceId = await sha256Base64Url(raw)
  return { protocolVersions: [2], publicOrigin: "https://rusty.example", service: { serviceId, publicKey },
    capabilities: { modes: ["blind"], applicationWrites: false, classification: false } }
}

const response = (value: unknown) => Response.json(value)

describe("Rusty service discovery", () => {
  it("discovers and pins a protocol-2 blind service", async () => {
    const value = await descriptor()
    const fetcher = async (input: RequestInfo | URL) => {
      expect(String(input)).toBe("https://rusty.example/.well-known/mesh-lighthouse")
      return response(value)
    }
    await expect(discoverRustyService("rusty.example", fetcher)).resolves.toMatchObject({
      origin: "https://rusty.example", serviceId: value.service.serviceId, servicePublicKey: value.service.publicKey,
    })
  })

  it("rejects a descriptor with a mismatched identity, origin, or blind policy", async () => {
    const value = await descriptor()
    await expect(discoverRustyService("rusty.example", async () => response({
      ...value, service: { ...value.service, serviceId: "A".repeat(43) },
    }))).rejects.toThrow(/pin/i)
    await expect(discoverRustyService("rusty.example", async () => response({ ...value, publicOrigin: "https://foreign.example" })))
      .rejects.toThrow()
    await expect(discoverRustyService("rusty.example", async () => response({ ...value,
      capabilities: { ...value.capabilities, applicationWrites: true },
    }))).rejects.toThrow()
  })
})
