import { describe, expect, it } from "vitest"
import { decodeWireMessage, encodeWireMessage, IrohMeshNode, irohEndpointIdFromSeed, type IrohNode } from "./index"

describe("mesh transport wire", () => {
  it("Given a structured payload, when sent over the wire, then its shape survives", () => {
    const payload = { kind: "sync", roomId: "one", bytes: [1, 2, 3] }
    expect(decodeWireMessage(encodeWireMessage(payload))).toEqual(payload)
  })

  it("Given malformed input, when decoded, then it is rejected", () => {
    expect(() => decodeWireMessage(new TextEncoder().encode("not json"))).toThrow("Invalid wire")
  })

  it("Given one node seed, when its endpoint is calculated twice, then its public address is stable", async () => {
    const seed = new Uint8Array(32).fill(7)
    expect(await irohEndpointIdFromSeed(seed)).toBe(await irohEndpointIdFromSeed(seed))
    expect(await irohEndpointIdFromSeed(seed)).toMatch(/^[0-9a-f]{64}$/)
  })

  it("Given browser transport shutdown stalls, when the mesh node closes, then cleanup still completes", async () => {
    const stalled = {
      endpointId: "stalled",
      close: () => new Promise<void>(() => {}),
    } as IrohNode

    await expect(new IrohMeshNode(stalled, 5).close()).resolves.toBeUndefined()
  })
})
