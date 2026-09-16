import { describe, expect, it, vi } from "vitest"
import { decodeWireMessage, encodeWireMessage, IrohMeshNode, irohEndpointIdFromSeed, isMeshNetworkFailure, MeshNetworkError, MeshReconnectPolicy, MeshTraceBuffer, startMeshHeartbeat, type IrohNode, type MeshConnection } from "./index"

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

  it("Given a lost direct stream, when reconnecting, then relay wins and remains preferred during cooldown", async () => {
    const direct = { close: vi.fn() } as unknown as MeshConnection
    const relay = { close: vi.fn() } as unknown as MeshConnection
    const dial = vi.fn(async () => direct)
    const dialRelay = vi.fn(async () => relay)
    const policy = new MeshReconnectPolicy({ fallbackDelayMs: 0 })
    const node = { dial, dialRelay }

    policy.recordFailure("phone", new MeshNetworkError("connection lost"))
    await expect(policy.dial(node, "phone", "endpoint")).resolves.toBe(relay)
    expect(dial).not.toHaveBeenCalled()
  })

  it("Given a direct dial fails, when relay exists, then the same attempt starts relay immediately", async () => {
    const relay = { close: vi.fn() } as unknown as MeshConnection
    const policy = new MeshReconnectPolicy({ fallbackDelayMs: 60_000 })
    const node = {
      dial: vi.fn(async () => { throw new MeshNetworkError("direct unavailable") }),
      dialRelay: vi.fn(async () => relay),
    }

    await expect(policy.dial(node, "phone", "endpoint")).resolves.toBe(relay)
    expect(node.dialRelay).toHaveBeenCalledOnce()
  })

  it("Given every device route fails on the network, when failures are aggregated, then reconnect remains an offline state", () => {
    const directAndRelay = new AggregateError([
      new MeshNetworkError("direct unavailable"),
      new MeshNetworkError("relay unavailable"),
    ], "All promises were rejected")
    const routes = new AggregateError([directAndRelay], "All routes failed for device phone")

    expect(isMeshNetworkFailure(routes)).toBe(true)
  })

  it("Given an aggregate contains a protocol failure, when classified, then it is not hidden as offline", () => {
    const routes = new AggregateError([
      new MeshNetworkError("relay unavailable"),
      new Error("Unexpected mesh peer"),
    ], "All routes failed for device phone")

    expect(isMeshNetworkFailure(routes)).toBe(false)
  })

  it("Given one heartbeat is pending, when another interval passes, then probes do not stack", async () => {
    vi.useFakeTimers()
    let finish!: () => void
    const heartbeat = vi.fn(() => new Promise<void>(resolve => { finish = resolve }))
    const stop = startMeshHeartbeat({ heartbeat }, vi.fn(), { random: () => 0.5 })

    await vi.advanceTimersByTimeAsync(10_000)
    expect(heartbeat).toHaveBeenCalledOnce()
    finish()
    await Promise.resolve()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(heartbeat).toHaveBeenCalledTimes(2)
    stop()
    vi.useRealTimers()
  })

  it("Given lifecycle events exceed capacity, when inspected, then the trace remains ordered and bounded", () => {
    const sink = { info: vi.fn(), warn: vi.fn() }
    const trace = new MeshTraceBuffer("app.mesh", 2, sink)
    trace.trace("node.start", { runId: 1 })
    trace.trace("dial.start", { runId: 1 })
    trace.trace("session.closed", { runId: 1 }, "warn")

    expect(trace.snapshot()).toEqual([
      expect.objectContaining({ sequence: 2, event: "dial.start" }),
      expect.objectContaining({ sequence: 3, event: "session.closed", level: "warn" }),
    ])
    expect(sink.warn).toHaveBeenCalledOnce()
  })
})
