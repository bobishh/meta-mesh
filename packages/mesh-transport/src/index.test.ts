import { describe, expect, it, vi } from "vitest"
import { decodeWireMessage, encodeWireMessage, IrohMeshNode, irohEndpointIdFromSeed, MeshNetworkError, MeshReconnectPolicy, MeshTraceBuffer, startMeshHeartbeat, type IrohConnection, type IrohNode, type IrohStream, type MeshConnection } from "./index"

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

  it("Given two requests target one endpoint, when both complete, then one connection carries two streams", async () => {
    const stream = (): IrohStream => ({
      send: vi.fn(async () => undefined),
      read: vi.fn(async () => encodeWireMessage({ status: "ok" })),
      closeSend: vi.fn(async () => undefined),
    })
    const connection: IrohConnection = {
      openStream: vi.fn(async () => stream()),
      acceptStream: vi.fn(),
      close: vi.fn(async () => undefined),
    }
    const node = {
      endpointId: "local",
      dialRelay: vi.fn(async () => connection),
      accept: vi.fn(),
      close: vi.fn(async () => undefined),
    } satisfies IrohNode
    const mesh = new IrohMeshNode(node)

    await expect(mesh.request("remote", { sequence: 1 })).resolves.toEqual({ status: "ok" })
    await expect(mesh.request("remote", { sequence: 2 })).resolves.toEqual({ status: "ok" })

    expect(node.dialRelay).toHaveBeenCalledOnce()
    expect(connection.openStream).toHaveBeenCalledTimes(2)
    expect(connection.close).not.toHaveBeenCalled()

    await mesh.close()
    expect(connection.close).toHaveBeenCalledOnce()
  })

  it("Given a pooled connection loses a stream, when the next request runs, then it dials a fresh connection", async () => {
    const failed: IrohConnection = {
      openStream: vi.fn(async () => ({
        send: vi.fn(async () => undefined),
        read: vi.fn(async () => { throw new Error("connection lost") }),
        closeSend: vi.fn(async () => undefined),
      })),
      acceptStream: vi.fn(),
      close: vi.fn(async () => undefined),
    }
    const healthy: IrohConnection = {
      openStream: vi.fn(async () => ({
        send: vi.fn(async () => undefined),
        read: vi.fn(async () => encodeWireMessage({ status: "recovered" })),
        closeSend: vi.fn(async () => undefined),
      })),
      acceptStream: vi.fn(),
      close: vi.fn(async () => undefined),
    }
    const node = {
      endpointId: "local",
      dialRelay: vi.fn()
        .mockResolvedValueOnce(failed)
        .mockResolvedValueOnce(healthy),
      accept: vi.fn(),
      close: vi.fn(async () => undefined),
    } as unknown as IrohNode
    const mesh = new IrohMeshNode(node)

    await expect(mesh.request("remote", { sequence: 1 })).rejects.toThrow("connection lost")
    await expect(mesh.request("remote", { sequence: 2 })).resolves.toEqual({ status: "recovered" })

    expect(node.dialRelay).toHaveBeenCalledTimes(2)
    expect(failed.close).toHaveBeenCalledOnce()
    await mesh.close()
  })

  it("Given a peer rejects one request, when another request runs, then the healthy connection remains reusable", async () => {
    const responses = [{ error: "Not authorized" }, { status: "ok" }]
    const connection: IrohConnection = {
      openStream: vi.fn(async () => ({
        send: vi.fn(async () => undefined),
        read: vi.fn(async () => encodeWireMessage(responses.shift())),
        closeSend: vi.fn(async () => undefined),
      })),
      acceptStream: vi.fn(),
      close: vi.fn(async () => undefined),
    }
    const node = {
      endpointId: "local",
      dialRelay: vi.fn(async () => connection),
      accept: vi.fn(),
      close: vi.fn(async () => undefined),
    } satisfies IrohNode
    const mesh = new IrohMeshNode(node)

    await expect(mesh.request("remote", { sequence: 1 })).rejects.toThrow("Not authorized")
    await expect(mesh.request("remote", { sequence: 2 })).resolves.toEqual({ status: "ok" })

    expect(node.dialRelay).toHaveBeenCalledOnce()
    expect(connection.openStream).toHaveBeenCalledTimes(2)
    await mesh.close()
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

  it("Given an IrohMeshNode started with module, when gossip or blob engines are requested, then WASM engines are instantiated", () => {
    class MockGossip {
      constructor(public peerId: string) {}
    }
    class MockBlob {}
    const mockModule = {
      default: vi.fn(),
      BrowserNode: { start: vi.fn() },
      WasmGossipEngine: MockGossip,
      WasmBlobEngine: MockBlob,
    }
    const node = {
      endpointId: "peer-abc-123",
      dialRelay: vi.fn(),
      accept: vi.fn(),
      close: vi.fn(),
    } satisfies IrohNode

    const meshNode = new IrohMeshNode(node, 1000, mockModule)
    const gossipEngine = meshNode.createGossipEngine()
    expect(gossipEngine).toBeInstanceOf(MockGossip)
    expect(gossipEngine.peerId).toBe("peer-abc-123")

    const blobEngine = meshNode.createBlobEngine()
    expect(blobEngine).toBeInstanceOf(MockBlob)
  })
})
