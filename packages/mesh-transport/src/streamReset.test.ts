import { describe, expect, it, vi } from "vitest"
import { meshNetworkConnection, MeshNetworkError, type IrohConnection, type IrohStream, type MeshIngressBudgetProfile } from "./index"

const profile: MeshIngressBudgetProfile = {
  maxHeaderBytes: () => 4096, maxFrameBytes: () => 1024, maxPayloadBytes: () => 1024,
  maxLogicalTransferBytes: () => 1024, maxTransferPages: () => 1, maxTransferDeadlineMs: () => 1000,
  maxInFlightBytesPerConnection: () => 1024, maxConcurrentFramesPerConnection: () => 1,
}

class ResettableStream {
  resetCount = 0
  async reset() {
    this.resetCount += 1
  }

  async send(_bytes: Uint8Array) {}
  async read() { return new Uint8Array() }
  async readPairingFrame(maximumBytes?: number) { return (await this.read()).slice(0, maximumBytes) }
  async closeSend() {}
}

class GetterResettableStream {
  resetCount = 0
  async send(_bytes: Uint8Array) {}
  async read() { return new Uint8Array() }
  async readPairingFrame(maximumBytes?: number) { return (await this.read()).slice(0, maximumBytes) }
  async closeSend() {}
  get reset() {
    return async () => { this.resetCount += 1 }
  }
}

describe("mesh transport stream reset", () => {
  it.each(["openStream", "acceptStream"] as const)(
    "Given a stream has a prototype reset method, when %s wraps it, then reset keeps its receiver and connection",
    async acquisition => {
      const stream = new ResettableStream()
      const originalConnection = {
        remoteEndpointId: "peer-one",
        openStream: vi.fn(async () => stream as unknown as IrohStream),
        acceptStream: vi.fn(async () => stream as unknown as IrohStream),
        close: vi.fn(async () => undefined),
      } satisfies IrohConnection

      const wrappedConnection = meshNetworkConnection(originalConnection, profile)
      const wrappedStream = await wrappedConnection[acquisition]() as IrohStream & { reset?: () => Promise<void> }

      await wrappedStream.reset?.()

      expect(wrappedStream.reset).toBeTypeOf("function")
      expect(stream.resetCount).toBe(1)
      expect(wrappedConnection).not.toBe(originalConnection)
      expect(originalConnection[acquisition]).toHaveBeenCalledOnce()
      expect(wrappedConnection.remoteEndpointId).toBe("peer-one")
    },
  )

  it("Given reset is exposed by a getter, when an accepted stream is wrapped, then reset remains available", async () => {
    const stream = new GetterResettableStream()
    const connection = {
      openStream: async () => stream as unknown as IrohStream,
      acceptStream: async () => stream as unknown as IrohStream,
      close: async () => undefined,
    } satisfies IrohConnection

    const wrappedStream = await meshNetworkConnection(connection, profile).acceptStream() as IrohStream & { reset?: () => Promise<void> }
    await wrappedStream.reset?.()

    expect(stream.resetCount).toBe(1)
  })

  it("Given reset rejects, when an opened stream is reset, then the failure becomes MeshNetworkError", async () => {
    const stream = new ResettableStream()
    vi.spyOn(stream, "reset").mockRejectedValueOnce(new Error("stream reset failed"))
    const connection = {
      openStream: async () => stream as unknown as IrohStream,
      acceptStream: async () => stream as unknown as IrohStream,
      close: async () => undefined,
    } satisfies IrohConnection
    const wrappedStream = await meshNetworkConnection(connection, profile).openStream() as IrohStream & { reset?: () => Promise<void> }

    await expect(wrappedStream.reset?.()).rejects.toBeInstanceOf(MeshNetworkError)
    await expect(wrappedStream.reset?.()).resolves.toBeUndefined()
  })

  it("Given reset throws synchronously, when an accepted stream is reset, then the failure becomes MeshNetworkError", async () => {
    const stream = {
      reset: () => { throw new Error("synchronous reset failure") },
      send: async () => undefined,
      read: async () => new Uint8Array(),
      readPairingFrame: async () => new Uint8Array(),
      closeSend: async () => undefined,
    } satisfies IrohStream
    const connection = {
      openStream: async () => stream,
      acceptStream: async () => stream,
      close: async () => undefined,
    } satisfies IrohConnection
    const wrappedStream = await meshNetworkConnection(connection, profile).acceptStream()

    await expect(wrappedStream.reset?.()).rejects.toBeInstanceOf(MeshNetworkError)
  })

  it("Given one peer stalls, when reset is pending, then its next bounded read waits for cancellation", async () => {
    vi.useFakeTimers()
    try {
      const stalled = new ResettableStream()
      stalled.readPairingFrame = () => new Promise<Uint8Array<ArrayBuffer>>(() => {})
      let finishReset!: () => void
      const resetStarted = vi.fn(() => new Promise<void>(resolve => { finishReset = resolve }))
      stalled.reset = resetStarted
      const stalledConnection = {
        remoteEndpointId: "peer-shared",
        openStream: async () => stalled as IrohStream,
        acceptStream: async () => stalled as IrohStream,
        close: vi.fn(async () => undefined),
      } satisfies IrohConnection
      const healthy = new ResettableStream()
      const healthyRead = vi.fn(async () => new Uint8Array([7]))
      healthy.readPairingFrame = healthyRead
      const healthyConnection = {
        remoteEndpointId: "peer-shared",
        openStream: async () => healthy as IrohStream,
        acceptStream: async () => healthy as IrohStream,
        close: vi.fn(async () => undefined),
      } satisfies IrohConnection
      const limits = { ...profile, maxTransferDeadlineMs: () => 10 }
      const stalledStream = await meshNetworkConnection(stalledConnection, limits).openStream()
      const stalledRead = stalledStream.read()
      const healthyStream = await meshNetworkConnection(healthyConnection, limits).openStream()
      const healthyResult = healthyStream.read()
      expect(healthyRead).not.toHaveBeenCalled()
      const rejected = expect(stalledRead).rejects.toThrow(/deadline/i)
      await vi.advanceTimersByTimeAsync(10)
      expect(resetStarted).toHaveBeenCalledOnce()
      expect(healthyRead).not.toHaveBeenCalled()
      finishReset()
      await rejected
      await expect(healthyResult).resolves.toEqual(new Uint8Array([7]))
      expect(healthyRead).toHaveBeenCalledOnce()
      expect(stalledConnection.close).not.toHaveBeenCalled()
      expect(healthyConnection.close).not.toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })

  it("Given a legacy stream has no reset method, when wrapped, then it remains usable without reset", async () => {
    const stream: IrohStream = {
      send: vi.fn(async () => undefined),
      read: vi.fn(async () => new Uint8Array([1, 2, 3])),
      readPairingFrame: vi.fn(async () => new Uint8Array([1, 2, 3])),
      closeSend: vi.fn(async () => undefined),
    }
    const connection = {
      openStream: async () => stream,
      acceptStream: async () => stream,
      close: async () => undefined,
    } satisfies IrohConnection

    const wrappedStream = await meshNetworkConnection(connection, profile).openStream() as IrohStream & { reset?: () => Promise<void> }

    expect(wrappedStream.reset).toBeUndefined()
    await expect(wrappedStream.read()).resolves.toEqual(new Uint8Array([1, 2, 3]))
    await expect(wrappedStream.send(new Uint8Array([4]))).resolves.toBeUndefined()
    await expect(wrappedStream.closeSend()).resolves.toBeUndefined()
  })
})
