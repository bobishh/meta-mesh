import { describe, expect, it, vi } from "vitest"
import { meshNetworkConnection, MeshNetworkError, type IrohConnection, type IrohStream } from "./index"

class ResettableStream {
  resetCount = 0
  async reset() {
    this.resetCount += 1
  }

  async send(_bytes: Uint8Array) {}
  async read() { return new Uint8Array() }
  async closeSend() {}
}

class GetterResettableStream {
  resetCount = 0
  async send(_bytes: Uint8Array) {}
  async read() { return new Uint8Array() }
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

      const wrappedConnection = meshNetworkConnection(originalConnection)
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

    const wrappedStream = await meshNetworkConnection(connection).acceptStream() as IrohStream & { reset?: () => Promise<void> }
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
    const wrappedStream = await meshNetworkConnection(connection).openStream() as IrohStream & { reset?: () => Promise<void> }

    await expect(wrappedStream.reset?.()).rejects.toBeInstanceOf(MeshNetworkError)
    await expect(wrappedStream.reset?.()).resolves.toBeUndefined()
  })

  it("Given reset throws synchronously, when an accepted stream is reset, then the failure becomes MeshNetworkError", async () => {
    const stream = {
      reset: () => { throw new Error("synchronous reset failure") },
      send: async () => undefined,
      read: async () => new Uint8Array(),
      closeSend: async () => undefined,
    } satisfies IrohStream
    const connection = {
      openStream: async () => stream,
      acceptStream: async () => stream,
      close: async () => undefined,
    } satisfies IrohConnection
    const wrappedStream = await meshNetworkConnection(connection).acceptStream()

    await expect(wrappedStream.reset?.()).rejects.toBeInstanceOf(MeshNetworkError)
  })

  it("Given a legacy stream has no reset method, when wrapped, then it remains usable without reset", async () => {
    const stream: IrohStream = {
      send: vi.fn(async () => undefined),
      read: vi.fn(async () => new Uint8Array([1, 2, 3])),
      closeSend: vi.fn(async () => undefined),
    }
    const connection = {
      openStream: async () => stream,
      acceptStream: async () => stream,
      close: async () => undefined,
    } satisfies IrohConnection

    const wrappedStream = await meshNetworkConnection(connection).openStream() as IrohStream & { reset?: () => Promise<void> }

    expect(wrappedStream.reset).toBeUndefined()
    await expect(wrappedStream.read()).resolves.toEqual(new Uint8Array([1, 2, 3]))
    await expect(wrappedStream.send(new Uint8Array([4]))).resolves.toBeUndefined()
    await expect(wrappedStream.closeSend()).resolves.toBeUndefined()
  })
})
