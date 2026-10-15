import { describe, expect, it, vi } from "vitest"
import { meshNetworkConnection, MeshNetworkError, type IrohConnection, type IrohStream } from "./index"

class BoundedReadStream {
  readonly calls: Array<{ receiver: BoundedReadStream; maximumBytes: number | undefined }> = []

  async read(maximumBytes?: number) {
    this.calls.push({ receiver: this, maximumBytes })
    return new Uint8Array(maximumBytes === undefined ? [1, 2, 3] : [1].slice(0, maximumBytes))
  }

  async send(_bytes: Uint8Array) {}
  async closeSend() {}
}

describe("mesh transport stream read limits", () => {
  it.each(["openStream", "acceptStream"] as const)(
    "Given a byte limit, when %s returns a stream, then read forwards the limit with the original receiver",
    async acquisition => {
      const stream = new BoundedReadStream()
      const connection = {
        openStream: vi.fn(async () => stream as IrohStream),
        acceptStream: vi.fn(async () => stream as IrohStream),
        close: vi.fn(async () => undefined),
      } satisfies IrohConnection
      const wrapped = meshNetworkConnection(connection)
      const wrappedStream = await wrapped[acquisition]() as IrohStream & {
        read(maximumBytes?: number): Promise<Uint8Array>
      }

      await expect(wrappedStream.read(2)).resolves.toEqual(new Uint8Array([1]))

      expect(stream.calls).toEqual([{ receiver: stream, maximumBytes: 2 }])
      expect(connection[acquisition]).toHaveBeenCalledOnce()
    },
  )

  it("Given no byte limit, when a legacy read runs, then the wrapper calls read without arguments", async () => {
    const read = vi.fn(async function (this: BoundedReadStream, maximumBytes?: number) {
      this.calls.push({ receiver: this, maximumBytes })
      return new Uint8Array([1, 2, 3])
    })
    const stream = new BoundedReadStream()
    stream.read = read
    const connection = {
      openStream: async () => stream as IrohStream,
      acceptStream: async () => stream as IrohStream,
      close: async () => undefined,
    } satisfies IrohConnection
    const wrappedStream = await meshNetworkConnection(connection).openStream()

    await expect(wrappedStream.read()).resolves.toEqual(new Uint8Array([1, 2, 3]))

    expect(read).toHaveBeenCalledOnce()
    expect(read.mock.calls[0]).toHaveLength(0)
    expect(stream.calls[0]?.receiver).toBe(stream)
  })

  it.each([-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 32])(
    "Given an invalid byte limit %s, when a wrapped read starts, then it rejects before calling the raw stream",
    async maximumBytes => {
      const stream = new BoundedReadStream()
      const rawRead = vi.spyOn(stream, "read")
      const connection = {
        openStream: async () => stream as IrohStream,
        acceptStream: async () => stream as IrohStream,
        close: async () => undefined,
      } satisfies IrohConnection
      const wrappedStream = await meshNetworkConnection(connection).openStream() as IrohStream & {
        read(maximumBytes?: number): Promise<Uint8Array>
      }

      await expect(wrappedStream.read(maximumBytes)).rejects.toThrow()
      expect(rawRead).not.toHaveBeenCalled()
    },
  )

  it("Given a bounded read rejects, when its stream is wrapped, then the rejection becomes MeshNetworkError", async () => {
    const stream = new BoundedReadStream()
    vi.spyOn(stream, "read").mockRejectedValueOnce(new Error("bounded read failed"))
    const connection = {
      openStream: async () => stream as IrohStream,
      acceptStream: async () => stream as IrohStream,
      close: async () => undefined,
    } satisfies IrohConnection
    const wrappedStream = await meshNetworkConnection(connection).acceptStream() as IrohStream & {
      read(maximumBytes?: number): Promise<Uint8Array>
    }

    await expect(wrappedStream.read(128)).rejects.toBeInstanceOf(MeshNetworkError)
  })
})
