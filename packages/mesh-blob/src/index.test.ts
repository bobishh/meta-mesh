import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { MemoryMeshStore } from "../../mesh-browser-store/src/index"
import { BrowserIdentityStore } from "../../mesh-identity/src/index"
import { decodePairingFrame, encodePairingFrame, installPairingCodec } from "../../mesh-pairing/src/index"
import {
  BLOB_REQUEST_FRAME,
  BLOB_RESPONSE_FRAME,
  BLOB_CHUNK_BYTES,
  MAX_BLOB_BYTES,
  MeshBlobStore,
  createBlobDescriptor,
  createBlobRequest,
  createBlobResponse,
  createIrohBlobDescriptor,
  requestBlob,
  respondToBlobRequest,
  verifyBlobBytes,
  verifyBlobRequest,
  verifyBlobResponse,
  type BlobEngineInterface,
  type BlobDescriptor,
  type RequestBlobOptions,
} from "./index"

const requestBlobWithOptions = (
  connection: Parameters<typeof requestBlob>[0], secret: string, profile: Parameters<typeof requestBlob>[2],
  scopeId: string, descriptor: BlobDescriptor, options: RequestBlobOptions,
) => requestBlob(connection, secret, profile, scopeId, descriptor, options)

function responseStream(descriptor: BlobDescriptor, bytes: Uint8Array, secret: string) {
  let request: Awaited<ReturnType<typeof createBlobRequest>> | undefined
  return {
    async send(frame: Uint8Array) {
      request = JSON.parse(new TextDecoder().decode(decodePairingFrame(frame, BLOB_REQUEST_FRAME, secret)))
    },
    async closeSend() {},
    async read() {
      if (!request) throw new Error("Request frame missing")
      const { offset, length } = request.payload
      const response = createBlobResponse(request, descriptor, bytes.slice(offset, Math.min(offset + length, bytes.length)))
      return encodePairingFrame(BLOB_RESPONSE_FRAME, secret, new TextEncoder().encode(JSON.stringify(response)))
    },
  }
}

async function settlesWithin(promise: Promise<unknown>, milliseconds: number): Promise<boolean> {
  return Promise.race([
    promise.then(() => true, () => true),
    new Promise<boolean>(resolve => setTimeout(() => resolve(false), milliseconds)),
  ])
}

describe("mesh blob transfer", () => {
  let alice: Awaited<ReturnType<BrowserIdentityStore["bootstrap"]>>
  let restoreCodec: (() => void) | undefined

  beforeEach(async () => {
    restoreCodec = installPairingCodec({
      encode(type, secret, bytes) {
        const header = new TextEncoder().encode(`${JSON.stringify({ type, version: "0.0.1", secret })}\n`)
        const frame = new Uint8Array(header.byteLength + bytes.byteLength)
        frame.set(header)
        frame.set(bytes, header.byteLength)
        return frame
      },
      inspect(frame) {
        const separator = frame.indexOf(10)
        return JSON.parse(new TextDecoder().decode(frame.slice(0, separator)))
      },
      decode(frame, expectedType, expectedSecret) {
        const separator = frame.indexOf(10)
        const header = JSON.parse(new TextDecoder().decode(frame.slice(0, separator)))
        if (header.type !== expectedType || header.secret !== expectedSecret) throw new Error("Pairing authorization failed")
        return frame.slice(separator + 1)
      },
    })
    alice = await new BrowserIdentityStore({ storageKey: crypto.randomUUID() }).bootstrap("Alice")
  })

  afterEach(() => restoreCodec?.())

  it("Given full-size chunk responses, when downloading, then bound each raw read without truncating valid frames", async () => {
    const bytes = new Uint8Array(BLOB_CHUNK_BYTES + 13).fill(27)
    const descriptor = await createBlobDescriptor(bytes, "bounded.bin", "application/octet-stream")
    const reads: Array<ReturnType<typeof vi.fn>> = []
    const connection = { async openStream() {
      const stream = responseStream(descriptor, bytes, "workspace-secret")
      const read = vi.fn(async (_maximumBytes?: number) => stream.read())
      reads.push(read)
      return { ...stream, read }
    } }
    await expect(requestBlob(connection, "workspace-secret", alice, "room-1", descriptor)).resolves.toEqual(bytes)
    expect(reads).toHaveLength(2)
    for (const read of reads) expect(read).toHaveBeenCalledWith(Math.ceil(BLOB_CHUNK_BYTES / 3) * 4 + 4096)
  })

  it.each([true, false])(
    "Given a peer pads a valid response over its frame budget, when the adapter enforces limits=%s, then reject without file bytes and reset only the stream",
    async boundedAdapter => {
      const bytes = new TextEncoder().encode("original file")
      const descriptor = await createBlobDescriptor(bytes, "bounded.txt", "text/plain")
      const stream = responseStream(descriptor, bytes, "workspace-secret")
      const reset = vi.fn(async () => undefined)
      const close = vi.fn(async () => undefined)
      const connection = { close, async openStream() { return { ...stream, reset, async read(maximumBytes?: number) {
        const frame = await stream.read()
        const padded = new Uint8Array(Math.ceil(BLOB_CHUNK_BYTES / 3) * 4 + 4097).fill(32)
        padded.set(frame)
        if (boundedAdapter && maximumBytes !== undefined && padded.length > maximumBytes) throw new Error("Stream read limit exceeded")
        return padded
      } } } }
      await expect(requestBlob(connection, "workspace-secret", alice, "room-1", descriptor)).rejects.toThrow(/limit|large/i)
      expect(reset).toHaveBeenCalledOnce()
      expect(close).not.toHaveBeenCalled()
    },
  )

  it("Given a room member and stored bytes, when ranges are requested, then signed access and content hash verify", async () => {
    const bytes = new TextEncoder().encode("hello across mesh")
    const descriptor = await createBlobDescriptor(bytes, "hello.txt", "text/plain")
    const store = new MeshBlobStore(new MemoryMeshStore())
    await store.put(descriptor, bytes)
    const request = await createBlobRequest(alice, "room-1", descriptor.blobId, 0, 8)

    await expect(verifyBlobRequest(request, alice.identity, [alice.certificate], "room-1")).resolves.toEqual(request)
    const response = createBlobResponse(request, descriptor, (await store.get(descriptor.blobId))!.slice(0, 8))
    expect(verifyBlobResponse(response, request, descriptor)).toEqual(new TextEncoder().encode("hello ac"))
    await expect(store.getVerified(descriptor)).resolves.toEqual(bytes)
  })

  it("Given oversized or corrupted bytes, when described or loaded, then transfer is rejected", async () => {
    await expect(createBlobDescriptor(new Uint8Array(MAX_BLOB_BYTES + 1), "huge.bin", "application/octet-stream"))
      .rejects.toThrow("8 MiB")
    const bytes = new TextEncoder().encode("right")
    const descriptor = await createBlobDescriptor(bytes, "file.txt", "text/plain")
    const store = new MeshBlobStore(new MemoryMeshStore())
    await store.put(descriptor, bytes)
    await store.putUnsafe(descriptor.blobId, new TextEncoder().encode("wrong"))

    await expect(store.getVerified(descriptor)).rejects.toThrow("Blob content does not match descriptor")
  })

  it("Given iroh-blobs engine and file bytes, when described and stored, then Automerge descriptor retains Blake3 metadata and ticket", async () => {
    const mockBlobEngine: BlobEngineInterface = {
      createBlob: vi.fn((data: Uint8Array, name: string, mediaType: string, nodeEndpoint?: string | null) => {
        const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        return {
          kind: "blob" as const,
          version: 1 as const,
          blobId: `blake3:${hash}`,
          hash,
          ticket: `blob:${hash}@${nodeEndpoint || "local"}`,
          name,
          mediaType,
          size: data.byteLength,
        }
      }),
      putBlob: vi.fn(),
      getBlob: vi.fn((hash: string) => hash.includes("0123") ? new TextEncoder().encode("iroh blob payload") : undefined),
      hasBlob: vi.fn((hash: string) => hash.includes("0123")),
      verifyBlob: vi.fn((hash: string, data: Uint8Array) => hash.includes("0123") && data.byteLength === 17),
    }

    const bytes = new TextEncoder().encode("iroh blob payload")
    const descriptor = await createIrohBlobDescriptor(mockBlobEngine, bytes, "image.png", "image/png", "endpoint-1")

    expect(descriptor.blobId).toMatch(/^blake3:[0-9a-f]{64}$/)
    expect(descriptor.hash).toBe("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    expect(descriptor.ticket).toContain("endpoint-1")
    expect(descriptor.size).toBe(bytes.byteLength)

    const store = new MeshBlobStore(new MemoryMeshStore(), "blobs", mockBlobEngine)
    await store.put(descriptor, bytes)
    expect(mockBlobEngine.putBlob).toHaveBeenCalledWith(descriptor.hash, bytes)

    const loaded = await store.getVerified(descriptor)
    expect(loaded).toEqual(bytes)
    expect(await store.has(descriptor)).toBe(true)
  })

  it("Given an asynchronous native blob engine, when bytes are described and loaded, then every operation is awaited", async () => {
    const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    const bytes = new TextEncoder().encode("native blob")
    const engine: BlobEngineInterface = {
      createBlob: vi.fn(async (_data, name, mediaType) => ({
        kind: "blob" as const, version: 1 as const, blobId: `blake3:${hash}`, hash,
        ticket: "blob-ticket", name, mediaType, size: bytes.byteLength,
      })),
      putBlob: vi.fn(async () => undefined),
      getBlob: vi.fn(async () => bytes),
      hasBlob: vi.fn(async () => true),
      verifyBlob: vi.fn(async () => true),
      fetchBlob: vi.fn(async () => bytes),
    }

    const descriptor = await createIrohBlobDescriptor(engine, bytes, "native.jpg", "image/jpeg")
    const store = new MeshBlobStore(new MemoryMeshStore(), "blobs", engine)
    await store.put(descriptor, bytes)

    await expect(store.getVerified(descriptor)).resolves.toEqual(bytes)
    await expect(store.has(descriptor)).resolves.toBe(true)
    expect(engine.createBlob).toHaveBeenCalledOnce()
    expect(engine.putBlob).toHaveBeenCalledOnce()
  })

  it("Given a blake3 blobId, when blob request is created and verified, then it succeeds", async () => {
    const blake3BlobId = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    const request = await createBlobRequest(alice, "room-1", blake3BlobId, 0, 8)
    await expect(verifyBlobRequest(request, alice.identity, [alice.certificate], "room-1")).resolves.toEqual(request)
  })

  it("Given an authenticated mesh stream, when a multi-chunk blob is requested, then verified bytes arrive", async () => {
    const bytes = new Uint8Array(256 * 1024 + 7).fill(23)
    const descriptor = await createBlobDescriptor(bytes, "large.bin", "application/octet-stream")
    const store = new MeshBlobStore(new MemoryMeshStore())
    await store.put(descriptor, bytes)
    const connection = {
      async openStream() {
        let response: Uint8Array | undefined
        let release!: () => void
        const ready = new Promise<void>(resolve => { release = resolve })
        return {
          async send(frame: Uint8Array) {
            await respondToBlobRequest({
              async send(value) { response = value },
              async closeSend() { release() },
            }, frame, {
              secret: "workspace-secret",
              scopeId: "workspace-1",
              identity: alice.identity,
              certificates: [alice.certificate],
              descriptor: async blobId => blobId === descriptor.blobId ? descriptor : undefined,
              bytes: value => store.getVerified(value),
            })
          },
          async closeSend() {},
          async read() { await ready; return response! },
        }
      },
    }

    await expect(requestBlob(connection, "workspace-secret", alice, "workspace-1", descriptor)).resolves.toEqual(bytes)
  })

  it("Given openStream never resolves, when the caller aborts, then settle promptly without closing the connection", async () => {
    const bytes = new TextEncoder().encode("abort during open")
    const descriptor = await createBlobDescriptor(bytes, "abort.txt", "text/plain")
    let release!: (stream: ReturnType<typeof responseStream>) => void
    const opened = new Promise<ReturnType<typeof responseStream>>(resolve => { release = resolve })
    const expected = responseStream(descriptor, bytes, "workspace-secret")
    const stream = { ...expected, send: vi.fn(expected.send), closeSend: vi.fn(expected.closeSend) }
    const controller = new AbortController()
    const connection = { openStream: vi.fn(() => opened), close: vi.fn() }
    const pending = requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor,
      { signal: controller.signal })
    await vi.waitFor(() => expect(connection.openStream).toHaveBeenCalledOnce())
    controller.abort(new Error("caller stopped"))

    const prompt = await settlesWithin(pending, 50)
    release(stream)
    await expect(pending).rejects.toThrow(/abort|stopped/i)
    await vi.waitFor(() => expect(stream.closeSend).toHaveBeenCalledOnce())
    expect(prompt).toBe(true)
    expect(stream.send).not.toHaveBeenCalled()
    expect(stream.closeSend).toHaveBeenCalledOnce()
    expect(connection.close).not.toHaveBeenCalled()
  })

  it("Given a pending read after send half-close, when authority aborts, then reset that stream and settle its underlying read without closing the connection", async () => {
    const descriptor = await createBlobDescriptor(new Uint8Array([1]), "reset.bin", "application/octet-stream")
    let rejectRead!: (error: Error) => void
    let readSettled = false
    const read = new Promise<Uint8Array>((_resolve, reject) => { rejectRead = reject }).finally(() => { readSettled = true })
    const stream = { send: vi.fn(async () => {}), closeSend: vi.fn(async () => {}), read: vi.fn(() => read),
      reset: vi.fn(async () => { rejectRead(new Error("Stream reset")) }) }
    const connection = { openStream: vi.fn(async () => stream), close: vi.fn() }
    const controller = new AbortController()
    const pending = requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor, { signal: controller.signal })
    await vi.waitFor(() => expect(stream.read).toHaveBeenCalledOnce())
    controller.abort(new Error("Device authority changed"))
    await expect(pending).rejects.toThrow("Device authority changed")
    await vi.waitFor(() => expect(stream.reset).toHaveBeenCalledOnce())
    expect(readSettled).toBe(true)
    expect(stream.closeSend).toHaveBeenCalledOnce()
    expect(connection.close).not.toHaveBeenCalled()
  })

  it("Given a stream opens after cancellation, when its late handle arrives, then reset it without sending a request or closing the connection", async () => {
    const bytes = new Uint8Array([1])
    const descriptor = await createBlobDescriptor(bytes, "late-reset.bin", "application/octet-stream")
    const expected = responseStream(descriptor, bytes, "workspace-secret")
    const stream = { ...expected, send: vi.fn(expected.send), closeSend: vi.fn(expected.closeSend), reset: vi.fn(async () => {}) }
    let release!: (value: typeof stream) => void
    const opening = new Promise<typeof stream>(resolve => { release = resolve })
    const connection = { openStream: vi.fn(() => opening), close: vi.fn() }
    const controller = new AbortController()
    const pending = requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor, { signal: controller.signal })
    await vi.waitFor(() => expect(connection.openStream).toHaveBeenCalledOnce())
    controller.abort(new Error("Session replaced"))
    await expect(pending).rejects.toThrow("Session replaced")
    release(stream)
    await vi.waitFor(() => expect(stream.reset).toHaveBeenCalledOnce())
    expect(stream.send).not.toHaveBeenCalled()
    expect(stream.closeSend).not.toHaveBeenCalled()
    expect(connection.close).not.toHaveBeenCalled()
  })

  it("Given an authenticated multi-chunk download succeeds, when each response is consumed, then release each stream while retaining the connection", async () => {
    const bytes = new Uint8Array(BLOB_CHUNK_BYTES + 9).fill(51)
    const descriptor = await createBlobDescriptor(bytes, "release.bin", "application/octet-stream")
    const streams: Array<ReturnType<typeof responseStream> & { reset: ReturnType<typeof vi.fn> }> = []
    const connection = { openStream: async () => {
      const stream = { ...responseStream(descriptor, bytes, "workspace-secret"), reset: vi.fn(async () => {}) }
      streams.push(stream)
      return stream
    }, close: vi.fn() }
    expect(await requestBlob(connection, "workspace-secret", alice, "workspace-1", descriptor)).toEqual(bytes)
    expect(streams).toHaveLength(2)
    for (const stream of streams) expect(stream.reset).toHaveBeenCalledOnce()
    expect(connection.close).not.toHaveBeenCalled()
  })

  it("Given stream reset itself rejects, when aborting a pending read, then preserve the caller's reason", async () => {
    const descriptor = await createBlobDescriptor(new Uint8Array([1]), "reset-failure.bin", "application/octet-stream")
    const stream = { send: async () => {}, closeSend: async () => {}, read: vi.fn(() => new Promise<Uint8Array>(() => {})),
      reset: vi.fn(async () => { throw new Error("Reset failed") }) }
    const controller = new AbortController()
    const pending = requestBlobWithOptions({ openStream: async () => stream }, "workspace-secret", alice, "workspace-1", descriptor, { signal: controller.signal })
    await vi.waitFor(() => expect(stream.read).toHaveBeenCalledOnce())
    controller.abort(new Error("Caller stopped"))
    await expect(pending).rejects.toThrow("Caller stopped")
    expect(stream.reset).toHaveBeenCalledOnce()
  })

  it("Given an already aborted signal, when requesting a blob, then do not open a stream", async () => {
    const descriptor = await createBlobDescriptor(new Uint8Array([1]), "stopped.bin", "application/octet-stream")
    const controller = new AbortController()
    controller.abort(new Error("caller stopped"))
    const connection = { openStream: vi.fn() }

    await expect(requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor,
      { signal: controller.signal })).rejects.toThrow(/caller stopped/i)
    expect(connection.openStream).not.toHaveBeenCalled()
  })

  it("Given cancellation while send is pending, when best-effort stream close throws, then preserve cancellation reason", async () => {
    const descriptor = await createBlobDescriptor(new Uint8Array([1]), "send-abort.bin", "application/octet-stream")
    let beginSend!: () => void
    const sendStarted = new Promise<void>(resolve => { beginSend = resolve })
    const pendingSend = new Promise<void>(() => {})
    const stream = {
      send: vi.fn(() => { beginSend(); return pendingSend }),
      closeSend: vi.fn(() => { throw new Error("stream close failed") }),
      async read() { throw new Error("unused") },
    }
    const controller = new AbortController()
    const connection = { openStream: async () => stream }
    const pending = requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor,
      { signal: controller.signal })
    await sendStarted
    controller.abort(new Error("caller stopped"))

    await expect(pending).rejects.toThrow(/caller stopped/i)
    expect(stream.closeSend).toHaveBeenCalledOnce()
  })

  it("Given openStream exceeds its absolute deadline, when no stream arrives, then reject the transfer", async () => {
    const descriptor = await createBlobDescriptor(new Uint8Array([1]), "deadline.bin", "application/octet-stream")
    const never = new Promise<never>(() => {})
    const connection = { openStream: vi.fn(() => never) }

    await expect(requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor,
      { deadlineAt: Date.now() + 25 })).rejects.toThrow(/deadline/i)
  })

  it("Given a deadline exceeds the platform timer limit, when a chunk is pending briefly, then do not expire it early", async () => {
    const bytes = new TextEncoder().encode("long deadline")
    const descriptor = await createBlobDescriptor(bytes, "long.txt", "text/plain")
    let request: Awaited<ReturnType<typeof createBlobRequest>> | undefined
    let release!: (frame: Uint8Array) => void
    let markReadStarted!: () => void
    const readStarted = new Promise<void>(resolve => { markReadStarted = resolve })
    const lateFrame = new Promise<Uint8Array>(resolve => { release = resolve })
    const stream = {
      async send(frame: Uint8Array) {
        request = JSON.parse(new TextDecoder().decode(decodePairingFrame(frame, BLOB_REQUEST_FRAME, "workspace-secret")))
      },
      async closeSend() {},
      read() { markReadStarted(); return lateFrame },
    }
    const connection = { openStream: async () => stream }
    const pending = requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor,
      { deadlineAt: Date.now() + 2_147_483_648 })
    const outcome = pending.then(value => ({ value }), error => ({ error }))
    const reachedRead = await Promise.race([readStarted.then(() => true), outcome.then(() => false)])
    expect(reachedRead).toBe(true)
    await new Promise(resolve => setTimeout(resolve, 10))
    if (!request) throw new Error("Request frame missing")
    const response = createBlobResponse(request, descriptor, bytes)
    release(encodePairingFrame(BLOB_RESPONSE_FRAME, "workspace-secret", new TextEncoder().encode(JSON.stringify(response))))

    await expect(outcome).resolves.toEqual({ value: bytes })
  })

  it("Given a pending chunk read, when aborted and the frame arrives late, then return no partial bytes", async () => {
    const bytes = new TextEncoder().encode("late frame")
    const descriptor = await createBlobDescriptor(bytes, "late.txt", "text/plain")
    let request: Awaited<ReturnType<typeof createBlobRequest>> | undefined
    let release!: (frame: Uint8Array) => void
    const lateFrame = new Promise<Uint8Array>(resolve => { release = resolve })
    const stream = {
      async send(frame: Uint8Array) {
        request = JSON.parse(new TextDecoder().decode(decodePairingFrame(frame, BLOB_REQUEST_FRAME, "workspace-secret")))
      },
      async closeSend() {}, read: vi.fn(() => lateFrame),
    }
    const controller = new AbortController()
    const connection = { openStream: async () => stream }
    const pending = requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor,
      { signal: controller.signal })
    await vi.waitFor(() => expect(stream.read).toHaveBeenCalledOnce())
    controller.abort(new Error("authority changed"))
    const prompt = await settlesWithin(pending, 50)
    if (!request) throw new Error("Request frame missing")
    const response = createBlobResponse(request, descriptor, bytes)
    release(encodePairingFrame(BLOB_RESPONSE_FRAME, "workspace-secret", new TextEncoder().encode(JSON.stringify(response))))

    await expect(pending).rejects.toThrow(/abort|authority|changed/i)
    expect(prompt).toBe(true)
  })

  it("Given authority is revoked after one chunk, when the next chunk would start, then reject without partial bytes", async () => {
    const bytes = new Uint8Array(BLOB_CHUNK_BYTES + 3).fill(7)
    const descriptor = await createBlobDescriptor(bytes, "multi.bin", "application/octet-stream")
    let allowed = true
    const connection = {
      openStream: vi.fn(async () => {
        const stream = responseStream(descriptor, bytes, "workspace-secret")
        return { ...stream, async read() { allowed = false; return stream.read() } }
      }),
    }

    await expect(requestBlobWithOptions(connection, "workspace-secret", alice, "workspace-1", descriptor, {
      ensureCurrent() { if (!allowed) throw new Error("Authority changed") },
    })).rejects.toThrow(/authority changed/i)
    expect(connection.openStream).toHaveBeenCalledOnce()
  })
})


describe("Blake3 content addressing", () => {
  const bytes = new TextEncoder().encode("abc")
  const hash = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
  const descriptor = {
    kind: "blob" as const, version: 1 as const, blobId: `blake3:${hash}`,
    name: "abc.txt", mediaType: "text/plain", size: 3,
  }

  it("verifies persisted bytes without a running WASM node", async () => {
    const storage = new MemoryMeshStore()
    const store = new MeshBlobStore(storage)
    await store.put(descriptor, bytes)
    await expect(store.getVerified(descriptor)).resolves.toEqual(bytes)
    await store.putUnsafe(descriptor.blobId, new TextEncoder().encode("xyz"))
    await expect(store.getVerified(descriptor)).rejects.toThrow("Blob content does not match descriptor")
  })

  it("rejects corrupt bytes before persistence", async () => {
    const storage = new MemoryMeshStore()
    const store = new MeshBlobStore(storage)
    await expect(store.put(descriptor, new TextEncoder().encode("xyz")))
      .rejects.toThrow("Blob content does not match descriptor")
    expect(await storage.get("blobs", descriptor.blobId)).toBeUndefined()
  })

  it("does not let a redundant hash override the content address", async () => {
    const other = { ...descriptor, hash: "0".repeat(64) }
    const engine = { verifyBlob: vi.fn(() => true) } as unknown as BlobEngineInterface
    await expect(verifyBlobBytes(other, bytes, engine)).rejects.toThrow("Invalid blob descriptor")
    expect(engine.verifyBlob).not.toHaveBeenCalled()
  })
})
