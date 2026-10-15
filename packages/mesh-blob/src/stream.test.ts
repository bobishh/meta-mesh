import { blake3HashFor, createBlobDescriptor } from "./index"
import { BLOB_CHUNK_BYTES, MAX_BLOB_BYTES } from "./index"
import { chunkBlobSource, createBlobStreamDescriptor, createBlobStreamVerifier, type BlobByteSource } from "./stream"
import { describe, expect, it } from "vitest"

async function* chunks(...values: Uint8Array[]): AsyncGenerator<Uint8Array> {
  yield* values
}

function bytes(length: number, value = 7): Uint8Array {
  return new Uint8Array(length).fill(value)
}

async function collect(source: AsyncIterable<Uint8Array>): Promise<Uint8Array[]> {
  const result: Uint8Array[] = []
  for await (const chunk of source) result.push(chunk)
  return result
}

describe("streaming blob helpers", () => {
  it("verifies SHA-256 and BLAKE3 incrementally across arbitrary chunk boundaries", async () => {
    const value = bytes(BLOB_CHUNK_BYTES + 19)
    const sha = await createBlobDescriptor(value, "payload.bin", "application/octet-stream")
    const shaVerifier = createBlobStreamVerifier(sha)
    shaVerifier.update(value.slice(0, 13))
    shaVerifier.update(value.slice(13, BLOB_CHUNK_BYTES))
    shaVerifier.update(value.slice(BLOB_CHUNK_BYTES))
    expect(() => shaVerifier.finish()).not.toThrow()

    const blake = { ...sha, blobId: `blake3:${blake3HashFor(value).toUpperCase()}` }
    const blakeVerifier = createBlobStreamVerifier(blake)
    blakeVerifier.update(value.slice(0, 100))
    blakeVerifier.update(value.slice(100))
    expect(() => blakeVerifier.finish()).not.toThrow()
  })

  it("rejects wrong bytes, size, invalid chunks, and use after finish", async () => {
    const descriptor = await createBlobDescriptor(bytes(3), "x", "text/plain")
    const mismatch = createBlobStreamVerifier(descriptor)
    mismatch.update(bytes(3, 8))
    expect(() => mismatch.finish()).toThrow()

    const short = createBlobStreamVerifier(descriptor)
    short.update(bytes(2))
    expect(() => short.finish()).toThrow()

    const long = createBlobStreamVerifier(descriptor)
    expect(() => long.update(bytes(BLOB_CHUNK_BYTES + 1))).toThrow()
    expect(() => long.update(new Uint8Array())).toThrow()
    expect(() => long.update([1] as unknown as Uint8Array)).toThrow()

    const finished = createBlobStreamVerifier(descriptor)
    finished.update(bytes(3))
    finished.finish()
    expect(() => finished.update(bytes(1))).toThrow()
    expect(() => finished.finish()).toThrow()
  })

  it("captures descriptor fields and releases the source on an early consumer return", async () => {
    const value = bytes(4)
    const descriptor = await createBlobDescriptor(value, "x", "text/plain")
    const verifier = createBlobStreamVerifier(descriptor)
    descriptor.blobId = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    verifier.update(value)
    expect(() => verifier.finish()).not.toThrow()

    let closed = false
    const source: BlobByteSource = {
      async *[Symbol.asyncIterator]() {
        try {
          yield bytes(BLOB_CHUNK_BYTES)
          yield bytes(1)
        } finally {
          closed = true
        }
      },
    }
    const iterator = chunkBlobSource(source)
    await iterator.next()
    await iterator.return(undefined)
    expect(closed).toBe(true)
  })

  it("rechunks irregular inputs into detached canonical chunks", async () => {
    const source = chunks(bytes(100_000, 1), bytes(200_000, 2), bytes(200_000, 3), bytes(100_000, 3))
    const result = await collect(chunkBlobSource(source))
    expect(result.map(chunk => chunk.byteLength)).toEqual([BLOB_CHUNK_BYTES, BLOB_CHUNK_BYTES, 75_712])
    expect(result[0].slice(0, 100_000).every(value => value === 1)).toBe(true)
    expect(result[0].slice(100_000).every(value => value === 2)).toBe(true)
    expect(result[1].slice(0, 37_856).every(value => value === 2)).toBe(true)
    expect(result[1].slice(37_856).every(value => value === 3)).toBe(true)
    expect(result[0].buffer).not.toBe(result[1].buffer)
  })

  it("rejects empty, zero-length, oversized, and over-limit sources and closes iterators", async () => {
    await expect(collect(chunkBlobSource(chunks()))).rejects.toThrow()
    await expect(collect(chunkBlobSource(chunks(new Uint8Array())))).rejects.toThrow()
    await expect(collect(chunkBlobSource(chunks(bytes(BLOB_CHUNK_BYTES + 1))))).rejects.toThrow()
    const overLimit: BlobByteSource = {
      async *[Symbol.asyncIterator]() {
        for (let remaining = MAX_BLOB_BYTES + 1; remaining > 0; remaining -= BLOB_CHUNK_BYTES) {
          yield bytes(Math.min(BLOB_CHUNK_BYTES, remaining))
        }
      },
    }
    await expect(collect(chunkBlobSource(overLimit))).rejects.toThrow()

    let closed = false
    const source: BlobByteSource = {
      async *[Symbol.asyncIterator]() {
        try {
          yield bytes(BLOB_CHUNK_BYTES)
          yield bytes(BLOB_CHUNK_BYTES + 1)
        } finally {
          closed = true
        }
      },
    }
    await expect(collect(chunkBlobSource(source))).rejects.toThrow()
    expect(closed).toBe(true)
  })

  it("streams a descriptor with the same normalization and exact size checks", async () => {
    const input = chunks(bytes(4))
    const descriptor = await createBlobStreamDescriptor(input, 4, "  report\n.txt  ", "TEXT/PLAIN")
    expect(descriptor.name).toBe("report.txt")
    expect(descriptor.mediaType).toBe("text/plain")
    expect(descriptor.size).toBe(4)

    await expect(createBlobStreamDescriptor(chunks(bytes(3)), 4, "x", "text/plain")).rejects.toThrow()
    await expect(createBlobStreamDescriptor(chunks(bytes(5)), 4, "x", "text/plain")).rejects.toThrow()
    const tooLarge: BlobByteSource = {
      async *[Symbol.asyncIterator]() {
        for (let remaining = MAX_BLOB_BYTES + 1; remaining > 0; remaining -= BLOB_CHUNK_BYTES) {
          yield bytes(Math.min(BLOB_CHUNK_BYTES, remaining))
        }
      },
    }
    await expect(createBlobStreamDescriptor(tooLarge, MAX_BLOB_BYTES + 1, "x", "text/plain")).rejects.toThrow()
  })
})
