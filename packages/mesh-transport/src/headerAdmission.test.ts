import { afterEach, expect, it, vi } from "vitest"
import { meshNetworkConnection, type IrohConnection, type IrohStream, type MeshIngressBudgetProfile } from "./index"

const profile = {
  maxHeaderBytes: () => 64, maxFrameBytes: () => 1024, maxPayloadBytes: () => 1024,
  maxLogicalTransferBytes: () => 1024, maxTransferPages: () => 1, maxTransferDeadlineMs: () => 1000,
  maxInFlightBytesPerConnection: () => 2048, maxConcurrentFramesPerConnection: () => 2,
  maxConcurrentHeadersPerConnection: () => 8,
} satisfies MeshIngressBudgetProfile & { maxConcurrentHeadersPerConnection(): number }
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers() })
async function settle() { for (let pass = 0; pass < 30; pass++) await Promise.resolve() }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }

function staged(peer: string, header: Promise<number>, body: () => Promise<Uint8Array>) {
  const admitted = vi.fn(async (_maximum: number, admit: (limit: number) => Promise<void>) => {
    await admit(await header)
    return body()
  })
  const legacy = vi.fn(async () => { await header; return body() })
  const raw = { read: legacy, readPairingFrame: legacy, readPairingFrameAdmitted: admitted,
    send: async () => {}, closeSend: async () => {}, reset: vi.fn(async () => {}) } satisfies IrohStream & {
      readPairingFrameAdmitted(maximum: number, admit: (limit: number) => Promise<void>): Promise<Uint8Array>
    }
  const connection = { remoteEndpointId: peer, openStream: async () => raw, acceptStream: async () => raw,
    close: vi.fn(async () => {}) } satisfies IrohConnection
  return { connection: meshNetworkConnection(connection, profile), admitted, legacy, raw }
}

it("Given two responses have no header yet, when a heartbeat arrives on another scope, then admit it without waiting for those responses", async () => {
  const peer = crypto.randomUUID(), header = deferred<number>()
  const idle = [staged(peer, header.promise, async () => new Uint8Array([1])), staged(peer, header.promise, async () => new Uint8Array([2]))]
  const heartbeat = staged(peer, Promise.resolve(40), async () => new Uint8Array([3]))
  const connections = [...idle, heartbeat]
  const reads = idle.map(async entry => (await entry.connection.openStream()).read().catch(error => error))
  await settle()
  let received: Uint8Array | undefined
  const ack = (await heartbeat.connection.openStream()).read().then(bytes => { received = bytes }, () => {})
  try {
    await settle()
    expect(received).toEqual(new Uint8Array([3]))
    expect(heartbeat.admitted).toHaveBeenCalledOnce()
  } finally {
    await Promise.all(connections.map(entry => entry.connection.close()))
    header.resolve(1024)
    await Promise.all([...reads, ack])
  }
})

it("Given three scopes burst requests and acknowledgements, when all headers are ready, then queue payloads within the shared byte budget without rejecting ordinary traffic", async () => {
  const peer = crypto.randomUUID(), release = deferred<void>()
  let active = 0, peak = 0
  const connections = Array.from({ length: 6 }, () => staged(peer, Promise.resolve(900), async () => {
    active++; peak = Math.max(peak, active)
    await release.promise
    active--
    return new Uint8Array([7])
  }))
  const reads = connections.map(async entry => (await entry.connection.openStream()).read().catch(error => error))
  await settle()
  // Two 900-byte payloads plus the four other 64-byte headers would exceed 2048.
  expect(peak).toBe(1)
  release.resolve()
  const results = await Promise.all(reads)
  await Promise.all(connections.map(entry => entry.connection.close()))
  expect(results).toEqual(Array.from({ length: 6 }, () => new Uint8Array([7])))
})

it("Given bounded header reads fill the peer allowance, when another starts, then reject it without entering native read and release reservations on close", async () => {
  const peer = crypto.randomUUID(), header = deferred<number>()
  const pending = Array.from({ length: 8 }, () => staged(peer, header.promise, async () => new Uint8Array([1])))
  const reads = pending.map(async entry => (await entry.connection.openStream()).read().catch(error => error))
  await settle()
  const overflow = staged(peer, Promise.resolve(40), async () => new Uint8Array([3]))
  await expect((await overflow.connection.openStream()).read()).rejects.toThrow(/concurrency/)
  expect(overflow.admitted).not.toHaveBeenCalled()
  await Promise.all(pending.map(entry => entry.connection.close()))
  header.resolve(900)
  await Promise.all(reads)
  await expect((await overflow.connection.openStream()).read()).resolves.toEqual(new Uint8Array([3]))
  await overflow.connection.close()
})

it("Given payload admission waits for shared bytes, when that connection closes, then cancel its queued promotion and let other scopes complete", async () => {
  const peer = crypto.randomUUID(), release = deferred<void>()
  const active = staged(peer, Promise.resolve(1024), async () => { await release.promise; return new Uint8Array([1]) })
  const activeResult = (await active.connection.openStream()).read()
  await settle()
  const queued = staged(peer, Promise.resolve(1024), async () => new Uint8Array([2]))
  const extraHeader = deferred<number>()
  const idle = staged(peer, extraHeader.promise, async () => new Uint8Array([4]))
  const idleResult = (await idle.connection.openStream()).read().catch(error => error)
  const queuedResult = (await queued.connection.openStream()).read().catch(error => error)
  await settle()
  await queued.connection.close()
  expect(await queuedResult).toBeInstanceOf(Error)
  await idle.connection.close()
  extraHeader.resolve(40)
  await idleResult
  release.resolve()
  await expect(activeResult).resolves.toEqual(new Uint8Array([1]))
  await active.connection.close()
  const replacement = staged(peer, Promise.resolve(1024), async () => new Uint8Array([5]))
  await expect((await replacement.connection.openStream()).read()).resolves.toEqual(new Uint8Array([5]))
  await replacement.connection.close()
})
