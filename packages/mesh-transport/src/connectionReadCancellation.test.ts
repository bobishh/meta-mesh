import { afterEach, expect, it, vi } from "vitest"
import { meshNetworkConnection, MeshNetworkError, type IrohConnection, type IrohStream, type MeshIngressBudgetProfile } from "./index"
import { isMeshDialNetworkFailure } from "@meta-uber/mesh-runtime"

const limits: MeshIngressBudgetProfile = {
  maxHeaderBytes: () => 4096, maxFrameBytes: () => 1024, maxPayloadBytes: () => 1024,
  maxLogicalTransferBytes: () => 1024, maxTransferPages: () => 1, maxTransferDeadlineMs: () => 10,
  maxInFlightBytesPerConnection: () => 1024, maxConcurrentFramesPerConnection: () => 1,
}
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers() })

function connection(peer: string, read: () => Promise<Uint8Array>): IrohConnection {
  const stream: IrohStream = { read, readPairingFrame: read, send: async () => {}, closeSend: async () => {}, reset: async () => {} }
  return { remoteEndpointId: peer, openStream: async () => stream, acceptStream: async () => stream, close: vi.fn(async () => {}) }
}
async function settle() { for (let pass = 0; pass < 12; pass++) await Promise.resolve() }

it("Given active and queued reads on a failed route, when its connection closes, then both cancel immediately and a replacement route can read", async () => {
  vi.useFakeTimers()
  const peer = crypto.randomUUID()
  const route = meshNetworkConnection(connection(peer, () => new Promise(() => {})), limits)
  const stream = await route.openStream()
  const errors: unknown[] = []
  void stream.read().catch(error => errors.push(error))
  void stream.read().catch(error => errors.push(error))
  await settle()
  await route.close()
  await settle()
  expect(errors).toHaveLength(2)
  for (const error of errors) expect(error).toBeInstanceOf(MeshNetworkError)
  const replacement = meshNetworkConnection(connection(peer, async () => new Uint8Array([7])), limits)
  await expect((await replacement.openStream()).read()).resolves.toEqual(new Uint8Array([7]))
  await replacement.close()
})

it("Given another connection waits in the same peer budget, when the failed connection closes, then only its own work cancels and the waiting connection proceeds", async () => {
  vi.useFakeTimers()
  const peer = crypto.randomUUID()
  const failed = meshNetworkConnection(connection(peer, () => new Promise(() => {})), limits)
  const error = vi.fn()
  void (await failed.openStream()).read().catch(error)
  await settle()
  const healthyRead = vi.fn(async () => new Uint8Array([9]))
  const healthy = meshNetworkConnection(connection(peer, healthyRead), limits)
  const result = (await healthy.openStream()).read()
  await settle()
  expect(healthyRead).not.toHaveBeenCalled()
  await failed.close()
  await settle()
  expect(error).toHaveBeenCalledOnce()
  await expect(result).resolves.toEqual(new Uint8Array([9]))
  await healthy.close()
})

it("Given a stream response deadline, when a dial aggregates it, then the typed transport timeout stays an offline retry instead of a protocol error", async () => {
  vi.useFakeTimers()
  const wrapped = meshNetworkConnection(connection(crypto.randomUUID(), () => new Promise(() => {})), limits)
  const outcome = (await wrapped.openStream()).read().catch(error => error)
  await vi.advanceTimersByTimeAsync(10)
  const failure = await outcome
  expect(failure).toBeInstanceOf(MeshNetworkError)
  expect(isMeshDialNetworkFailure(new AggregateError([failure], "All routes failed for device sleeping"))).toBe(true)
  await wrapped.close()
})

it("Given a read has timed out with reset pending, when its connection closes, then closing releases the lease after transport cancellation", async () => {
  vi.useFakeTimers()
  const peer = crypto.randomUUID()
  const raw = connection(peer, () => new Promise(() => {}))
  const rawStream = await raw.openStream()
  rawStream.reset = vi.fn(() => new Promise(() => {}))
  let finishClose!: () => void
  raw.close = vi.fn(() => new Promise(resolve => { finishClose = resolve }))
  const failed = meshNetworkConnection(raw, limits)
  const outcome = (await failed.openStream()).read().catch(error => error)
  await vi.advanceTimersByTimeAsync(10)
  expect(rawStream.reset).toHaveBeenCalledOnce()
  const healthyRead = vi.fn(async () => new Uint8Array([5]))
  const healthy = meshNetworkConnection(connection(peer, healthyRead), limits)
  const result = (await healthy.openStream()).read()
  const firstClose = failed.close()
  expect(failed.close()).toBe(firstClose)
  await settle()
  expect(raw.close).toHaveBeenCalledOnce()
  expect(healthyRead).not.toHaveBeenCalled()
  finishClose()
  await firstClose
  await expect(outcome).resolves.toBeInstanceOf(MeshNetworkError)
  await expect(result).resolves.toEqual(new Uint8Array([5]))
  await expect(failed.openStream()).rejects.toBeInstanceOf(MeshNetworkError)
  await healthy.close()
})

it("Given a failed connection only has queued reads, when closed, then its queue entries disappear without cancelling the active connection", async () => {
  vi.useFakeTimers()
  const peer = crypto.randomUUID()
  let finishRead!: (bytes: Uint8Array) => void
  const active = meshNetworkConnection(connection(peer, () => new Promise(resolve => { finishRead = resolve })), limits)
  const activeResult = (await active.openStream()).read()
  await settle()
  const failedRead = vi.fn(async () => new Uint8Array([1]))
  const failed = meshNetworkConnection(connection(peer, failedRead), limits)
  const stream = await failed.openStream()
  const result = stream.read().catch(error => error)
  await settle()
  await failed.close()
  await expect(result).resolves.toBeInstanceOf(MeshNetworkError)
  await expect(stream.read()).rejects.toBeInstanceOf(MeshNetworkError)
  expect(failedRead).not.toHaveBeenCalled()
  finishRead(new Uint8Array([4]))
  await expect(activeResult).resolves.toEqual(new Uint8Array([4]))
  expect(vi.getTimerCount()).toBe(0)
  await active.close()
})
