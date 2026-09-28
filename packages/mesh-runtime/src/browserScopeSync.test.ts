import { describe, expect, it, vi } from "vitest"
import type { RustMeshScopeRuntime } from "@meta-uber/mesh-replication/runtime"
import { BrowserMeshScopeSync } from "./browserScopeSync"

describe("BrowserMeshScopeSync shutdown", () => {
  it("reports wait time separately from work held in the scope queue", async () => {
    let finishRead!: (bytes: Uint8Array) => void
    let readCount = 0
    const readDocument = vi.fn(() => {
      readCount += 1
      return readCount === 1
        ? new Promise<Uint8Array>(resolve => { finishRead = resolve })
        : Promise.resolve(new Uint8Array([2]))
    })
    const timings: Array<{ operation: string; phase: string; elapsedMs: number }> = []
    const runtime = {
      preparePublish: vi.fn(() => ({ controlFrames: [], controlSnapshot: new Uint8Array() })),
      finishPublish: vi.fn(),
      publishFrame: vi.fn(() => undefined),
    } as unknown as RustMeshScopeRuntime
    const scope = new BrowserMeshScopeSync(runtime, {
      readDocument,
      persistDocument: vi.fn(),
      onTiming: timing => timings.push(timing),
    })
    const send = vi.fn(async () => true)

    const publishing = scope.publish(send)
    await vi.waitFor(() => expect(readDocument).toHaveBeenCalledOnce())
    const reconciling = scope.reconcile(send)
    expect(timings.some(timing => timing.operation === "reconcile" && timing.phase === "queue-wait")).toBe(false)
    finishRead(new Uint8Array([1]))
    await Promise.all([publishing, reconciling])

    expect(timings.map(({ operation, phase }) => `${operation}:${phase}`)).toEqual([
      "publish:queue-wait", "publish:queue-run", "reconcile:queue-wait", "reconcile:queue-run",
    ])
    expect(timings.every(({ elapsedMs }) => elapsedMs >= 0)).toBe(true)
    await scope.close()
  })

  it("runs document-only anti-entropy without reading control payloads", async () => {
    const runtime = {
      publishFrame: vi.fn(() => new Uint8Array([7])),
    } as unknown as RustMeshScopeRuntime
    const host = {
      readDocument: vi.fn(async () => new Uint8Array([1])),
      readAuthorization: vi.fn(async () => ({ proof: true })),
      readChat: vi.fn(async () => ({ messages: [] })),
      readMesh: vi.fn(async () => ({ peers: [] })),
      persistDocument: vi.fn(),
    }
    const scope = new BrowserMeshScopeSync(runtime, host)
    const send = vi.fn(async () => true)

    await expect(scope.reconcile(send)).resolves.toBe(true)

    expect(runtime.publishFrame).toHaveBeenCalledWith(new Uint8Array([1]), { proof: true })
    expect(send).toHaveBeenCalledWith(new Uint8Array([7]), "document")
    expect(host.readChat).not.toHaveBeenCalled()
    expect(host.readMesh).not.toHaveBeenCalled()
  })

  it("Given document read is pending, when session closes, then Rust is freed after the read and no publish starts", async () => {
    let finishRead!: (bytes: Uint8Array) => void
    const readDocument = vi.fn(() => new Promise<Uint8Array>(resolve => { finishRead = resolve }))
    const runtime = {
      preparePublish: vi.fn(), free: vi.fn(),
    } as unknown as RustMeshScopeRuntime
    const scope = new BrowserMeshScopeSync(runtime, { readDocument, persistDocument: vi.fn() })
    const send = vi.fn(async () => true)

    const publishing = scope.publish(send)
    await vi.waitFor(() => expect(readDocument).toHaveBeenCalledOnce())
    const closing = scope.close()
    expect(runtime.free).not.toHaveBeenCalled()
    finishRead(new Uint8Array([1]))

    await expect(publishing).resolves.toBe(false)
    await closing
    expect(runtime.preparePublish).not.toHaveBeenCalled()
    expect(send).not.toHaveBeenCalled()
    expect(runtime.free).toHaveBeenCalledOnce()
    await expect(scope.publish(send)).resolves.toBe(false)
  })

  it("Given stream send is pending, when session closes, then Rust completes publish before free", async () => {
    let finishSend!: () => void
    const sent = new Promise<void>(resolve => { finishSend = resolve })
    const order: string[] = []
    const runtime = {
      preparePublish: vi.fn(() => ({ documentFrame: new Uint8Array([1]), controlFrames: [], controlSnapshot: new Uint8Array([2]) })),
      finishPublish: vi.fn(() => { order.push("finish") }),
      free: vi.fn(() => { order.push("free") }),
    } as unknown as RustMeshScopeRuntime
    const scope = new BrowserMeshScopeSync(runtime, { readDocument: async () => new Uint8Array([1]), persistDocument: vi.fn() })
    const send = vi.fn(async () => { await sent; return false })

    const publishing = scope.publish(send)
    await vi.waitFor(() => expect(send).toHaveBeenCalledOnce())
    const closing = scope.close()
    expect(runtime.free).not.toHaveBeenCalled()
    finishSend()

    await expect(publishing).resolves.toBe(false)
    await closing
    expect(order).toEqual(["finish", "free"])
  })
})
