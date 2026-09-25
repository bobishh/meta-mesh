import { describe, expect, it, vi } from "vitest"
import type { RustMeshScopeRuntime } from "@meta-uber/mesh-replication/runtime"
import { BrowserMeshScopeSync } from "./browserScopeSync"

describe("BrowserMeshScopeSync shutdown", () => {
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
