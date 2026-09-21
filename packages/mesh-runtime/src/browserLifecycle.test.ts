import { describe, expect, it, vi } from "vitest"
import { BrowserMeshLifecycle } from "./browserLifecycle"

describe("BrowserMeshLifecycle", () => {
  it("runs host work, stops it through abort, and releases the instance once", async () => {
    let running = 0
    let finish: (() => void) | undefined
    const shutdown = vi.fn(async () => {})
    const lifecycle = new BrowserMeshLifecycle({
      canStart: async () => true,
      acquireInstance: vi.fn(async () => {}),
      runOnce: async signal => {
        running += 1
        await new Promise<void>(resolve => {
          finish = resolve
          signal.addEventListener("abort", resolve, { once: true })
        })
      },
      shutdown,
      trace: vi.fn(), reportRestart: vi.fn(), notify: vi.fn(async () => {}), retryChanged: vi.fn(),
    })
    const release = vi.fn(async () => {})

    await lifecycle.start()
    await vi.waitFor(() => expect(running).toBe(1))
    await lifecycle.stop(true, release)
    finish?.()

    expect(lifecycle.stopped).toBe(true)
    expect(shutdown).toHaveBeenCalled()
    expect(release).toHaveBeenCalledOnce()
  })

  it("does not create a process while start conditions are unavailable", async () => {
    const runOnce = vi.fn(async () => {})
    const lifecycle = new BrowserMeshLifecycle({
      canStart: async () => false,
      acquireInstance: vi.fn(async () => {}), runOnce, shutdown: vi.fn(async () => {}),
      trace: vi.fn(), reportRestart: vi.fn(), notify: vi.fn(async () => {}), retryChanged: vi.fn(),
    })

    await lifecycle.start()

    expect(runOnce).not.toHaveBeenCalled()
    expect(lifecycle.stopped).toBe(true)
  })
})
