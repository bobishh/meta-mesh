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
          signal.addEventListener("abort", () => resolve(), { once: true })
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

  it("does not revive a stopped runtime after an in-flight start check", async () => {
    let finishCheck!: (allowed: boolean) => void
    const checked = new Promise<boolean>(resolve => { finishCheck = resolve })
    const acquireInstance = vi.fn(async () => {})
    const runOnce = vi.fn(async () => {})
    const lifecycle = new BrowserMeshLifecycle({
      canStart: () => checked,
      acquireInstance, runOnce, shutdown: vi.fn(async () => {}),
      trace: vi.fn(), reportRestart: vi.fn(), notify: vi.fn(async () => {}), retryChanged: vi.fn(),
    })

    const starting = lifecycle.start()
    await lifecycle.stop()
    finishCheck(true)
    await starting

    expect(acquireInstance).not.toHaveBeenCalled()
    expect(runOnce).not.toHaveBeenCalled()
    expect(lifecycle.stopped).toBe(true)
  })
})

describe("BrowserMeshLifecycle recovery without page reload", () => {
  it("retries a failed startup notification instead of leaving running state without a task", async () => {
    vi.useFakeTimers()
    const runOnce = vi.fn(async (signal: AbortSignal) => {
      await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve(), { once: true }))
    })
    const notify = vi.fn().mockRejectedValueOnce(new Error("temporary UI notification failure")).mockResolvedValue(undefined)
    const lifecycle = new BrowserMeshLifecycle({
      canStart: async () => true, acquireInstance: async () => {}, runOnce,
      shutdown: async () => {}, trace: vi.fn(), reportRestart: vi.fn(), notify, retryChanged: vi.fn(),
    })
    try {
      await lifecycle.start()
      await vi.advanceTimersByTimeAsync(1_000)
      expect(runOnce).toHaveBeenCalledOnce()
      expect(lifecycle.stopped).toBe(false)
    } finally {
      await lifecycle.stop()
      vi.useRealTimers()
    }
  })
})

describe("BrowserMeshLifecycle fault sequences", () => {
  it.each([0, 1, 3])("recovers in the same instance after %i failed cleanup attempts", async failures => {
    vi.useFakeTimers()
    const order: string[] = []
    let attempts = 0
    let failedCleanups = 0
    const lifecycle = new BrowserMeshLifecycle({
      canStart: async () => true, acquireInstance: async () => {},
      runOnce: async signal => {
        order.push("run")
        if (++attempts === 1) throw new Error("browser runtime node is closed")
        await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve(), { once: true }))
      },
      shutdown: async () => {
        if (failedCleanups++ < failures) { order.push("cleanup-failed"); throw new Error("temporary cleanup failure") }
        order.push("cleaned")
      },
      trace: vi.fn(), reportRestart: vi.fn(), notify: async () => {}, retryChanged: vi.fn(),
    })
    try {
      await lifecycle.start()
      await vi.advanceTimersByTimeAsync((failures + 1) * 1_000)
      expect(attempts).toBe(2)
      expect(order.slice(0, failures + 3)).toEqual(["run", ...Array(failures).fill("cleanup-failed"), "cleaned", "run"])
      await lifecycle.stop()
      await vi.advanceTimersByTimeAsync(60_000)
      expect(attempts).toBe(2)
    } finally { await lifecycle.stop(); vi.useRealTimers() }
  })

  it("does not let a stale start check consume a newer start after stop", async () => {
    let oldCheck!: (allowed: boolean) => void
    let newCheck!: (allowed: boolean) => void
    const checks = [new Promise<boolean>(r => { oldCheck = r }), new Promise<boolean>(r => { newCheck = r })]
    const acquireInstance = vi.fn(async () => {})
    const runOnce = vi.fn(async (signal: AbortSignal) => {
      await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve(), { once: true }))
    })
    const lifecycle = new BrowserMeshLifecycle({
      canStart: () => checks.shift()!, acquireInstance, runOnce,
      shutdown: async () => {}, trace: vi.fn(), reportRestart: vi.fn(), notify: async () => {}, retryChanged: vi.fn(),
    })
    const oldStart = lifecycle.start()
    await lifecycle.stop()
    const newStart = lifecycle.start()
    oldCheck(false)
    await oldStart
    newCheck(true)
    await newStart
    try { expect(acquireInstance).toHaveBeenCalledOnce(); expect(runOnce).toHaveBeenCalledOnce() }
    finally { await lifecycle.stop() }
  })

  it("waits for a cancelled acquisition and releases its lease before a newer start", async () => {
    let finishAcquire!: () => void
    const acquisition = new Promise<void>(resolve => { finishAcquire = resolve })
    const acquireInstance = vi.fn()
      .mockImplementationOnce(() => acquisition)
      .mockResolvedValue(undefined)
    const release = vi.fn(async () => {})
    const runOnce = vi.fn(async (signal: AbortSignal) => {
      await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve(), { once: true }))
    })
    const lifecycle = new BrowserMeshLifecycle({
      canStart: async () => true, acquireInstance, runOnce,
      shutdown: async () => {}, trace: vi.fn(), reportRestart: vi.fn(), notify: async () => {}, retryChanged: vi.fn(),
    })

    const staleStart = lifecycle.start()
    await vi.waitFor(() => expect(acquireInstance).toHaveBeenCalledOnce())
    const stopping = lifecycle.stop(true, release)
    const successorStart = lifecycle.start()
    expect(release).not.toHaveBeenCalled()
    expect(acquireInstance).toHaveBeenCalledOnce()
    expect(runOnce).not.toHaveBeenCalled()
    finishAcquire()
    await Promise.all([staleStart, stopping, successorStart])
    expect(release).toHaveBeenCalledOnce()

    try {
      expect(acquireInstance).toHaveBeenCalledTimes(2)
      expect(runOnce).toHaveBeenCalledOnce()
    } finally { await lifecycle.stop() }
  })

  it("joins concurrent stops and releases the instance only after cleanup", async () => {
    let finishCleanup!: () => void
    const cleanup = new Promise<void>(resolve => { finishCleanup = resolve })
    const release = vi.fn(async () => {})
    const lifecycle = new BrowserMeshLifecycle({
      canStart: async () => true, acquireInstance: async () => {},
      runOnce: async signal => {
        await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve(), { once: true }))
      },
      shutdown: vi.fn(() => cleanup), trace: vi.fn(), reportRestart: vi.fn(), notify: async () => {}, retryChanged: vi.fn(),
    })
    await lifecycle.start()

    const first = lifecycle.stop(true, release)
    const second = lifecycle.stop(true, release)
    await Promise.resolve()
    expect(release).not.toHaveBeenCalled()
    finishCleanup()
    await Promise.all([first, second])
    expect(release).toHaveBeenCalledOnce()
  })
})

describe("BrowserMeshLifecycle eventual recovery under finite faults", () => {
  it.each([1, 2, 4].flatMap(runFailures => [0, 2].flatMap(cleanupFailures => [0, 1].map(notifyFailures => ({ runFailures, cleanupFailures, notifyFailures })))))
    ("reaches a live run after $runFailures run, $cleanupFailures cleanup and $notifyFailures notify failures", async ({ runFailures, cleanupFailures, notifyFailures }) => {
      vi.useFakeTimers()
      let runs = 0
      let cleanups = 0
      let notifications = 0
      let connected = false
      const lifecycle = new BrowserMeshLifecycle({
        canStart: async () => true, acquireInstance: async () => {},
        notify: async () => { if (notifications++ < notifyFailures) throw new Error("notification unavailable") },
        runOnce: async signal => {
          if (runs++ < runFailures) throw new Error("node/network unavailable")
          connected = true
          await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve(), { once: true }))
          connected = false
        },
        shutdown: async () => { if (cleanups++ < cleanupFailures) throw new Error("cleanup unavailable") },
        trace: vi.fn(), reportRestart: vi.fn(), retryChanged: vi.fn(),
      })
      try {
        await lifecycle.start()
        await vi.advanceTimersByTimeAsync((runFailures + cleanupFailures + notifyFailures + 1) * 1_000)
        expect(connected).toBe(true)
        expect(runs).toBe(runFailures + 1)
        await lifecycle.stop()
        await vi.advanceTimersByTimeAsync(60_000)
        expect(connected).toBe(false)
        expect(runs).toBe(runFailures + 1)
      } finally { await lifecycle.stop(); vi.useRealTimers() }
    })
})
