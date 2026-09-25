import { meshRustRuntime, type RustMeshLifecycleState } from "@meta-uber/mesh-replication/runtime"

export type BrowserMeshLifecycleHost = {
  canStart(): Promise<boolean>
  acquireInstance(): Promise<void>
  runOnce(signal: AbortSignal): Promise<void>
  shutdown(): Promise<void>
  trace(event: string, detail?: Record<string, unknown>, level?: "info" | "warn"): void
  reportRestart(error: unknown): void
  notify(): Promise<void>
  retryChanged(): void
}

/**
 * Owns browser runtime process lifetime. Hosts retain transport creation,
 * authenticated handshakes and document synchronization in `runOnce`.
 */
export class BrowserMeshLifecycle {
  private task: Promise<void> | undefined
  private abortController: AbortController | undefined
  private retryTimer: ReturnType<typeof setTimeout> | undefined
  private startGeneration = 0
  private acquisitionTask: Promise<void> | undefined
  private stopTask: Promise<void> | undefined
  private releaseAfterStop: (() => Promise<void>) | undefined
  private releaseRequested = false
  private readonly state: RustMeshLifecycleState

  constructor(private readonly host: BrowserMeshLifecycleHost) {
    this.state = meshRustRuntime().createMeshLifecycleState()
  }

  get stopped(): boolean { return this.state.stopped }
  get externallyPaused(): boolean { return this.state.externallyPaused }
  get disposed(): boolean { return this.state.disposed }

  async start(): Promise<void> {
    if (this.stopTask) await this.stopTask
    if (!this.state.beginStart()) return
    const generation = ++this.startGeneration
    try {
      const allowed = await this.host.canStart()
      if (generation !== this.startGeneration) return
      if (!allowed) { this.state.cancelStart(); return }
      if (!this.state.canContinueStart()) return
      const acquisition = this.host.acquireInstance()
      this.acquisitionTask = acquisition
      try { await acquisition }
      finally { if (this.acquisitionTask === acquisition) this.acquisitionTask = undefined }
      if (generation !== this.startGeneration || !this.state.completeStart()) return
    } catch (error) {
      if (generation !== this.startGeneration) return
      this.state.cancelStart()
      throw error
    }
    this.host.trace("mesh.start")
    if (this.state.stopped) return
    this.abortController = new AbortController()
    this.task = this.run(this.abortController.signal)
  }

  stop(releaseInstance = true, release?: () => Promise<void>): Promise<void> {
    ++this.startGeneration
    if (releaseInstance) {
      this.releaseRequested = true
      this.releaseAfterStop ??= release
    }
    if (this.stopTask) return this.stopTask
    const operation = this.performStop()
    let tracked!: Promise<void>
    tracked = operation.finally(() => {
      if (this.stopTask !== tracked) return
      this.stopTask = undefined
      this.releaseAfterStop = undefined
      this.releaseRequested = false
    })
    this.stopTask = tracked
    return tracked
  }

  private async performStop(): Promise<void> {
    const shouldShutdown = this.state.stop()
    try {
      if (shouldShutdown) {
        this.host.trace("mesh.stop")
        this.clearWait()
        this.abortController?.abort()
        this.abortController = undefined
        this.host.retryChanged()
        await this.shutdownAfterRun()
        await this.task?.catch(() => {})
        this.task = undefined
        await this.shutdownAfterRun()
      } else {
        await this.acquisitionTask?.catch(() => {})
      }
      if (this.releaseRequested) {
        this.releaseRequested = false
        await this.releaseAfterStop?.()
      }
    } finally { if (shouldShutdown) this.state.finishStop() }
  }

  async pause(release?: () => Promise<void>): Promise<void> {
    this.state.pause()
    await this.stop(false, release)
  }

  async resume(start: () => Promise<void>): Promise<void> {
    if (!this.state.resume()) return
    await start()
  }

  async dispose(stop: () => Promise<void>): Promise<void> {
    this.state.dispose()
    await stop()
  }

  async wait(ms: number, signal: AbortSignal): Promise<void> {
    if (signal.aborted) return
    await new Promise<void>(resolve => {
      const finish = () => {
        this.clearWait()
        signal.removeEventListener("abort", finish)
        resolve()
      }
      this.clearWait()
      this.retryTimer = setTimeout(finish, ms)
      signal.addEventListener("abort", finish, { once: true })
    })
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      try {
        await this.host.notify()
        if (!signal.aborted) await this.host.runOnce(signal)
      } catch (error) {
        if (!signal.aborted) this.host.reportRestart(error)
      } finally {
        await this.shutdownAfterRun(signal)
      }
      if (!signal.aborted) await this.wait(1_000, signal)
    }
  }

  private async shutdownAfterRun(signal?: AbortSignal): Promise<void> {
    // A failed cleanup must neither kill the supervisor nor start a second
    // node over resources which the host has not finished releasing.
    while (true) {
      try { await this.host.shutdown(); return }
      catch (error) { this.host.reportRestart(error) }
      if (!signal || signal.aborted) return
      await this.wait(1_000, signal)
    }
  }

  private clearWait(): void {
    clearTimeout(this.retryTimer)
    this.retryTimer = undefined
  }
}
