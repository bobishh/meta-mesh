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
  private readonly state: RustMeshLifecycleState

  constructor(private readonly host: BrowserMeshLifecycleHost) {
    this.state = meshRustRuntime().createMeshLifecycleState()
  }

  get stopped(): boolean { return this.state.stopped }
  get externallyPaused(): boolean { return this.state.externallyPaused }
  get disposed(): boolean { return this.state.disposed }

  async start(): Promise<void> {
    if (!this.state.beginStart()) return
    try {
      if (!await this.host.canStart()) { this.state.cancelStart(); return }
      if (!this.state.canContinueStart()) return
      await this.host.acquireInstance()
      if (!this.state.completeStart()) return
    } catch (error) {
      this.state.cancelStart()
      throw error
    }
    this.host.trace("mesh.start")
    await this.host.notify()
    if (this.state.stopped) return
    this.abortController = new AbortController()
    this.task = this.run(this.abortController.signal)
  }

  async stop(releaseInstance = true, release?: () => Promise<void>): Promise<void> {
    if (!this.state.stop()) {
      if (releaseInstance) await release?.()
      return
    }
    this.host.trace("mesh.stop")
    this.clearWait()
    this.abortController?.abort()
    this.abortController = undefined
    this.host.retryChanged()
    try {
      await this.host.shutdown()
      await this.task?.catch(() => {})
      this.task = undefined
      await this.host.shutdown()
      if (releaseInstance) await release?.()
    } finally { this.state.finishStop() }
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
        await this.host.runOnce(signal)
      } catch (error) {
        if (!signal.aborted) this.host.reportRestart(error)
      } finally {
        await this.host.shutdown()
      }
      if (!signal.aborted) await this.wait(1_000, signal)
    }
  }

  private clearWait(): void {
    clearTimeout(this.retryTimer)
    this.retryTimer = undefined
  }
}
