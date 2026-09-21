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
  private _stopped = true
  private _externallyPaused = false
  private _disposed = false

  constructor(private readonly host: BrowserMeshLifecycleHost) {}

  get stopped(): boolean { return this._stopped }
  get externallyPaused(): boolean { return this._externallyPaused }
  get disposed(): boolean { return this._disposed }

  async start(): Promise<void> {
    if (!this._stopped || this._externallyPaused || this._disposed) return
    if (!await this.host.canStart()) return
    if (!this._stopped || this._externallyPaused || this._disposed) return
    await this.host.acquireInstance()
    if (!this._stopped || this._externallyPaused || this._disposed) return
    this._stopped = false
    this.host.trace("mesh.start")
    await this.host.notify()
    this.abortController = new AbortController()
    this.task = this.run(this.abortController.signal)
  }

  async stop(releaseInstance = true, release?: () => Promise<void>): Promise<void> {
    if (this._stopped) {
      if (releaseInstance) await release?.()
      return
    }
    this._stopped = true
    this.host.trace("mesh.stop")
    this.clearWait()
    this.abortController?.abort()
    this.abortController = undefined
    this.host.retryChanged()
    await this.host.shutdown()
    await this.task?.catch(() => {})
    this.task = undefined
    await this.host.shutdown()
    if (releaseInstance) await release?.()
  }

  async pause(release?: () => Promise<void>): Promise<void> {
    this._externallyPaused = true
    await this.stop(false, release)
  }

  async resume(start: () => Promise<void>): Promise<void> {
    if (this._disposed) return
    this._externallyPaused = false
    await start()
  }

  async dispose(stop: () => Promise<void>): Promise<void> {
    this._disposed = true
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
