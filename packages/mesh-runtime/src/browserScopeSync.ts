import { meshRustRuntime, type RustMeshScopeFrameEffect, type RustMeshScopeRuntime } from "@meta-uber/mesh-replication/runtime"

/** Scope computation can run behind an asynchronous worker boundary. */
export type MeshScopeExecutor = {
  [K in Exclude<keyof RustMeshScopeRuntime, "free">]:
    (...args: Parameters<RustMeshScopeRuntime[K]>) => ReturnType<RustMeshScopeRuntime[K]> | Promise<ReturnType<RustMeshScopeRuntime[K]>>
} & { free?(): void | Promise<void> }

export type MeshScopeStream = {
  send(bytes: Uint8Array): Promise<void>
  read(): Promise<Uint8Array>
  closeSend(): Promise<void>
}
export type MeshScopeSendFrame = (frame: Uint8Array, kind: "document" | "control") => Promise<boolean>
export type MeshScopeTiming = {
  operation: "receive" | "publish" | "reconcile"
  phase: "queue-wait" | "queue-run" | "out-of-queue-callback"
  operationId: number
  elapsedMs: number
  frameBytes?: number
}

export type MeshScopeHost = {
  readDocument(): Promise<Uint8Array>
  readAuthorization?(document: Uint8Array): Promise<unknown>
  readChat?(known: Set<string>): Promise<unknown>
  readMesh?(): Promise<unknown>
  persistDocument(document: Uint8Array, proof: unknown): Promise<boolean | void>
  onDocumentAccepted?(acceptedChanges: number): void
  mergeDurableBatch?(payload: Uint8Array): Promise<void>
  mergeAuthorization?(authorization: unknown): Promise<void>
  mergeChat?(chat: unknown): Promise<void>
  mergeMesh?(mesh: unknown): Promise<void>
  onGossip?(payload: Uint8Array): Promise<void>
  onOwnerWorkspaceOffer?(payload: Uint8Array): Promise<void>
  onBlobRequest?(stream: MeshScopeStream, frame: Uint8Array): Promise<void>
  onHandoffRequest?(stream: MeshScopeStream, frame: Uint8Array): Promise<void>
  onWorkspaceSnapshot?(payload: Uint8Array): Promise<void>
  onTiming?(timing: MeshScopeTiming): void
  readProofPage?(cacheKey: string): Promise<Uint8Array | undefined>
  writeProofPage?(cacheKey: string, payload: Uint8Array): Promise<void>
}

/** Executes Rust scope effects against browser storage and transport callbacks. */
export class BrowserMeshScopeSync {
  private queue: Promise<unknown> = Promise.resolve()
  private closing = false
  private closed?: Promise<void>
  private knownChat = new Set<string>()
  private timingSequence = 0
  private proofTimer?: ReturnType<typeof setTimeout>
  private proofGeneration = 0
  constructor(private readonly runtime: MeshScopeExecutor, private readonly host: MeshScopeHost) {}

  static create(workspaceId: string, secret: string, host: MeshScopeHost): BrowserMeshScopeSync {
    return new BrowserMeshScopeSync(meshRustRuntime().createMeshScopeRuntime(workspaceId, secret), host)
  }

  startDocumentSync(localDeviceId: string, remoteDeviceId: string): void {
    this.queue = this.queue.then(() => this.runtime.startDocumentSync(localDeviceId, remoteDeviceId))
    void this.queue.catch(() => undefined)
  }

  receive(stream: MeshScopeStream, frame: Uint8Array): Promise<void> {
    if (this.closing) return Promise.resolve()
    const enqueuedAt = now()
    const operationId = ++this.timingSequence
    let queueStartedAt = enqueuedAt
    const prepared = this.queue.then(() => {
      queueStartedAt = now()
      this.reportTiming("receive", "queue-wait", enqueuedAt, operationId, frame.byteLength)
      return this.runtime.receiveFrame(frame)
    }, () => {
      queueStartedAt = now()
      this.reportTiming("receive", "queue-wait", enqueuedAt, operationId, frame.byteLength)
      return this.runtime.receiveFrame(frame)
    })
    // Gossip callback must stay outside document/control serialization. It may
    // publish another stream and waiting here recreates the old sync deadlock.
    const queued = prepared.then(async effect => {
      if (effect?.kind === "gossip") return
      try {
        if (!effect) return await stream.closeSend()
        await this.apply(stream, frame, effect)
      } finally { this.reportTiming("receive", "queue-run", queueStartedAt, operationId, frame.byteLength) }
    })
    this.queue = queued.catch(async error => {
      this.clearProofTimer()
      try { await this.runtime.rejectDocumentReceive() } catch { /* no candidate remains pending */ }
      throw error
    })
    const guarded = this.queue
    return prepared.then(async effect => {
      if (effect?.kind !== "gossip") return guarded as Promise<void>
      const startedAt = now()
      try { await this.apply(stream, frame, effect) }
      finally { this.reportTiming("receive", "out-of-queue-callback", startedAt, operationId, frame.byteLength) }
    })
  }

  async publish(sendFrame: MeshScopeSendFrame): Promise<boolean> {
    if (this.closing) return false
    const enqueuedAt = now()
    const operationId = ++this.timingSequence
    const run = async () => {
      this.reportTiming("publish", "queue-wait", enqueuedAt, operationId)
      const startedAt = now()
      try {
      if (this.closing) return false
      const document = await this.host.readDocument()
      const proof = this.host.readAuthorization ? await this.host.readAuthorization(document) : undefined
      const nextKnownChat = new Set(this.knownChat)
      const chat = this.host.readChat ? await this.host.readChat(nextKnownChat) : undefined
      const mesh = this.host.readMesh ? await this.host.readMesh() : undefined
      if (this.closing) return false
      const plan = await this.runtime.preparePublish(document, proof, proof, chat, mesh)
      let allFramesSent = false
      try {
        if (plan.documentFrame && !await sendFrame(toBytes(plan.documentFrame), "document")) return false
        for (const frame of plan.controlFrames) {
          if (!await sendFrame(toBytes(frame), "control")) return false
        }
        allFramesSent = true
        this.knownChat = nextKnownChat
        return true
      } finally { await this.runtime.finishPublish(toBytes(plan.controlSnapshot), allFramesSent) }
      } finally { this.reportTiming("publish", "queue-run", startedAt, operationId) }
    }
    this.queue = this.queue.then(run, run)
    return this.queue as Promise<boolean>
  }

  async reconcile(sendFrame: MeshScopeSendFrame): Promise<boolean> {
    if (this.closing) return false
    const enqueuedAt = now()
    const operationId = ++this.timingSequence
    const run = async () => {
      this.reportTiming("reconcile", "queue-wait", enqueuedAt, operationId)
      const startedAt = now()
      try {
      if (this.closing) return false
      const document = await this.host.readDocument()
      const proof = this.host.readAuthorization ? await this.host.readAuthorization(document) : undefined
      if (this.closing) return false
      const frame = await this.runtime.publishFrame(document, proof)
      return !frame || await sendFrame(toBytes(frame), "document")
      } finally { this.reportTiming("reconcile", "queue-run", startedAt, operationId) }
    }
    this.queue = this.queue.then(run, run)
    return this.queue as Promise<boolean>
  }

  private async apply(stream: MeshScopeStream, frame: Uint8Array, effect: RustMeshScopeFrameEffect): Promise<void> {
    switch (effect.kind) {
      case "proofSource": {
        const cached = await this.runtime.provideCachedProofPage(toBytes(effect.payload))
        if (cached) { await stream.send(toBytes(cached)); await stream.closeSend(); return }
        const document = await this.host.readDocument()
        const authorization = await this.host.readAuthorization?.(document)
        if (!authorization) throw new Error("Missing authorization proof history")
        await stream.send(toBytes(await this.runtime.provideProofPage(toBytes(effect.payload), document, authorization)))
        await stream.closeSend()
        return
      }
      case "proofRequest": {
        const cached = await this.host.readProofPage?.(effect.cacheKey).catch(() => undefined)
        if (cached) {
          let accepted: RustMeshScopeFrameEffect | undefined
          try { accepted = await this.runtime.acceptProofPage(cached) } catch { /* discard corrupt untrusted cache */ }
          if (accepted) return this.apply(stream, frame, accepted)
        }
        await stream.send(toBytes(effect.frame))
        await stream.closeSend()
        this.clearProofTimer()
        const generation = this.proofGeneration
        this.proofTimer = setTimeout(() => {
          this.queue = this.queue.catch(() => {}).then(async () => {
            if (generation !== this.proofGeneration || this.closing) return
            this.clearProofTimer()
            try { await this.runtime.rejectDocumentReceive() } catch { /* already completed */ }
          })
        }, 20_000)
        return
      }
      case "proofPageReceived": {
        this.clearProofTimer()
        await this.host.writeProofPage?.(effect.cacheKey, toBytes(effect.payload)).catch(() => {})
        return this.apply(stream, frame, await this.runtime.continueProofReceive())
      }
      case "needDocument": {
        let pending = true
        try {
          const document = await this.host.readDocument()
          const proof = this.host.readAuthorization ? await this.host.readAuthorization(document) : undefined
          const prepared = await this.runtime.provideDocument(document, proof)
          if (prepared.kind !== "documentReceive") {
            pending = false
            return await this.apply(stream, frame, prepared)
          }
          let persisted = false
          persisted = !prepared.shouldPersist || (await this.host.persistDocument(toBytes(prepared.document), prepared.proof)) !== false
          // complete(false) consumes pending state while aborting Rust sync.
          pending = false
          const completion = await this.runtime.completeDocumentReceive(persisted)
          if (completion.response) await stream.send(toBytes(completion.response))
          if (completion.closeSend) await stream.closeSend()
          this.host.onDocumentAccepted?.(prepared.acceptedChanges)
        } catch (error) {
          if (pending) {
            try { await this.runtime.rejectDocumentReceive() } catch { /* completion failure already owns error */ }
          }
          throw error
        }
        return
      }
      case "control":
        for (const action of effect.effects) await this.applyControl(action, effect.control)
        if (effect.closeSend) await stream.closeSend()
        return
      case "gossip":
        if (!this.host.onGossip) throw new Error("Unsupported gossip packet")
        await this.host.onGossip(toBytes(effect.payload))
        if (effect.closeSend) await stream.closeSend()
        return
      case "heartbeat":
        await stream.send(toBytes(effect.acknowledgement))
        if (effect.closeSend) await stream.closeSend()
        return
      case "durableBatch":
        if (!this.host.mergeDurableBatch) throw new Error("Unsupported durable batch")
        try {
          await this.host.mergeDurableBatch(toBytes(effect.payload))
          await this.finishSaved(stream, true)
        } catch (error) {
          await this.abortSaved()
          throw error
        }
        return
      case "ownerWorkspaceOffer":
        if (!this.host.onOwnerWorkspaceOffer) throw new Error("Unsupported owner workspace offer")
        try {
          await this.host.onOwnerWorkspaceOffer(toBytes(effect.payload))
          await this.finishSaved(stream, true)
        } catch (error) {
          await this.abortSaved()
          throw error
        }
        return
      case "blobRequest":
        if (!this.host.onBlobRequest) throw new Error("Unsupported blob request")
        await this.host.onBlobRequest(stream, frame)
        return
      case "handoffRequest":
        if (!this.host.onHandoffRequest) throw new Error("Unsupported handoff request")
        await this.host.onHandoffRequest(stream, frame)
        return
      case "workspaceSnapshot":
        if (!this.host.onWorkspaceSnapshot) throw new Error("Unsupported workspace snapshot")
        await this.host.onWorkspaceSnapshot(toBytes(effect.payload))
        if (effect.closeSend) await stream.closeSend()
        return
      case "documentReceive": {
        this.clearProofTimer()
        try {
          const persisted = !effect.shouldPersist || (await this.host.persistDocument(toBytes(effect.document), effect.proof)) !== false
          const completion = await this.runtime.completeDocumentReceive(persisted)
          if (completion.response) await stream.send(toBytes(completion.response))
          if (completion.closeSend) await stream.closeSend()
          this.host.onDocumentAccepted?.(effect.acceptedChanges)
        } catch (error) {
          try { await this.runtime.rejectDocumentReceive() } catch { /* preserve original failure */ }
          throw error
        }
        return
      }
    }
  }

  private clearProofTimer(): void {
    this.proofGeneration++
    if (this.proofTimer) clearTimeout(this.proofTimer)
    this.proofTimer = undefined
  }

  private async applyControl(action: string, control: { authorization?: unknown; chat?: unknown; mesh?: unknown }): Promise<void> {
    if (action === "mergeAuthorization") {
      if (!this.host.mergeAuthorization) throw new Error("Unsupported mesh authorization control")
      await this.host.mergeAuthorization(control.authorization)
      await this.runtime.resetDocument()
    } else if (action === "mergeChat") {
      if (!this.host.mergeChat) throw new Error("Unsupported mesh chat control")
      await this.host.mergeChat(control.chat)
    } else if (action === "mergeMesh") {
      if (!this.host.mergeMesh) throw new Error("Unsupported mesh metadata control")
      await this.host.mergeMesh(control.mesh)
    } else if (action !== "closeSend") {
      throw new Error(`Unsupported Rust scope effect: ${action}`)
    }
  }

  private async finishSaved(stream: MeshScopeStream, persisted: boolean): Promise<void> {
    const completion = await this.runtime.completeSavedReceive(persisted)
    if (completion.response) await stream.send(toBytes(completion.response))
    if (completion.closeSend) await stream.closeSend()
  }

  private async abortSaved(): Promise<void> {
    try { await this.runtime.completeSavedReceive(false) } catch { /* preserve host failure */ }
  }

  private reportTiming(operation: MeshScopeTiming["operation"], phase: MeshScopeTiming["phase"], startedAt: number,
    operationId: number, frameBytes?: number): void {
    try { this.host.onTiming?.({ operation, phase, operationId, elapsedMs: Math.max(0, now() - startedAt),
      ...(frameBytes === undefined ? {} : { frameBytes }) }) }
    catch { /* diagnostic observers must not affect synchronization */ }
  }

  close(): Promise<void> {
    if (!this.closed) {
      this.closing = true
      this.clearProofTimer()
      this.closed = this.queue.then(() => {}, () => {}).then(async () => { await this.runtime.free?.() })
    }
    return this.closed
  }
}

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now()
}

function toBytes(value: Uint8Array | number[]): Uint8Array {
  return value instanceof Uint8Array ? value : Uint8Array.from(value)
}
