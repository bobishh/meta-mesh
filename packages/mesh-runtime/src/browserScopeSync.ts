import { meshRustRuntime, type RustMeshScopeFrameEffect, type RustMeshScopeRuntime } from "@meta-uber/mesh-replication/runtime"

export type MeshScopeStream = {
  send(bytes: Uint8Array): Promise<void>
  read(): Promise<Uint8Array>
  closeSend(): Promise<void>
}
export type MeshScopeSendFrame = (frame: Uint8Array, kind: "document" | "control") => Promise<boolean>

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
}

/** Executes Rust scope effects against browser storage and transport callbacks. */
export class BrowserMeshScopeSync {
  private queue: Promise<unknown> = Promise.resolve()
  private closing = false
  private closed?: Promise<void>
  private knownChat = new Set<string>()
  constructor(private readonly runtime: RustMeshScopeRuntime, private readonly host: MeshScopeHost) {}

  static create(workspaceId: string, secret: string, host: MeshScopeHost): BrowserMeshScopeSync {
    return new BrowserMeshScopeSync(meshRustRuntime().createMeshScopeRuntime(workspaceId, secret), host)
  }

  startDocumentSync(localDeviceId: string, remoteDeviceId: string): void {
    this.runtime.startDocumentSync(localDeviceId, remoteDeviceId)
  }

  receive(stream: MeshScopeStream, frame: Uint8Array): Promise<void> {
    if (this.closing) return Promise.resolve()
    const prepared = this.queue.then(() => this.runtime.receiveFrame(frame), () => this.runtime.receiveFrame(frame))
    // Gossip callback must stay outside document/control serialization. It may
    // publish another stream and waiting here recreates the old sync deadlock.
    const queued = prepared.then(effect => {
      if (effect?.kind === "gossip") return
      if (!effect) return stream.closeSend()
      return this.apply(stream, frame, effect)
    })
    this.queue = queued
    return prepared.then(effect => effect?.kind === "gossip" ? this.apply(stream, frame, effect) : queued)
  }

  async publish(sendFrame: MeshScopeSendFrame): Promise<boolean> {
    if (this.closing) return false
    const run = async () => {
      if (this.closing) return false
      const document = await this.host.readDocument()
      const proof = this.host.readAuthorization ? await this.host.readAuthorization(document) : undefined
      const nextKnownChat = new Set(this.knownChat)
      const chat = this.host.readChat ? await this.host.readChat(nextKnownChat) : undefined
      const mesh = this.host.readMesh ? await this.host.readMesh() : undefined
      if (this.closing) return false
      const plan = this.runtime.preparePublish(document, proof, proof, chat, mesh)
      let allFramesSent = false
      try {
        if (plan.documentFrame && !await sendFrame(toBytes(plan.documentFrame), "document")) return false
        for (const frame of plan.controlFrames) {
          if (!await sendFrame(toBytes(frame), "control")) return false
        }
        allFramesSent = true
        this.knownChat = nextKnownChat
        return true
      } finally { this.runtime.finishPublish(toBytes(plan.controlSnapshot), allFramesSent) }
    }
    this.queue = this.queue.then(run, run)
    return this.queue as Promise<boolean>
  }

  private async apply(stream: MeshScopeStream, frame: Uint8Array, effect: RustMeshScopeFrameEffect): Promise<void> {
    switch (effect.kind) {
      case "needDocument": {
        let pending = true
        try {
          const document = await this.host.readDocument()
          const proof = this.host.readAuthorization ? await this.host.readAuthorization(document) : undefined
          const prepared = this.runtime.provideDocument(document, proof)
          if (prepared.kind !== "documentReceive") throw new Error("Rust scope returned invalid document effect")
          let persisted = false
          persisted = !prepared.shouldPersist || (await this.host.persistDocument(toBytes(prepared.document), prepared.proof)) !== false
          // complete(false) consumes pending state while aborting Rust sync.
          pending = false
          const completion = this.runtime.completeDocumentReceive(persisted)
          if (completion.response) await stream.send(toBytes(completion.response))
          if (completion.closeSend) await stream.closeSend()
          this.host.onDocumentAccepted?.(prepared.acceptedChanges)
        } catch (error) {
          if (pending) {
            try { this.runtime.rejectDocumentReceive() } catch { /* completion failure already owns error */ }
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
          this.abortSaved()
          throw error
        }
        return
      case "ownerWorkspaceOffer":
        if (!this.host.onOwnerWorkspaceOffer) throw new Error("Unsupported owner workspace offer")
        try {
          await this.host.onOwnerWorkspaceOffer(toBytes(effect.payload))
          await this.finishSaved(stream, true)
        } catch (error) {
          this.abortSaved()
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
      case "documentReceive":
        throw new Error("Document receive requires Rust scope document plan")
    }
  }

  private async applyControl(action: string, control: { authorization?: unknown; chat?: unknown; mesh?: unknown }): Promise<void> {
    if (action === "mergeAuthorization") {
      if (!this.host.mergeAuthorization) throw new Error("Unsupported mesh authorization control")
      await this.host.mergeAuthorization(control.authorization)
      this.runtime.resetDocument()
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
    const completion = this.runtime.completeSavedReceive(persisted)
    if (completion.response) await stream.send(toBytes(completion.response))
    if (completion.closeSend) await stream.closeSend()
  }

  private abortSaved(): void {
    try { this.runtime.completeSavedReceive(false) } catch { /* preserve host failure */ }
  }

  close(): Promise<void> {
    if (!this.closed) {
      this.closing = true
      this.closed = this.queue.then(() => {}, () => {}).then(() => { this.runtime.free?.() })
    }
    return this.closed
  }
}

function toBytes(value: Uint8Array | number[]): Uint8Array {
  return value instanceof Uint8Array ? value : Uint8Array.from(value)
}
