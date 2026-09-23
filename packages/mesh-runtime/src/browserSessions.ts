import { startMeshHeartbeat, type MeshConnection } from "@meta-uber/mesh-transport"
import type { MeshHandshakeFeatures } from "./handshake"
import { meshRustRuntime, type RustMeshSessionLifecycleState } from "@meta-uber/mesh-replication/runtime"

export type BrowserMeshSession = {
  publish(): Promise<void>
  close(): Promise<void>
  done: Promise<unknown>
  heartbeat?: () => Promise<void>
}

export type BrowserMeshSessionEntry<C extends MeshConnection, S extends BrowserMeshSession> = {
  connectionId: string
  workspaceId: string
  deviceId: string
  instanceId: string
  endpoint: string
  remoteIssuedAt: string
  remoteRouteSequence?: number
  direction: "incoming" | "outgoing"
  connection: C
  session: S
  ownershipReceiptSupported?: boolean
  remotePersonId: string
  ownerWorkspaceOfferFrame?: MeshHandshakeFeatures["ownerWorkspaceOfferFrame"]
  blobTransferSupported?: boolean
  runtimeGeneration?: number
  evict(cause: string): Promise<void>
}

type SessionRuntime = {
  admitSession(candidate: {
    key: { workspaceId: string; deviceId: string; instanceId: string }
    connectionId: string
    remoteIssuedAt: string
    remoteRouteSequence?: number
    direction: "incoming" | "outgoing"
  }, preferred: "incoming" | "outgoing"): { decision: "accepted" | "rejected"; generation?: number }
  removeSession(key: { workspaceId: string; deviceId: string; instanceId: string }, generation: number): string | null
}

type SessionLifecycleKey = { workspaceId: string; deviceId: string; instanceId: string }

export type BrowserMeshSessionHost<C extends MeshConnection, S extends BrowserMeshSession, P> = {
  profile(): Promise<P>
  deviceId(profile: P): string
  credential(workspaceId: string): Promise<unknown | undefined>
  create(input: {
    connection: C
    credential: unknown
    workspaceId: string
    deviceId: string
    instanceId: string
    profile: P
    connectionId: string
    remotePersonId: string
    ownerWorkspaceSupported: boolean
    ownerWorkspaceOfferFrame?: MeshHandshakeFeatures["ownerWorkspaceOfferFrame"]
    blobTransferSupported: boolean
    remoteEndpoint: string
  }): { session: S; reset?(): void }
  runtime(): SessionRuntime
  key(workspaceId: string, deviceId: string, instanceId: string): string
  stopped(): boolean
  trace(event: string, detail?: Record<string, unknown>, level?: "info" | "warn"): void
  diagnosticCleared(): void
  currentRemoved(entry: BrowserMeshSessionEntry<C, S>): Promise<void>
  notify(): Promise<void>
  publishRecovered(key: string, entry: BrowserMeshSessionEntry<C, S>): Promise<void>
  /** A completed handshake alone is not proof that the stream survived. */
  stableSession?(key: string, entry: BrowserMeshSessionEntry<C, S>): void
  protocolFailure(stage: string, error: unknown): void
  networkFailure(peerKey: string, error: unknown): void
}

/** Shared session lifecycle; product hosts provide authenticated document sync. */
export class BrowserMeshSessions<C extends MeshConnection, S extends BrowserMeshSession, P> {
  readonly entries: Map<string, BrowserMeshSessionEntry<C, S>>
  private readonly lifecycle: RustMeshSessionLifecycleState

  constructor(private readonly host: BrowserMeshSessionHost<C, S, P>, entries?: Map<string, BrowserMeshSessionEntry<C, S>>,
    lifecycle?: RustMeshSessionLifecycleState) {
    this.entries = entries ?? new Map<string, BrowserMeshSessionEntry<C, S>>()
    this.lifecycle = lifecycle ?? meshRustRuntime().createMeshSessionLifecycleState()
  }

  async install(input: {
    workspaceId: string
    deviceId: string
    instanceId: string
    remoteIssuedAt: string
    remoteRouteSequence?: number
    direction: "incoming" | "outgoing"
    connection: C
    heartbeatSupported?: boolean
    connectionId: string
    ownershipReceiptSupported?: boolean
    remotePersonId?: string
    ownerWorkspaceSupported?: boolean
    ownerWorkspaceOfferFrame?: MeshHandshakeFeatures["ownerWorkspaceOfferFrame"]
    blobTransferSupported?: boolean
    remoteEndpoint?: string
  }): Promise<boolean> {
    const key = this.host.key(input.workspaceId, input.deviceId, input.instanceId)
    const profile = await this.host.profile()
    const credential = await this.host.credential(input.workspaceId)
    if (!credential) { await input.connection.close(); return false }
    const preferred = meshRustRuntime().state.preferredSessionDirection(this.host.deviceId(profile), input.deviceId)
    const previous = this.entries.get(key)
    const admission = this.host.runtime().admitSession({
      key: { workspaceId: input.workspaceId, deviceId: input.deviceId, instanceId: input.instanceId },
      connectionId: input.connectionId, remoteIssuedAt: input.remoteIssuedAt,
      remoteRouteSequence: input.remoteRouteSequence, direction: input.direction,
    }, preferred)
    if (admission.decision !== "accepted") {
      this.host.trace("session.rejected", { connectionId: input.connectionId, peerId: short(input.deviceId), direction: input.direction, reason: "duplicate direction" })
      await input.connection.close()
      return false
    }
    if (admission.generation === undefined) {
      await input.connection.close()
      return false
    }
    const generation = admission.generation
    const sessionKey: SessionLifecycleKey = {
      workspaceId: input.workspaceId, deviceId: input.deviceId, instanceId: input.instanceId,
    }
    let lifecycleInstall: ReturnType<RustMeshSessionLifecycleState["register"]>
    try {
      lifecycleInstall = this.lifecycle.register(sessionKey, input.connectionId, generation, Date.now())
    } catch (error) {
      this.host.runtime().removeSession(sessionKey, generation)
      await input.connection.close()
      throw error
    }
    let created: ReturnType<BrowserMeshSessionHost<C, S, P>["create"]>
    try {
      created = this.host.create({
        connection: input.connection, credential, workspaceId: input.workspaceId, deviceId: input.deviceId, instanceId: input.instanceId,
        profile, connectionId: input.connectionId,
        remotePersonId: input.remotePersonId ?? "", ownerWorkspaceSupported: input.ownerWorkspaceSupported ?? false,
        ownerWorkspaceOfferFrame: input.ownerWorkspaceOfferFrame,
        blobTransferSupported: input.blobTransferSupported ?? false,
        remoteEndpoint: input.remoteEndpoint ?? "",
      })
    } catch (error) {
      const decision = this.lifecycle.evict(sessionKey, generation)
      if (decision.wasCurrent) this.host.runtime().removeSession(sessionKey, generation)
      if (previous && lifecycleInstall.replacedConnectionId === previous.connectionId) await previous.evict("replaced")
      await input.connection.close()
      throw error
    }
    let stopHeartbeat: (() => void) | undefined
    let stableTimer: ReturnType<typeof setTimeout> | undefined
    const entry: BrowserMeshSessionEntry<C, S> = {
      connectionId: input.connectionId, workspaceId: input.workspaceId, deviceId: input.deviceId,
      instanceId: input.instanceId, endpoint: input.remoteEndpoint ?? "",
      remoteIssuedAt: input.remoteIssuedAt, remoteRouteSequence: input.remoteRouteSequence, direction: input.direction,
      connection: input.connection, session: created.session, ownershipReceiptSupported: input.ownershipReceiptSupported,
      remotePersonId: input.remotePersonId ?? "", ownerWorkspaceOfferFrame: input.ownerWorkspaceOfferFrame,
      blobTransferSupported: input.blobTransferSupported,
      runtimeGeneration: generation,
      evict: async cause => {
        const decision = this.lifecycle.evict(sessionKey, generation)
        if (!decision.shouldClose) return
        stopHeartbeat?.()
        if (stableTimer) clearTimeout(stableTimer)
        const removed = decision.wasCurrent
          ? this.host.runtime().removeSession(sessionKey, generation)
          : null
        const wasCurrent = decision.wasCurrent && removed === input.connectionId && this.entries.get(key) === entry
        if (wasCurrent) {
          this.entries.delete(key)
          created.reset?.()
          await this.host.currentRemoved(entry)
        }
        this.host.trace("session.closed", { connectionId: input.connectionId, peerId: short(input.deviceId),
          workspaceId: short(input.workspaceId), instanceId: short(input.instanceId), wasCurrent, cause })
        await Promise.allSettled([created.session.close(), input.connection.close()])
      },
    }
    this.entries.set(key, entry)
    this.host.trace("session.started", {
      connectionId: input.connectionId, peerId: short(input.deviceId), instanceId: short(input.instanceId),
      workspaceId: short(input.workspaceId), direction: input.direction, heartbeat: Boolean(input.heartbeatSupported),
      incremental: true, replaced: Boolean(lifecycleInstall.replacedConnectionId),
      blobTransfer: Boolean(input.blobTransferSupported),
    })
    this.host.diagnosticCleared()
    if (previous && lifecycleInstall.replacedConnectionId === previous.connectionId) void previous.evict("replaced")
    queueMicrotask(() => {
      const plan = this.lifecycle.callbackPlan(sessionKey, generation, "recovery", Date.now())
      if (plan.publishRecovery) {
        this.host.trace("session.recovery.started", { connectionId: input.connectionId, peerId: short(input.deviceId) })
        void this.host.publishRecovered(key, entry)
      }
    })
    stableTimer = setTimeout(() => {
      const plan = this.lifecycle.callbackPlan(sessionKey, generation, "stable", Date.now())
      if (plan.stable && this.entries.get(key) === entry) {
        this.host.stableSession?.(key, entry)
      }
    }, lifecycleInstall.stableAfterMs)
    if (input.heartbeatSupported) {
      stopHeartbeat = startMeshHeartbeat(created.session, error => {
        const plan = this.lifecycle.callbackPlan(sessionKey, generation, "heartbeatFailed", Date.now())
        if (!plan.reportFailure) return
        this.host.networkFailure(key, error)
        this.host.trace("session.heartbeat.failed", { connectionId: input.connectionId, peerId: short(input.deviceId), reason: message(error) }, "warn")
        this.host.protocolFailure(`Heartbeat ${short(input.deviceId, 6)}`, error)
        if (plan.evict) void entry.evict("heartbeat failed")
      })
    }
    void created.session.done.then(
      () => this.finishReceive(sessionKey, generation, entry, "receiveSucceeded"),
      error => this.finishReceive(sessionKey, generation, entry, "receiveFailed", error),
    )
    await this.host.notify()
    return true
  }

  async publishAll(broadcast: (workspaceId: string) => Promise<void>, onFailure: (key: string, entry: BrowserMeshSessionEntry<C, S>, error: unknown) => Promise<void>): Promise<void> {
    const entries = new Map([...this.entries].map(([key, entry]) => [entry.connectionId, [key, entry] as const]))
    await Promise.allSettled(this.lifecycle.publishPlan().map(async workspace => {
      await Promise.all(workspace.connectionIds.map(async connectionId => {
        const item = entries.get(connectionId)
        if (!item) return
        const [key, entry] = item
        try { await entry.session.publish() }
        catch (error) { await onFailure(key, entry, error) }
      }))
      await broadcast(workspace.workspaceId)
    }))
  }

  async closeAll(cause = "runtime stopped"): Promise<void> {
    await Promise.allSettled([...this.entries.values()].map(entry => entry.evict(cause)))
    this.lifecycle.clear()
  }

  private finishReceive(sessionKey: SessionLifecycleKey, generation: number,
    entry: BrowserMeshSessionEntry<C, S>, event: "receiveSucceeded" | "receiveFailed", error?: unknown): void {
    const plan = this.lifecycle.callbackPlan(sessionKey, generation, event, Date.now())
    if (plan.reportFailure && error !== undefined) {
      this.host.networkFailure(this.host.key(entry.workspaceId, entry.deviceId, entry.instanceId), error)
      this.host.trace("session.receive.failed", { connectionId: entry.connectionId, peerId: short(entry.deviceId),
        workspaceId: short(entry.workspaceId), instanceId: short(entry.instanceId), reason: message(error) }, "warn")
      this.host.protocolFailure(`Receive ${short(entry.deviceId, 6)}`, error)
    }
    if (plan.evict) void entry.evict("receive loop ended")
  }
}

function short(value: string, length = 8): string { return value.slice(0, length) }
function message(error: unknown): string { return error instanceof Error ? error.message : String(error) }
