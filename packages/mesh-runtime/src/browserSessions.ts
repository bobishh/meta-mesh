import { startMeshHeartbeat, type MeshConnection } from "@meta-uber/mesh-transport"
import type { MeshHandshakeFeatures } from "./handshake"
import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

export type BrowserMeshSession = {
  publish(): Promise<void>
  close(): Promise<void>
  done: Promise<unknown>
  heartbeat?: () => Promise<void>
}

export type BrowserMeshSessionEntry<C extends MeshConnection, S extends BrowserMeshSession> = {
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

  constructor(private readonly host: BrowserMeshSessionHost<C, S, P>, entries?: Map<string, BrowserMeshSessionEntry<C, S>>) {
    this.entries = entries ?? new Map<string, BrowserMeshSessionEntry<C, S>>()
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
    const created = this.host.create({
      connection: input.connection, credential, workspaceId: input.workspaceId, deviceId: input.deviceId, instanceId: input.instanceId,
      profile, connectionId: input.connectionId,
      remotePersonId: input.remotePersonId ?? "", ownerWorkspaceSupported: input.ownerWorkspaceSupported ?? false,
      ownerWorkspaceOfferFrame: input.ownerWorkspaceOfferFrame,
      blobTransferSupported: input.blobTransferSupported ?? false,
      remoteEndpoint: input.remoteEndpoint ?? "",
    })
    let evicted = false
    let stopHeartbeat: (() => void) | undefined
    let stableTimer: ReturnType<typeof setTimeout> | undefined
    const entry: BrowserMeshSessionEntry<C, S> = {
      workspaceId: input.workspaceId, deviceId: input.deviceId, instanceId: input.instanceId, endpoint: input.remoteEndpoint ?? "",
      remoteIssuedAt: input.remoteIssuedAt, remoteRouteSequence: input.remoteRouteSequence, direction: input.direction,
      connection: input.connection, session: created.session, ownershipReceiptSupported: input.ownershipReceiptSupported,
      remotePersonId: input.remotePersonId ?? "", ownerWorkspaceOfferFrame: input.ownerWorkspaceOfferFrame,
      blobTransferSupported: input.blobTransferSupported,
      runtimeGeneration: admission.generation,
      evict: async cause => {
        if (evicted) return
        evicted = true
        stopHeartbeat?.()
        if (stableTimer) clearTimeout(stableTimer)
        const removed = entry.runtimeGeneration === undefined ? input.connectionId : this.host.runtime().removeSession(
          { workspaceId: input.workspaceId, deviceId: input.deviceId, instanceId: input.instanceId }, entry.runtimeGeneration,
        )
        const wasCurrent = removed === input.connectionId && this.entries.get(key) === entry
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
      incremental: true, replaced: Boolean(previous),
      blobTransfer: Boolean(input.blobTransferSupported),
    })
    this.host.diagnosticCleared()
    void previous?.evict("replaced")
    queueMicrotask(() => { void this.host.publishRecovered(key, entry) })
    stableTimer = setTimeout(() => {
      if (!evicted && this.entries.get(key) === entry) this.host.stableSession?.(key, entry)
    }, 10_000)
    if (input.heartbeatSupported) {
      stopHeartbeat = startMeshHeartbeat(created.session, error => {
        if (evicted) return
        this.host.networkFailure(key, error)
        this.host.trace("session.heartbeat.failed", { connectionId: input.connectionId, peerId: short(input.deviceId), reason: message(error) }, "warn")
        this.host.protocolFailure(`Heartbeat ${short(input.deviceId, 6)}`, error)
        void entry.evict("heartbeat failed")
      })
    }
    void created.session.done.catch(error => {
      if (evicted) return
      this.host.networkFailure(key, error)
      this.host.trace("session.receive.failed", { connectionId: input.connectionId, peerId: short(input.deviceId),
        workspaceId: short(input.workspaceId), instanceId: short(input.instanceId), reason: message(error) }, "warn")
      this.host.protocolFailure(`Receive ${short(input.deviceId, 6)}`, error)
    }).finally(() => entry.evict("receive loop ended"))
    await this.host.notify()
    return true
  }

  async publishAll(broadcast: (workspaceId: string) => Promise<void>, onFailure: (key: string, entry: BrowserMeshSessionEntry<C, S>, error: unknown) => Promise<void>): Promise<void> {
    const byWorkspace = new Map<string, Array<[string, BrowserMeshSessionEntry<C, S>]>>()
    for (const item of this.entries) {
      const entries = byWorkspace.get(item[1].workspaceId) ?? []
      entries.push(item)
      byWorkspace.set(item[1].workspaceId, entries)
    }
    await Promise.allSettled([...byWorkspace].map(async ([workspaceId, entries]) => {
      await broadcast(workspaceId)
      await Promise.all(entries.map(async ([key, entry]) => {
        try { await entry.session.publish() }
        catch (error) { await onFailure(key, entry, error) }
      }))
    }))
  }
}

function short(value: string, length = 8): string { return value.slice(0, length) }
function message(error: unknown): string { return error instanceof Error ? error.message : String(error) }
