import { BrowserGossipDriver, type GossipDelivery, type GossipStateMachine } from "@meta-uber/mesh-replication/gossip"
import { meshRustRuntime, type RustGossipLifecycleState } from "@meta-uber/mesh-replication/runtime"

export type BrowserGossipSession = {
  endpoint: string
  deviceId: string
  publish(): Promise<void>
}

export type BrowserGossipHost = {
  isStopped(): boolean
  createEngine(): GossipStateMachine | undefined
  endpoints(workspaceId: string): string[]
  encodeWorkspaceUpdate(workspaceId: string, nonce: string): Uint8Array
  isWorkspaceUpdate(payload: Uint8Array, workspaceId: string): boolean
  transportSecret(workspaceId: string): Promise<string | undefined>
  session(workspaceId: string, endpoint: string): BrowserGossipSession | undefined
  send(workspaceId: string, endpoint: string, secret: string, packet: Uint8Array): Promise<void>
  publishAll(): Promise<void>
  trace(event: string, detail?: Record<string, unknown>, level?: "info" | "warn"): void
}

/**
 * The browser-specific Iroh gossip driver belongs to the shared runtime. Hosts
 * supply authenticated streams and document publication; this class owns topic
 * replacement, packet serialization boundaries and neighbour transitions.
 */
export class BrowserMeshGossip {
  private readonly drivers = new Map<string, BrowserGossipDriver>()
  private readonly refreshes = new Map<string, Promise<void>>()
  private readonly lifecycle: RustGossipLifecycleState

  constructor(private readonly host: BrowserGossipHost, topicPrefix?: string) {
    this.lifecycle = meshRustRuntime().createGossipLifecycleState(topicPrefix)
  }

  topic(workspaceId: string): string { return this.lifecycle.topic(workspaceId) }

  refresh(workspaceId: string): Promise<void> {
    const previous = this.refreshes.get(workspaceId) ?? Promise.resolve()
    const current = previous.catch(() => undefined).then(() => this.rebuild(workspaceId))
    this.refreshes.set(workspaceId, current)
    void current.finally(() => {
      if (this.refreshes.get(workspaceId) === current) this.refreshes.delete(workspaceId)
    })
    return current
  }

  async rebuild(workspaceId: string): Promise<void> {
    const endpoints = this.host.endpoints(workspaceId)
    const intent = this.lifecycle.planRebuild({ workspaceId, endpoints, stopped: this.host.isStopped(), engineAvailable: true, transportSecretAvailable: true })
    if (intent.closePrevious) this.closeDriver(workspaceId)
    if (intent.action !== "start") return
    const secret = await this.host.transportSecret(workspaceId)
    const secretPlan = this.lifecycle.planRebuild({ workspaceId, endpoints, stopped: this.host.isStopped(), engineAvailable: true, transportSecretAvailable: Boolean(secret) })
    if (secretPlan.closePrevious) this.closeDriver(workspaceId)
    if (secretPlan.action !== "start" || !secret) return
    const engine = this.host.createEngine()
    const plan = this.lifecycle.planRebuild({ workspaceId, endpoints, stopped: this.host.isStopped(), engineAvailable: Boolean(engine), transportSecretAvailable: true })
    if (plan.closePrevious) this.closeDriver(workspaceId)
    if (plan.action !== "start" || !engine || !secret) return
    const driver = new BrowserGossipDriver(engine, {
      send: async (endpoint, packet) => {
        if (!this.host.session(workspaceId, endpoint)) throw new Error("Gossip peer session is unavailable")
        try {
          await this.host.send(workspaceId, endpoint, secret, packet)
          this.host.trace("gossip.sent", { workspaceId: short(workspaceId), endpoint: short(endpoint) })
        } catch (error) {
          this.host.trace("gossip.send.failed", { workspaceId: short(workspaceId), endpoint: short(endpoint), reason: message(error) }, "warn")
          throw error
        }
      },
      deliver: delivery => this.receive(workspaceId, delivery),
    })
    this.drivers.set(workspaceId, driver)
    try {
      await driver.joinTopic(plan.topic, plan.endpoints)
      this.lifecycle.started(workspaceId)
      this.host.trace("gossip.started", { workspaceId: short(workspaceId), peers: plan.endpoints.length })
    } catch (error) {
      if (this.drivers.get(workspaceId) === driver) this.drivers.delete(workspaceId)
      driver.close()
      this.lifecycle.startFailed(workspaceId)
      this.host.trace("gossip.start.failed", { workspaceId: short(workspaceId), reason: message(error) }, "warn")
    }
  }

  async receivePacket(workspaceId: string, endpoint: string, packet: Uint8Array): Promise<void> {
    let driver = this.drivers.get(workspaceId)
    let action = this.lifecycle.receiveAction(workspaceId, Boolean(driver), Boolean(this.host.session(workspaceId, endpoint)))
    if (action === "refresh") {
      await this.refresh(workspaceId)
      driver = this.drivers.get(workspaceId)
      action = this.lifecycle.receiveAction(workspaceId, Boolean(driver), Boolean(this.host.session(workspaceId, endpoint)))
    }
    if (action !== "handle" || !driver) return
    await driver.handleMessage(endpoint, packet)
    const neighbors = driver.activeNeighbors(this.topic(workspaceId)).length
    const neighbor = this.lifecycle.observeNeighbors(workspaceId, neighbors)
    this.host.trace("gossip.packet", { workspaceId: short(workspaceId), neighbors })
    if (neighbor.change === "up") {
      this.host.trace("gossip.neighbor.up", { workspaceId: short(workspaceId), neighbors })
      if (neighbor.publishAll) queueMicrotask(() => { void this.host.publishAll() })
    } else if (neighbor.change === "down") this.host.trace("gossip.neighbor.down", { workspaceId: short(workspaceId), neighbors })
  }

  async broadcast(workspaceId: string): Promise<Set<string> | undefined> {
    const driver = this.drivers.get(workspaceId)
    const plan = this.lifecycle.broadcastPlan(workspaceId, Boolean(driver))
    if (!plan.broadcast || !driver) return undefined
    await driver.broadcast(plan.topic, this.host.encodeWorkspaceUpdate(workspaceId, crypto.randomUUID()))
    const neighbors = new Set(driver.activeNeighbors(plan.topic))
    this.host.trace("gossip.broadcast", { workspaceId: short(workspaceId), neighbors: neighbors.size })
    return neighbors
  }

  close(workspaceId: string): void {
    this.closeDriver(workspaceId)
    this.lifecycle.close(workspaceId)
  }

  closeAll(): void {
    for (const workspaceId of [...this.drivers.keys()]) this.close(workspaceId)
    this.lifecycle.closeAll()
  }

  async waitForRefreshes(): Promise<void> { await Promise.allSettled(this.refreshes.values()) }

  private async receive(workspaceId: string, delivery: GossipDelivery): Promise<void> {
    const session = this.host.session(workspaceId, delivery.deliveredFrom)
    const action = this.lifecycle.deliveryAction(workspaceId, delivery.topic, Boolean(session), this.host.isWorkspaceUpdate(delivery.content, workspaceId))
    if (action === "ignoreTopic" || action === "ignorePayload") return
    if (action === "rejectSession") {
      this.host.trace("gossip.rejected", { workspaceId: short(workspaceId), endpoint: short(delivery.deliveredFrom) }, "warn")
      return
    }
    if (action !== "publish" || !session) return
    this.host.trace("gossip.delivered", { workspaceId: short(workspaceId), peerId: short(session.deviceId) })
    await session.publish()
  }

  private closeDriver(workspaceId: string): void {
    this.drivers.get(workspaceId)?.close()
    this.drivers.delete(workspaceId)
  }
}

function short(value: string): string { return value.slice(0, 8) }
function message(error: unknown): string { return error instanceof Error ? error.message : String(error) }
