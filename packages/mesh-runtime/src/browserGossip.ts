import { BrowserGossipDriver, type GossipDelivery, type GossipStateMachine } from "@meta-uber/mesh-replication/gossip"

export type BrowserGossipSession = {
  endpoint: string
  deviceId: string
  publish(): Promise<void>
}

export type BrowserGossipTopology = { changed: boolean; endpoints: string[] }

export type BrowserGossipHost = {
  isStopped(): boolean
  createEngine(): GossipStateMachine | undefined
  endpoints(workspaceId: string): string[]
  setEndpoints(workspaceId: string, endpoints: string[]): BrowserGossipTopology
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
  private readonly neighborCounts = new Map<string, number>()

  constructor(private readonly host: BrowserGossipHost, private readonly topicPrefix = "mesh-workspace-") {}

  topic(workspaceId: string): string { return `${this.topicPrefix}${workspaceId}` }

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
    const topology = this.host.setEndpoints(workspaceId, endpoints)
    if (!this.host.isStopped() && topology.endpoints.length && this.drivers.has(workspaceId) && !topology.changed) return
    this.close(workspaceId)
    const engine = this.host.createEngine()
    if (this.host.isStopped() || !engine || !topology.endpoints.length) return
    const secret = await this.host.transportSecret(workspaceId)
    if (!secret) return
    const topic = this.topic(workspaceId)
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
    this.neighborCounts.set(workspaceId, 0)
    try {
      await driver.joinTopic(topic, topology.endpoints)
      this.host.trace("gossip.started", { workspaceId: short(workspaceId), peers: topology.endpoints.length })
    } catch (error) {
      if (this.drivers.get(workspaceId) === driver) this.drivers.delete(workspaceId)
      driver.close()
      this.host.trace("gossip.start.failed", { workspaceId: short(workspaceId), reason: message(error) }, "warn")
    }
  }

  async receivePacket(workspaceId: string, endpoint: string, packet: Uint8Array): Promise<void> {
    let driver = this.drivers.get(workspaceId)
    if (!driver) {
      await this.refresh(workspaceId)
      driver = this.drivers.get(workspaceId)
    }
    if (!driver || !this.host.session(workspaceId, endpoint)) return
    await driver.handleMessage(endpoint, packet)
    const neighbors = driver.activeNeighbors(this.topic(workspaceId)).length
    const previous = this.neighborCounts.get(workspaceId) ?? 0
    this.neighborCounts.set(workspaceId, neighbors)
    this.host.trace("gossip.packet", { workspaceId: short(workspaceId), neighbors })
    if (neighbors > previous) {
      this.host.trace("gossip.neighbor.up", { workspaceId: short(workspaceId), neighbors })
      queueMicrotask(() => { void this.host.publishAll() })
    } else if (neighbors < previous) this.host.trace("gossip.neighbor.down", { workspaceId: short(workspaceId), neighbors })
  }

  async broadcast(workspaceId: string): Promise<Set<string> | undefined> {
    const driver = this.drivers.get(workspaceId)
    if (!driver) return undefined
    const topic = this.topic(workspaceId)
    await driver.broadcast(topic, new TextEncoder().encode(JSON.stringify({
      version: 1, kind: "workspace-update", workspaceId, nonce: crypto.randomUUID(),
    })))
    const neighbors = new Set(driver.activeNeighbors(topic))
    this.host.trace("gossip.broadcast", { workspaceId: short(workspaceId), neighbors: neighbors.size })
    return neighbors
  }

  close(workspaceId: string): void {
    this.drivers.get(workspaceId)?.close()
    this.drivers.delete(workspaceId)
    this.neighborCounts.delete(workspaceId)
  }

  closeAll(): void {
    for (const workspaceId of this.drivers.keys()) this.close(workspaceId)
  }

  async waitForRefreshes(): Promise<void> { await Promise.allSettled(this.refreshes.values()) }

  private async receive(workspaceId: string, delivery: GossipDelivery): Promise<void> {
    if (delivery.topic !== this.topic(workspaceId)) return
    const session = this.host.session(workspaceId, delivery.deliveredFrom)
    if (!session) {
      this.host.trace("gossip.rejected", { workspaceId: short(workspaceId), endpoint: short(delivery.deliveredFrom) }, "warn")
      return
    }
    let value: { version?: unknown; kind?: unknown; workspaceId?: unknown }
    try { value = JSON.parse(new TextDecoder().decode(delivery.content)) }
    catch { return }
    if (value.version !== 1 || value.kind !== "workspace-update" || value.workspaceId !== workspaceId) return
    this.host.trace("gossip.delivered", { workspaceId: short(workspaceId), peerId: short(session.deviceId) })
    await session.publish()
  }
}

function short(value: string): string { return value.slice(0, 8) }
function message(error: unknown): string { return error instanceof Error ? error.message : String(error) }
