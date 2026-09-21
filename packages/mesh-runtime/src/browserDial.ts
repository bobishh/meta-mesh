import { selectScopedNeighbors } from "@meta-uber/mesh-replication/gossip"

export type BrowserDialPeer = {
  workspaceId: string
  deviceId: string
  instanceId?: string
  revokedAt?: string | null
}

export type BrowserMeshDialHost<P extends BrowserDialPeer> = {
  peers(): Promise<P[]>
  hasSession(workspaceId: string, deviceId: string): boolean
  deviceKey(workspaceId: string, deviceId: string): string
  peerKey(workspaceId: string, deviceId: string, instanceId?: string): string
  routeFailures(key: string): number
  retryAt(key: string, fallback: number): number
  routeAttemptActive(key: string): boolean
  dial(routes: P[], signal: AbortSignal): Promise<void>
  onRetries(retries: Record<string, number>): void
}

/**
 * Selects peer routes and owns single-flight retry scheduling. Route transport,
 * authority verification and document installation remain host operations.
 */
export class BrowserMeshDialScheduler<P extends BrowserDialPeer> {
  constructor(private readonly host: BrowserMeshDialHost<P>) {}

  async schedule(localDeviceId: string, signal: AbortSignal, now = Date.now()): Promise<void> {
    const peers = await this.select(localDeviceId, now)
    const grouped = this.group(peers)
    const retries: Record<string, number> = {}
    for (const [key, routes] of grouped) this.scheduleDevice(key, routes, signal, retries, now)
    this.host.onRetries(retries)
  }

  private async select(localDeviceId: string, now: number): Promise<P[]> {
    const candidates = (await this.host.peers()).filter(peer => !peer.revokedAt && peer.deviceId !== localDeviceId)
    const selected = new Set<string>()
    for (const workspaceId of new Set(candidates.map(peer => peer.workspaceId))) {
      const deviceIds = selectScopedNeighbors({ localDeviceId, now, candidates: candidates
        .filter(peer => peer.workspaceId === workspaceId)
        .map(peer => ({ deviceId: peer.deviceId, health: -this.host.routeFailures(this.host.peerKey(peer.workspaceId, peer.deviceId, peer.instanceId)) })) })
      for (const deviceId of deviceIds) selected.add(`${workspaceId}:${deviceId}`)
    }
    return candidates.filter(peer => selected.has(`${peer.workspaceId}:${peer.deviceId}`))
  }

  private group(peers: P[]): Map<string, P[]> {
    const result = new Map<string, P[]>()
    for (const peer of peers) {
      const key = this.host.deviceKey(peer.workspaceId, peer.deviceId)
      const routes = result.get(key) ?? []
      routes.push(peer)
      result.set(key, routes)
    }
    return result
  }

  private scheduleDevice(key: string, routes: P[], signal: AbortSignal, retries: Record<string, number>, now: number): void {
    const first = routes[0]!
    if (signal.aborted || this.host.hasSession(first.workspaceId, first.deviceId)) return
    if (this.host.routeAttemptActive(key)) return this.setRetry(retries, first.workspaceId, now + 1_000)
    const ready = routes.filter(peer => now >= this.host.retryAt(this.host.peerKey(peer.workspaceId, peer.deviceId, peer.instanceId), now))
    if (ready.length) return void this.host.dial(ready, signal)
    this.setRetry(retries, first.workspaceId, Math.min(...routes.map(peer =>
      this.host.retryAt(this.host.peerKey(peer.workspaceId, peer.deviceId, peer.instanceId), now))))
  }

  private setRetry(retries: Record<string, number>, workspaceId: string, retryAt: number): void {
    retries[workspaceId] = Math.min(retries[workspaceId] ?? Infinity, retryAt)
  }
}
