import { meshRustRuntime } from "@meta-uber/mesh-replication/runtime"

export type BrowserDialPeer = {
  workspaceId: string
  deviceId: string
  instanceId?: string
  revokedAt?: string | null
}

export type BrowserMeshDialHost<P extends BrowserDialPeer> = {
  peers(): Promise<P[]>
  hasSession(workspaceId: string, deviceId: string, instanceId?: string): boolean
  peerKey(workspaceId: string, deviceId: string, instanceId?: string): string
  routeFailures(key: string): number
  retryAt(key: string, fallback: number): number
  routeAttemptActive(key: string): boolean
  dial(routes: P[], signal: AbortSignal): Promise<void>
  onRetries(retries: Record<string, number>): void
}

/** Browser I/O adapter for Rust dial selection and retry scheduling. */
export class BrowserMeshDialScheduler<P extends BrowserDialPeer> {
  constructor(private readonly host: BrowserMeshDialHost<P>) {}

  async schedule(localDeviceId: string, localInstanceId: string, signal: AbortSignal, now = Date.now()): Promise<void> {
    const peers = await this.host.peers()
    const plan = meshRustRuntime().state.planDialSchedule({ localDeviceId, localInstanceId, nowMs: now,
      routes: peers.map(peer => {
        const key = this.host.peerKey(peer.workspaceId, peer.deviceId, peer.instanceId)
        return { workspaceId: peer.workspaceId, deviceId: peer.deviceId, instanceId: peer.instanceId ?? "legacy", revoked: Boolean(peer.revokedAt),
          health: -this.host.routeFailures(key), retryAtMs: this.host.retryAt(key, now),
          hasSession: this.host.hasSession(peer.workspaceId, peer.deviceId, peer.instanceId),
          attemptActive: this.host.routeAttemptActive(key) }
      }) })
    if (!signal.aborted) for (const indices of plan.readyGroups) void this.host.dial(indices.map(index => peers[index]!), signal)
    this.host.onRetries(plan.retries)
  }
}
