import { meshRustRuntime } from "./runtime"

export type GossipBounds = {
  low: number
  target: number
  high: number
  eagerFanout: number
  maximumOfferHashes: number
  maximumWants: number
  maximumChanges: number
  maximumFrameBytes: number
  seenCapacity: number
  baseBackoffMs: number
}

export const DEFAULT_GOSSIP_BOUNDS: GossipBounds = {
  low: 2,
  target: 4,
  high: 6,
  eagerFanout: 3,
  maximumOfferHashes: 64,
  maximumWants: 64,
  maximumChanges: 32,
  maximumFrameBytes: 256 * 1024,
  seenCapacity: 2_048,
  baseBackoffMs: 1_000,
}

export type GossipCandidate = {
  deviceId: string
  health?: number
  backedOffUntil?: number
}

export function selectScopedNeighbors(input: {
  localDeviceId: string
  candidates: readonly GossipCandidate[]
  bounds?: GossipBounds
  now?: number
  rotation?: number
}): string[] {
  const bounds = input.bounds ?? DEFAULT_GOSSIP_BOUNDS
  return meshRustRuntime().state.selectScopedNeighbors(
    input.localDeviceId,
    input.candidates,
    bounds,
    input.now ?? Date.now(),
    input.rotation ?? 0,
  )
}

export type GossipSend = { peer: string; packet: Uint8Array }
export type GossipDelivery = { topic: string; deliveredFrom: string; content: Uint8Array }
export type GossipScheduledTimer = { timerId: bigint | number; delayMs: bigint | number }
export type GossipStep = {
  topicId?: string
  sends: GossipSend[]
  deliveries: GossipDelivery[]
  timers: GossipScheduledTimer[]
  disconnects: string[]
  neighborsUp: string[]
  neighborsDown: string[]
}

export interface GossipStateMachine {
  joinTopic(topicName: string, bootstrapPeers: string[]): GossipStep
  leaveTopic(topicName: string): GossipStep
  broadcast(topicName: string, content: Uint8Array): GossipStep
  handleMessage(sender: string, rawPacket: Uint8Array): GossipStep
  expireTimer(timerId: bigint): GossipStep
  peerDisconnected(peer: string): GossipStep
  activeNeighbors(topicName: string): string[]
}

export type BrowserGossipTransport = {
  send(peer: string, packet: Uint8Array): Promise<void>
  disconnect?(peer: string): Promise<void> | void
  deliver?(delivery: GossipDelivery): Promise<void> | void
}

export class BrowserGossipDriver {
  private queue: Promise<void> = Promise.resolve()
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>()
  private closed = false

  constructor(
    private readonly state: GossipStateMachine,
    private readonly transport: BrowserGossipTransport,
  ) {}

  joinTopic(topicName: string, bootstrapPeers: string[]): Promise<string> {
    return this.enqueue(() => this.state.joinTopic(topicName, bootstrapPeers))
      .then(step => step.topicId ?? "")
  }

  leaveTopic(topicName: string): Promise<void> {
    return this.enqueue(() => this.state.leaveTopic(topicName)).then(() => undefined)
  }

  broadcast(topicName: string, content: Uint8Array): Promise<void> {
    return this.enqueue(() => this.state.broadcast(topicName, content)).then(() => undefined)
  }

  handleMessage(sender: string, rawPacket: Uint8Array): Promise<GossipDelivery[]> {
    return this.enqueue(() => this.state.handleMessage(sender, rawPacket)).then(step => step.deliveries)
  }

  peerDisconnected(peer: string): Promise<void> {
    return this.enqueue(() => this.state.peerDisconnected(peer)).then(() => undefined)
  }

  activeNeighbors(topicName: string): string[] {
    return this.state.activeNeighbors(topicName)
  }

  close(): void {
    this.closed = true
    for (const timer of this.timers.values()) clearTimeout(timer)
    this.timers.clear()
  }

  private enqueue(operation: () => GossipStep): Promise<GossipStep> {
    let result!: GossipStep
    const run = this.queue.then(async () => {
      if (this.closed) throw new Error("Gossip driver is closed")
      result = operation()
      await this.drive(result)
    })
    this.queue = run.catch(() => undefined)
    return run.then(() => result)
  }

  private async drive(initial: GossipStep): Promise<void> {
    const pending = [initial]
    while (pending.length) {
      const step = pending.shift()!
      for (const timer of step.timers) this.scheduleTimer(timer)
      for (const delivery of step.deliveries) await this.transport.deliver?.(delivery)
      for (const peer of step.disconnects) await this.transport.disconnect?.(peer)
      for (const send of step.sends) {
        try {
          await this.transport.send(send.peer, send.packet)
        } catch {
          pending.push(this.state.peerDisconnected(send.peer))
        }
      }
    }
  }

  private scheduleTimer(timer: GossipScheduledTimer): void {
    const key = String(timer.timerId)
    const previous = this.timers.get(key)
    if (previous) clearTimeout(previous)
    const delay = Math.max(0, Math.min(Number(timer.delayMs), 2_147_483_647))
    const handle = setTimeout(() => {
      this.timers.delete(key)
      if (!this.closed) void this.enqueue(() => this.state.expireTimer(BigInt(timer.timerId)))
    }, delay)
    this.timers.set(key, handle)
  }
}
