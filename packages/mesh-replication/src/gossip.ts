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

export type GossipChange = { hash: string; bytes: Uint8Array; proof?: unknown }

export type GossipFrame =
  | { version: 1; kind: "offer"; scopeId: string; documentId: string; hashes: string[] }
  | { version: 1; kind: "want"; scopeId: string; documentId: string; hashes: string[] }
  | { version: 1; kind: "changes"; scopeId: string; documentId: string; changes: GossipChange[] }

export type GossipDispatch = { targetDeviceId: string; frame: GossipFrame }

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

type GossipOptions = {
  bounds?: Partial<GossipBounds>
  authorize(scopeId: string, remoteDeviceId: string, documentId: string): boolean | Promise<boolean>
  hasChange(scopeId: string, documentId: string, hash: string): boolean | Promise<boolean>
  loadChange(scopeId: string, documentId: string, hash: string): GossipChange | undefined | Promise<GossipChange | undefined>
  admitChanges(scopeId: string, documentId: string, changes: readonly GossipChange[], remoteDeviceId: string): readonly string[] | Promise<readonly string[]>
  claim?(documentId: string, targetDeviceId: string, batchId: string): boolean | Promise<boolean>
  now?: () => number
}

export class SparseGossip {
  readonly bounds: GossipBounds
  private readonly candidates = new Map<string, GossipCandidate[]>()
  private readonly neighbors = new Map<string, string[]>()
  private readonly seen = new Map<string, true>()
  private readonly failures = new Map<string, number>()

  constructor(private readonly localDeviceId: string, private readonly options: GossipOptions) {
    this.bounds = { ...DEFAULT_GOSSIP_BOUNDS, ...options.bounds }
    meshRustRuntime().state.selectScopedNeighbors(this.localDeviceId, [], this.bounds, 0, 0)
  }

  updateScope(scopeId: string, candidates: readonly GossipCandidate[], rotation = 0): string[] {
    this.candidates.set(scopeId, [...candidates])
    const selected = selectScopedNeighbors({
      localDeviceId: this.localDeviceId,
      candidates,
      bounds: this.bounds,
      now: this.options.now?.() ?? Date.now(),
      rotation,
    })
    this.neighbors.set(scopeId, selected)
    return selected
  }

  markFailure(scopeId: string, deviceId: string): void {
    const key = `${scopeId}\u0000${deviceId}`
    const count = (this.failures.get(key) ?? 0) + 1
    this.failures.set(key, count)
    const until = (this.options.now?.() ?? Date.now()) + Math.min(this.bounds.baseBackoffMs * 2 ** (count - 1), 60_000)
    const candidates = (this.candidates.get(scopeId) ?? []).map(candidate =>
      candidate.deviceId === deviceId ? { ...candidate, backedOffUntil: until } : candidate)
    this.updateScope(scopeId, candidates, count)
  }

  neighborDevices(scopeId: string): string[] {
    return [...(this.neighbors.get(scopeId) ?? [])]
  }

  underConnected(scopeId: string): boolean {
    return this.neighborDevices(scopeId).length < this.bounds.low
  }

  async publish(scopeId: string, documentId: string, hashes: readonly string[]): Promise<GossipDispatch[]> {
    const bounded = [...new Set(hashes)].slice(0, this.bounds.maximumOfferHashes)
    if (bounded.length === 0) return []
    const batchId = bounded.join(".")
    const result: GossipDispatch[] = []
    for (const targetDeviceId of this.neighborDevices(scopeId).slice(0, this.bounds.eagerFanout)) {
      if (!await this.options.authorize(scopeId, targetDeviceId, documentId)) continue
      if (this.options.claim && !await this.options.claim(documentId, targetDeviceId, batchId)) continue
      result.push({ targetDeviceId, frame: { version: 1, kind: "offer", scopeId, documentId, hashes: bounded } })
    }
    return result
  }

  async receive(remoteDeviceId: string, frame: GossipFrame): Promise<GossipDispatch[]> {
    this.validateFrame(frame)
    if (!await this.options.authorize(frame.scopeId, remoteDeviceId, frame.documentId)) throw new Error("Unauthorized gossip scope")
    if (frame.kind === "offer") {
      const hashes: string[] = []
      for (const hash of frame.hashes) {
        if (!await this.options.hasChange(frame.scopeId, frame.documentId, hash)) hashes.push(hash)
        if (hashes.length >= this.bounds.maximumWants) break
      }
      return hashes.length ? [{ targetDeviceId: remoteDeviceId, frame: {
        version: 1, kind: "want", scopeId: frame.scopeId, documentId: frame.documentId, hashes,
      } }] : []
    }
    if (frame.kind === "want") {
      const changes: GossipChange[] = []
      for (const hash of frame.hashes) {
        const change = await this.options.loadChange(frame.scopeId, frame.documentId, hash)
        if (change) changes.push(change)
        if (changes.length >= this.bounds.maximumChanges) break
      }
      return changes.length ? [{ targetDeviceId: remoteDeviceId, frame: {
        version: 1, kind: "changes", scopeId: frame.scopeId, documentId: frame.documentId, changes,
      } }] : []
    }

    const fresh = frame.changes.filter(change => !this.seen.has(`${frame.scopeId}\u0000${frame.documentId}\u0000${change.hash}`))
    const accepted = await this.options.admitChanges(frame.scopeId, frame.documentId, fresh, remoteDeviceId)
    for (const hash of accepted) this.remember(`${frame.scopeId}\u0000${frame.documentId}\u0000${hash}`)
    if (accepted.length === 0) return []
    return (await this.publish(frame.scopeId, frame.documentId, accepted))
      .filter(dispatch => dispatch.targetDeviceId !== remoteDeviceId)
  }

  private remember(key: string): void {
    this.seen.delete(key)
    this.seen.set(key, true)
    while (this.seen.size > this.bounds.seenCapacity) this.seen.delete(this.seen.keys().next().value!)
  }

  private validateFrame(frame: GossipFrame): void {
    if (frame?.version !== 1 || !frame.scopeId || !frame.documentId || !["offer", "want", "changes"].includes(frame.kind)) {
      throw new Error("Invalid gossip frame")
    }
    if ((frame.kind === "offer" && frame.hashes.length > this.bounds.maximumOfferHashes) ||
      (frame.kind === "want" && frame.hashes.length > this.bounds.maximumWants) ||
      (frame.kind === "changes" && frame.changes.length > this.bounds.maximumChanges)) throw new Error("Gossip frame exceeds item limit")
    const hashes = frame.kind === "changes" ? frame.changes.map(change => change.hash) : frame.hashes
    if (hashes.some(hash => typeof hash !== "string" || !hash || hash.length > 256) || new Set(hashes).size !== hashes.length) {
      throw new Error("Invalid gossip hashes")
    }
    if (frame.kind === "changes" && frame.changes.some(change => !(change.bytes instanceof Uint8Array))) {
      throw new Error("Invalid gossip change bytes")
    }
    let byteLength: number
    try {
      byteLength = frame.kind === "changes"
        ? frame.changes.reduce((total, change) => total + change.hash.length + change.bytes.byteLength + JSON.stringify(change.proof ?? null).length, 0)
        : frame.hashes.reduce((total, hash) => total + hash.length, 0)
    } catch {
      throw new Error("Invalid gossip proof")
    }
    if (byteLength > this.bounds.maximumFrameBytes) throw new Error("Gossip frame exceeds byte limit")
  }
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

export interface GossipEngineInterface {
  joinTopic(topicName: string, bootstrapPeers: string[]): Promise<string>
  leaveTopic(topicName: string): Promise<void>
  broadcast(topicName: string, content: Uint8Array): Promise<void>
  handleMessage(sender: string, rawPacket: Uint8Array): Promise<GossipDelivery[]>
  activeNeighbors(topicName: string): string[]
}

export class IrohGossipTopic {
  topicId = ""

  constructor(
    readonly topicName: string,
    private readonly engine: GossipEngineInterface,
    bootstrapPeers: string[] = [],
  ) {
    this.ready = this.engine.joinTopic(topicName, bootstrapPeers).then(topicId => { this.topicId = topicId })
  }

  private readonly ready: Promise<void>

  async broadcast(message: Uint8Array): Promise<void> {
    await this.ready
    await this.engine.broadcast(this.topicName, message)
  }

  async receive(sender: string, rawPacket: Uint8Array): Promise<GossipDelivery[]> {
    await this.ready
    return this.engine.handleMessage(sender, rawPacket)
  }

  activeNeighbors(): string[] {
    return this.engine.activeNeighbors(this.topicName)
  }

  async leave(): Promise<void> {
    await this.ready
    await this.engine.leaveTopic(this.topicName)
  }
}
import { meshRustRuntime } from "./runtime"
