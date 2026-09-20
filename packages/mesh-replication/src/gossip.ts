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

export interface GossipEngineInterface {
  joinTopic(topicName: string, bootstrapPeers: string[]): string
  leaveTopic(topicName: string): void
  broadcast(topicName: string, content: Uint8Array): Uint8Array
  handleMessage(sender: string, rawPacket: Uint8Array): Uint8Array | undefined
  activeNeighbors(topicName: string): string[]
}

export class IrohGossipTopic {
  readonly topicId: string

  constructor(
    readonly topicName: string,
    private readonly engine: GossipEngineInterface,
    bootstrapPeers: string[] = [],
  ) {
    this.topicId = this.engine.joinTopic(topicName, bootstrapPeers)
  }

  broadcast(message: Uint8Array): Uint8Array {
    return this.engine.broadcast(this.topicName, message)
  }

  receive(sender: string, rawPacket: Uint8Array): Uint8Array | undefined {
    return this.engine.handleMessage(sender, rawPacket)
  }

  activeNeighbors(): string[] {
    return this.engine.activeNeighbors(this.topicName)
  }

  leave(): void {
    this.engine.leaveTopic(this.topicName)
  }
}
import { meshRustRuntime } from "./runtime"

