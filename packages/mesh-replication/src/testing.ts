import type { DeviceBatch, DeviceRoute, DurableBatchAck, RouteBatchSender } from "./protocol"

export class ManualClock {
  constructor(private current: number = 0) {}

  now = (): number => this.current

  advance(milliseconds: number): void {
    if (!Number.isFinite(milliseconds) || milliseconds < 0) throw new Error("Invalid clock advance")
    this.current += milliseconds
  }
}

export class SequenceRandom {
  private cursor = 0

  constructor(private readonly values: readonly number[]) {
    if (values.length === 0 || values.some(value => value < 0 || value >= 1)) {
      throw new Error("Random sequence must contain values in [0, 1)")
    }
  }

  next = (): number => {
    const value = this.values[this.cursor % this.values.length]
    this.cursor += 1
    return value
  }
}

export type Admission = {
  batch: DeviceBatch
  acceptedHashes: string[]
  duplicate: boolean
}

export class MemoryDurableBatchStore {
  private readonly changes = new Map<string, Uint8Array>()
  readonly admissions: Admission[] = []

  async admit(batch: DeviceBatch): Promise<Admission> {
    let duplicate = true
    const acceptedHashes: string[] = []
    for (const change of batch.changes) {
      acceptedHashes.push(change.hash)
      if (!this.changes.has(change.hash)) {
        duplicate = false
        this.changes.set(change.hash, change.bytes.slice())
      }
    }
    const admission = { batch, acceptedHashes, duplicate }
    this.admissions.push(admission)
    return admission
  }

  hashes(): string[] {
    return [...this.changes.keys()].sort()
  }
}

type RouteBehavior = "fail-before-commit" | "commit-and-ack" | "commit-and-lose-ack"

export class ScriptedRouteNetwork {
  readonly attempts: string[] = []

  constructor(
    private readonly receiverDeviceId: string,
    private readonly store: MemoryDurableBatchStore,
    private readonly behaviorByRoute: Readonly<Record<string, RouteBehavior>>,
  ) {}

  send: RouteBatchSender = async (route, batch) => {
    this.attempts.push(route.instanceId)
    const behavior = this.behaviorByRoute[route.instanceId] ?? "fail-before-commit"
    if (behavior === "fail-before-commit") throw new Error(`route ${route.instanceId} failed`)
    const admission = await this.store.admit(batch)
    if (behavior === "commit-and-lose-ack") throw new Error(`route ${route.instanceId} lost acknowledgement`)
    return durableAck(batch, this.receiverDeviceId, admission.acceptedHashes)
  }
}

export function deviceRoute(
  instanceId: string,
  sequence = 1,
  overrides: Partial<DeviceRoute> = {},
): DeviceRoute {
  return {
    kind: "mesh-device-route",
    version: 1,
    scopeId: "scope-1",
    personId: "person-remote",
    deviceId: "device-remote",
    instanceId,
    endpoint: `iroh://${instanceId}`,
    sequence,
    issuedAt: "2026-09-15T10:00:00.000Z",
    expiresAt: "2026-09-15T10:10:00.000Z",
    signerKeyId: "device-remote",
    signature: `signature-${instanceId}-${sequence}`,
    ...overrides,
  }
}

export function deviceBatch(batchId = "batch-1", hashes = ["change-1"]): DeviceBatch {
  return {
    protocolVersion: 1,
    scopeId: "scope-1",
    documentId: "document-1",
    batchId,
    changes: hashes.map(hash => ({ hash, bytes: new TextEncoder().encode(hash) })),
  }
}

export function durableAck(batch: DeviceBatch, receiverDeviceId: string, acceptedHashes: string[]): DurableBatchAck {
  return {
    kind: "mesh-durable-batch-ack",
    version: 1,
    scopeId: batch.scopeId,
    documentId: batch.documentId,
    batchId: batch.batchId,
    receiverDeviceId,
    acceptedHashes,
    acceptedHeads: acceptedHashes,
    committedAt: "2026-09-15T10:00:01.000Z",
    signerKeyId: receiverDeviceId,
    signature: `ack-${receiverDeviceId}-${batch.batchId}`,
  }
}
